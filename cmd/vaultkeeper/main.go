// Command vaultkeeper runs Vault without a standing root token. Root exists only
// for minutes, for one allowlisted task, opened with the operator's PGP key and
// revoked (and the revocation verified) on every exit path. Unseal-key quorum comes
// from autohsm nodes, each contributing its own HSM-wrapped share directly to Vault.
//
// Subcommands:
//
//	root-task <task> --approval-contract FILE   generate root, run one task, revoke
//	rekey --approval-contract FILE              new 5/3 shares; re-wrap 1..4 on the nodes
//	rotate-keyring                              rotate the barrier key via a narrow AppRole
//	status                                      seal, keyring age, foreign ceremony attempts
//
// Threats: Protects against a standing root token existing at all; against a root token
// outliving its single task (revoked on success, on error, and on SIGTERM/SIGINT/SIGHUP,
// then verified by a lookup that must return 403; exit 0 requires that proof); against
// free-form use of root (three hardcoded tasks, arguments validated, the policy file
// pinned by SHA-256); against someone else's ceremony being hijacked or cancelled
// (vaultkeeper refuses to start while any attempt exists and only ever cancels an attempt
// whose nonce it started); against a share or decrypted token reaching disk, stdout,
// logs or alarms (gpg decrypts into a pipe; new node shares go to the node over stdin;
// new shares are written to disk only PGP-encrypted); and against share-harvesting
// attempts (nodes contribute only to attempts pinned to the operator key; status alarms
// on any attempt vaultkeeper did not start); and against forged or substituted results
// (a result is trusted only once Vault shows the attempt consumed; a decrypted token must
// be a fresh auth/token/root token created after the attempt started; a rekey requires
// Vault-side verification of shares 1-3 before Vault switches, a local Shamir proof that
// share 4 lies on the same polynomial before anything is delivered, share 5 counted only
// after verify-share5, every encrypted share saved first and deleted only by rekey-cleanup
// after an unseal drill, and nothing ever gated on a node's own selftest report).
// Does NOT protect against: root on 3 nodes at once; code on the operator workstation
// that captures the gpg passphrase (until the hardware-key upgrade; after it, only during
// a touch); a malicious Vault binary on the vault host; an operator who can be induced to
// approve a ceremony and touch the key; or an attacker cancelling attempts (DoS).
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/afterdarksys/secretserver-autohsm/internal/alarm"
	"github.com/afterdarksys/secretserver-autohsm/internal/ceremony"
	"github.com/afterdarksys/secretserver-autohsm/internal/vaultclient"
)

// Exit codes.
const (
	exitOK      = 0
	exitFail    = 1
	exitUsage   = 64
	exitSealed  = 2
	exitForeign = 3
)

func main() {
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	// Caught for the whole run: a terminating signal cancels the context, and
	// root-task's deferred revoke still runs before the process exits.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	code := run(ctx, os.Args[1:], os.Stdin, os.Stdout, os.Stderr, log)
	stop()
	os.Exit(code)
}

func usage(w io.Writer) {
	fmt.Fprint(w, `vaultkeeper — no standing Vault root token

usage:
  vaultkeeper root-task revoke-token <accessor>       --approval-contract FILE [--config PATH]
  vaultkeeper root-task rekey-cancel                  --approval-contract FILE [--config PATH]
  vaultkeeper root-task policy-write <name> <sha256>  --approval-contract FILE [--config PATH]
  vaultkeeper rekey --approval-contract FILE [--shred-init-file PATH] [--config PATH]
  vaultkeeper verify-share5 <vault-share5.STAMP.gpg> [--config PATH]   (needs the offline key)
  vaultkeeper rekey-cleanup <STAMP> [--shred-init-file PATH] [--config PATH]
  vaultkeeper rotate-keyring [--config PATH]
  vaultkeeper status [--config PATH]

default config: `+defaultConfigPath()+`
`)
}

type cliArgs struct {
	cmd        string
	positional []string
	config     string
	approval   string
	shredInit  string
}

func parseArgs(args []string) (*cliArgs, error) {
	if len(args) == 0 {
		return nil, fmt.Errorf("missing subcommand")
	}
	a := &cliArgs{cmd: args[0], config: defaultConfigPath()}
	for i := 1; i < len(args); i++ {
		v := args[i]
		next := func() (string, error) {
			if i+1 >= len(args) || args[i+1] == "" {
				return "", fmt.Errorf("%s needs a value", v)
			}
			i++
			return args[i], nil
		}
		var err error
		switch v {
		case "--config":
			a.config, err = next()
		case "--approval-contract":
			a.approval, err = next()
		case "--shred-init-file":
			a.shredInit, err = next()
		default:
			if strings.HasPrefix(v, "-") {
				return nil, fmt.Errorf("unknown flag %q", v)
			}
			a.positional = append(a.positional, v)
		}
		if err != nil {
			return nil, err
		}
	}
	return a, nil
}

// operatorKey is the operator's PGP key as held by gpg (see GPG).
type operatorKey interface {
	ExportPublicKey(ctx context.Context, fpr string) (string, error)
	Decrypt(ctx context.Context, ciphertext []byte) ([]byte, error)
	DecryptFor(ctx context.Context, fpr string, ciphertext []byte) ([]byte, error)
}

// app is one vaultkeeper invocation with its dependencies.
type app struct {
	cfg      *Config
	vc       *vaultclient.Client
	gpg      operatorKey
	runner   Runner
	notifier *alarm.Notifier
	log      *slog.Logger
	out      io.Writer
	in       io.Reader
	// revokeBackoff is the base delay between revoke attempts.
	revokeBackoff time.Duration
}

func run(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer, log *slog.Logger) int {
	a, err := parseArgs(args)
	if err != nil {
		fmt.Fprintln(stderr, err)
		usage(stderr)
		return exitUsage
	}
	switch a.cmd {
	case "root-task", "rekey", "rotate-keyring", "status", "verify-share5", "rekey-cleanup":
	case "-h", "--help", "help":
		usage(stdout)
		return exitOK
	default:
		usage(stderr)
		return exitUsage
	}

	vk, err := newApp(a, stdin, stdout, stderr, log)
	if err != nil {
		// Before the notifier exists no alarm can be sent: this error line
		// (stderr, so the journal under systemd) and the exit status are the
		// only signal. Monitor the unit's failed state.
		log.Error("setup failed; no alarm could be sent", "command", a.cmd, "error", err)
		return exitFail
	}
	switch a.cmd {
	case "root-task":
		err = vk.cmdRootTask(ctx, a)
	case "rekey":
		err = vk.cmdRekey(ctx, a)
	case "rotate-keyring":
		err = vk.cmdRotate(ctx)
	case "verify-share5":
		err = vk.cmdVerifyShare5(ctx, a)
	case "rekey-cleanup":
		err = vk.cmdRekeyCleanup(ctx, a)
	case "status":
		return vk.cmdStatus(ctx)
	}
	if err != nil {
		log.Error(a.cmd+" failed", "error", err)
		var u usageError
		if errors.As(err, &u) {
			return exitUsage
		}
		return exitFail
	}
	return exitOK
}

type usageError struct{ error }

func newApp(a *cliArgs, stdin io.Reader, stdout, stderr io.Writer, log *slog.Logger) (*app, error) {
	cfg, err := loadConfig(a.config)
	if err != nil {
		return nil, err
	}
	vc, err := cfg.vaultClient()
	if err != nil {
		return nil, err
	}
	notifier, err := newNotifier(cfg, log)
	if err != nil {
		return nil, err
	}
	vk := &app{cfg: cfg, vc: vc, gpg: &GPG{Path: cfg.GPGPath, Operator: cfg.OperatorFingerprint},
		notifier: notifier, log: log, out: stdout, in: stdin, revokeBackoff: time.Second}
	if len(cfg.Runner.Exec) > 0 {
		vk.runner = &ExecRunner{Argv: cfg.Runner.Exec, Approval: a.approval, Timeout: cfg.Runner.Timeout, Stderr: stderr}
	} else {
		vk.runner = &ManualRunner{Out: stderr, In: stdin, Approval: a.approval}
	}
	return vk, nil
}

// newNotifier builds the alarm notifier, pinning alarm.ca_cert_path when set.
func newNotifier(cfg *Config, log *slog.Logger) (*alarm.Notifier, error) {
	if cfg.Alarm.CACertPath == "" {
		return alarm.New(cfg.Alarm.WebhookURL, log)
	}
	pemBytes, err := os.ReadFile(cfg.Alarm.CACertPath)
	if err != nil {
		return nil, fmt.Errorf("alarm.ca_cert_path: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemBytes) {
		return nil, fmt.Errorf("alarm.ca_cert_path holds no PEM certificate")
	}
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS13}}}
	return alarm.NewWithClient(cfg.Alarm.WebhookURL, client, log)
}

// requireApproval checks the approval contract exists and is a regular file.
// vaultkeeper does not interpret it: the operator's runner enforces it.
func requireApproval(path string) error {
	if path == "" {
		return usageError{fmt.Errorf("--approval-contract FILE is required")}
	}
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("approval contract: %w", err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("approval contract %s is not a regular file", path)
	}
	return nil
}

// attemptView is the part of a generate-root or rekey status the collector
// follows. current and done are decided per operation by the poll function:
// current means our attempt (by nonce) is still the one in Vault; done means
// it has been consumed, so a result can exist. A result line is trusted only
// when done is true.
type attemptView struct {
	current  bool
	done     bool
	progress int
	required int
}

// collect triggers node contributions one node at a time until the attempt
// identified by nonce is consumed, and returns the completing node's result.
// Any output that should have held a result but could not be parsed is
// saved raw to output_dir, so a result is never silently lost.
func (vk *app) collect(ctx context.Context, op, nonce string, poll func(context.Context) (attemptView, error)) (*ceremony.Result, error) {
	for _, node := range vk.cfg.Nodes {
		before, err := poll(ctx)
		if err != nil {
			return nil, err
		}
		if !before.current || before.done {
			return nil, fmt.Errorf("%s attempt %.8s is no longer collecting shares (cancelled or replaced by someone else)", op, nonce)
		}
		vk.log.Info("requesting contribution", "op", op, "node", node.Name, "progress", before.progress, "required", before.required)

		out, cerr := vk.runner.Contribute(ctx, node, op)
		if ctx.Err() != nil {
			if len(out) > 0 {
				vk.saveRaw(op, node, out, "interrupted")
			}
			return nil, ctx.Err()
		}
		var res *ceremony.Result
		var perr error
		if out != nil {
			res, perr = ceremony.FindResult(out)
		}

		var after attemptView
		if res != nil || perr != nil {
			// The output claims completion: check Vault right now. A claim
			// Vault does not back up is rejected below, never waited out.
			if after, err = poll(ctx); err != nil {
				return nil, err
			}
		} else if cerr != nil {
			// The node failed (HSM down, refused): one look at Vault, then
			// move on. It may still have been the completing submitter.
			after, err = poll(ctx)
			if err != nil {
				return nil, err
			}
			if !after.done {
				vk.log.Warn("node did not contribute", "node", node.Name, "error", cerr)
				continue
			}
		} else {
			after, err = vk.waitProgress(ctx, before, poll)
			if err != nil {
				vk.log.Warn("no progress from node", "node", node.Name, "error", err)
				if ctx.Err() != nil {
					return nil, ctx.Err()
				}
				continue
			}
		}

		if !after.done {
			if res != nil || perr != nil {
				// A result while our attempt is still collecting shares is
				// forged or premature. Never trust it.
				return nil, fmt.Errorf("%s returned a result line while attempt %.8s was still in progress; rejected as forged", node.Name, nonce)
			}
			if !after.current {
				return nil, fmt.Errorf("%s attempt was cancelled or replaced during the ceremony", op)
			}
			continue
		}

		// Our attempt is consumed: this node's output must hold the result.
		if res != nil && perr == nil {
			r, cerr := checkResult(res, op, nonce)
			if cerr == nil {
				return r, nil
			}
			perr = cerr
		}
		raw := out
		if out == nil {
			if p, ok := vk.runner.(resultPrompter); ok {
				pasted, err := p.PromptResult(ctx, node, op)
				if err != nil {
					return nil, fmt.Errorf("%s attempt completed but no result line was provided: %w", op, err)
				}
				r, err := ceremony.ParseResult(string(pasted))
				if err == nil {
					r, err = checkResult(r, op, nonce)
				}
				if err == nil {
					return r, nil
				}
				perr, raw = err, pasted
			}
		}
		where := vk.saveRaw(op, node, raw, "unparsed")
		if perr == nil {
			perr = fmt.Errorf("no result line")
		}
		// For generate-root Vault cannot tell completion from cancellation:
		// both clear the attempt.
		return nil, fmt.Errorf("CRITICAL: %s attempt ended (completed or cancelled) at %s but no usable result was returned (%v); raw node output saved to %s",
			op, node.Name, perr, where)
	}
	return nil, fmt.Errorf("%s did not reach threshold with %d nodes", op, len(vk.cfg.Nodes))
}

func checkResult(res *ceremony.Result, op, nonce string) (*ceremony.Result, error) {
	if res.Op != op || res.Nonce != nonce {
		return nil, fmt.Errorf("result line is for %s attempt %.8s, not ours", res.Op, res.Nonce)
	}
	return res, nil
}

// waitProgress polls until progress moves past before, or the attempt is
// consumed or gone.
func (vk *app) waitProgress(ctx context.Context, before attemptView, poll func(context.Context) (attemptView, error)) (attemptView, error) {
	deadline := time.Now().Add(vk.cfg.Runner.Timeout)
	for {
		cur, err := poll(ctx)
		if err == nil && (cur.done || !cur.current || cur.progress > before.progress) {
			return cur, nil
		}
		if time.Now().After(deadline) {
			if err != nil {
				return attemptView{}, err
			}
			return attemptView{}, fmt.Errorf("timed out after %s waiting for progress", vk.cfg.Runner.Timeout)
		}
		select {
		case <-ctx.Done():
			return attemptView{}, ctx.Err()
		case <-time.After(vk.cfg.PollInterval):
		}
	}
}

// saveFile writes data to output_dir/name, 0600, never overwriting.
func (vk *app) saveFile(name string, data []byte) (string, error) {
	if vk.cfg.OutputDir == "" {
		return "", fmt.Errorf("output_dir is not set")
	}
	return vk.saveFileIn(vk.cfg.OutputDir, name, data)
}

// saveFileIn writes data to dir/name, 0600, never overwriting.
func (vk *app) saveFileIn(dir, name string, data []byte) (string, error) {
	p := filepath.Join(dir, name)
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return "", err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return "", err
	}
	return p, f.Close()
}

func stamp() string { return time.Now().UTC().Format("20060102T150405.000000000Z") }

// saveRaw keeps a node's raw output (it holds only progress lines and
// PGP-encrypted results, never a share) when it could not be parsed.
func (vk *app) saveRaw(op string, node Node, raw []byte, why string) string {
	p, err := vk.saveFile(fmt.Sprintf("vaultkeeper-raw-%s-%s-%s.txt", op, node.Name, stamp()), raw)
	if err != nil {
		vk.log.Error("CRITICAL: could not save raw node output", "op", op, "node", node.Name, "error", err)
		fmt.Fprintf(vk.out, "CRITICAL: raw %s output of %s (%s), PGP-encrypted content only:\n%s\n", op, node.Name, why, raw)
		return "(stdout above)"
	}
	fmt.Fprintf(vk.out, "CRITICAL: raw %s output of %s (%s) saved to %s\n", op, node.Name, why, p)
	return p
}

// preserve saves the (PGP-encrypted) result line so a later failure never
// loses it.
func (vk *app) preserve(res *ceremony.Result) string {
	line, err := res.Line()
	if err != nil {
		return ""
	}
	p, err := vk.saveFile(fmt.Sprintf("vaultkeeper-result-%s-%.8s-%s.txt", res.Op, res.Nonce, stamp()), []byte(line+"\n"))
	if err != nil {
		fmt.Fprintln(vk.out, line)
		return "(stdout above)"
	}
	fmt.Fprintf(vk.out, "encrypted result line saved to %s\n", p)
	return p
}
