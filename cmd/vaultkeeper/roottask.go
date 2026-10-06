package main

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"github.com/afterdarksys/secretserver-autohsm/internal/ceremony"
	"github.com/afterdarksys/secretserver-autohsm/internal/config"
	"github.com/afterdarksys/secretserver-autohsm/internal/secure"
	"github.com/afterdarksys/secretserver-autohsm/internal/vaultclient"
)

// The task allowlist, v1. Hardcoded on purpose: there is no free-form path,
// no shell, and no way to add a task without changing this file.
const (
	taskRevokeToken = "revoke-token"
	taskRekeyCancel = "rekey-cancel"
	taskPolicyWrite = "policy-write"
)

const maxPolicySize = 64 << 10

var (
	accessorRE   = regexp.MustCompile(`^[A-Za-z0-9]{24}$`)
	policyNameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)
	sha256RE     = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// task is one fully validated allowlisted task. Everything it needs (for
// policy-write, the policy bytes) is loaded and checked before any ceremony
// starts, so a bad argument never costs a root token.
type task struct {
	name       string
	accessor   string
	policyName string
	policy     []byte
}

func parseTask(args []string, policyDir string) (*task, error) {
	if len(args) == 0 {
		return nil, usageError{fmt.Errorf("root-task needs a task: %s <accessor> | %s | %s <name> <sha256>", taskRevokeToken, taskRekeyCancel, taskPolicyWrite)}
	}
	switch args[0] {
	case taskRevokeToken:
		if len(args) != 2 {
			return nil, usageError{fmt.Errorf("%s takes exactly one accessor", taskRevokeToken)}
		}
		if !accessorRE.MatchString(args[1]) {
			return nil, usageError{fmt.Errorf("%s: accessor must be 24 alphanumeric characters", taskRevokeToken)}
		}
		return &task{name: taskRevokeToken, accessor: args[1]}, nil
	case taskRekeyCancel:
		if len(args) != 1 {
			return nil, usageError{fmt.Errorf("%s takes no arguments", taskRekeyCancel)}
		}
		return &task{name: taskRekeyCancel}, nil
	case taskPolicyWrite:
		if len(args) != 3 {
			return nil, usageError{fmt.Errorf("%s takes <name> <sha256>", taskPolicyWrite)}
		}
		name, sum := args[1], args[2]
		if !policyNameRE.MatchString(name) || name == "root" {
			return nil, usageError{fmt.Errorf("%s: invalid policy name %q", taskPolicyWrite, name)}
		}
		if !sha256RE.MatchString(sum) {
			return nil, usageError{fmt.Errorf("%s: sha256 must be 64 lowercase hex characters", taskPolicyWrite)}
		}
		if policyDir == "" {
			return nil, fmt.Errorf("%s: policy_dir is not configured", taskPolicyWrite)
		}
		policy, err := readPinnedFile(filepath.Join(policyDir, name+".hcl"), sum)
		if err != nil {
			return nil, err
		}
		return &task{name: taskPolicyWrite, policyName: name, policy: policy}, nil
	}
	return nil, usageError{fmt.Errorf("task %q is not on the allowlist (%s, %s, %s)", args[0], taskRevokeToken, taskRekeyCancel, taskPolicyWrite)}
}

// readPinnedFile reads path once and returns its bytes only if their SHA-256
// equals want. The bytes returned are the bytes hashed: no re-read later.
func readPinnedFile(path, want string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	b, err := config.ReadBounded(f, maxPolicySize)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	sum := sha256.Sum256(b)
	got := hex.EncodeToString(sum[:])
	if subtle.ConstantTimeCompare([]byte(got), []byte(want)) != 1 {
		return nil, fmt.Errorf("%s: sha256 is %s, not the pinned %s", path, got, want)
	}
	return b, nil
}

func (vk *app) cmdRootTask(ctx context.Context, a *cliArgs) error {
	if err := requireApproval(a.approval); err != nil {
		return err
	}
	if err := vk.cfg.requireCeremony(); err != nil {
		return err
	}
	t, err := parseTask(a.positional, vk.cfg.PolicyDir)
	if err != nil {
		return err
	}
	return vk.rootTask(ctx, t)
}

// rootTask runs the whole ceremony. Once a root token exists, every return
// path (including a cancelled context from SIGTERM) goes through the
// deferred revoke, and success is reported only if revocation is verified.
func (vk *app) rootTask(ctx context.Context, t *task) (err error) {
	cur, err := vk.vc.GenerateRootAttempt(ctx)
	if err != nil {
		return fmt.Errorf("read generate-root attempt: %w", err)
	}
	if cur.Started {
		vk.notifier.Event(ctx, "vaultkeeper_foreign_attempt", "vaultkeeper",
			fmt.Sprintf("op=generate-root nonce=%.8s pgp_fingerprint=%q", cur.Nonce, cur.PGPFingerprint))
		return fmt.Errorf("a generate-root attempt (nonce %.8s, pgp_fingerprint %q) is already in progress; refusing to start and NOT cancelling it", cur.Nonce, cur.PGPFingerprint)
	}

	pub, err := vk.gpg.ExportPublicKey(ctx, vk.cfg.OperatorFingerprint)
	if err != nil {
		return err
	}
	// The ceremony token must be created after this instant (Vault reports
	// creation_time in whole seconds; allow clock skew).
	started := time.Now()
	st, err := vk.vc.StartGenerateRoot(ctx, pub)
	if err != nil {
		return fmt.Errorf("start generate-root: %w", err)
	}
	nonce := st.Nonce
	if err := ceremony.CheckGenerateRoot(st, vk.cfg.OperatorFingerprint); err != nil {
		vk.cancelGenerateRootIfOurs(nonce)
		return fmt.Errorf("vault did not lock the attempt to the operator key: %w", err)
	}
	if err := vk.recordAttempt(ceremony.OpGenerateRoot, nonce); err != nil {
		vk.cancelGenerateRootIfOurs(nonce)
		return err
	}
	defer vk.clearAttempt(ceremony.OpGenerateRoot)
	vk.log.Info("generate-root started", "nonce", nonce[:8], "required", st.Required)

	res, err := vk.collect(ctx, ceremony.OpGenerateRoot, nonce, func(ctx context.Context) (attemptView, error) {
		s, err := vk.vc.GenerateRootAttempt(ctx)
		if err != nil {
			return attemptView{}, err
		}
		// generate-root clears the attempt on completion, so "consumed" is
		// "our nonce is no longer the current attempt".
		current := s.Started && s.Nonce == nonce
		return attemptView{current: current, done: !current, progress: s.Progress, required: s.Required}, nil
	})
	if err != nil {
		if !vk.cancelGenerateRootIfOurs(nonce) {
			// Our attempt is gone: it may have completed, in which case a
			// root token exists, encrypted to the operator key.
			vk.notifier.Event(context.Background(), "vaultkeeper_root_undecrypted", "vaultkeeper",
				"nonce="+nonce[:8]+" attempt ended (completed or cancelled) without a usable result; a root token may be live")
		}
		return err
	}
	undecrypted := func(why string) {
		where := vk.preserve(res)
		vk.notifier.Event(context.Background(), "vaultkeeper_root_undecrypted", "vaultkeeper",
			"nonce="+nonce[:8]+" "+why+"; encrypted result at "+where)
	}
	if !ceremony.FingerprintEqual(res.PGPFingerprint, vk.cfg.OperatorFingerprint) {
		undecrypted("result not encrypted to the operator key")
		return fmt.Errorf("result is not encrypted to the operator key")
	}
	ct, err := base64.StdEncoding.DecodeString(res.EncodedToken)
	if err != nil {
		undecrypted("result token is not base64")
		return fmt.Errorf("decode encrypted token: %w", err)
	}
	// A signal must not abandon a decrypt halfway: once gpg returns the token
	// we can revoke it, whereas a killed decrypt leaves an unrevokable root.
	dctx, dcancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Minute)
	token, err := vk.gpg.Decrypt(dctx, ct)
	dcancel()
	if err != nil {
		undecrypted("decrypt failed")
		return fmt.Errorf("a root token was generated but could not be decrypted, so it cannot be revoked by this run; "+
			"it is usable only with the operator key. Decrypt the saved result line by hand and revoke it: %w", err)
	}

	// From here on a root token exists. Revoke it on every path.
	accessor := ""
	label := "root token"
	defer func() {
		rerr := vk.revokeAndVerify(token, accessor, label)
		secure.Wipe(token)
		if rerr != nil {
			err = errors.Join(err, rerr)
		}
	}()

	info, err := vk.vc.LookupSelf(ctx, token)
	if err != nil {
		return fmt.Errorf("lookup of generated token: %w", err)
	}
	accessor = info.Accessor
	if ferr := freshRootToken(info, started); ferr != nil {
		label = "rejected token"
		// Not this ceremony's token (for example a pre-minted root token
		// encrypted to the operator key and substituted for the real
		// result). It is revoked below; the real ceremony token may be live.
		undecrypted("substituted token rejected (" + ferr.Error() + "); the real ceremony token may be live")
		return fmt.Errorf("decrypted token is not a fresh root token from this ceremony (%w); "+
			"it will be revoked, but the real ceremony token may still be live", ferr)
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("interrupted before task: %w", err)
	}
	if err := vk.runTask(ctx, token, accessor, t); err != nil {
		return fmt.Errorf("task %s: %w", t.name, err)
	}
	vk.log.Info("task completed", "task", t.name)
	return nil
}

// rootSkew tolerates clock skew between this host and Vault.
const rootSkew = 5 * time.Second

// freshRootToken requires exactly what generate-root produces: policies
// exactly [root], no TTL, no expiry, created by auth/token/root, and created
// after this ceremony's attempt started.
func freshRootToken(info *vaultclient.TokenInfo, started time.Time) error {
	if len(info.Policies) != 1 || info.Policies[0] != "root" {
		return fmt.Errorf("policies %v, want exactly [root]", info.Policies)
	}
	if info.TTL != 0 || info.ExpireTime != nil {
		return fmt.Errorf("token expires; a generated root token does not")
	}
	if info.Path != "auth/token/root" {
		return fmt.Errorf("token was created by %q, not generate-root", info.Path)
	}
	if info.CreationTime < started.Add(-rootSkew).Unix() {
		return fmt.Errorf("token was created before this ceremony started")
	}
	return nil
}

func (vk *app) runTask(ctx context.Context, token []byte, ownAccessor string, t *task) error {
	switch t.name {
	case taskRevokeToken:
		if subtle.ConstantTimeCompare([]byte(t.accessor), []byte(ownAccessor)) == 1 {
			return fmt.Errorf("refusing to revoke the ceremony's own token as the task")
		}
		if err := vk.vc.RevokeAccessor(ctx, token, t.accessor); err != nil {
			return err
		}
		// Prove it: the accessor must now be unknown to Vault.
		_, err := vk.vc.LookupAccessor(ctx, token, t.accessor)
		var apiErr *vaultclient.APIError
		if err == nil {
			return fmt.Errorf("accessor still resolves after revoke")
		}
		if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusBadRequest {
			return fmt.Errorf("could not confirm revocation: %w", err)
		}
		fmt.Fprintf(vk.out, "revoked token accessor %s (lookup now: %s)\n", t.accessor, apiErr.Status)
		return nil
	case taskRekeyCancel:
		rk, err := vk.vc.RekeyAttempt(ctx)
		if err != nil {
			return err
		}
		if !rk.Started {
			fmt.Fprintln(vk.out, "no rekey attempt in progress")
			return nil
		}
		if err := vk.vc.CancelRekey(ctx, token, rk.Nonce); err != nil {
			return err
		}
		fmt.Fprintln(vk.out, "rekey attempt cancelled")
		return nil
	case taskPolicyWrite:
		if err := vk.vc.WritePolicy(ctx, token, t.policyName, t.policy); err != nil {
			return err
		}
		sum := sha256.Sum256(t.policy)
		fmt.Fprintf(vk.out, "wrote policy %s (sha256 %s)\n", t.policyName, hex.EncodeToString(sum[:]))
		return nil
	}
	return fmt.Errorf("task %q is not on the allowlist", t.name)
}

// revokeAndVerify revokes the ceremony token and proves it with a lookup
// that must return 403. It deliberately ignores the caller's context: it
// must also run after SIGTERM cancelled that context.
func (vk *app) revokeAndVerify(token []byte, accessor, label string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	var last error
	for i := 0; i < 6 && ctx.Err() == nil; i++ {
		if i > 0 {
			select {
			case <-ctx.Done():
			case <-time.After(time.Duration(i) * vk.revokeBackoff):
			}
		}
		if err := vk.vc.RevokeSelf(ctx, token); err != nil {
			last = err
		}
		_, err := vk.vc.LookupSelf(ctx, token)
		var apiErr *vaultclient.APIError
		if errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusForbidden {
			if label == "root token" {
				fmt.Fprintln(vk.out, "root token revoked (lookup-self: 403)")
			} else {
				fmt.Fprintln(vk.out, label+" revoked/invalid (lookup-self: 403)")
			}
			vk.log.Info(label+" revoked and verified", "accessor", accessor)
			return nil
		}
		if err == nil {
			last = fmt.Errorf("token still valid after revoke-self")
		} else {
			last = err
		}
	}
	vk.notifier.Event(context.Background(), "vaultkeeper_root_revoke_unverified", "vaultkeeper", "accessor="+accessor)
	return fmt.Errorf("ROOT TOKEN REVOCATION NOT VERIFIED (accessor %s): revoke it now; last error: %v", accessor, last)
}

// cancelGenerateRootIfOurs cancels the current attempt only if it is still
// the one we started. Someone else's attempt is never cancelled. It reports
// whether our attempt was still current.
func (vk *app) cancelGenerateRootIfOurs(nonce string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cur, err := vk.vc.GenerateRootAttempt(ctx)
	if err != nil {
		return true // unknown: do not claim it ended
	}
	if !cur.Started || cur.Nonce != nonce {
		return false
	}
	if err := vk.vc.CancelGenerateRoot(ctx, nil); err != nil {
		vk.log.Warn("could not cancel our generate-root attempt", "nonce", nonce[:8], "error", err)
		return true
	}
	vk.log.Info("cancelled our generate-root attempt", "nonce", nonce[:8])
	return true
}
