// Command autohsm keeps a HashiCorp Vault unsealed using key shares that are
// wrapped by an HSM and bound to a configured node context.
//
// Subcommands:
//
//	watch     poll Vault and unseal when sealed (the daemon; this is what systemd runs)
//	status    print Vault's current seal state and exit (exit 2 if sealed)
//	wrap      wrap one unseal share for this node+index, reading plaintext from stdin
//	selftest  verify config, CA pinning, HSM login, and that every share unwraps
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"github.com/afterdarksys/secretserver-autohsm/internal/alarm"
	"github.com/afterdarksys/secretserver-autohsm/internal/config"
	"github.com/afterdarksys/secretserver-autohsm/internal/fingerprint"
	"github.com/afterdarksys/secretserver-autohsm/internal/keysource"
	"github.com/afterdarksys/secretserver-autohsm/internal/secure"
	"github.com/afterdarksys/secretserver-autohsm/internal/vaultclient"
	"github.com/afterdarksys/secretserver-autohsm/internal/watch"
)

const defaultConfigPath = "/etc/autohsm/autohsm.yaml"

// exitSealed is a distinct code so external monitors can alert on "sealed"
// without parsing output.
const exitSealed = 2

// exitTerminal tells systemd that restarting cannot help without operator
// intervention (for example, stale shares or an unsafe threshold layout).
const exitTerminal = 78

const maxShareSize = 4096

func main() {
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}
	cmd := os.Args[1]
	cfgPath := configPathFromArgs(os.Args[2:])

	var err error
	switch cmd {
	case "watch":
		err = runWatch(cfgPath, log)
	case "status":
		err = runStatus(cfgPath)
	case "wrap":
		err = runWrap(cfgPath, os.Args[2:])
	case "selftest":
		err = runSelftest(cfgPath, log)
	case "-h", "--help", "help":
		usage()
		return
	default:
		usage()
		os.Exit(1)
	}

	if err != nil {
		switch exitCode(err) {
		case exitSealed:
			fmt.Fprintln(os.Stderr, err)
			os.Exit(exitSealed)
		case exitTerminal:
			log.Error("terminal failure; operator intervention required", "error", err)
			os.Exit(exitTerminal)
		}
		log.Error("fatal", "error", err)
		os.Exit(1)
	}
}

func exitCode(err error) int {
	var sealed sealedError
	if errors.As(err, &sealed) {
		return exitSealed
	}
	// A rejected PIN is terminal: a restart loop would retry C_Login and burn
	// a hardware token's PIN retry counter. An unusable HSM configuration or
	// key cannot be fixed by restarting either.
	if errors.Is(err, watch.ErrTerminal) || errors.Is(err, keysource.ErrPINRejected) ||
		errors.Is(err, keysource.ErrHSMMisconfigured) {
		return exitTerminal
	}
	return 1
}

func usage() {
	fmt.Fprint(os.Stderr, `autohsm — keep Vault unsealed with HSM-wrapped, context-bound key shares

usage:
  autohsm watch    [--config PATH]              run the daemon (systemd entrypoint)
  autohsm status   [--config PATH]              print seal state; exit 2 if sealed
  autohsm wrap     [--config PATH] --index N    wrap a share read from stdin
  autohsm selftest [--config PATH]              verify config, TLS pin, HSM, and shares

default config: `+defaultConfigPath+`
`)
}

func configPathFromArgs(args []string) string {
	for i, a := range args {
		if a == "--config" && i+1 < len(args) {
			return args[i+1]
		}
		if strings.HasPrefix(a, "--config=") {
			return strings.TrimPrefix(a, "--config=")
		}
	}
	return defaultConfigPath
}

type sealedError struct{ msg string }

func (e sealedError) Error() string { return e.msg }

// build wires config into a Vault client and a key source. daemon must be
// true only for the long-running "watch" subcommand: it refuses a
// pin_env-sourced PIN there, because that value sits exposed in
// /proc/<pid>/environ for as long as the process runs, unlike pin_file
// which is read once and can be tightly permissioned or removed. Short-lived
// subcommands (status, wrap, selftest) do not carry that exposure window.
func build(cfgPath string, daemon bool) (*config.Config, *vaultclient.Client, keysource.Source, error) {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return nil, nil, nil, err
	}
	vc, src, err := buildFromConfig(cfg, daemon)
	if err != nil {
		return nil, nil, nil, err
	}
	return cfg, vc, src, nil
}

func buildFromConfig(cfg *config.Config, daemon bool) (*vaultclient.Client, keysource.Source, error) {
	if daemon && cfg.Keys.Source == "pkcs11" && cfg.Keys.PKCS11.PINEnv != "" {
		return nil, nil, fmt.Errorf(
			"keys.pkcs11.pin_env is not allowed for the watch daemon (it stays exposed in /proc/<pid>/environ for the process's entire lifetime); use keys.pkcs11.pin_file instead")
	}
	vc, err := newVaultClient(cfg)
	if err != nil {
		return nil, nil, err
	}
	src, err := openKeySource(cfg, daemon)
	if err != nil {
		return nil, nil, err
	}
	return vc, src, nil
}

func newVaultClient(cfg *config.Config) (*vaultclient.Client, error) {
	return vaultclient.New(vaultclient.Config{
		Address:    cfg.Vault.Address,
		CACertPath: cfg.Vault.CACertPath,
		Timeout:    cfg.Vault.Timeout,
		MinTLS13:   cfg.Vault.RequireTLS13 != nil && *cfg.Vault.RequireTLS13,
	})
}

// openKeySource opens the configured key source. For the watch daemon
// (deferUnavailable) an HSM that is merely absent at startup does not fail
// the open: the watcher's HSM probe reconnects with backoff and alarms, the
// same path as a mid-run outage. Short-lived commands fail immediately.
func openKeySource(cfg *config.Config, deferUnavailable bool) (keysource.Source, error) {
	switch cfg.Keys.Source {
	case "pkcs11":
		// The PIN is re-read (pin_file) for each login, including a re-login
		// after a lost session, and wiped by the source right after C_Login.
		return keysource.OpenPKCS11(keysource.PKCS11Options{
			ModulePath: cfg.Keys.PKCS11.ModulePath,
			TokenLabel: cfg.Keys.PKCS11.TokenLabel,
			KeyLabel:   cfg.Keys.PKCS11.KeyLabel,
			ReadPIN:    cfg.Keys.PKCS11.ResolvePIN,

			DeferUnavailable: deferUnavailable,
		})
	case "file":
		// Development only; config.Validate already required the explicit opt-in.
		key, err := devKeyFromEnv()
		if err != nil {
			return nil, err
		}
		defer secure.Wipe(key)
		return keysource.NewSoftware(key)
	default:
		return nil, fmt.Errorf("unsupported key source %q", cfg.Keys.Source)
	}
}

// devKeyFromEnv reads the development wrapping key. Deliberately env-only so it
// never lands in a config file that might be committed.
func devKeyFromEnv() ([]byte, error) {
	const env = "AUTOHSM_DEV_KEY"
	v := os.Getenv(env)
	if v == "" {
		return nil, fmt.Errorf("%s must hold a 64-char hex AES-256 key when keys.source=file", env)
	}
	key, err := hexDecode(v)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", env, err)
	}
	return key, nil
}

// randNonce returns a 12-byte GCM nonce from the OS CSPRNG. Never a counter,
// never time-derived: a repeated nonce under the same key breaks GCM entirely.
func randNonce() ([]byte, error) {
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}
	return nonce, nil
}

func hexDecode(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if len(s) != 64 {
		return nil, fmt.Errorf("expected 64 hex characters (32 bytes), got %d", len(s))
	}
	out := make([]byte, 32)
	for i := 0; i < 32; i++ {
		v, err := strconv.ParseUint(s[i*2:i*2+2], 16, 8)
		if err != nil {
			return nil, fmt.Errorf("invalid hex")
		}
		out[i] = byte(v)
	}
	return out, nil
}

func runWatch(cfgPath string, log *slog.Logger) error {
	// Configuration errors are terminal (exit 78): restarting cannot fix a
	// file an operator has to edit.
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return fmt.Errorf("%w: %w", watch.ErrTerminal, err)
	}
	notifier, err := alarm.New(cfg.Alarm.WebhookURL, log)
	if err != nil {
		return fmt.Errorf("%w: %w", watch.ErrTerminal, err)
	}

	err = watchWithConfig(cfg, notifier, log)
	if errors.Is(err, context.Canceled) {
		log.Info("shutting down")
		return nil
	}
	if err != nil {
		// Once the daemon exits nothing else reports a sealed Vault, so its
		// last act is an alarm. The loop's context may already be cancelled;
		// the notifier's own client timeout bounds this call.
		notifier.DaemonFailed(context.Background(), cfg.NodeID, err)
	}
	return err
}

func watchWithConfig(cfg *config.Config, notifier *alarm.Notifier, log *slog.Logger) error {
	vc, src, err := buildFromConfig(cfg, true)
	if err != nil {
		// With DeferUnavailable, anything left here is configuration (CA,
		// pin_env, module, key) or a rejected PIN: terminal.
		return fmt.Errorf("%w: %w", watch.ErrTerminal, err)
	}
	defer src.Close()

	shares := make([]watch.Share, 0, len(cfg.Keys.Shares))
	for _, s := range cfg.Keys.Shares {
		shares = append(shares, watch.Share{Index: s.Index, Path: s.Path})
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	w := watch.New(vc, src, watch.Options{
		NodeID:            cfg.NodeID,
		Shares:            shares,
		Interval:          cfg.Watch.Interval,
		MaxUnsealAttempts: cfg.Watch.MaxUnsealAttempts,
		StatePath:         "/run/autohsm/submitted-shares",
		Logger:            log,
		OnSealed: func(st *vaultclient.SealStatus) {
			notifier.SealedDetected(ctx, cfg.NodeID, st.Sealed, st.Threshold, st.Shares, st.Progress)
		},
		OnUnreachable: func(pollErr error) {
			notifier.VaultUnreachable(ctx, cfg.NodeID, pollErr)
		},
		OnHSMLost: func(hsmErr error) {
			notifier.HSMUnavailable(ctx, cfg.NodeID, hsmErr)
		},
		OnHSMRecovered: func() {
			notifier.HSMRecovered(ctx, cfg.NodeID)
		},
		OnSharesStale: func(st *vaultclient.SealStatus, staleErr error) {
			notifier.SharesStale(ctx, cfg.NodeID, st.Sealed, st.Threshold, st.Shares, st.Progress, staleErr)
		},
	})

	log.Info("autohsm watching",
		"node", cfg.NodeID,
		"vault", cfg.Vault.Address,
		"shares_held", len(shares),
		"interval", cfg.Watch.Interval.String())

	return w.Run(ctx)
}

// runStatus needs only the config and the pinned Vault client. It never opens
// the HSM: a cron monitor must not require (or exercise) the PIN, and an HSM
// outage must not mask Vault's seal state.
func runStatus(cfgPath string) error {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return err
	}
	vc, err := newVaultClient(cfg)
	if err != nil {
		return err
	}

	st, err := vc.SealStatus(context.Background())
	if err != nil {
		return err
	}
	fmt.Printf("sealed=%t initialized=%t threshold=%d shares=%d progress=%d version=%s\n",
		st.Sealed, st.Initialized, st.Threshold, st.Shares, st.Progress, st.Version)
	if st.Sealed {
		return sealedError{msg: "vault is SEALED"}
	}
	return nil
}

// runWrap reads a plaintext unseal share from stdin and prints the wrapped
// envelope. The plaintext is never echoed and is wiped before returning.
func runWrap(cfgPath string, args []string) error {
	index := 0
	for i, a := range args {
		if a == "--index" && i+1 < len(args) {
			n, err := strconv.Atoi(args[i+1])
			if err != nil {
				return fmt.Errorf("--index must be a number")
			}
			index = n
		}
	}
	if index < 1 {
		return fmt.Errorf("--index N (>=1) is required: it is bound into the wrapped share")
	}

	cfg, _, src, err := build(cfgPath, false)
	if err != nil {
		return err
	}
	defer src.Close()

	fmt.Fprintf(os.Stderr, "reading share %d for node %q from stdin...\n", index, cfg.NodeID)
	share, err := readShare(os.Stdin)
	if err != nil {
		return err
	}
	defer secure.Wipe(share)

	aad := keysource.AAD(cfg.NodeID, index)

	var envelope string
	switch cfg.Keys.Source {
	case "file":
		key, kerr := devKeyFromEnv()
		if kerr != nil {
			return kerr
		}
		defer secure.Wipe(key)
		envelope, err = keysource.WrapSoftware(key, share, aad)
	default:
		nonce, nerr := randNonce()
		if nerr != nil {
			return nerr
		}
		envelope, err = keysource.Wrap(src, nonce, share, aad)
	}
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "wrapped share %d for node %q (%s)\n", index, cfg.NodeID, fingerprint.Of(share))
	fmt.Println(envelope)
	return nil
}

func readShare(r io.Reader) ([]byte, error) {
	// Bounded single-buffer read (see config.ReadBounded): no reallocation
	// copies of the plaintext share are left behind in the heap.
	raw, err := config.ReadBounded(r, maxShareSize+2)
	if err != nil {
		return nil, fmt.Errorf("read share from stdin: %w", err)
	}
	share := bytes.TrimRight(raw, "\r\n")
	if len(share) == 0 {
		secure.Wipe(raw)
		return nil, fmt.Errorf("refusing to wrap an empty share")
	}
	if len(share) > maxShareSize {
		secure.Wipe(raw)
		return nil, fmt.Errorf("share exceeds %d bytes", maxShareSize)
	}
	if bytes.IndexByte(share, '\n') >= 0 || bytes.IndexByte(share, '\r') >= 0 {
		secure.Wipe(raw)
		return nil, fmt.Errorf("share input must contain exactly one line")
	}
	return share, nil
}

func runSelftest(cfgPath string, log *slog.Logger) error {
	cfg, vc, src, err := build(cfgPath, false)
	if err != nil {
		return fmt.Errorf("config/TLS/HSM setup: %w", err)
	}
	defer src.Close()

	log.Info("config loaded", "node", cfg.NodeID, "source", cfg.Keys.Source)

	st, err := vc.SealStatus(context.Background())
	if err != nil {
		return fmt.Errorf("vault unreachable or CA pin wrong: %w", err)
	}
	log.Info("vault reachable over pinned TLS", "sealed", st.Sealed, "threshold", st.Threshold)
	if err := watch.ValidateShareLayout(len(cfg.Keys.Shares), st.Threshold); err != nil {
		return fmt.Errorf("unsafe share distribution: %w", err)
	}

	// Prove every configured share unwraps for THIS node before we ever need it.
	for _, s := range cfg.Keys.Shares {
		sf, rerr := config.OpenSecretFile(s.Path, fmt.Sprintf("share %d", s.Index))
		if rerr != nil {
			return fmt.Errorf("share %d: %w", s.Index, rerr)
		}
		blob, rerr := config.ReadBounded(sf, maxShareSize)
		sf.Close()
		if rerr != nil {
			return fmt.Errorf("share %d: %w", s.Index, rerr)
		}
		plain, uerr := src.Unwrap(context.Background(), blob, keysource.AAD(cfg.NodeID, s.Index))
		if uerr != nil {
			return fmt.Errorf("share %d failed to unwrap (wrong node, index, or HSM key): %w", s.Index, uerr)
		}
		secure.Wipe(plain)
		log.Info("share unwraps correctly", "index", s.Index, "blob_fp", fingerprint.Of(blob))
	}

	log.Info("selftest OK", "shares_verified", len(cfg.Keys.Shares))
	return nil
}
