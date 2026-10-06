package main

// contribute: submit this node's share(s) to a vaultkeeper generate-root or
// rekey ceremony, directly from the node to Vault.
//
// Threats: Vault's ceremony endpoints can be reachable without authentication, so
// anyone who can reach Vault can start an attempt and try to collect node shares. A
// node contributes only to an attempt whose output is PGP-encrypted to a key pinned in
// its own config (generate-root: the operator key; never an OTP attempt), with the exact
// rekey shape vaultkeeper uses (5 shares, threshold 3, no backup, verification required,
// keys in the pinned order [operator x4, offline]). Every refusal happens
// before the HSM is opened and before any write to Vault. The share is unwrapped inside
// this process only, sent only to the pinned Vault over the pinned TLS CA, bound to the
// validated attempt by its nonce (a replaced attempt rejects it), and wiped right after.
// Output and alarms carry op, nonce prefix and progress only; a completing node prints
// the PGP-encrypted result, never a share, an OTP or a decrypted token.
// Does NOT protect against root on the node itself, against a malicious Vault, or
// against an attacker who only wants to cancel attempts (denial of service).

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/afterdarksys/secretserver-autohsm/internal/alarm"
	"github.com/afterdarksys/secretserver-autohsm/internal/ceremony"
	"github.com/afterdarksys/secretserver-autohsm/internal/config"
	"github.com/afterdarksys/secretserver-autohsm/internal/keysource"
	"github.com/afterdarksys/secretserver-autohsm/internal/secure"
	"github.com/afterdarksys/secretserver-autohsm/internal/vaultclient"
)

// parseContributeArgs accepts exactly one op and, optionally, --config PATH.
// Anything else is refused so the command matches an exact-command runbook.
func parseContributeArgs(args []string) (string, error) {
	op := ""
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--config" && i+1 < len(args):
			i++
		case len(a) > len("--config=") && a[:len("--config=")] == "--config=":
		case (a == ceremony.OpGenerateRoot || a == ceremony.OpRekey) && op == "":
			op = a
		default:
			return "", fmt.Errorf("usage: autohsm contribute generate-root|rekey [--config PATH] (unexpected argument %q)", a)
		}
	}
	if op == "" {
		return "", fmt.Errorf("usage: autohsm contribute generate-root|rekey [--config PATH]")
	}
	return op, nil
}

func runContribute(cfgPath string, args []string, log *slog.Logger) error {
	op, err := parseContributeArgs(args)
	if err != nil {
		return err
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return err
	}
	notifier, err := alarm.New(cfg.Alarm.WebhookURL, log)
	if err != nil {
		return err
	}
	vc, err := newVaultClient(cfg)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	return contribute(ctx, cfg, vc, func() (keysource.Source, error) {
		return openKeySource(cfg, false)
	}, op, os.Stdout, notifier, log)
}

// contribute is runContribute with its dependencies injected. openSource is
// called only after the attempt has passed every check.
func contribute(ctx context.Context, cfg *config.Config, vc *vaultclient.Client,
	openSource func() (keysource.Source, error), op string, stdout io.Writer,
	notifier *alarm.Notifier, log *slog.Logger) error {

	nonce, attemptRequired, err := checkAttempt(ctx, cfg, vc, op)
	if err != nil {
		if errors.Is(err, ceremony.ErrRefused) {
			notifier.ContributeRefused(ctx, cfg.NodeID, op, err)
			log.Warn("contribute refused", "op", op, "node", cfg.NodeID, "reason", err)
		}
		return err
	}

	src, err := openSource()
	if err != nil {
		return err
	}
	defer src.Close()

	progress, required := 0, 0
	for _, s := range cfg.Keys.Shares {
		share, err := unwrapShare(ctx, src, cfg.NodeID, s)
		if err != nil {
			return err
		}
		var result *ceremony.Result
		switch op {
		case ceremony.OpGenerateRoot:
			var st *vaultclient.GenerateRootStatus
			st, err = vc.SubmitGenerateRootShare(ctx, share, nonce)
			if err == nil {
				progress, required = st.Progress, st.Required
				if st.Complete {
					progress, required = attemptRequired, attemptRequired
					result, err = ceremony.GenerateRootResult(st, nonce, cfg.Vaultkeeper.PGPFingerprint)
				}
			}
		case ceremony.OpRekey:
			var st *vaultclient.RekeyStatus
			st, err = vc.SubmitRekeyShare(ctx, share, nonce)
			if err == nil {
				progress, required = st.Progress, st.Required
				if st.Complete {
					// The completing rekey reply carries no progress fields.
					progress, required = attemptRequired, attemptRequired
					result, err = ceremony.RekeyResult(st, nonce, cfg.Vaultkeeper.PGPFingerprint, cfg.Vaultkeeper.OfflineFingerprint)
				}
			}
		}
		secure.Wipe(share)
		if err != nil {
			return fmt.Errorf("contribute share %d: %w", s.Index, err)
		}

		line := fmt.Sprintf("contribute op=%s nonce=%s progress=%d/%d", op, nonce[:8], progress, required)
		fmt.Fprintln(stdout, line)
		log.Info("contributed", "op", op, "node", cfg.NodeID, "index", s.Index,
			"nonce", nonce[:8], "progress", progress, "required", required)
		notifier.Contributed(ctx, cfg.NodeID, op, nonce[:8], progress, required)

		if result != nil {
			// Only PGP-encrypted material, already re-checked against the pins.
			out, err := result.Line()
			if err != nil {
				return err
			}
			fmt.Fprintln(stdout, out)
			return nil
		}
	}
	return nil
}

// checkAttempt reads the current attempt and applies the refusal matrix. It
// performs no write and does not touch the HSM.
func checkAttempt(ctx context.Context, cfg *config.Config, vc *vaultclient.Client, op string) (nonce string, required int, err error) {
	switch op {
	case ceremony.OpGenerateRoot:
		if cfg.Vaultkeeper.PGPFingerprint == "" {
			return "", 0, ceremony.CheckGenerateRoot(nil, "")
		}
		st, err := vc.GenerateRootAttempt(ctx)
		if err != nil {
			return "", 0, fmt.Errorf("read generate-root attempt: %w", err)
		}
		if err := ceremony.CheckGenerateRoot(st, cfg.Vaultkeeper.PGPFingerprint); err != nil {
			return "", 0, err
		}
		return st.Nonce, st.Required, nil
	case ceremony.OpRekey:
		if cfg.Vaultkeeper.PGPFingerprint == "" || cfg.Vaultkeeper.OfflineFingerprint == "" {
			return "", 0, ceremony.CheckRekey(nil, "", "")
		}
		st, err := vc.RekeyAttempt(ctx)
		if err != nil {
			return "", 0, fmt.Errorf("read rekey attempt: %w", err)
		}
		if err := ceremony.CheckRekey(st, cfg.Vaultkeeper.PGPFingerprint, cfg.Vaultkeeper.OfflineFingerprint); err != nil {
			return "", 0, err
		}
		return st.Nonce, st.Required, nil
	}
	return "", 0, fmt.Errorf("unknown contribute op %q", op)
}

func unwrapShare(ctx context.Context, src keysource.Source, nodeID string, s config.ShareConfig) ([]byte, error) {
	sf, err := config.OpenSecretFile(s.Path, fmt.Sprintf("share %d", s.Index))
	if err != nil {
		return nil, err
	}
	blob, err := config.ReadBounded(sf, maxShareSize)
	sf.Close()
	if err != nil {
		return nil, fmt.Errorf("share %d: %w", s.Index, err)
	}
	share, err := src.Unwrap(ctx, blob, keysource.AAD(nodeID, s.Index))
	if err != nil {
		return nil, fmt.Errorf("share %d failed to unwrap: %w", s.Index, err)
	}
	return share, nil
}
