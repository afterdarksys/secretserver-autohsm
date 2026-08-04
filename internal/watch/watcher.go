// Asset: autohsm-watcher
// Purpose: Poll Vault's seal state and submit this node's unwrapped shares when it is sealed.
// Threats: Bounds the damage of a misconfigured or hostile environment: caps consecutive
// unseal attempts so a wrong key set cannot hammer Vault indefinitely, wipes plaintext
// shares immediately after submission, and never logs share material (fingerprints only).
// Reports a sealed Vault loudly so an unseal failure is visible rather than silent — the
// failure mode that let a sealed Vault go unnoticed for months. Does NOT decide policy:
// holding >= threshold shares on one node defeats the design and is a deployment concern.
// Deps: none beyond internal packages
// Example: w := watch.New(client, source, opts); w.Run(ctx)
// Status: tested
// License: proprietary
// Provenance: original
package watch

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/afterdarksys/secretserver-autohsm/internal/fingerprint"
	"github.com/afterdarksys/secretserver-autohsm/internal/keysource"
	"github.com/afterdarksys/secretserver-autohsm/internal/secure"
	"github.com/afterdarksys/secretserver-autohsm/internal/vaultclient"
)

// Share is one wrapped share this node holds.
type Share struct {
	Index int
	Path  string
}

// Options configures the loop.
type Options struct {
	NodeID            string
	Shares            []Share
	Interval          time.Duration
	MaxUnsealAttempts int
	Logger            *slog.Logger
	// OnSealed is invoked whenever a sealed Vault is observed (alarm hook).
	OnSealed func(status *vaultclient.SealStatus)
}

// Sealer is the subset of the Vault client the watcher needs.
type Sealer interface {
	SealStatus(ctx context.Context) (*vaultclient.SealStatus, error)
	SubmitUnsealShare(ctx context.Context, share []byte) (*vaultclient.SealStatus, error)
}

// Watcher polls Vault and unseals when required.
type Watcher struct {
	vault  Sealer
	source keysource.Source
	opts   Options
	log    *slog.Logger

	// consecutiveFailures latches toward MaxUnsealAttempts; reset on success.
	consecutiveFailures int
}

// New builds a watcher.
func New(v Sealer, src keysource.Source, opts Options) *Watcher {
	log := opts.Logger
	if log == nil {
		log = slog.New(slog.NewTextHandler(os.Stderr, nil))
	}
	if opts.Interval <= 0 {
		opts.Interval = 30 * time.Second
	}
	if opts.MaxUnsealAttempts <= 0 {
		opts.MaxUnsealAttempts = 5
	}
	return &Watcher{vault: v, source: src, opts: opts, log: log}
}

// Run polls until ctx is cancelled. It returns only on cancellation or when the
// consecutive-failure budget is exhausted (fail closed and stay loud).
func (w *Watcher) Run(ctx context.Context) error {
	ticker := time.NewTicker(w.opts.Interval)
	defer ticker.Stop()

	// Check immediately: a daemon starting after a reboot should not wait a
	// full interval while Vault sits sealed.
	if err := w.Tick(ctx); err != nil {
		return err
	}
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if err := w.Tick(ctx); err != nil {
				return err
			}
		}
	}
}

// Tick performs one poll-and-maybe-unseal cycle.
func (w *Watcher) Tick(ctx context.Context) error {
	st, err := w.vault.SealStatus(ctx)
	if err != nil {
		// A transient reachability problem is not a reason to give up; it is a
		// reason to be noisy. The failure budget only counts unseal rejections.
		w.log.Warn("vault seal-status check failed", "error", err)
		return nil
	}

	if !st.Sealed {
		if w.consecutiveFailures > 0 {
			w.log.Info("vault is unsealed again", "previous_failures", w.consecutiveFailures)
		}
		w.consecutiveFailures = 0
		return nil
	}

	// Sealed: alarm first, so the operator learns about it even if unsealing fails.
	w.log.Error("vault is SEALED",
		"threshold", st.Threshold, "shares", st.Shares, "progress", st.Progress)
	if w.opts.OnSealed != nil {
		w.opts.OnSealed(st)
	}

	if !st.Initialized {
		// Never attempt to unseal an uninitialised Vault: that state means a
		// re-init happened and our shares are stale.
		w.log.Error("vault reports uninitialized; refusing to submit shares (stale key material?)")
		return nil
	}

	if err := w.submitShares(ctx); err != nil {
		w.consecutiveFailures++
		w.log.Error("unseal attempt failed",
			"error", err,
			"consecutive_failures", w.consecutiveFailures,
			"max", w.opts.MaxUnsealAttempts)
		if w.consecutiveFailures >= w.opts.MaxUnsealAttempts {
			return fmt.Errorf(
				"giving up after %d consecutive unseal failures: shares are likely wrong for this Vault (re-initialised?)",
				w.consecutiveFailures)
		}
		return nil
	}

	w.consecutiveFailures = 0
	return nil
}

// submitShares unwraps and submits each share this node holds, wiping plaintext
// as soon as Vault has consumed it.
func (w *Watcher) submitShares(ctx context.Context) error {
	for _, sh := range w.opts.Shares {
		blob, err := os.ReadFile(sh.Path)
		if err != nil {
			return fmt.Errorf("read wrapped share %d: %w", sh.Index, err)
		}

		aad := keysource.AAD(w.opts.NodeID, sh.Index)
		plain, err := w.source.Unwrap(ctx, blob, aad)
		if err != nil {
			return fmt.Errorf("unwrap share %d: %w", sh.Index, err)
		}

		st, err := w.vault.SubmitUnsealShare(ctx, plain)
		// Wipe immediately, on both paths, before inspecting the result.
		secure.Wipe(plain)
		if err != nil {
			return fmt.Errorf("submit share %d: %w", sh.Index, err)
		}

		w.log.Info("submitted unseal share",
			"index", sh.Index,
			"share_fp", fingerprint.Of(blob),
			"progress", st.Progress,
			"threshold", st.Threshold,
			"sealed", st.Sealed)

		if !st.Sealed {
			w.log.Info("vault unsealed")
			return nil
		}
	}
	// Not an error: this node legitimately may hold fewer than the threshold,
	// with peers supplying the rest. Staying below threshold is the design.
	return nil
}
