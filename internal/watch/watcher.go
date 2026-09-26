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
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/afterdarksys/secretserver-autohsm/internal/config"
	"github.com/afterdarksys/secretserver-autohsm/internal/fingerprint"
	"github.com/afterdarksys/secretserver-autohsm/internal/keysource"
	"github.com/afterdarksys/secretserver-autohsm/internal/secure"
	"github.com/afterdarksys/secretserver-autohsm/internal/vaultclient"
)

// maxShareFileSize bounds a wrapped-share file read. Envelopes are small
// (nonce + ciphertext + tag, base64-ish encoded); this matches the plaintext
// share size bound cmd/autohsm enforces on wrap input, with headroom for the
// envelope encoding overhead.
const maxShareFileSize = 8192

// ErrTerminal marks a condition that requires operator intervention. The CLI
// maps it to a dedicated exit status so the service manager does not erase the
// failure latch by immediately restarting the process.
var ErrTerminal = errors.New("terminal autohsm failure")

// ValidateShareLayout enforces the distribution property that gives this
// design its security value: one node must never hold enough shares to unseal.
func ValidateShareLayout(localShares, threshold int) error {
	if threshold > 0 && localShares >= threshold {
		return fmt.Errorf("%w: this node holds %d shares, meeting Vault's threshold of %d; refusing an unsafe single-node unseal layout",
			ErrTerminal, localShares, threshold)
	}
	return nil
}

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
	// StatePath persists accepted share indexes across daemon crashes within a
	// host boot. Put it under /run so a machine reboot starts a fresh episode.
	StatePath string
	Logger    *slog.Logger
	// OnSealed is invoked whenever a sealed Vault is observed (alarm hook).
	OnSealed func(status *vaultclient.SealStatus)
	// OnUnreachable is invoked whenever a seal-status poll itself fails (alarm
	// hook). A Vault we cannot even reach is not a reason to stay quiet: it is
	// exactly the silent-failure condition this package exists to surface.
	OnUnreachable func(pollErr error)
	// OnHSMLost fires once per HSM outage (session lost and not re-established);
	// OnHSMRecovered fires when it comes back.
	OnHSMLost      func(err error)
	OnHSMRecovered func()
	// OnSharesStale fires when Vault rejects the key material itself, then
	// again with exponential backoff while Vault stays sealed. It replaces
	// OnSealed while the watcher is in that state.
	OnSharesStale func(status *vaultclient.SealStatus, err error)
	// Now overrides the clock (tests only).
	Now func() time.Time
}

// maxHSMBackoff caps the delay between HSM reconnect attempts; maxStaleBackoff
// caps the delay between repeated shares_stale alarms.
const (
	maxHSMBackoff   = 5 * time.Minute
	maxStaleBackoff = time.Hour
)

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
	// submitted tracks shares accepted during the current unseal attempt. Vault
	// ignores a duplicate part within an attempt, so resubmitting is harmless to
	// Vault; the latch exists so a waiting node does not re-unwrap through the
	// HSM, re-send key material, and log a submission on every poll.
	submitted map[int]bool
	// submittedNonce is Vault's unseal nonce at the time submitted was last
	// updated. It identifies which sealed episode the latch belongs to.
	submittedNonce string
	stateLoaded    bool

	// HSM outage state: while hsmDown, reconnects are attempted no more often
	// than hsmBackoff, and no unseal is attempted.
	hsmDown    bool
	hsmBackoff time.Duration
	hsmNextTry time.Time

	// sharesStale latches for the life of the process once Vault rejects the
	// key material: no further submissions, and shares_stale reminders with
	// backoff instead of a vault_sealed alarm every poll.
	sharesStale     bool
	staleErr        error
	staleBackoff    time.Duration
	staleNextRemind time.Time
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
	if opts.Now == nil {
		opts.Now = time.Now
	}
	return &Watcher{vault: v, source: src, opts: opts, log: log, submitted: make(map[int]bool)}
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
		if w.opts.OnUnreachable != nil {
			w.opts.OnUnreachable(err)
		}
		return nil
	}
	if err := w.loadSubmittedState(); err != nil {
		return fmt.Errorf("%w: load submission state: %v", ErrTerminal, err)
	}

	// Vault's nonce is untrusted input written verbatim into a line-oriented
	// state file; a value containing a newline could inject a bogus line on
	// persist. Treat anything but a plain single-line token as "no nonce" and
	// fall back to the Progress==0 heuristic rather than trust it.
	if strings.ContainsAny(st.Nonce, "\n\r") {
		w.log.Warn("vault returned a malformed unseal nonce; ignoring it")
		st.Nonce = ""
	}

	// Probe the HSM on every poll, not only when unsealing, so a lost token is
	// reported while Vault is still unsealed rather than discovered at the
	// next reboot.
	if err := w.checkHSM(ctx); err != nil {
		return err
	}

	if !st.Sealed {
		if w.consecutiveFailures > 0 {
			w.log.Info("vault is unsealed again", "previous_failures", w.consecutiveFailures)
		}
		w.consecutiveFailures = 0
		clear(w.submitted)
		w.submittedNonce = ""
		if err := w.removeSubmittedState(); err != nil {
			w.log.Warn("could not clear submission state", "error", err)
		}
		return nil
	}

	// A sealed episode's identity is Vault's unseal nonce: empty while
	// progress is 0, minted when the first share of an attempt is accepted, and
	// returned in each unseal reply (which is what the latch records). Any
	// share this node had accepted in the CURRENT attempt was latched under
	// that attempt's nonce, so a nonempty Vault nonce that differs from the
	// latch's (including an empty latch nonce from an older state file) means
	// the latch belongs to an earlier attempt, even when a peer has already
	// pushed progress above 0. Progress==0 covers a Vault reporting no nonce.
	stale := len(w.submitted) > 0 &&
		((st.Nonce != "" && st.Nonce != w.submittedNonce) ||
			(st.Nonce == "" && st.Progress == 0))
	if stale {
		clear(w.submitted)
		w.submittedNonce = ""
		if err := w.removeSubmittedState(); err != nil {
			return fmt.Errorf("%w: clear stale submission state: %v", ErrTerminal, err)
		}
	}

	if w.sharesStale {
		// Fail closed: never submit again in this process. Remind with
		// backoff rather than alarming on every poll.
		w.log.Error("vault is SEALED; not submitting: vault rejected this key material (restart after re-provisioning shares)",
			"threshold", st.Threshold, "shares", st.Shares, "progress", st.Progress)
		if now := w.opts.Now(); !now.Before(w.staleNextRemind) {
			w.staleBackoff = min(w.staleBackoff*2, maxStaleBackoff)
			w.staleNextRemind = now.Add(w.staleBackoff)
			if w.opts.OnSharesStale != nil {
				w.opts.OnSharesStale(st, w.staleErr)
			}
		}
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
	if err := ValidateShareLayout(len(w.opts.Shares), st.Threshold); err != nil {
		return err
	}

	if w.hsmDown {
		w.log.Error("HSM unavailable; cannot unwrap shares", "next_retry", w.hsmNextTry.Format(time.RFC3339))
		return nil
	}

	if err := w.submitShares(ctx); err != nil {
		switch {
		case errors.Is(err, keysource.ErrPINRejected):
			return fmt.Errorf("%w: %v", ErrTerminal, err)
		case errors.Is(err, keysource.ErrHSMUnavailable):
			// Not the shares' fault: do not consume the unseal budget.
			w.markHSMDown(err)
			return nil
		case vaultclient.IsKeyRejected(err):
			w.enterSharesStale(st, err)
			return nil
		}
		w.consecutiveFailures++
		w.log.Error("unseal attempt failed",
			"error", err,
			"consecutive_failures", w.consecutiveFailures,
			"max", w.opts.MaxUnsealAttempts)
		if w.consecutiveFailures >= w.opts.MaxUnsealAttempts {
			return fmt.Errorf(
				"%w: giving up after %d consecutive unseal failures: shares are likely wrong for this Vault (re-initialised?)",
				ErrTerminal, w.consecutiveFailures)
		}
		return nil
	}

	w.consecutiveFailures = 0
	return nil
}

// checkHSM probes a source that can lose its device. It returns an error only
// for a rejected PIN (terminal: retrying burns the token's PIN counter).
func (w *Watcher) checkHSM(ctx context.Context) error {
	hc, ok := w.source.(keysource.HealthChecker)
	if !ok {
		return nil
	}
	if w.hsmDown && w.opts.Now().Before(w.hsmNextTry) {
		return nil
	}
	err := hc.Health(ctx)
	switch {
	case err == nil:
		if w.hsmDown {
			w.hsmDown, w.hsmBackoff = false, 0
			w.log.Info("HSM session re-established")
			if w.opts.OnHSMRecovered != nil {
				w.opts.OnHSMRecovered()
			}
		}
	case errors.Is(err, keysource.ErrPINRejected):
		return fmt.Errorf("%w: %v", ErrTerminal, err)
	default:
		w.markHSMDown(err)
	}
	return nil
}

// markHSMDown records an HSM outage, alarming once per outage and doubling
// the reconnect delay (from one poll interval up to maxHSMBackoff).
func (w *Watcher) markHSMDown(err error) {
	if !w.hsmDown {
		w.hsmDown = true
		w.hsmBackoff = w.opts.Interval
		w.log.Error("HSM unavailable", "error", err)
		if w.opts.OnHSMLost != nil {
			w.opts.OnHSMLost(err)
		}
	} else {
		w.hsmBackoff = min(w.hsmBackoff*2, maxHSMBackoff)
		w.log.Warn("HSM still unavailable", "error", err, "retry_in", w.hsmBackoff.String())
	}
	w.hsmNextTry = w.opts.Now().Add(w.hsmBackoff)
}

// enterSharesStale latches the fail-closed state after Vault rejected the key
// material, and alarms immediately.
func (w *Watcher) enterSharesStale(st *vaultclient.SealStatus, err error) {
	w.sharesStale = true
	w.staleErr = err
	w.staleBackoff = w.opts.Interval
	w.staleNextRemind = w.opts.Now().Add(w.staleBackoff)
	clear(w.submitted)
	w.submittedNonce = ""
	if rerr := w.removeSubmittedState(); rerr != nil {
		w.log.Warn("could not clear submission state", "error", rerr)
	}
	w.log.Error("vault rejected the unseal key material; shares are stale or wrong for this Vault. Not submitting again until restarted",
		"error", err)
	if w.opts.OnSharesStale != nil {
		w.opts.OnSharesStale(st, err)
	}
}

// submitShares unwraps and submits each share this node holds, wiping plaintext
// as soon as Vault has consumed it.
func (w *Watcher) submitShares(ctx context.Context) error {
	for _, sh := range w.opts.Shares {
		if w.submitted[sh.Index] {
			continue
		}
		f, err := config.OpenSecretFile(sh.Path, fmt.Sprintf("share %d", sh.Index))
		if err != nil {
			return fmt.Errorf("read wrapped share %d: %w", sh.Index, err)
		}
		blob, err := config.ReadBounded(f, maxShareFileSize)
		f.Close()
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
		if !st.Sealed {
			// This share completed the unseal, so the attempt is over and
			// there is nothing to latch. Persisting it (Vault reports no nonce
			// once unsealed) would leave a latch that a later attempt, begun
			// before our next poll, could mistake for its own.
			clear(w.submitted)
			w.submittedNonce = ""
			if err := w.removeSubmittedState(); err != nil {
				w.log.Warn("could not clear submission state", "error", err)
			}
			// Neutral wording: a peer may have completed the unseal first, in
			// which case Vault answers any submission with sealed=false.
			w.log.Info("submitted unseal share; vault reports unsealed",
				"index", sh.Index, "share_fp", fingerprint.Of(blob))
			return nil
		}
		// Record the episode nonce Vault returned for THIS submission. The
		// seal-status nonce observed before submitting is empty for the first
		// share of an attempt, and a latch keyed to "" can never be recognised
		// as stale once a later episode mints a different nonce.
		if strings.ContainsAny(st.Nonce, "\n\r") {
			w.log.Warn("vault returned a malformed unseal nonce; ignoring it")
			st.Nonce = ""
		}
		if st.Nonce != w.submittedNonce {
			// A different nonce means a new attempt began (Vault restart or
			// reset) since our earlier submissions; they are not part of it.
			clear(w.submitted)
		}
		w.submitted[sh.Index] = true
		w.submittedNonce = st.Nonce
		if err := w.persistSubmittedState(); err != nil {
			return fmt.Errorf("%w: persist accepted share %d: %v", ErrTerminal, sh.Index, err)
		}

		w.log.Info("submitted unseal share",
			"index", sh.Index,
			"share_fp", fingerprint.Of(blob),
			"progress", st.Progress,
			"threshold", st.Threshold,
			"sealed", st.Sealed)
	}
	// Not an error: this node legitimately may hold fewer than the threshold,
	// with peers supplying the rest. Staying below threshold is the design.
	return nil
}

func (w *Watcher) loadSubmittedState() error {
	if w.stateLoaded || w.opts.StatePath == "" {
		w.stateLoaded = true
		return nil
	}
	w.stateLoaded = true
	f, err := os.Open(w.opts.StatePath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer f.Close()
	scanner := bufio.NewScanner(io.LimitReader(f, 4096))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		if rest, ok := strings.CutPrefix(line, "nonce:"); ok {
			w.submittedNonce = rest
			continue
		}
		idx, err := strconv.Atoi(line)
		if err != nil || idx < 1 {
			return fmt.Errorf("invalid share index %q", line)
		}
		w.submitted[idx] = true
	}
	return scanner.Err()
}

func (w *Watcher) persistSubmittedState() error {
	if w.opts.StatePath == "" {
		return nil
	}
	dir := filepath.Dir(w.opts.StatePath)
	tmp, err := os.CreateTemp(dir, ".submitted-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if w.submittedNonce != "" {
		if _, err := fmt.Fprintf(tmp, "nonce:%s\n", w.submittedNonce); err != nil {
			tmp.Close()
			return err
		}
	}
	indexes := make([]int, 0, len(w.submitted))
	for idx := range w.submitted {
		indexes = append(indexes, idx)
	}
	sort.Ints(indexes)
	for _, idx := range indexes {
		if _, err := fmt.Fprintf(tmp, "%d\n", idx); err != nil {
			tmp.Close()
			return err
		}
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, w.opts.StatePath)
}

func (w *Watcher) removeSubmittedState() error {
	if w.opts.StatePath == "" {
		return nil
	}
	err := os.Remove(w.opts.StatePath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}
