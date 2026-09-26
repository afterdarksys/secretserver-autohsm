package watch

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/afterdarksys/secretserver-autohsm/internal/keysource"
	"github.com/afterdarksys/secretserver-autohsm/internal/vaultclient"
)

type fakeVault struct {
	mu        sync.Mutex
	sealed    bool
	initted   bool
	submitted [][]byte
	statusErr error
	submitErr error
	// unsealAfter submissions flips sealed to false.
	unsealAfter int
	// nonce identifies the current sealed episode, mirroring Vault's real
	// seal-status "nonce" field.
	nonce string
	// mintNonce mirrors real Vault: the nonce is empty while progress is 0
	// and a fresh one is minted when the first share of an attempt arrives.
	mintNonce bool
	minted    int
}

func (f *fakeVault) SealStatus(context.Context) (*vaultclient.SealStatus, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.statusErr != nil {
		return nil, f.statusErr
	}
	return &vaultclient.SealStatus{Sealed: f.sealed, Initialized: f.initted, Threshold: 3, Shares: 5, Progress: len(f.submitted), Nonce: f.nonce}, nil
}

func (f *fakeVault) SubmitUnsealShare(_ context.Context, share []byte) (*vaultclient.SealStatus, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.submitErr != nil {
		return nil, f.submitErr
	}
	cp := append([]byte(nil), share...)
	f.submitted = append(f.submitted, cp)
	if f.mintNonce && f.nonce == "" {
		f.minted++
		f.nonce = fmt.Sprintf("vault-nonce-%d", f.minted)
	}
	if f.unsealAfter > 0 && len(f.submitted) >= f.unsealAfter {
		f.sealed = false
		if f.mintNonce {
			// Real Vault discards the attempt (and its nonce) once unsealed.
			f.submitted = nil
			f.nonce = ""
		}
	}
	return &vaultclient.SealStatus{Sealed: f.sealed, Initialized: true, Threshold: 3, Progress: len(f.submitted), Nonce: f.nonce}, nil
}

// resetAttempt mirrors a Vault restart or `sys/unseal reset`: progress and
// nonce are discarded.
func (f *fakeVault) resetAttempt() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.submitted = nil
	f.nonce = ""
}

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// setup writes a wrapped share for node/index and returns the source + path.
func setup(t *testing.T, node string, idx int, plaintext string) (keysource.Source, string) {
	t.Helper()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	blob, err := keysource.WrapSoftware(key, []byte(plaintext), keysource.AAD(node, idx))
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "share.wrapped")
	if err := os.WriteFile(p, []byte(blob), 0o600); err != nil {
		t.Fatal(err)
	}
	src, err := keysource.NewSoftware(key)
	if err != nil {
		t.Fatal(err)
	}
	return src, p
}

func TestUnsealsWhenSealed(t *testing.T) {
	src, path := setup(t, "apps2", 1, "share-one")
	v := &fakeVault{sealed: true, initted: true, unsealAfter: 1}

	w := New(v, src, Options{
		NodeID: "apps2",
		Shares: []Share{{Index: 1, Path: path}},
		Logger: quietLogger(),
	})
	if err := w.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(v.submitted) != 1 {
		t.Fatalf("expected 1 submission, got %d", len(v.submitted))
	}
	if string(v.submitted[0]) != "share-one" {
		t.Fatalf("wrong share submitted: %q", v.submitted[0])
	}
}

// A partial distributed unseal is stateful. Once this node's share has been
// accepted, subsequent polls must wait for peers instead of resubmitting it.
func TestDoesNotResubmitAcceptedShareWhileStillSealed(t *testing.T) {
	src, path := setup(t, "apps2", 1, "share-one")
	v := &fakeVault{sealed: true, initted: true}
	w := New(v, src, Options{
		NodeID: "apps2", Shares: []Share{{Index: 1, Path: path}}, Logger: quietLogger(),
	})

	for i := 0; i < 3; i++ {
		if err := w.Tick(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if got := len(v.submitted); got != 1 {
		t.Fatalf("submitted the same share %d times, want once", got)
	}
}

func TestSubmissionLatchResetsAfterObservedUnseal(t *testing.T) {
	src, path := setup(t, "apps2", 1, "share-one")
	v := &fakeVault{sealed: true, initted: true}
	w := New(v, src, Options{
		NodeID: "apps2", Shares: []Share{{Index: 1, Path: path}}, Logger: quietLogger(),
	})

	if err := w.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	v.sealed = false
	if err := w.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	v.sealed = true
	if err := w.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := len(v.submitted); got != 2 {
		t.Fatalf("new sealed episode submitted %d total shares, want 2", got)
	}
}

func TestSubmissionLatchSurvivesDaemonRestart(t *testing.T) {
	src, path := setup(t, "apps2", 1, "share-one")
	v := &fakeVault{sealed: true, initted: true}
	statePath := filepath.Join(t.TempDir(), "submitted")
	opts := Options{
		NodeID: "apps2", Shares: []Share{{Index: 1, Path: path}}, StatePath: statePath, Logger: quietLogger(),
	}
	if err := New(v, src, opts).Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := New(v, src, opts).Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := len(v.submitted); got != 1 {
		t.Fatalf("daemon restart caused %d submissions, want one", got)
	}
}

func TestZeroVaultProgressClearsPersistedLatch(t *testing.T) {
	src, path := setup(t, "apps2", 1, "share-one")
	statePath := filepath.Join(t.TempDir(), "submitted")
	if err := os.WriteFile(statePath, []byte("1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	v := &fakeVault{sealed: true, initted: true}
	w := New(v, src, Options{
		NodeID: "apps2", Shares: []Share{{Index: 1, Path: path}}, StatePath: statePath, Logger: quietLogger(),
	})
	if err := w.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := len(v.submitted); got != 1 {
		t.Fatalf("fresh Vault received %d shares, want one", got)
	}
}

func TestMalformedSubmissionStateIsTerminal(t *testing.T) {
	src, path := setup(t, "apps2", 1, "share-one")
	statePath := filepath.Join(t.TempDir(), "submitted")
	if err := os.WriteFile(statePath, []byte("not-an-index\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	v := &fakeVault{sealed: true, initted: true}
	w := New(v, src, Options{
		NodeID: "apps2", Shares: []Share{{Index: 1, Path: path}}, StatePath: statePath, Logger: quietLogger(),
	})
	if err := w.Tick(context.Background()); !errors.Is(err, ErrTerminal) {
		t.Fatalf("malformed state was not terminal: %v", err)
	}
}

// Regression: a stale submission latch from a prior sealed episode must not
// suppress our share in a NEW episode, even when that episode's Progress is
// already nonzero because a peer contributed before our next poll. Relying
// on Progress==0 alone would leave this node believing it has nothing left
// to submit for an episode it never actually acted in -- a deadlock if no
// other peer covers this node's share.
func TestStaleLatchClearsOnNonceChangeEvenWithNonzeroProgress(t *testing.T) {
	src, path := setup(t, "apps2", 1, "share-one")
	statePath := filepath.Join(t.TempDir(), "submitted")
	v := &fakeVault{sealed: true, initted: true, nonce: "episode-A"}
	opts := Options{
		NodeID: "apps2", Shares: []Share{{Index: 1, Path: path}}, StatePath: statePath, Logger: quietLogger(),
	}

	// Episode A: this node submits its share; the latch (and nonce) persist.
	if err := New(v, src, opts).Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := len(v.submitted); got != 1 {
		t.Fatalf("episode A: got %d submissions, want 1", got)
	}

	// Simulate a daemon restart racing a reseal we never directly observed: a
	// new episode begins (fresh nonce) and a peer has already contributed,
	// so Progress is nonzero going into our very first poll of episode B.
	v.mu.Lock()
	v.nonce = "episode-B"
	v.submitted = [][]byte{[]byte("peer-share")}
	v.mu.Unlock()

	if err := New(v, src, opts).Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := len(v.submitted); got != 2 {
		t.Fatalf("episode B: got %d total submissions, want 2 (peer + this node)", got)
	}
}

// Regression (reproduced against Vault 1.20 in scripts/e2e.sh): real Vault
// reports an empty nonce at progress 0 and mints one on the first accepted
// share. The latch must therefore record the nonce from the unseal RESPONSE.
// Recording the pre-submission (empty) nonce meant that after an unobserved
// reset, a peer contributing first left this node convinced it had already
// contributed, and the unseal stalled below threshold.
func TestLatchUsesNonceFromUnsealResponse(t *testing.T) {
	src, path := setup(t, "apps2", 1, "share-one")
	statePath := filepath.Join(t.TempDir(), "submitted")
	v := &fakeVault{sealed: true, initted: true, mintNonce: true}
	opts := Options{
		NodeID: "apps2", Shares: []Share{{Index: 1, Path: path}}, StatePath: statePath, Logger: quietLogger(),
	}

	if err := New(v, src, opts).Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	state, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if want := "nonce:vault-nonce-1\n1\n"; string(state) != want {
		t.Fatalf("persisted latch %q, want %q", state, want)
	}

	// Unobserved reset, then a peer contributes first to the new attempt.
	v.resetAttempt()
	if _, err := v.SubmitUnsealShare(context.Background(), []byte("peer-share")); err != nil {
		t.Fatal(err)
	}

	if err := New(v, src, opts).Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := len(v.submitted); got != 2 {
		t.Fatalf("new attempt got %d submissions, want 2 (peer + this node)", got)
	}
	// And the refreshed latch must stop a third submission in the same attempt.
	if err := New(v, src, opts).Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := len(v.submitted); got != 2 {
		t.Fatalf("same attempt resubmitted: %d submissions, want 2", got)
	}
}

// Regression (reproduced against Vault 1.20 in scripts/e2e.sh): when this
// node's share completes the unseal, Vault's reply carries no nonce. If that
// share was latched and Vault restarted before our next poll, a peer that
// contributed first to the new attempt left this node convinced it had
// already contributed, and the unseal stalled one share short.
func TestShareThatCompletesUnsealIsNotLatched(t *testing.T) {
	src, path := setup(t, "apps2", 3, "share-three")
	statePath := filepath.Join(t.TempDir(), "submitted")
	v := &fakeVault{sealed: true, initted: true, mintNonce: true, unsealAfter: 1}
	w := New(v, src, Options{
		NodeID: "apps2", Shares: []Share{{Index: 3, Path: path}}, StatePath: statePath, Logger: quietLogger(),
	})
	if err := w.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(statePath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("latch persisted for a share that completed the unseal: %v", err)
	}

	// Vault restarts before our next poll; a peer contributes first.
	v.mu.Lock()
	v.sealed, v.unsealAfter = true, 0
	v.mu.Unlock()
	if _, err := v.SubmitUnsealShare(context.Background(), []byte("peer-share")); err != nil {
		t.Fatal(err)
	}
	if err := w.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := len(v.submitted); got != 2 {
		t.Fatalf("new attempt got %d submissions, want 2 (peer + this node)", got)
	}
}

// A latch persisted without a nonce (older state file) cannot belong to an
// attempt that Vault identifies by a nonce, so it must not suppress this node.
func TestNoncelessLatchIsStaleWhenVaultReportsNonce(t *testing.T) {
	src, path := setup(t, "apps2", 1, "share-one")
	statePath := filepath.Join(t.TempDir(), "submitted")
	if err := os.WriteFile(statePath, []byte("1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	v := &fakeVault{sealed: true, initted: true, nonce: "peer-attempt", submitted: [][]byte{[]byte("peer")}}
	w := New(v, src, Options{
		NodeID: "apps2", Shares: []Share{{Index: 1, Path: path}}, StatePath: statePath, Logger: quietLogger(),
	})
	if err := w.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := len(v.submitted); got != 2 {
		t.Fatalf("got %d submissions, want 2 (peer + this node)", got)
	}
}

// vaultish mirrors real Vault unseal semantics: empty nonce at progress 0, a
// fresh nonce minted on the first part of an attempt, duplicate parts ignored,
// and the attempt discarded once the threshold is reached.
type vaultish struct {
	mu       sync.Mutex
	parts    []string
	nonce    string
	minted   int
	sealed   bool
	calls    int
	onSubmit func(call int)
}

func (v *vaultish) SealStatus(context.Context) (*vaultclient.SealStatus, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	return &vaultclient.SealStatus{Sealed: v.sealed, Initialized: true, Threshold: 3, Shares: 5, Progress: len(v.parts), Nonce: v.nonce}, nil
}

func (v *vaultish) addPart(k string) *vaultclient.SealStatus {
	for _, p := range v.parts {
		if p == k {
			return &vaultclient.SealStatus{Sealed: true, Initialized: true, Threshold: 3, Progress: len(v.parts), Nonce: v.nonce}
		}
	}
	if v.nonce == "" {
		v.minted++
		v.nonce = fmt.Sprintf("N%d", v.minted)
	}
	v.parts = append(v.parts, k)
	if len(v.parts) >= 3 {
		v.sealed, v.parts, v.nonce = false, nil, ""
	}
	return &vaultclient.SealStatus{Sealed: v.sealed, Initialized: true, Threshold: 3, Progress: len(v.parts), Nonce: v.nonce}
}

func (v *vaultish) SubmitUnsealShare(_ context.Context, share []byte) (*vaultclient.SealStatus, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	st := v.addPart(string(share))
	v.calls++
	if v.onSubmit != nil {
		v.onSubmit(v.calls)
	}
	return st, nil
}

// Regression (independent review): a node holding two shares whose Vault
// restarts between its two submissions must not carry the first share's
// index into the new attempt's latch. Before the fix the latch became {1,2}
// under the new nonce although that attempt only received share 2, and the
// unseal stalled at 2/3.
func TestLatchDropsIndexesFromEarlierAttemptMidPass(t *testing.T) {
	src, p1 := setup(t, "apps2", 1, "share-one")
	_, p2 := setup(t, "apps2", 2, "share-two")
	v := &vaultish{sealed: true}
	v.onSubmit = func(call int) {
		if call == 1 { // Vault restarts right after accepting share 1
			v.parts, v.nonce = nil, ""
		}
	}
	w := New(v, src, Options{
		NodeID: "apps2", Shares: []Share{{Index: 1, Path: p1}, {Index: 2, Path: p2}},
		StatePath: filepath.Join(t.TempDir(), "submitted"), Logger: quietLogger(),
	})
	if err := w.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	v.mu.Lock()
	v.addPart("share-three") // a peer contributes to the new attempt
	v.mu.Unlock()
	for i := 0; i < 3; i++ {
		if err := w.Tick(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if st, _ := v.SealStatus(context.Background()); st.Sealed {
		t.Fatalf("stalled sealed at %d/3; latch=%v@%s", st.Progress, w.submitted, w.submittedNonce)
	}
}

// Negative: an unsealed Vault must never receive shares.
func TestDoesNothingWhenUnsealed(t *testing.T) {
	src, path := setup(t, "apps2", 1, "share-one")
	v := &fakeVault{sealed: false, initted: true}

	w := New(v, src, Options{NodeID: "apps2", Shares: []Share{{Index: 1, Path: path}}, Logger: quietLogger()})
	if err := w.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(v.submitted) != 0 {
		t.Fatal("submitted a share to an unsealed vault")
	}
}

// Negative: an uninitialised Vault means our shares are stale (it was re-inited).
// Submitting them would be pointless and leaks share material to a fresh Vault.
func TestRefusesUninitializedVault(t *testing.T) {
	src, path := setup(t, "apps2", 1, "share-one")
	v := &fakeVault{sealed: true, initted: false}

	w := New(v, src, Options{NodeID: "apps2", Shares: []Share{{Index: 1, Path: path}}, Logger: quietLogger()})
	if err := w.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(v.submitted) != 0 {
		t.Fatal("submitted shares to an uninitialized vault")
	}
}

// Negative: a share wrapped for a different configured node context must not be
// submitted. This is an AAD integrity property, not physical host identity.
func TestRefusesShareWrappedForAnotherNodeContext(t *testing.T) {
	src, path := setup(t, "apps2", 1, "share-one")
	v := &fakeVault{sealed: true, initted: true}

	// Same share file, but this watcher believes it is dr1.
	w := New(v, src, Options{NodeID: "dr1", Shares: []Share{{Index: 1, Path: path}}, Logger: quietLogger()})
	if err := w.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(v.submitted) != 0 {
		t.Fatal("submitted a share wrapped for a different node")
	}
	if w.consecutiveFailures != 1 {
		t.Fatalf("expected the failure to be counted, got %d", w.consecutiveFailures)
	}
}

// Negative: repeated unseal failures must stop, not hammer Vault forever.
func TestGivesUpAfterMaxAttempts(t *testing.T) {
	src, path := setup(t, "apps2", 1, "share-one")
	v := &fakeVault{sealed: true, initted: true, submitErr: errors.New("vault rejects the key")}

	w := New(v, src, Options{
		NodeID:            "apps2",
		Shares:            []Share{{Index: 1, Path: path}},
		MaxUnsealAttempts: 3,
		Logger:            quietLogger(),
	})
	var err error
	for i := 0; i < 3; i++ {
		err = w.Tick(context.Background())
	}
	if err == nil {
		t.Fatal("watcher did not give up after the attempt budget was exhausted")
	}
	if !errors.Is(err, ErrTerminal) {
		t.Fatalf("attempt exhaustion is not terminal: %v", err)
	}
}

func TestRefusesSingleNodeThresholdLayout(t *testing.T) {
	src, path := setup(t, "apps2", 1, "share-one")
	v := &fakeVault{sealed: true, initted: true}
	w := New(v, src, Options{
		NodeID: "apps2",
		Shares: []Share{
			{Index: 1, Path: path}, {Index: 2, Path: path}, {Index: 3, Path: path},
		},
		Logger: quietLogger(),
	})
	err := w.Tick(context.Background())
	if !errors.Is(err, ErrTerminal) {
		t.Fatalf("unsafe threshold layout was not terminal: %v", err)
	}
	if len(v.submitted) != 0 {
		t.Fatal("submitted a share from an unsafe single-node layout")
	}
}

func TestValidateShareLayout(t *testing.T) {
	for _, tc := range []struct {
		local, threshold int
		terminal         bool
	}{
		{1, 3, false},
		{2, 3, false},
		{3, 3, true},
		{4, 3, true},
		{1, 0, false},
	} {
		err := ValidateShareLayout(tc.local, tc.threshold)
		if errors.Is(err, ErrTerminal) != tc.terminal {
			t.Fatalf("local=%d threshold=%d error=%v", tc.local, tc.threshold, err)
		}
	}
}

// Regression: a Vault the daemon cannot reach must still raise the alarm,
// not just log quietly. Otherwise an unreachable Vault (as opposed to a
// confirmed-sealed one) can go unnoticed indefinitely.
func TestAlarmFiresOnUnreachable(t *testing.T) {
	src, path := setup(t, "apps2", 1, "share-one")
	v := &fakeVault{statusErr: errors.New("connection refused")}

	var fired int
	var gotErr error
	w := New(v, src, Options{
		NodeID: "apps2", Shares: []Share{{Index: 1, Path: path}},
		Logger: quietLogger(),
		OnUnreachable: func(pollErr error) {
			fired++
			gotErr = pollErr
		},
	})
	if err := w.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if fired != 1 {
		t.Fatalf("unreachable alarm fired %d times, want 1", fired)
	}
	if gotErr == nil || gotErr.Error() != "connection refused" {
		t.Fatalf("unreachable alarm did not carry the poll error: %v", gotErr)
	}
}

// A transient status error must not consume the unseal budget.
func TestStatusErrorDoesNotConsumeBudget(t *testing.T) {
	src, path := setup(t, "apps2", 1, "share-one")
	v := &fakeVault{statusErr: errors.New("connection refused")}

	w := New(v, src, Options{
		NodeID: "apps2", Shares: []Share{{Index: 1, Path: path}},
		MaxUnsealAttempts: 2, Logger: quietLogger(),
	})
	for i := 0; i < 5; i++ {
		if err := w.Tick(context.Background()); err != nil {
			t.Fatalf("transient status error escalated: %v", err)
		}
	}
	if w.consecutiveFailures != 0 {
		t.Fatalf("status errors consumed the unseal budget: %d", w.consecutiveFailures)
	}
}

// The alarm hook must fire whenever a sealed Vault is observed, even if the
// subsequent unseal fails — being loud is the whole point.
func TestAlarmFiresOnSealed(t *testing.T) {
	src, path := setup(t, "apps2", 1, "share-one")
	v := &fakeVault{sealed: true, initted: true, submitErr: errors.New("nope")}

	var fired int
	w := New(v, src, Options{
		NodeID: "apps2", Shares: []Share{{Index: 1, Path: path}},
		Logger:   quietLogger(),
		OnSealed: func(*vaultclient.SealStatus) { fired++ },
	})
	_ = w.Tick(context.Background())
	if fired != 1 {
		t.Fatalf("alarm fired %d times, want 1", fired)
	}
}

// hsmSource wraps a software source with a controllable device state.
type hsmSource struct {
	keysource.Source
	healthErr   error
	unwrapErr   error
	healthCalls int
}

func (h *hsmSource) Health(context.Context) error {
	h.healthCalls++
	return h.healthErr
}

func (h *hsmSource) Unwrap(ctx context.Context, blob, aad []byte) ([]byte, error) {
	if h.unwrapErr != nil {
		return nil, h.unwrapErr
	}
	return h.Source.Unwrap(ctx, blob, aad)
}

type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time          { return c.t }
func (c *fakeClock) advance(d time.Duration) { c.t = c.t.Add(d) }

func TestHSMOutageAlarmsOnceBacksOffAndRecovers(t *testing.T) {
	sw, path := setup(t, "apps2", 1, "share-one")
	src := &hsmSource{Source: sw, healthErr: fmt.Errorf("%w: CKR_DEVICE_REMOVED", keysource.ErrHSMUnavailable)}
	v := &fakeVault{sealed: true, initted: true}
	clk := &fakeClock{t: time.Unix(1_000_000, 0)}
	var lost, recovered int
	w := New(v, src, Options{
		NodeID: "apps2", Shares: []Share{{Index: 1, Path: path}}, Interval: time.Second,
		MaxUnsealAttempts: 1, Logger: quietLogger(), Now: clk.now,
		OnHSMLost: func(error) { lost++ }, OnHSMRecovered: func() { recovered++ },
	})

	for i := 0; i < 5; i++ {
		if err := w.Tick(context.Background()); err != nil {
			t.Fatalf("HSM outage must not be terminal: %v", err)
		}
	}
	if lost != 1 || len(v.submitted) != 0 || w.consecutiveFailures != 0 {
		t.Fatalf("lost=%d submitted=%d failures=%d; want 1 alarm, nothing submitted, budget untouched",
			lost, len(v.submitted), w.consecutiveFailures)
	}
	if src.healthCalls != 1 {
		t.Fatalf("health probed %d times inside the backoff window, want 1", src.healthCalls)
	}
	clk.advance(time.Second)
	_ = w.Tick(context.Background())
	if src.healthCalls != 2 || w.hsmBackoff != 2*time.Second {
		t.Fatalf("after backoff: calls=%d backoff=%s, want 2 and 2s", src.healthCalls, w.hsmBackoff)
	}
	for i := 0; i < 20; i++ { // backoff is capped
		clk.advance(maxHSMBackoff)
		_ = w.Tick(context.Background())
	}
	if w.hsmBackoff != maxHSMBackoff || lost != 1 {
		t.Fatalf("backoff=%s lost=%d, want cap %s and still one alarm", w.hsmBackoff, lost, maxHSMBackoff)
	}

	src.healthErr = nil
	clk.advance(maxHSMBackoff)
	if err := w.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if recovered != 1 || len(v.submitted) != 1 {
		t.Fatalf("recovered=%d submitted=%d, want recovery alarm and the share submitted", recovered, len(v.submitted))
	}
}

// A lost HSM must be reported while Vault is still unsealed, not discovered
// only at the next reboot.
func TestHSMLossReportedWhileUnsealed(t *testing.T) {
	sw, path := setup(t, "apps2", 1, "share-one")
	src := &hsmSource{Source: sw, healthErr: keysource.ErrHSMUnavailable}
	var lost int
	w := New(&fakeVault{sealed: false, initted: true}, src, Options{
		NodeID: "apps2", Shares: []Share{{Index: 1, Path: path}}, Logger: quietLogger(),
		OnHSMLost: func(error) { lost++ },
	})
	if err := w.Tick(context.Background()); err != nil || lost != 1 {
		t.Fatalf("err=%v lost=%d, want nil and 1", err, lost)
	}
}

// Negative: a PIN rejection (initially or on re-login) is terminal so the
// service manager does not retry and burn the token's PIN counter; an unusable
// HSM configuration or key is terminal because retrying cannot fix it.
func TestPINRejectionIsTerminal(t *testing.T) {
	sw, path := setup(t, "apps2", 1, "share-one")
	for name, src := range map[string]*hsmSource{
		"pin health":           {Source: sw, healthErr: keysource.ErrPINRejected},
		"pin unwrap":           {Source: sw, unwrapErr: keysource.ErrPINRejected},
		"misconfigured health": {Source: sw, healthErr: fmt.Errorf("%w: no AES secret key labelled", keysource.ErrHSMMisconfigured)},
		"misconfigured unwrap": {Source: sw, unwrapErr: fmt.Errorf("%w: key is unsafe", keysource.ErrHSMMisconfigured)},
	} {
		v := &fakeVault{sealed: true, initted: true}
		w := New(v, src, Options{NodeID: "apps2", Shares: []Share{{Index: 1, Path: path}}, Logger: quietLogger(), MaxUnsealAttempts: 5})
		if err := w.Tick(context.Background()); !errors.Is(err, ErrTerminal) {
			t.Fatalf("%s: PIN rejection returned %v, want ErrTerminal", name, err)
		}
		if len(v.submitted) != 0 {
			t.Fatalf("%s: submitted after PIN rejection", name)
		}
	}
}

func TestUnwrapHSMLossDoesNotConsumeBudget(t *testing.T) {
	sw, path := setup(t, "apps2", 1, "share-one")
	src := &hsmSource{Source: sw, unwrapErr: fmt.Errorf("%w: CKR_SESSION_HANDLE_INVALID", keysource.ErrHSMUnavailable)}
	var lost int
	w := New(&fakeVault{sealed: true, initted: true}, src, Options{
		NodeID: "apps2", Shares: []Share{{Index: 1, Path: path}}, Logger: quietLogger(),
		MaxUnsealAttempts: 1, OnHSMLost: func(error) { lost++ },
	})
	if err := w.Tick(context.Background()); err != nil {
		t.Fatalf("HSM loss during unwrap was terminal: %v", err)
	}
	if lost != 1 || w.consecutiveFailures != 0 || !w.hsmDown {
		t.Fatalf("lost=%d failures=%d down=%v", lost, w.consecutiveFailures, w.hsmDown)
	}
}

// Stale shares (Vault re-initialised): Vault rejects the combined key set.
// The watcher must alarm shares_stale once, stop submitting for the life of
// the process, stop per-poll vault_sealed alarms, and remind with backoff.
func TestStaleSharesLatchFailsClosedWithBackoffAlarms(t *testing.T) {
	src, path := setup(t, "apps2", 1, "share-one")
	rejected := &vaultclient.APIError{Method: "PUT", Path: "/v1/sys/unseal", StatusCode: 400, Status: "400 Bad Request",
		Messages: []string{"unable to retrieve stored keys: invalid key: failed to decrypt keys from storage"}}
	v := &fakeVault{sealed: true, initted: true, submitErr: rejected}
	clk := &fakeClock{t: time.Unix(1_000_000, 0)}
	var stale, sealed int
	w := New(v, src, Options{
		NodeID: "apps2", Shares: []Share{{Index: 1, Path: path}}, Interval: time.Second,
		MaxUnsealAttempts: 1, Logger: quietLogger(), Now: clk.now,
		OnSealed:      func(*vaultclient.SealStatus) { sealed++ },
		OnSharesStale: func(*vaultclient.SealStatus, error) { stale++ },
	})
	if err := w.Tick(context.Background()); err != nil {
		t.Fatalf("stale shares must latch, not exit: %v", err)
	}
	if stale != 1 || !w.sharesStale {
		t.Fatalf("stale alarms=%d latched=%v, want 1 and true", stale, w.sharesStale)
	}

	v.mu.Lock()
	v.submitErr = nil // even if Vault would now accept, we must not submit
	v.mu.Unlock()
	sealedBefore := sealed
	for i := 0; i < 10; i++ {
		clk.advance(100 * time.Millisecond)
		if err := w.Tick(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if len(v.submitted) != 0 {
		t.Fatalf("submitted %d shares after stale latch", len(v.submitted))
	}
	if sealed != sealedBefore {
		t.Fatalf("vault_sealed alarmed %d times in stale state, want 0", sealed-sealedBefore)
	}
	// 1s of polls at 100ms: exactly one reminder (after the 1s backoff).
	if stale != 2 {
		t.Fatalf("stale alarms after 1s = %d, want 2 (initial + one reminder)", stale)
	}
	for i := 0; i < 100; i++ {
		clk.advance(time.Minute)
		_ = w.Tick(context.Background())
	}
	if w.staleBackoff != maxStaleBackoff {
		t.Fatalf("stale reminder backoff %s, want capped at %s", w.staleBackoff, maxStaleBackoff)
	}
}
