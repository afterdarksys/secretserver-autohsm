package watch

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"testing"

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
}

func (f *fakeVault) SealStatus(context.Context) (*vaultclient.SealStatus, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.statusErr != nil {
		return nil, f.statusErr
	}
	return &vaultclient.SealStatus{Sealed: f.sealed, Initialized: f.initted, Threshold: 3, Shares: 5}, nil
}

func (f *fakeVault) SubmitUnsealShare(_ context.Context, share []byte) (*vaultclient.SealStatus, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.submitErr != nil {
		return nil, f.submitErr
	}
	cp := append([]byte(nil), share...)
	f.submitted = append(f.submitted, cp)
	if f.unsealAfter > 0 && len(f.submitted) >= f.unsealAfter {
		f.sealed = false
	}
	return &vaultclient.SealStatus{Sealed: f.sealed, Initialized: true, Threshold: 3, Progress: len(f.submitted)}, nil
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

// Negative: a share wrapped for a different node must not be submitted. This is
// the deployment-safety property — copying a share file to another host fails.
func TestRefusesShareWrappedForAnotherNode(t *testing.T) {
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
