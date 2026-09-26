//go:build integration

package watch

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/afterdarksys/secretserver-autohsm/internal/keysource"
	"github.com/miekg/pkcs11"
)

// TestSoftHSMStartupWithoutToken starts the watcher while the SoftHSM token
// store is absent (as if the HSM were not yet attached at boot), proves it
// alarms hsm_unavailable once, backs off, submits nothing and does not consume
// the unseal budget, then restores the token and proves it alarms
// hsm_recovered, unwraps through the real token, and unseals. It also proves
// the startup failures that must stay terminal (wrong PIN, missing key) are
// not deferred. Run with:
//
//	AUTOHSM_TEST_MODULE=/path/to/libsofthsm2.so go test -tags=integration ./internal/watch
func TestSoftHSMStartupWithoutToken(t *testing.T) {
	module := os.Getenv("AUTOHSM_TEST_MODULE")
	if module == "" {
		t.Skip("AUTOHSM_TEST_MODULE is not set")
	}
	util, err := exec.LookPath("softhsm2-util")
	if err != nil {
		t.Skip("softhsm2-util is not installed")
	}

	const (
		tokenLabel = "autohsm-startup"
		userPIN    = "123456"
		soPIN      = "12345678"
		keyLabel   = "autohsm-wrap"
		node       = "startup-node"
	)
	root := t.TempDir()
	tokenDir := filepath.Join(root, "tokens")
	if err := os.Mkdir(tokenDir, 0o700); err != nil {
		t.Fatal(err)
	}
	conf := filepath.Join(root, "softhsm2.conf")
	if err := os.WriteFile(conf, fmt.Appendf(nil, "directories.tokendir = %s\nobjectstore.backend = file\nlog.level = ERROR\nslots.removable = false\n", tokenDir), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SOFTHSM2_CONF", conf)
	if out, err := exec.Command(util, "--init-token", "--free", "--label", tokenLabel, "--so-pin", soPIN, "--pin", userPIN).CombinedOutput(); err != nil {
		t.Fatalf("init token: %v\n%s", err, out)
	}
	generateKey(t, module, tokenLabel, userPIN, keyLabel)

	pin := userPIN
	opts := keysource.PKCS11Options{
		ModulePath: module, TokenLabel: tokenLabel, KeyLabel: keyLabel,
		ReadPIN: func() ([]byte, error) { return []byte(pin), nil },
	}

	// Provision one wrapped share through the real token.
	src, err := keysource.OpenPKCS11(opts)
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, 12)
	envelope, err := keysource.Wrap(src, nonce, []byte("share-one"), keysource.AAD(node, 1))
	if err != nil {
		t.Fatal(err)
	}
	src.Close()
	sharePath := filepath.Join(root, "share-1.wrapped")
	if err := os.WriteFile(sharePath, []byte(envelope), 0o600); err != nil {
		t.Fatal(err)
	}

	// Terminal startup failures are never deferred.
	deferred := opts
	deferred.DeferUnavailable = true
	pin = "000000"
	if s, err := keysource.OpenPKCS11(deferred); !errors.Is(err, keysource.ErrPINRejected) {
		if s != nil {
			s.Close()
		}
		t.Fatalf("wrong PIN with DeferUnavailable: %v, want ErrPINRejected", err)
	}
	pin = userPIN
	missingKey := deferred
	missingKey.KeyLabel = "no-such-key"
	if s, err := keysource.OpenPKCS11(missingKey); !errors.Is(err, keysource.ErrHSMMisconfigured) {
		if s != nil {
			s.Close()
		}
		t.Fatalf("missing key with DeferUnavailable: %v, want ErrHSMMisconfigured", err)
	}

	// --- The token store is absent at startup.
	if err := os.Rename(tokenDir, tokenDir+".absent"); err != nil {
		t.Fatal(err)
	}
	if s, err := keysource.OpenPKCS11(opts); !errors.Is(err, keysource.ErrHSMUnavailable) {
		if s != nil {
			s.Close()
		}
		t.Fatalf("absent token without DeferUnavailable: %v, want ErrHSMUnavailable", err)
	}
	src, err = keysource.OpenPKCS11(deferred)
	if err != nil {
		t.Fatalf("absent token with DeferUnavailable must start: %v", err)
	}
	defer src.Close()

	v := &vaultish{sealed: true}
	clk := &fakeClock{t: time.Unix(1_000_000, 0)}
	var lost, recovered int
	w := New(v, src, Options{
		NodeID: node, Shares: []Share{{Index: 1, Path: sharePath}}, Interval: time.Second,
		MaxUnsealAttempts: 1, Logger: quietLogger(), Now: clk.now,
		OnHSMLost:      func(error) { lost++ },
		OnHSMRecovered: func() { recovered++ },
	})
	for i := 0; i < 6; i++ {
		if err := w.Tick(context.Background()); err != nil {
			t.Fatalf("absent HSM at startup must not be terminal: %v", err)
		}
		clk.advance(time.Second)
	}
	if lost != 1 || recovered != 0 || v.calls != 0 || w.consecutiveFailures != 0 {
		t.Fatalf("while absent: lost=%d recovered=%d submissions=%d failures=%d", lost, recovered, v.calls, w.consecutiveFailures)
	}
	if w.hsmBackoff <= time.Second {
		t.Fatalf("no backoff while absent: %s", w.hsmBackoff)
	}

	// --- The token appears. Two peers have already contributed.
	if err := os.Rename(tokenDir+".absent", tokenDir); err != nil {
		t.Fatal(err)
	}
	v.mu.Lock()
	v.addPart("peer-two")
	v.addPart("peer-three")
	v.mu.Unlock()
	clk.advance(maxHSMBackoff)
	if err := w.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	st, _ := v.SealStatus(context.Background())
	if recovered != 1 || v.calls != 1 || st.Sealed {
		t.Fatalf("after restore: recovered=%d submissions=%d sealed=%v; want 1, 1, unsealed", recovered, v.calls, st.Sealed)
	}
}

func generateKey(t *testing.T, module, tokenLabel, pin, label string) {
	t.Helper()
	ctx := pkcs11.New(module)
	if ctx == nil {
		t.Fatalf("load %s", module)
	}
	defer ctx.Destroy()
	if err := ctx.Initialize(); err != nil {
		t.Fatal(err)
	}
	defer ctx.Finalize()
	slots, err := ctx.GetSlotList(true)
	if err != nil {
		t.Fatal(err)
	}
	var slot uint
	found := false
	for _, s := range slots {
		if info, err := ctx.GetTokenInfo(s); err == nil && trimPad(info.Label) == tokenLabel {
			slot, found = s, true
		}
	}
	if !found {
		t.Fatalf("token %q not found", tokenLabel)
	}
	session, err := ctx.OpenSession(slot, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		t.Fatal(err)
	}
	defer ctx.CloseSession(session)
	if err := ctx.Login(session, pkcs11.CKU_USER, pin); err != nil {
		t.Fatal(err)
	}
	defer ctx.Logout(session)
	if _, err := ctx.GenerateKey(session,
		[]*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_KEY_GEN, nil)},
		[]*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
			pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
			pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
			pkcs11.NewAttribute(pkcs11.CKA_VALUE_LEN, 32),
			pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
			pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false),
			pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true),
			pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, true),
		}); err != nil {
		t.Fatal(err)
	}
}

func trimPad(s string) string {
	for len(s) > 0 && (s[len(s)-1] == ' ' || s[len(s)-1] == 0) {
		s = s[:len(s)-1]
	}
	return s
}
