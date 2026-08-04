//go:build integration

package keysource

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/miekg/pkcs11"
)

// TestSoftHSMPKCS11 provisions an isolated temporary token and exercises the
// real PKCS#11 module. Run with:
//
//	AUTOHSM_TEST_MODULE=/path/to/libsofthsm2.so go test -tags=integration ./internal/keysource
func TestSoftHSMPKCS11(t *testing.T) {
	module := os.Getenv("AUTOHSM_TEST_MODULE")
	if module == "" {
		t.Skip("AUTOHSM_TEST_MODULE is not set")
	}
	util, err := exec.LookPath("softhsm2-util")
	if err != nil {
		t.Skip("softhsm2-util is not installed")
	}

	root := t.TempDir()
	tokenDir := filepath.Join(root, "tokens")
	if err := os.Mkdir(tokenDir, 0o700); err != nil {
		t.Fatal(err)
	}
	conf := filepath.Join(root, "softhsm2.conf")
	confBody := fmt.Appendf(nil, `directories.tokendir = %s
objectstore.backend = file
objectstore.umask = 0077
log.level = ERROR
slots.removable = false
slots.mechanisms = ALL
`, tokenDir)
	if err := os.WriteFile(conf, confBody, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SOFTHSM2_CONF", conf)

	const (
		tokenLabel = "autohsm-integration"
		userPIN    = "123456"
		soPIN      = "12345678"
		safeLabel  = "autohsm-wrap"
		badLabel   = "autohsm-extractable"
	)
	cmd := exec.Command(util, "--init-token", "--free", "--label", tokenLabel, "--so-pin", soPIN, "--pin", userPIN)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("initialize SoftHSM token: %v\n%s", err, out)
	}

	ctx := pkcs11.New(module)
	if ctx == nil {
		t.Fatalf("load SoftHSM module %q", module)
	}
	if err := ctx.Initialize(); err != nil {
		ctx.Destroy()
		t.Fatal(err)
	}
	slots, err := ctx.GetSlotList(true)
	if err != nil {
		t.Fatal(err)
	}
	slot, err := selectSlot(ctx, slots, tokenLabel)
	if err != nil {
		t.Fatal(err)
	}
	session, err := ctx.OpenSession(slot, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		t.Fatal(err)
	}
	if err := ctx.Login(session, pkcs11.CKU_USER, userPIN); err != nil {
		t.Fatal(err)
	}
	generateAESKey := func(label string, extractable bool) {
		t.Helper()
		_, err := ctx.GenerateKey(session,
			[]*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_KEY_GEN, nil)},
			[]*pkcs11.Attribute{
				pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
				pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
				pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
				pkcs11.NewAttribute(pkcs11.CKA_VALUE_LEN, 32),
				pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
				pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, extractable),
				pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true),
				pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, true),
			})
		if err != nil {
			t.Fatalf("generate %q: %v", label, err)
		}
	}
	generateAESKey(safeLabel, false)
	generateAESKey(badLabel, true)
	_ = ctx.Logout(session)
	_ = ctx.CloseSession(session)
	_ = ctx.Finalize()
	ctx.Destroy()

	open := func(label string) (Source, error) {
		return OpenPKCS11(PKCS11Options{
			ModulePath: module,
			TokenLabel: tokenLabel,
			KeyLabel:   label,
			PIN:        []byte(userPIN),
		})
	}
	src, err := open(safeLabel)
	if err != nil {
		t.Fatalf("open validated key: %v", err)
	}

	plaintext := []byte("real-softhsm-unseal-share")
	aad := AAD("integration-node", 1)
	nonce := make([]byte, gcmNonceLen)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	envelope, err := Wrap(src, nonce, plaintext, aad)
	if err != nil {
		t.Fatalf("wrap through SoftHSM: %v", err)
	}
	got, err := src.Unwrap(context.Background(), []byte(envelope), aad)
	if err != nil {
		t.Fatalf("unwrap through SoftHSM: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("round trip got %q", got)
	}
	for i := range got {
		got[i] = 0
	}
	if _, err := src.Unwrap(context.Background(), []byte(envelope), AAD("other-node", 1)); err == nil {
		t.Fatal("SoftHSM accepted mismatched AAD")
	}
	parsed, err := ParseEnvelope([]byte(envelope))
	if err != nil {
		t.Fatal(err)
	}
	parsed.Ciphertext[0] ^= 0xff
	if _, err := src.Unwrap(context.Background(), []byte(MarshalEnvelope(parsed)), aad); err == nil {
		t.Fatal("SoftHSM accepted tampered ciphertext")
	}
	if err := src.Close(); err != nil {
		t.Fatal(err)
	}

	if unsafe, err := open(badLabel); err == nil {
		unsafe.Close()
		t.Fatal("extractable SoftHSM key passed startup validation")
	}
}
