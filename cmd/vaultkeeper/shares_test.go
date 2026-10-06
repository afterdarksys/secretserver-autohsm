package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"context"
)

const testStamp = "20261006T190000.000000000Z"

// cleanupFixture lays out the files of one rekey in the app's output dir.
func cleanupFixture(t *testing.T, vk *app, state string, share5Verified bool) string {
	dir := vk.cfg.OutputDir
	for i := 1; i <= 5; i++ {
		os.WriteFile(filepath.Join(dir, shareFileName(i, testStamp)), []byte("ENCRYPTED-"+string(rune('0'+i))), 0o600)
	}
	if state != "" {
		state = strings.Replace(state, `"__HASHES__"`, fixtureHashes(), 1)
		os.WriteFile(filepath.Join(dir, stateFileName(testStamp)), []byte(state), 0o600)
	}
	if share5Verified {
		sum := sha256.Sum256([]byte("ENCRYPTED-5"))
		os.WriteFile(filepath.Join(dir, share5MarkerName(testStamp)), []byte(hex.EncodeToString(sum[:])+"\n"), 0o600)
	}
	init := filepath.Join(t.TempDir(), "init.txt")
	os.WriteFile(init, []byte("plaintext init"), 0o600)
	return init
}

const provenJSON = `{"stamp":"` + testStamp + `","nonce":"x","sha256":"__HASHES__","vault_verified":[1,2,3],"consistent":[4]}`

func fixtureHashes() string {
	var parts []string
	for i := 1; i <= 5; i++ {
		sum := sha256.Sum256([]byte("ENCRYPTED-" + string(rune('0'+i))))
		parts = append(parts, `"`+string(rune('0'+i))+`":"`+hex.EncodeToString(sum[:])+`"`)
	}
	return "{" + strings.Join(parts, ",") + "}"
}

func countShareFiles(vk *app) int {
	m, _ := filepath.Glob(filepath.Join(vk.cfg.OutputDir, "vault-share[1-5].*.gpg"))
	return len(m)
}

func TestRekeyCleanupGates(t *testing.T) {
	cases := []struct {
		name     string
		state    string
		verified bool
		sealed   bool
		drill    error
		shred    bool
		wantErr  string
	}{
		{"no state", "", true, false, nil, false, "rekey state"},
		{"unproven state", `{"stamp":"` + testStamp + `","sha256":"__HASHES__","vault_verified":[],"consistent":[]}`, true, false, nil, false, "did not prove"},
		{"state without file hashes", `{"stamp":"` + testStamp + `","vault_verified":[1,2,3],"consistent":[4]}`, true, false, nil, false, "no file hash"},
		{"vault sealed", provenJSON, true, true, nil, false, "sealed"},
		{"no drill confirmation", provenJSON, true, false, errors.New("unseal drill not confirmed"), false, "drill"},
		{"shred with share 5 unverified", provenJSON, false, false, nil, true, "UNVERIFIED"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fv := newFakeVault(t)
			fv.sealed = tc.sealed
			vk, _, _ := newTestApp(t, fv)
			init := cleanupFixture(t, vk, tc.state, tc.verified)
			stubDrill(t, tc.drill)
			a := &cliArgs{positional: []string{testStamp}}
			if tc.shred {
				a.shredInit = init
			}
			err := vk.cmdRekeyCleanup(context.Background(), a)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err=%v, want %q", err, tc.wantErr)
			}
			if countShareFiles(vk) != 5 {
				t.Fatal("share files removed by a refused cleanup")
			}
			if _, err := os.Stat(init); err != nil {
				t.Fatal("init file shredded by a refused cleanup")
			}
		})
	}
}

func TestRekeyCleanupRemovesNodeSharesKeepsShare5(t *testing.T) {
	fv := newFakeVault(t)
	vk, _, _ := newTestApp(t, fv)
	init := cleanupFixture(t, vk, provenJSON, true)
	stubDrill(t, nil)
	if err := vk.cmdRekeyCleanup(context.Background(), &cliArgs{positional: []string{testStamp}, shredInit: init}); err != nil {
		t.Fatal(err)
	}
	if countShareFiles(vk) != 1 {
		t.Fatal("node share files not removed")
	}
	if _, err := os.Stat(filepath.Join(vk.cfg.OutputDir, shareFileName(5, testStamp))); err != nil {
		t.Fatal("share 5 removed")
	}
	if _, err := os.Stat(init); !os.IsNotExist(err) {
		t.Fatal("init not shredded")
	}
}

// A share 5 file changed after verification no longer satisfies the gate.
func TestShredGateDetectsChangedShare5(t *testing.T) {
	fv := newFakeVault(t)
	vk, _, _ := newTestApp(t, fv)
	cleanupFixture(t, vk, provenJSON, true)
	if err := vk.shredGate(vk.cfg.OutputDir, testStamp); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(vk.cfg.OutputDir, shareFileName(5, testStamp)), []byte("SWAPPED"), 0o600)
	if err := vk.shredGate(vk.cfg.OutputDir, testStamp); err == nil {
		t.Fatal("changed share 5 accepted")
	}
}

func TestConfirmDrillNeedsTerminal(t *testing.T) {
	if err := confirmDrill(strings.NewReader("unseal drill passed\n"), os.Stderr); err == nil {
		t.Fatal("non-terminal confirmation accepted")
	}
}

func TestSharesConsistentRejectsNonHex(t *testing.T) {
	if err := sharesConsistent([][]byte{[]byte("zz"), []byte("aa"), []byte("bb"), []byte("cc")}); err == nil {
		t.Fatal("non-hex share accepted")
	}
}

// L1: a share file swapped after the ceremony wrote it is never trusted:
// cleanup will not delete it and verify-share5 will not decrypt it.
func TestSwappedShareFileRefused(t *testing.T) {
	for _, idx := range []int{2, 5} {
		fv := newFakeVault(t)
		vk, _, key := newTestApp(t, fv)
		init := cleanupFixture(t, vk, provenJSON, true)
		os.WriteFile(filepath.Join(vk.cfg.OutputDir, shareFileName(idx, testStamp)), []byte("SWAPPED"), 0o600)
		stubDrill(t, nil)
		err := vk.cmdRekeyCleanup(context.Background(), &cliArgs{positional: []string{testStamp}, shredInit: init})
		if err == nil || !strings.Contains(err.Error(), "changed") {
			t.Fatalf("share %d: cleanup err=%v", idx, err)
		}
		if countShareFiles(vk) != 5 {
			t.Fatal("files removed despite a swapped share file")
		}
		vk.cfg.OfflineFingerprint = foreignFP
		vk.cfg.GPGPath = "/nonexistent/gpg"
		err = vk.cmdVerifyShare5(context.Background(), &cliArgs{positional: []string{filepath.Join(vk.cfg.OutputDir, shareFileName(5, testStamp))}})
		if err == nil || !strings.Contains(err.Error(), "changed") {
			t.Fatalf("share %d: verify-share5 err=%v", idx, err)
		}
		if key.decrypted != 0 {
			t.Fatal("a swapped file was decrypted")
		}
	}
}
