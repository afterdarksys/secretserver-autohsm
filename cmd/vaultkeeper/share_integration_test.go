package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/afterdarksys/secretserver-autohsm/internal/shamir"
)

// internal/shamir against shares produced by a real Vault: every 3-subset of
// the 5 init shares must combine to the same secret, and 2 shares must not.
func TestIntegrationShamirMatchesVaultShares(t *testing.T) {
	vaultBin, _ := requireIntegration(t)
	tv := startVault(t, vaultBin)
	parts := make([][]byte, len(tv.initHex))
	for i, h := range tv.initHex {
		b, err := hex.DecodeString(h)
		if err != nil {
			t.Fatal(err)
		}
		parts[i] = b
	}
	var ref []byte
	n := 0
	for a := 0; a < 5; a++ {
		for b := a + 1; b < 5; b++ {
			for c := b + 1; c < 5; c++ {
				s, err := shamir.Combine([][]byte{parts[a], parts[b], parts[c]})
				if err != nil {
					t.Fatal(err)
				}
				if ref == nil {
					ref = s
				} else if !bytes.Equal(ref, s) {
					t.Fatalf("Vault shares %d,%d,%d combine differently", a+1, b+1, c+1)
				}
				n++
			}
		}
	}
	if n != 10 || len(ref) != len(parts[0])-1 {
		t.Fatalf("checked %d subsets, secret %d bytes", n, len(ref))
	}
	if two, _ := shamir.Combine(parts[:2]); bytes.Equal(two, ref) {
		t.Fatal("two Vault shares reconstructed the threshold-3 secret")
	}
	if err := shamir.Consistent(parts, 3); err != nil {
		t.Fatal(err)
	}
	t.Logf("internal/shamir: all 10 triples of real %s init shares agree", tv.version)
}

// assertNoDamage: no init file shredded, every encrypted share file kept.
func assertNoDamage(t *testing.T, in *integ, initFile string) {
	t.Helper()
	if _, err := os.Stat(initFile); err != nil {
		t.Fatalf("init file shredded: %v", err)
	}
	m, _ := filepath.Glob(filepath.Join(in.k.outDir, "vault-share[1-5].*.gpg"))
	if len(m) != 5 {
		t.Fatalf("share files not all kept: %v", m)
	}
}

func setupInitFile(t *testing.T, in *integ) string {
	f := filepath.Join(t.TempDir(), "init-plaintext.txt")
	write(t, f, strings.Join(in.tv.initHex, "\n"))
	return f
}

// C1-residual: the completing node replaces only shares 4 and 5, which Vault
// never verifies. The local consistency proof catches it: nothing is
// delivered, nothing deleted or shredded, and the inconsistency alarm fires.
func TestIntegrationRekeyReplacedShares4And5(t *testing.T) {
	in := setupInteg(t, "", "")
	initFile := setupInitFile(t, in)
	r4, r5 := make([]byte, 33), make([]byte, 33)
	rand.Read(r4)
	rand.Read(r5)
	r4[32], r5[32] = 4, 5
	keys := filepath.Join(t.TempDir(), "keys")
	write(t, keys, encryptTo(t, in.op, in.op.fpr, []byte(hex.EncodeToString(r4)))+"\n"+
		encryptTo(t, in.op, in.off.fpr, []byte(hex.EncodeToString(r5)))+"\n")
	t.Setenv("VK_FORGE", "filter")
	t.Setenv("VK_FILTER_MODE", "replace45")
	t.Setenv("VK_FORGE_KEYS", keys)
	before := snapshotEnvelopes(t, in.f)

	code, out := in.keeper(t, "rekey", "--approval-contract", in.k.approval, "--shred-init-file", initFile)
	if code == 0 || !strings.Contains(out, "share 4 is not consistent") || !strings.Contains(out, "before verify; rekey cancelled") {
		t.Fatalf("replaced share 4 not caught before verify (exit %d):\n%s", code, out)
	}
	assertNoDamage(t, in, initFile)
	if a := in.alarmed("vaultkeeper_rekey_inconsistent"); !strings.Contains(a, "before verify") {
		t.Fatalf("no inconsistency alarm: %s", in.alarms.String())
	}
	// Cancelled before Vault switched: nodes untouched, no rekey pending, and
	// the OLD shares still unseal Vault.
	assertUntouched(t, in, before)
	in.finish(t)
}

// C1-residual: share 4 is a copy of share 2 (same x coordinate).
func TestIntegrationRekeyDuplicateShareInFour(t *testing.T) {
	in := setupInteg(t, "", "")
	initFile := setupInitFile(t, in)
	t.Setenv("VK_FORGE", "filter")
	t.Setenv("VK_FILTER_MODE", "dup2into4")
	before := snapshotEnvelopes(t, in.f)

	code, out := in.keeper(t, "rekey", "--approval-contract", in.k.approval, "--shred-init-file", initFile)
	if code == 0 || !strings.Contains(out, "before verify; rekey cancelled") {
		t.Fatalf("duplicated share 4 not caught before verify (exit %d):\n%s", code, out)
	}
	assertNoDamage(t, in, initFile)
	if a := in.alarmed("vaultkeeper_rekey_inconsistent"); !strings.Contains(a, "before verify") {
		t.Fatalf("no inconsistency alarm: %s", in.alarms.String())
	}
	assertUntouched(t, in, before)
	in.finish(t)
}

// C1-residual: a node swallows its new share and reports success. Nothing
// is gated on that claim: no shred, every file kept, and the rekey ends with
// the "unconfirmed" alarm (share 5 unverified, drill pending). The unseal
// drill is what exposes the lying node.
func TestIntegrationRekeyNodeDiscardsShare(t *testing.T) {
	in := setupInteg(t, "", "")
	initFile := setupInitFile(t, in)
	t.Setenv("VK_FORGE", "discard")
	t.Setenv("VK_FORGE_NODE", "node-c")
	before := snapshotEnvelopes(t, in.f)

	code, out := in.keeper(t, "rekey", "--approval-contract", in.k.approval, "--shred-init-file", initFile)
	if code != 0 || !strings.Contains(out, "node node-c: share 3 re-wrapped, node reports selftest OK") {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	if after, _ := os.ReadFile(in.f.nodes[2].sharePath()); !bytes.Equal(after, before["node-c"]) {
		t.Fatal("harness: node-c was supposed to discard its share")
	}
	assertNoDamage(t, in, initFile)
	if a := in.alarmed("vaultkeeper_rekey_unconfirmed"); !strings.Contains(a, "share5=UNVERIFIED") {
		t.Fatalf("no unconfirmed alarm: %s", in.alarms.String())
	}
	// Cleanup refuses without a drill confirmation...
	stubDrill(t, errDrill)
	if code, out := in.keeper(t, "rekey-cleanup", rekeyStamp(t, in)); code == 0 {
		t.Fatalf("cleanup without a drill:\n%s", out)
	}
	assertNoDamage(t, in, initFile)
	// ...and the drill fails with node-c's (old) share in the set.
	ctx := context.Background()
	in.tv.api(t, in.tv.rootToken, http.MethodPut, "/v1/sys/seal", nil, nil, 204)
	var lastErr error
	for _, n := range []int{0, 1, 2} {
		_, lastErr = in.tv.vc.SubmitUnsealShare(ctx, in.f.nodes[n].unwrapCurrent(t))
	}
	if st, _ := in.tv.vc.SealStatus(ctx); !st.Sealed || lastErr == nil {
		t.Fatal("drill with the lying node's share unsealed Vault")
	}
	in.tv.api(t, "", http.MethodPut, "/v1/sys/unseal", map[string]any{"reset": true}, nil, 200)
	unsealWithFiles(t, in, []int{1, 2, 3})
	in.finish(t)
}

var errDrill = os.ErrPermission

// unsealWithFiles seals Vault (if needed) and unseals it with the given
// operator-encrypted share files, proving they are the live shares.
func unsealWithFiles(t *testing.T, in *integ, idx []int) {
	t.Helper()
	ctx := context.Background()
	if st, _ := in.tv.vc.SealStatus(ctx); !st.Sealed {
		in.tv.api(t, in.tv.rootToken, http.MethodPut, "/v1/sys/seal", nil, nil, 204)
	}
	ts := rekeyStamp(t, in)
	for _, i := range idx {
		ct, _ := os.ReadFile(filepath.Join(in.k.outDir, shareFileName(i, ts)))
		share := bytes.TrimSpace(in.op.run(t, ct, "--batch", "--quiet", "--decrypt"))
		in.secrets["new share file "+string(rune('0'+i))] = string(share)
		if _, err := in.tv.vc.SubmitUnsealShare(ctx, share); err != nil {
			t.Fatalf("share file %d rejected: %v", i, err)
		}
	}
	if st, _ := in.tv.vc.SealStatus(ctx); st.Sealed {
		t.Fatal("the Vault-verified share files do not unseal")
	}
}
