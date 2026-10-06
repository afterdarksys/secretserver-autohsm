package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/afterdarksys/secretserver-autohsm/internal/ceremony"
)

// Hostile-runner integration tests: a forged or substituted ceremony result
// must never touch the nodes or strand Vault, and an unreadable result must
// be saved, not lost.

// encryptTo encrypts plain to fpr with the given keyring, returning base64.
func encryptTo(t *testing.T, h *gpgHome, fpr string, plain []byte) string {
	t.Helper()
	ct := h.run(t, plain, "--batch", "--trust-model", "always", "--encrypt", "--recipient", fpr)
	return base64.StdEncoding.EncodeToString(ct)
}

// forgedRekeyLine is a well-formed rekey result whose five shares are random
// values the attacker made up, encrypted to the right keys in the right order.
func forgedRekeyLine(t *testing.T, in *integ) string {
	t.Helper()
	keys := make([]string, 5)
	for i := range keys {
		b := make([]byte, 33)
		rand.Read(b)
		fpr := in.op.fpr
		if i == 4 {
			fpr = in.off.fpr
		}
		keys[i] = encryptTo(t, in.op, fpr, []byte(hex.EncodeToString(b)))
	}
	line, err := (&ceremony.Result{Op: ceremony.OpRekey, Nonce: "00000000-0000-0000-0000-000000000000",
		KeysBase64: keys, PGPFingerprints: ceremony.RekeyLayout(in.op.fpr, in.off.fpr)}).Line()
	if err != nil {
		t.Fatal(err)
	}
	return strings.Replace(line, "00000000-0000-0000-0000-000000000000", "__NONCE__", 1)
}

func setForge(t *testing.T, mode, node, path, line string) {
	f := filepath.Join(t.TempDir(), "forged.line")
	write(t, f, line+"\n")
	t.Setenv("VK_FORGE", mode)
	t.Setenv("VK_FORGE_NODE", node)
	t.Setenv("VK_FORGE_PATH", path)
	t.Setenv("VK_FORGE_LINE", f)
}

func snapshotEnvelopes(t *testing.T, f *fleet) map[string][]byte {
	m := map[string][]byte{}
	for _, n := range f.nodes {
		b, err := os.ReadFile(n.sharePath())
		if err != nil {
			t.Fatal(err)
		}
		m[n.name] = b
	}
	return m
}

// assertUntouched: envelopes byte-identical, no install happened, no rekey
// pending, and the OLD shares still unseal Vault.
func assertUntouched(t *testing.T, in *integ, before map[string][]byte) {
	t.Helper()
	for _, n := range in.f.nodes {
		b, _ := os.ReadFile(n.sharePath())
		if !bytes.Equal(b, before[n.name]) {
			t.Fatalf("%s envelope changed", n.name)
		}
		if _, err := os.Stat(n.sharePath() + ".prev"); err == nil {
			t.Fatalf("%s: an install happened", n.name)
		}
	}
	ctx := context.Background()
	if rk, _ := in.tv.vc.RekeyAttempt(ctx); rk.Started {
		t.Fatal("rekey attempt left pending")
	}
	in.tv.api(t, in.tv.rootToken, http.MethodPut, "/v1/sys/seal", nil, nil, 204)
	for i := 0; i < 3; i++ {
		if _, err := in.tv.vc.SubmitUnsealShare(ctx, []byte(in.tv.initHex[i])); err != nil {
			t.Fatalf("old share %d rejected: Vault was rekeyed by a forged result: %v", i+1, err)
		}
	}
	if st, _ := in.tv.vc.SealStatus(ctx); st.Sealed {
		t.Fatal("old shares no longer unseal")
	}
}

// C1: a forged result appended to the FIRST node's output, before quorum,
// is rejected; the ceremony aborts and nothing changes.
func TestIntegrationRekeyForgedResultBeforeQuorum(t *testing.T) {
	in := setupInteg(t, "", "")
	setForge(t, "append", "node-a", "rekey/init", forgedRekeyLine(t, in))
	before := snapshotEnvelopes(t, in.f)
	code, out := in.keeper(t, "rekey", "--approval-contract", in.k.approval)
	if code == 0 || !strings.Contains(out, "rejected as forged") {
		t.Fatalf("forged early result not rejected (exit %d):\n%s", code, out)
	}
	assertUntouched(t, in, before)
	in.finish(t)
}

// C1: the completing node's real result is swapped for a forged one with
// the right nonce and layout. Verification fails, Vault keeps the old
// shares, and no node is touched.
func TestIntegrationRekeySubstitutedResultAtCompletion(t *testing.T) {
	in := setupInteg(t, "", "")
	setForge(t, "replace", "", "", forgedRekeyLine(t, in))
	before := snapshotEnvelopes(t, in.f)
	code, out := in.keeper(t, "rekey", "--approval-contract", in.k.approval)
	// Random forged shares fail the local consistency proof (before verify);
	// a consistent forgery would fail Vault's verification. Either way the
	// rekey is cancelled while Vault is still on the old shares.
	if code == 0 || !strings.Contains(out, "rekey cancelled") || !strings.Contains(out, "Vault keeps the old shares") {
		t.Fatalf("substituted result not caught before Vault switched (exit %d):\n%s", code, out)
	}
	assertUntouched(t, in, before)
	// The ceremony never deletes share files; these belong to the cancelled
	// rekey and open nothing. No rekey state is recorded.
	if m, _ := filepath.Glob(filepath.Join(in.k.outDir, "vault-share*")); len(m) != 5 {
		t.Fatalf("share files: %v", m)
	}
	if _, err := provenState(in.k.outDir, rekeyStamp(t, in)); err == nil {
		t.Fatal("a cancelled rekey is recorded as proven")
	}
	in.finish(t)
}

// M1: the real generate-root result is swapped for a pre-minted orphan root
// token encrypted to the operator key. vaultkeeper decrypts it, sees it is
// not this ceremony's token, runs no task, revokes it, and says the real
// ceremony token may be live (it is: the substitution discarded it).
func TestIntegrationRootTaskSubstitutedTokenRejected(t *testing.T) {
	in := setupInteg(t, "", "")
	var orphan struct {
		Auth struct {
			ClientToken string `json:"client_token"`
			Accessor    string `json:"accessor"`
		} `json:"auth"`
	}
	in.tv.api(t, in.tv.rootToken, http.MethodPost, "/v1/auth/token/create-orphan", map[string]any{"policies": []string{"root"}}, &orphan, 200)
	in.secrets["pre-minted root"] = orphan.Auth.ClientToken
	line, _ := (&ceremony.Result{Op: ceremony.OpGenerateRoot, Nonce: "00000000-0000-0000-0000-000000000000",
		EncodedToken: encryptTo(t, in.op, in.op.fpr, []byte(orphan.Auth.ClientToken)), PGPFingerprint: in.op.fpr}).Line()
	setForge(t, "replace", "", "", strings.Replace(line, "00000000-0000-0000-0000-000000000000", "__NONCE__", 1))

	var victim struct {
		Auth struct {
			Accessor string `json:"accessor"`
		} `json:"auth"`
	}
	in.tv.api(t, in.tv.rootToken, http.MethodPost, "/v1/auth/token/create-orphan", map[string]any{"policies": []string{"default"}}, &victim, 200)
	initAcc := in.tv.accessorOf(t, in.tv.rootToken)

	code, out := in.keeper(t, "root-task", "revoke-token", victim.Auth.Accessor, "--approval-contract", in.k.approval)
	if code == 0 || !strings.Contains(out, "may still be live") || !strings.Contains(out, "auth/token/create-orphan") ||
		!strings.Contains(out, "rejected token revoked/invalid (lookup-self: 403)") || strings.Contains(out, "root token revoked") {
		t.Fatalf("substituted token not rejected and reported as such (exit %d):\n%s", code, out)
	}
	if st := in.tv.api(t, in.tv.rootToken, http.MethodPost, "/v1/auth/token/lookup-accessor", map[string]string{"accessor": victim.Auth.Accessor}, nil, 0); st != 200 {
		t.Fatal("the task ran with a substituted token")
	}
	if st := in.tv.api(t, orphan.Auth.ClientToken, http.MethodGet, "/v1/auth/token/lookup-self", nil, nil, 0); st != http.StatusForbidden {
		t.Fatal("the substituted root token was not revoked")
	}
	// The real ceremony token was discarded by the substitution and is live:
	// exactly what the alarm warns about.
	if live := in.tv.rootTokensOtherThan(t, initAcc); len(live) != 1 {
		t.Fatalf("expected the discarded ceremony token to be the one live root token, got %v", live)
	}
	in.finish(t)
}

// H1: a runner that labels output lines hides the result line from the
// strict parser. The raw output is saved (0600) and the token in it is still
// recoverable with the operator key: nothing is lost.
func TestIntegrationRootTaskPrefixedRunnerOutputSaved(t *testing.T) {
	in := setupInteg(t, "", "")
	setForge(t, "prefix", "", "", "unused")
	code, out := in.keeper(t, "root-task", "rekey-cancel", "--approval-contract", in.k.approval)
	if code == 0 || !strings.Contains(out, "CRITICAL") {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	raws, _ := filepath.Glob(filepath.Join(in.k.outDir, "vaultkeeper-raw-generate-root-node-c-*"))
	if len(raws) != 1 {
		t.Fatalf("raw output not saved: %v\n%s", raws, out)
	}
	if info, _ := os.Stat(raws[0]); info.Mode().Perm() != 0o600 {
		t.Fatalf("raw file mode %v", info.Mode().Perm())
	}
	raw, _ := os.ReadFile(raws[0])
	var line string
	for _, l := range strings.Split(string(raw), "\n") {
		if strings.HasPrefix(l, "node-c | "+ceremony.ResultPrefix) {
			line = strings.TrimPrefix(l, "node-c | ")
		}
	}
	res, err := ceremony.ParseResult(line)
	if err != nil {
		t.Fatalf("saved raw output holds no recoverable result: %v\n%s", err, raw)
	}
	ct, _ := base64.StdEncoding.DecodeString(res.EncodedToken)
	token := strings.TrimSpace(string(in.op.run(t, ct, "--batch", "--quiet", "--decrypt")))
	in.secrets["recovered ceremony token"] = token
	var info struct {
		Data struct {
			Policies []string `json:"policies"`
		} `json:"data"`
	}
	in.tv.api(t, token, http.MethodGet, "/v1/auth/token/lookup-self", nil, &info, 200)
	if len(info.Data.Policies) != 1 || info.Data.Policies[0] != "root" {
		t.Fatalf("recovered token policies %v", info.Data.Policies)
	}
	in.tv.api(t, token, http.MethodPost, "/v1/auth/token/revoke-self", nil, nil, 204)
	in.finish(t)
}

// A consistent forgery (the CURRENT shares replayed, encrypted to the right
// keys in the right order) passes the local consistency proof; Vault's
// verification then rejects it and the rekey is cancelled.
func TestIntegrationRekeyReplayedConsistentSharesFailVerify(t *testing.T) {
	in := setupInteg(t, "", "")
	keys := make([]string, 5)
	for i := range keys {
		fpr := in.op.fpr
		if i == 4 {
			fpr = in.off.fpr
		}
		keys[i] = encryptTo(t, in.op, fpr, []byte(in.tv.initHex[i]))
	}
	line, _ := (&ceremony.Result{Op: ceremony.OpRekey, Nonce: "00000000-0000-0000-0000-000000000000",
		KeysBase64: keys, PGPFingerprints: ceremony.RekeyLayout(in.op.fpr, in.off.fpr)}).Line()
	setForge(t, "replace", "", "", strings.Replace(line, "00000000-0000-0000-0000-000000000000", "__NONCE__", 1))
	before := snapshotEnvelopes(t, in.f)
	code, out := in.keeper(t, "rekey", "--approval-contract", in.k.approval)
	if code == 0 || !strings.Contains(out, "rekey verification failed") || !strings.Contains(out, "Vault keeps the old shares") {
		t.Fatalf("replayed shares not rejected by verification (exit %d):\n%s", code, out)
	}
	assertUntouched(t, in, before)
	in.finish(t)
}
