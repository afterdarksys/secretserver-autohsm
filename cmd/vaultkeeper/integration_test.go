package main

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/afterdarksys/secretserver-autohsm/internal/keysource"
	"github.com/afterdarksys/secretserver-autohsm/internal/vaultclient"
)

type integ struct {
	tv       *testVault
	op, off  *gpgHome
	f        *fleet
	k        *keeperEnv
	gpgBin   string
	captured []string // every piece of output, for the leak grep
	secrets  map[string]string
	alarms   *syncBuffer // every webhook body vaultkeeper posted
}

// alarmed returns the posted alarm bodies that carry event.
func (in *integ) alarmed(event string) string {
	var out []string
	for _, l := range strings.Split(in.alarms.String(), "\n") {
		if strings.Contains(l, `"event":"`+event+`"`) {
			out = append(out, l)
		}
	}
	return strings.Join(out, "\n")
}

func setupInteg(t *testing.T, gpgPath, extra string) *integ {
	vaultBin, gpgBin := requireIntegration(t)
	in := &integ{tv: startVault(t, vaultBin), gpgBin: gpgBin}
	t.Logf("integration: real %s, file storage, 5 shares / threshold 3", in.tv.version)
	in.op = newGPGHome(t, gpgBin, "test-operator <operator@example.invalid>")
	in.off = newGPGHome(t, gpgBin, "test-offline <offline@example.invalid>")
	// The operator keyring holds only the PUBLIC half of the offline key.
	in.op.importPublic(t, in.off)
	in.f = newFleet(t, in.tv, in.op.fpr, in.off.fpr)
	if gpgPath == "" {
		gpgPath = gpgBin
	}
	// A TLS webhook receiver; vaultkeeper pins its CA via alarm.ca_cert_path.
	in.alarms = &syncBuffer{}
	hook := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		in.alarms.Write(append(b, '\n'))
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(hook.Close)
	hookCA := filepath.Join(t.TempDir(), "hook-ca.pem")
	write(t, hookCA, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: hook.Certificate().Raw})))
	extra += fmt.Sprintf("alarm:\n  webhook_url: %s\n  ca_cert_path: %s\n", hook.URL, hookCA)
	in.k = newKeeper(t, in.tv, in.f, in.op, in.off.fpr, gpgPath, extra)
	in.secrets = map[string]string{"init root token": in.tv.rootToken}
	for i := range in.tv.initHex {
		in.secrets["init share hex "+string(rune('1'+i))] = in.tv.initHex[i]
		in.secrets["init share b64 "+string(rune('1'+i))] = in.tv.initB64[i]
	}
	return in
}

func (in *integ) keeper(t *testing.T, args ...string) (int, string) {
	code, out := runKeeper(t, in.k, args...)
	in.captured = append(in.captured, out)
	if os.Getenv("VK_TEST_LOG") != "" {
		t.Logf("vaultkeeper %v -> exit %d\n%s", args, code, out)
	}
	return code, out
}

// finish runs the secret-leak grep over everything this test captured: the
// vaultkeeper output, node stderr (through the runner), node stdout (teed by
// the runner shim), and the Vault server log.
func (in *integ) finish(t *testing.T) {
	nodeOut, _ := os.ReadFile(in.f.stdoutLog)
	leakCheck(t, "vaultkeeper/runner output", strings.Join(in.captured, "\n"), in.secrets)
	leakCheck(t, "node stdout", string(nodeOut), in.secrets)
	leakCheck(t, "vault server log", in.tv.log.String(), in.secrets)
	leakCheck(t, "alarm webhook bodies", in.alarms.String(), in.secrets)
}

// Acceptance 3: root-task revoke-token against a real 5/3 Vault, 3 node
// contributions; afterwards the target accessor is gone and no root token
// other than the harness's own init token exists (the generated one is
// revoked, verified by vaultkeeper with a 403 lookup).
func TestIntegrationRootTaskRevokeToken(t *testing.T) {
	in := setupInteg(t, "", "")
	// Stand-in for the exposed standing root: an orphan root token.
	var created struct {
		Auth struct {
			ClientToken string `json:"client_token"`
			Accessor    string `json:"accessor"`
		} `json:"auth"`
	}
	in.tv.api(t, in.tv.rootToken, http.MethodPost, "/v1/auth/token/create-orphan", map[string]any{"policies": []string{"root"}}, &created, 200)
	in.secrets["standing root token"] = created.Auth.ClientToken
	initAcc := in.tv.accessorOf(t, in.tv.rootToken)

	code, out := in.keeper(t, "root-task", "revoke-token", created.Auth.Accessor, "--approval-contract", in.k.approval)
	if code != 0 {
		t.Fatalf("root-task exit %d:\n%s", code, out)
	}
	for _, want := range []string{"revoked token accessor " + created.Auth.Accessor, "root token revoked (lookup-self: 403)"} {
		if !strings.Contains(out, want) {
			t.Fatalf("output lacks %q:\n%s", want, out)
		}
	}
	if n := strings.Count(out, "contribute op=generate-root"); n != 0 {
		t.Logf("note: contribute lines appear in vaultkeeper output %d times", n)
	}
	nodeOut, _ := os.ReadFile(in.f.stdoutLog)
	if got := strings.Count(string(nodeOut), "contribute op=generate-root"); got != 3 {
		t.Fatalf("want exactly 3 node contributions, got %d:\n%s", got, nodeOut)
	}
	// Target accessor: not found.
	if st := in.tv.api(t, in.tv.rootToken, http.MethodPost, "/v1/auth/token/lookup-accessor", map[string]string{"accessor": created.Auth.Accessor}, nil, 0); st != http.StatusBadRequest {
		t.Fatalf("target accessor lookup status %d, want 400 (invalid accessor)", st)
	}
	if st := in.tv.api(t, created.Auth.ClientToken, http.MethodGet, "/v1/auth/token/lookup-self", nil, nil, 0); st != http.StatusForbidden {
		t.Fatalf("standing root still valid: %d", st)
	}
	if extra := in.tv.rootTokensOtherThan(t, initAcc); len(extra) != 0 {
		t.Fatalf("root tokens left behind: %v", extra)
	}
	if gr, _ := in.tv.vc.GenerateRootAttempt(context.Background()); gr.Started {
		t.Fatal("generate-root attempt left in progress")
	}
	in.finish(t)
}

// Acceptance 4: SIGTERM after decrypt still revokes. A gpg wrapper sends
// SIGTERM to the real vaultkeeper process the moment decrypt finishes (and
// lingers so the signal lands while the root token is live).
func TestIntegrationRootTaskSIGTERMAfterDecryptRevokes(t *testing.T) {
	_, gpgBin := requireIntegration(t)
	wrapper := filepath.Join(t.TempDir(), "gpg-sigterm.sh")
	if err := os.WriteFile(wrapper, []byte(`#!/bin/bash
"`+gpgBin+`" "$@"; rc=$?
case " $* " in *" --decrypt "*) kill -TERM $PPID; sleep 1;; esac
exit $rc
`), 0o700); err != nil {
		t.Fatal(err)
	}
	in := setupInteg(t, wrapper, "")
	var created struct {
		Auth struct {
			Accessor string `json:"accessor"`
		} `json:"auth"`
	}
	in.tv.api(t, in.tv.rootToken, http.MethodPost, "/v1/auth/token/create-orphan", map[string]any{"policies": []string{"default"}}, &created, 200)
	initAcc := in.tv.accessorOf(t, in.tv.rootToken)

	bin := filepath.Join(t.TempDir(), "vaultkeeper")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("build vaultkeeper: %v: %s", err, out)
	}
	cmd := exec.Command(bin, "root-task", "revoke-token", created.Auth.Accessor,
		"--approval-contract", in.k.approval, "--config", in.k.cfgPath)
	cmd.Env = append(os.Environ(), "GNUPGHOME="+in.k.gpgHome)
	out, err := cmd.CombinedOutput()
	in.captured = append(in.captured, string(out))
	if err == nil {
		t.Fatalf("vaultkeeper exited 0 despite SIGTERM before the task:\n%s", out)
	}
	if ee, ok := err.(*exec.ExitError); !ok || ee.Sys().(syscall.WaitStatus).Signaled() {
		t.Fatalf("vaultkeeper was killed by the signal instead of handling it: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "root token revoked (lookup-self: 403)") {
		t.Fatalf("no verified revoke after SIGTERM:\n%s", out)
	}
	if extra := in.tv.rootTokensOtherThan(t, initAcc); len(extra) != 0 {
		t.Fatalf("generated root token survived SIGTERM: %v\n%s", extra, out)
	}
	// The task never ran: the target is still valid.
	if st := in.tv.api(t, in.tv.rootToken, http.MethodPost, "/v1/auth/token/lookup-accessor", map[string]string{"accessor": created.Auth.Accessor}, nil, 0); st != 200 {
		t.Fatalf("task ran after SIGTERM (target lookup %d)", st)
	}
	in.finish(t)
}

// Acceptance 5: rekey produces 5 new shares; 4 are re-wrapped and selftest
// passes on all 4 nodes; the new node shares unseal, the old ones do not;
// share 5 is stored only PGP-encrypted to the offline key and works.
func TestIntegrationRekey(t *testing.T) {
	in := setupInteg(t, "", "")
	initFile := filepath.Join(t.TempDir(), "init-plaintext.txt")
	write(t, initFile, strings.Join(in.tv.initHex, "\n"))

	code, out := in.keeper(t, "rekey", "--approval-contract", in.k.approval, "--shred-init-file", initFile)
	if code != 0 {
		t.Fatalf("rekey exit %d:\n%s", code, out)
	}
	for _, n := range in.f.nodes {
		if !strings.Contains(out, "node "+n.name+": share ") || !strings.Contains(out, "selftest OK") {
			t.Fatalf("node %s not re-wrapped + selftested:\n%s", n.name, out)
		}
	}
	// The ceremony shreds nothing and deletes nothing: share 5 is unverified.
	if _, err := os.Stat(initFile); err != nil {
		t.Fatalf("init file shredded during the ceremony: %v", err)
	}
	if !strings.Contains(out, "NOT shredding") || !strings.Contains(out, "UNVERIFIED") {
		t.Fatalf("shred refusal not explained:\n%s", out)
	}
	ts := rekeyStamp(t, in)
	for i := 1; i <= 5; i++ {
		info, err := os.Stat(filepath.Join(in.k.outDir, shareFileName(i, ts)))
		if err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("share file %d: %v", i, err)
		}
	}
	if a := in.alarmed("vaultkeeper_rekey_unconfirmed"); !strings.Contains(a, "share5=UNVERIFIED") {
		t.Fatalf("no unconfirmed alarm: %q", in.alarms.String())
	}
	enc5, _ := os.ReadFile(filepath.Join(in.k.outDir, shareFileName(5, ts)))
	// It is encrypted to the offline key: the operator keyring cannot open it.
	if c := exec.Command(in.gpgBin, "--batch", "--decrypt"); true {
		c.Env = append(os.Environ(), "GNUPGHOME="+in.op.dir)
		c.Stdin = strings.NewReader(string(enc5))
		if err := c.Run(); err == nil {
			t.Fatal("share 5 decrypts with the operator key")
		}
	}
	share5 := strings.TrimSpace(string(in.off.run(t, enc5, "--batch", "--quiet", "--decrypt")))
	// Each node kept its previous envelope, which still opens the OLD share.
	for _, n := range in.f.nodes {
		prev, err := os.ReadFile(n.sharePath() + ".prev")
		if err != nil {
			t.Fatalf("%s: no .prev envelope: %v", n.name, err)
		}
		src, _ := keysource.NewSoftware(n.devKey)
		old, err := src.Unwrap(context.Background(), prev, keysource.AAD(n.name, n.index))
		if err != nil || string(old) != in.tv.initHex[n.index-1] {
			t.Fatalf("%s: .prev does not hold the old share", n.name)
		}
	}

	newShares := map[string][]byte{}
	for _, n := range in.f.nodes {
		newShares[n.name] = n.unwrapCurrent(t)
		in.secrets["new share "+n.name] = string(newShares[n.name])
		for i := range in.tv.initHex {
			if string(newShares[n.name]) == in.tv.initHex[i] {
				t.Fatalf("%s still holds an old share", n.name)
			}
		}
	}
	in.secrets["new share 5"] = share5

	ctx := context.Background()
	seal := func() { in.tv.api(t, in.tv.rootToken, http.MethodPut, "/v1/sys/seal", nil, nil, 204) }
	reset := func() { in.tv.api(t, "", http.MethodPut, "/v1/sys/unseal", map[string]any{"reset": true}, nil, 200) }

	// Old shares no longer unseal.
	seal()
	var lastErr error
	for i := 0; i < 3; i++ {
		_, lastErr = in.tv.vc.SubmitUnsealShare(ctx, []byte(in.tv.initHex[i]))
	}
	if st, _ := in.tv.vc.SealStatus(ctx); !st.Sealed || lastErr == nil {
		t.Fatalf("old shares unsealed the rekeyed Vault (err=%v)", lastErr)
	}
	reset()
	// Three new node shares unseal.
	var st *vaultclient.SealStatus
	for _, n := range in.f.nodes[:3] {
		var err error
		if st, err = in.tv.vc.SubmitUnsealShare(ctx, newShares[n.name]); err != nil {
			t.Fatal(err)
		}
	}
	if st.Sealed {
		t.Fatal("new node shares did not unseal")
	}
	// Share 5 plus any two nodes also unseals (the rollback guarantee).
	seal()
	for _, s := range [][]byte{[]byte(share5), newShares["node-c"], newShares["node-d"]} {
		var err error
		if st, err = in.tv.vc.SubmitUnsealShare(ctx, s); err != nil {
			t.Fatal(err)
		}
	}
	if st.Sealed {
		t.Fatal("share 5 + two node shares did not unseal")
	}

	// Cleanup is refused while share 5 is unverified...
	stubDrill(t, nil)
	code, out = in.keeper(t, "rekey-cleanup", ts, "--shred-init-file", initFile)
	if code == 0 || !strings.Contains(out, "UNVERIFIED") {
		t.Fatalf("shred allowed with share 5 unverified (exit %d):\n%s", code, out)
	}
	// ...verify-share5 where the offline key is (temporarily) present...
	in.op.importSecret(t, in.off)
	code, out = in.keeper(t, "verify-share5", filepath.Join(in.k.outDir, shareFileName(5, ts)))
	if code != 0 || !strings.Contains(out, "share 5 VERIFIED") {
		t.Fatalf("verify-share5 exit %d:\n%s", code, out)
	}
	// ...then cleanup after the drill: 1-4 removed, share 5 kept, init shredded.
	code, out = in.keeper(t, "rekey-cleanup", ts, "--shred-init-file", initFile)
	if code != 0 {
		t.Fatalf("rekey-cleanup exit %d:\n%s", code, out)
	}
	for i := 1; i <= 4; i++ {
		if _, err := os.Stat(filepath.Join(in.k.outDir, shareFileName(i, ts))); !os.IsNotExist(err) {
			t.Fatalf("share file %d not removed", i)
		}
	}
	if _, err := os.Stat(filepath.Join(in.k.outDir, shareFileName(5, ts))); err != nil {
		t.Fatal("share 5 file removed")
	}
	if _, err := os.Stat(initFile); !os.IsNotExist(err) {
		t.Fatal("init file not shredded after full proof")
	}
	in.finish(t)
}

// rekeyStamp returns the stamp of the single rekey in the output dir.
func rekeyStamp(t *testing.T, in *integ) string {
	t.Helper()
	m, _ := filepath.Glob(filepath.Join(in.k.outDir, "vault-share1.*.gpg"))
	if len(m) != 1 {
		t.Fatalf("want one rekey in output dir, got %v", m)
	}
	return strings.TrimSuffix(strings.TrimPrefix(filepath.Base(m[0]), "vault-share1."), ".gpg")
}

// stubDrill stands in for the terminal confirmation of an unseal drill.
func stubDrill(t *testing.T, err error) {
	old := confirmDrill
	confirmDrill = func(io.Reader, io.Writer) error { return err }
	t.Cleanup(func() { confirmDrill = old })
}

// Acceptance 6: rotate-keyring with the narrow AppRole advances the keyring
// term, and that AppRole is refused on sys/generate-root and on secret/.
func TestIntegrationRotateKeyring(t *testing.T) {
	secretDir := t.TempDir()
	secretPath := filepath.Join(secretDir, "secret-id")
	in := setupInteg(t, "", "approle:\n  role_id: ROLEID\n  secret_id_path: "+secretPath+"\n")
	root := in.tv.rootToken
	in.tv.api(t, root, http.MethodPost, "/v1/sys/auth/approle", map[string]string{"type": "approle"}, nil, 204)
	in.tv.api(t, root, http.MethodPost, "/v1/sys/mounts/secret", map[string]any{"type": "kv", "options": map[string]string{"version": "2"}}, nil, 204)
	// The policy and role settings shipped in deploy/, with the placeholder
	// CIDR bound to loopback.
	policy, err := os.ReadFile("../../deploy/vaultkeeper-rotate-policy.hcl")
	if err != nil {
		t.Fatal(err)
	}
	in.tv.api(t, root, http.MethodPut, "/v1/sys/policies/acl/vaultkeeper-rotate", map[string]string{"policy": string(policy)}, nil, 204)
	roleJSON, err := os.ReadFile("../../deploy/vaultkeeper-rotate-role.json")
	if err != nil {
		t.Fatal(err)
	}
	var role map[string]any
	if err := json.Unmarshal([]byte(strings.ReplaceAll(string(roleJSON), "192.0.2.10/32", "127.0.0.1/32")), &role); err != nil {
		t.Fatal(err)
	}
	in.tv.api(t, root, http.MethodPost, "/v1/auth/approle/role/vaultkeeper-rotate", role, nil, 204)
	var rid, sid struct {
		Data struct {
			RoleID   string `json:"role_id"`
			SecretID string `json:"secret_id"`
		} `json:"data"`
	}
	in.tv.api(t, root, http.MethodGet, "/v1/auth/approle/role/vaultkeeper-rotate/role-id", nil, &rid, 200)
	in.tv.api(t, root, http.MethodPost, "/v1/auth/approle/role/vaultkeeper-rotate/secret-id", nil, &sid, 200)
	write(t, secretPath, sid.Data.SecretID+"\n")
	// token_num_uses must cover rotate-keyring (key-status, rotate,
	// key-status, revoke-self) and status (key-status, revoke-self).
	in.secrets["approle secret_id"] = sid.Data.SecretID
	cfg, _ := os.ReadFile(in.k.cfgPath)
	write(t, in.k.cfgPath, strings.Replace(string(cfg), "ROLEID", rid.Data.RoleID, 1))

	before := keyTerm(t, in.tv)
	code, out := in.keeper(t, "rotate-keyring")
	if code != 0 {
		t.Fatalf("rotate-keyring exit %d:\n%s", code, out)
	}
	if after := keyTerm(t, in.tv); after != before+1 {
		t.Fatalf("term %d -> %d, want +1\n%s", before, after, out)
	}

	// The same AppRole, logged in by the harness: 403 outside its two paths.
	tok, err := in.tv.vc.AppRoleLogin(context.Background(), "approle", rid.Data.RoleID, []byte(sid.Data.SecretID))
	if err != nil {
		t.Fatal(err)
	}
	in.secrets["approle token"] = string(tok)
	for _, p := range []struct{ method, path string }{
		{http.MethodGet, "/v1/secret/data/anything"},
		{http.MethodPut, "/v1/secret/data/anything"},
		{http.MethodPut, "/v1/sys/policies/acl/escalate"},
		{http.MethodPost, "/v1/auth/token/create"},
		{http.MethodPut, "/v1/sys/seal"},
	} {
		if st := in.tv.api(t, string(tok), p.method, p.path, map[string]string{}, nil, 0); st != http.StatusForbidden {
			t.Errorf("approle %s %s: status %d, want 403", p.method, p.path, st)
		}
	}
	// sys/generate-root/attempt: the AppRole must gain nothing over an
	// anonymous caller. With unauthenticated ceremony endpoints (1.x
	// default; 2.x with enable_unauthenticated_access) both may start an
	// attempt, which is exactly why the node-side PGP pin is the boundary.
	// With them authenticated (2.x default) the AppRole gets 403.
	anon := in.tv.api(t, "", http.MethodPut, "/v1/sys/generate-root/attempt", map[string]any{}, nil, 0)
	in.tv.api(t, "", http.MethodDelete, "/v1/sys/generate-root/attempt", nil, nil, 0)
	withRole := in.tv.api(t, string(tok), http.MethodPut, "/v1/sys/generate-root/attempt", map[string]any{}, nil, 0)
	in.tv.api(t, "", http.MethodDelete, "/v1/sys/generate-root/attempt", nil, nil, 0)
	if withRole != anon || (anon != 200 && withRole != http.StatusForbidden) {
		t.Errorf("generate-root/attempt: approle %d vs anonymous %d", withRole, anon)
	}
	t.Logf("generate-root/attempt PUT on %s: anonymous %d, approle %d", in.tv.version, anon, withRole)
	// status uses the same AppRole for the keyring line.
	code, out = in.keeper(t, "status")
	if code != 0 || !strings.Contains(out, "keyring: term=") {
		t.Fatalf("status exit %d:\n%s", code, out)
	}
	in.finish(t)
}

func keyTerm(t *testing.T, tv *testVault) int {
	var ks struct {
		Data struct {
			Term int `json:"term"`
		} `json:"data"`
	}
	tv.api(t, tv.rootToken, http.MethodGet, "/v1/sys/key-status", nil, &ks, 200)
	return ks.Data.Term
}

// An attacker who can reach Vault starts their own attempts. Nodes refuse
// both an OTP attempt and one locked to the attacker's PGP key, with no
// progress; status alarms (exit 3); root-task refuses to start and does not
// cancel the foreign attempt.
func TestIntegrationAttackerAttemptsRefused(t *testing.T) {
	in := setupInteg(t, "", "")
	ctx := context.Background()

	// OTP attempt, the way `vault operator generate-root -generate-otp` does it.
	var otp struct {
		Nonce string `json:"nonce"`
		OTP   string `json:"otp"`
	}
	in.tv.api(t, "", http.MethodPut, "/v1/sys/generate-root/attempt", map[string]any{}, &otp, 200)
	in.secrets["attacker OTP"] = otp.OTP
	for _, n := range in.f.nodes {
		out, err := in.f.contributeDirect(t, in.k.approval, n, "generate-root")
		in.captured = append(in.captured, out)
		if err == nil || !strings.Contains(out, "OTP") {
			t.Fatalf("%s contributed to an OTP attempt: %v\n%s", n.name, err, out)
		}
	}
	if gr, _ := in.tv.vc.GenerateRootAttempt(ctx); gr.Progress != 0 || gr.Nonce != otp.Nonce {
		t.Fatalf("OTP attempt progressed: %+v", gr)
	}

	code, out := in.keeper(t, "status")
	if code != exitForeign || !strings.Contains(out, "ours=false") {
		t.Fatalf("status did not flag the foreign attempt (exit %d):\n%s", code, out)
	}
	code, out = in.keeper(t, "root-task", "rekey-cancel", "--approval-contract", in.k.approval)
	if code == 0 || !strings.Contains(out, "NOT cancelling") {
		t.Fatalf("root-task started over a foreign attempt (exit %d):\n%s", code, out)
	}
	if gr, _ := in.tv.vc.GenerateRootAttempt(ctx); !gr.Started || gr.Nonce != otp.Nonce {
		t.Fatal("vaultkeeper cancelled someone else's attempt")
	}

	// PGP attempt locked to the attacker's own key.
	in.tv.api(t, "", http.MethodDelete, "/v1/sys/generate-root/attempt", nil, nil, 204)
	attacker := newGPGHome(t, in.gpgBin, "attacker <attacker@example.invalid>")
	pub := (&GPG{Path: in.gpgBin})
	t.Setenv("GNUPGHOME", attacker.dir)
	key, err := pub.ExportPublicKey(ctx, attacker.fpr)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := in.tv.vc.StartGenerateRoot(ctx, key); err != nil {
		t.Fatal(err)
	}
	for _, n := range in.f.nodes {
		out, err := in.f.contributeDirect(t, in.k.approval, n, "generate-root")
		in.captured = append(in.captured, out)
		if err == nil || !strings.Contains(out, "not the pinned key") {
			t.Fatalf("%s contributed to an attacker-key attempt: %v\n%s", n.name, err, out)
		}
	}
	// A rekey to the attacker key is refused too.
	in.tv.api(t, "", http.MethodDelete, "/v1/sys/generate-root/attempt", nil, nil, 204)
	if _, err := in.tv.vc.StartRekey(ctx, 5, 3, []string{key, key, key, key, key}); err != nil {
		t.Fatal(err)
	}
	out2, err := in.f.contributeDirect(t, in.k.approval, in.f.nodes[0], "rekey")
	in.captured = append(in.captured, out2)
	if err == nil || !strings.Contains(out2, "not the pinned key") {
		t.Fatalf("node contributed to an attacker rekey: %v\n%s", err, out2)
	}
	if rk, _ := in.tv.vc.RekeyAttempt(ctx); rk.Progress != 0 {
		t.Fatalf("attacker rekey progressed: %+v", rk)
	}
	// Give any async alarm/log writes a moment, then grep everything.
	time.Sleep(100 * time.Millisecond)
	in.finish(t)
}
