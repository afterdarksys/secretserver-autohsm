package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/afterdarksys/secretserver-autohsm/internal/alarm"
	"github.com/afterdarksys/secretserver-autohsm/internal/ceremony"
	"github.com/afterdarksys/secretserver-autohsm/internal/vaultclient"
)

const (
	opFP       = "600e44ad55f1d7c04f52946ab051837018556301"
	fakeNonce  = "f4fef122-4056-7c7a-0a6d-37707c6a03ec"
	fakeToken  = "hvs.FAKEROOTTOKENfakerootTOKEN0123"
	targetAcc  = "UwOl3tYIMNXMWt0aynETMZ21"
	ownAcc     = "X4w3dWzZRYeuSw2lGCaIJ8wF"
	foreignFP  = "0123456789abcdef0123456789abcdef01234567"
	validSHA   = "0000000000000000000000000000000000000000000000000000000000000000"
	encodedTok = "RU5DUllQVEVELVRPS0VO"
)

func TestParseTaskAllowlist(t *testing.T) {
	dir := t.TempDir()
	policy := []byte(`path "secret/*" { capabilities = ["read"] }` + "\n")
	if err := os.WriteFile(filepath.Join(dir, "reader.hcl"), policy, 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(policy)
	good := hex.EncodeToString(sum[:])

	for _, ok := range [][]string{
		{"revoke-token", targetAcc},
		{"rekey-cancel"},
		{"policy-write", "reader", good},
	} {
		if _, err := parseTask(ok, dir); err != nil {
			t.Fatalf("%v rejected: %v", ok, err)
		}
	}
	bad := map[string][]string{
		"no task":                 nil,
		"unknown task":            {"seal"},
		"free-form shell":         {"sh", "-c", "vault token create"},
		"task with shell suffix":  {"rekey-cancel;", "id"},
		"rekey-cancel extra arg":  {"rekey-cancel", "now"},
		"revoke-token no arg":     {"revoke-token"},
		"revoke-token two args":   {"revoke-token", targetAcc, targetAcc},
		"accessor wrong length":   {"revoke-token", targetAcc[:23]},
		"accessor metachar":       {"revoke-token", "UwOl3tYIMNXMWt0aynETMZ2;"},
		"accessor is a token":     {"revoke-token", fakeToken},
		"policy root":             {"policy-write", "root", good},
		"policy traversal":        {"policy-write", "../reader", good},
		"policy uppercase sha":    {"policy-write", "reader", strings.ToUpper(good)},
		"policy hash mismatch":    {"policy-write", "reader", validSHA},
		"policy missing file":     {"policy-write", "absent", good},
		"policy missing hash arg": {"policy-write", "reader"},
	}
	for name, args := range bad {
		if _, err := parseTask(args, dir); err == nil {
			t.Errorf("%s: %v accepted", name, args)
		}
	}
}

// policy-write uses exactly the bytes it hashed; there is no second read.
func TestPolicyWriteUsesHashedBytes(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "reader.hcl")
	orig := []byte("path \"a\" { capabilities = [\"read\"] }\n")
	os.WriteFile(p, orig, 0o600)
	sum := sha256.Sum256(orig)
	tk, err := parseTask([]string{"policy-write", "reader", hex.EncodeToString(sum[:])}, dir)
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(p, []byte("path \"*\" { capabilities = [\"sudo\"] }\n"), 0o600)
	if !bytes.Equal(tk.policy, orig) {
		t.Fatal("task holds bytes other than the ones hashed")
	}
}

// fakeVault is a stateful stand-in for the generate-root and token APIs.
type fakeVault struct {
	mu            sync.Mutex
	started       bool
	nonce, fp     string
	revoked       bool
	revokeWorks   bool
	revokeAccCode int
	tokenPath     string
	tokenCreated  int64
	sealed        bool
	calls         []string
	alarms        []string
	srv           *httptest.Server
	ca            string
}

func newFakeVault(t *testing.T) *fakeVault {
	fv := &fakeVault{revokeWorks: true, revokeAccCode: 204, tokenPath: "auth/token/root", tokenCreated: time.Now().Unix()}
	fv.srv = httptest.NewTLSServer(http.HandlerFunc(fv.serve))
	t.Cleanup(fv.srv.Close)
	fv.ca = filepath.Join(t.TempDir(), "ca.pem")
	os.WriteFile(fv.ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: fv.srv.Certificate().Raw}), 0o600)
	return fv
}

func (fv *fakeVault) serve(w http.ResponseWriter, r *http.Request) {
	fv.mu.Lock()
	defer fv.mu.Unlock()
	fv.calls = append(fv.calls, r.Method+" "+r.URL.Path)
	tok := r.Header.Get("X-Vault-Token")
	switch r.Method + " " + r.URL.Path {
	case "GET /v1/sys/generate-root/attempt":
		json.NewEncoder(w).Encode(map[string]any{"started": fv.started, "nonce": fv.nonce, "progress": 0, "required": 3, "pgp_fingerprint": fv.fp})
	case "PUT /v1/sys/generate-root/attempt":
		fv.started, fv.nonce, fv.fp = true, fakeNonce, opFP
		json.NewEncoder(w).Encode(map[string]any{"started": true, "nonce": fv.nonce, "required": 3, "pgp_fingerprint": fv.fp})
	case "DELETE /v1/sys/generate-root/attempt":
		fv.started, fv.nonce, fv.fp = false, "", ""
		w.WriteHeader(204)
	case "GET /v1/sys/seal-status":
		json.NewEncoder(w).Encode(map[string]any{"sealed": fv.sealed, "initialized": true, "t": 3, "n": 5})
	case "GET /v1/auth/token/lookup-self":
		if tok != fakeToken || fv.revoked {
			w.WriteHeader(403)
			io.WriteString(w, `{"errors":["permission denied"]}`)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"accessor": ownAcc, "policies": []string{"root"},
			"ttl": 0, "expire_time": nil, "path": fv.tokenPath, "creation_time": fv.tokenCreated}})
	case "POST /v1/auth/token/revoke-self":
		if fv.revokeWorks {
			fv.revoked = true
		}
		w.WriteHeader(204)
	case "POST /v1/auth/token/revoke-accessor":
		w.WriteHeader(fv.revokeAccCode)
		if fv.revokeAccCode >= 300 {
			io.WriteString(w, `{"errors":["internal error"]}`)
		}
	case "POST /v1/auth/token/lookup-accessor":
		w.WriteHeader(400)
		io.WriteString(w, `{"errors":["invalid accessor"]}`)
	default:
		w.WriteHeader(404)
	}
}

func (fv *fakeVault) saw(call string) bool {
	fv.mu.Lock()
	defer fv.mu.Unlock()
	for _, c := range fv.calls {
		if c == call {
			return true
		}
	}
	return false
}

// fakeRunner completes the attempt on the first contribution and returns
// the result line, as the third node would.
type fakeRunner struct {
	fv        *fakeVault
	nonce     string // override the nonce in the result line
	premature bool   // return a result without completing the attempt
	prefix    string // prefix every output line (a runner that labels lines)
}

func (r *fakeRunner) Contribute(_ context.Context, _ Node, op string) ([]byte, error) {
	r.fv.mu.Lock()
	nonce := r.fv.nonce
	if !r.premature {
		r.fv.started = false
	}
	r.fv.mu.Unlock()
	if r.nonce != "" {
		nonce = r.nonce
	}
	line, _ := (&ceremony.Result{Op: op, Nonce: nonce, EncodedToken: encodedTok, PGPFingerprint: opFP}).Line()
	return []byte(r.prefix + "contribute op=generate-root nonce=f4fef122 progress=3/3\n" + r.prefix + line + "\n"), nil
}
func (r *fakeRunner) Wrap(context.Context, Node, []byte) error { return errCannotPipe }
func (r *fakeRunner) Selftest(context.Context, Node) error     { return errCannotPipe }
func (r *fakeRunner) CanPipe() bool                            { return false }

type fakeKey struct {
	decrypted int
	onDecrypt func()
	fail      bool
}

func (k *fakeKey) ExportPublicKey(context.Context, string) (string, error) {
	return base64.StdEncoding.EncodeToString([]byte("PUBKEY")), nil
}
func (k *fakeKey) DecryptFor(ctx context.Context, _ string, ct []byte) ([]byte, error) {
	return k.Decrypt(ctx, ct)
}

func (k *fakeKey) Decrypt(_ context.Context, ct []byte) ([]byte, error) {
	k.decrypted++
	if k.fail || string(ct) != "ENCRYPTED-TOKEN" {
		return nil, io.ErrUnexpectedEOF
	}
	if k.onDecrypt != nil {
		k.onDecrypt()
	}
	return []byte(fakeToken), nil
}

func newTestApp(t *testing.T, fv *fakeVault) (*app, *bytes.Buffer, *fakeKey) {
	vc, err := vaultclient.New(vaultclient.Config{Address: fv.srv.URL, CACertPath: fv.ca})
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	log := slog.New(slog.NewTextHandler(&out, nil))
	hook := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		fv.mu.Lock()
		fv.alarms = append(fv.alarms, string(b))
		fv.mu.Unlock()
		w.WriteHeader(204)
	}))
	t.Cleanup(hook.Close)
	n, err := alarm.NewWithClient(hook.URL, hook.Client(), log)
	if err != nil {
		t.Fatal(err)
	}
	key := &fakeKey{}
	cfg := &Config{OperatorFingerprint: opFP, StateDir: t.TempDir(), OutputDir: t.TempDir(), GPGPath: "/nonexistent/gpg",
		PollInterval: 10 * time.Millisecond, Nodes: []Node{{"node-a", 1}, {"node-b", 2}, {"node-c", 3}}}
	cfg.Runner.Timeout = time.Second
	return &app{cfg: cfg, vc: vc, gpg: key, runner: &fakeRunner{fv: fv}, notifier: n, log: log, out: &out, revokeBackoff: time.Millisecond}, &out, key
}

func TestRootTaskHappyPathRevokes(t *testing.T) {
	fv := newFakeVault(t)
	vk, out, _ := newTestApp(t, fv)
	if err := vk.rootTask(context.Background(), &task{name: taskRevokeToken, accessor: targetAcc}); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if !fv.revoked || !fv.saw("POST /v1/auth/token/revoke-accessor") {
		t.Fatalf("calls %v", fv.calls)
	}
	if strings.Contains(out.String(), fakeToken) {
		t.Fatal("token printed")
	}
}

// Fail closed: a failing task still revokes (and verifies) before the error
// is reported.
func TestRootTaskRevokesWhenTaskFails(t *testing.T) {
	fv := newFakeVault(t)
	fv.revokeAccCode = 500
	vk, out, _ := newTestApp(t, fv)
	err := vk.rootTask(context.Background(), &task{name: taskRevokeToken, accessor: targetAcc})
	if err == nil || !strings.Contains(err.Error(), "task revoke-token") {
		t.Fatalf("err=%v", err)
	}
	if !fv.revoked || !strings.Contains(out.String(), "root token revoked (lookup-self: 403)") {
		t.Fatalf("root not revoked after task failure:\n%s", out)
	}
}

// The ceremony's own token is never an acceptable target.
func TestRootTaskRefusesOwnAccessorAndStillRevokes(t *testing.T) {
	fv := newFakeVault(t)
	vk, _, _ := newTestApp(t, fv)
	err := vk.rootTask(context.Background(), &task{name: taskRevokeToken, accessor: ownAcc})
	if err == nil || fv.saw("POST /v1/auth/token/revoke-accessor") || !fv.revoked {
		t.Fatalf("err=%v revoked=%t calls=%v", err, fv.revoked, fv.calls)
	}
}

// A revoke that cannot be verified is an error, never a quiet success.
func TestRootTaskUnverifiedRevokeFails(t *testing.T) {
	fv := newFakeVault(t)
	fv.revokeWorks = false
	vk, _, _ := newTestApp(t, fv)
	err := vk.rootTask(context.Background(), &task{name: taskRekeyCancel})
	if err == nil || !strings.Contains(err.Error(), "REVOCATION NOT VERIFIED") || !strings.Contains(err.Error(), ownAcc) {
		t.Fatalf("err=%v", err)
	}
	if strings.Contains(err.Error(), fakeToken) {
		t.Fatal("token in error")
	}
}

// SIGTERM (a cancelled context) after decrypt: the task does not run, the
// token is revoked, and the run fails.
func TestRootTaskCancelledAfterDecryptRevokes(t *testing.T) {
	fv := newFakeVault(t)
	vk, out, key := newTestApp(t, fv)
	ctx, cancel := context.WithCancel(context.Background())
	key.onDecrypt = cancel
	err := vk.rootTask(ctx, &task{name: taskRevokeToken, accessor: targetAcc})
	if err == nil {
		t.Fatal("cancelled run reported success")
	}
	if fv.saw("POST /v1/auth/token/revoke-accessor") {
		t.Fatal("task ran after cancellation")
	}
	if !fv.revoked {
		t.Fatalf("root not revoked after cancellation:\n%s", out)
	}
}

// An attempt someone else started blocks the ceremony and is left alone.
func TestRootTaskRefusesExistingAttemptWithoutCancelling(t *testing.T) {
	fv := newFakeVault(t)
	fv.started, fv.nonce, fv.fp = true, fakeNonce, foreignFP
	vk, _, key := newTestApp(t, fv)
	err := vk.rootTask(context.Background(), &task{name: taskRekeyCancel})
	if err == nil || !strings.Contains(err.Error(), "NOT cancelling") {
		t.Fatalf("err=%v", err)
	}
	if fv.saw("DELETE /v1/sys/generate-root/attempt") || fv.saw("PUT /v1/sys/generate-root/attempt") || key.decrypted != 0 {
		t.Fatalf("touched a foreign attempt: %v", fv.calls)
	}
}

// A result line for a different attempt is never decrypted, and our own
// attempt is cancelled.
func TestRootTaskRejectsResultForOtherNonce(t *testing.T) {
	fv := newFakeVault(t)
	vk, _, key := newTestApp(t, fv)
	vk.runner = &fakeRunner{fv: fv, nonce: "00000000-0000-0000-0000-000000000000"}
	if err := vk.rootTask(context.Background(), &task{name: taskRekeyCancel}); err == nil {
		t.Fatal("foreign result accepted")
	}
	if key.decrypted != 0 {
		t.Fatal("foreign result decrypted")
	}
}

func TestParseArgsRejectsUnknownFlags(t *testing.T) {
	if _, err := parseArgs([]string{"root-task", "rekey-cancel", "--force"}); err == nil {
		t.Fatal("unknown flag accepted")
	}
	a, err := parseArgs([]string{"root-task", "revoke-token", targetAcc, "--approval-contract", "/x", "--config", "/c"})
	if err != nil || a.approval != "/x" || a.config != "/c" || len(a.positional) != 2 {
		t.Fatalf("%+v %v", a, err)
	}
}

func TestRequireApproval(t *testing.T) {
	if err := requireApproval(""); err == nil {
		t.Fatal("missing approval accepted")
	}
	if err := requireApproval(t.TempDir()); err == nil {
		t.Fatal("directory accepted as approval contract")
	}
}

func (fv *fakeVault) alarmed(event string) string {
	fv.mu.Lock()
	defer fv.mu.Unlock()
	for _, a := range fv.alarms {
		if strings.Contains(a, `"event":"`+event+`"`) {
			return a
		}
	}
	return ""
}

func savedFiles(t *testing.T, vk *app) []string {
	m, _ := filepath.Glob(filepath.Join(vk.cfg.OutputDir, "*"))
	return m
}

// M1: a decrypted token that is not a fresh generate-root token (here a
// pre-minted orphan root token, or an old root token) is rejected before any
// task, revoked, and raises the alarm that the real ceremony token may be live.
func TestRootTaskRejectsSubstitutedToken(t *testing.T) {
	for name, mut := range map[string]func(*fakeVault){
		"pre-minted orphan": func(fv *fakeVault) { fv.tokenPath = "auth/token/create-orphan" },
		"old standing root": func(fv *fakeVault) { fv.tokenCreated = time.Now().Add(-time.Hour).Unix() },
	} {
		t.Run(name, func(t *testing.T) {
			fv := newFakeVault(t)
			mut(fv)
			vk, out, _ := newTestApp(t, fv)
			err := vk.rootTask(context.Background(), &task{name: taskRevokeToken, accessor: targetAcc})
			if err == nil || !strings.Contains(err.Error(), "may still be live") {
				t.Fatalf("err=%v", err)
			}
			if fv.saw("POST /v1/auth/token/revoke-accessor") {
				t.Fatal("task ran with a substituted token")
			}
			if !fv.revoked || !strings.Contains(out.String(), "rejected token revoked/invalid") || strings.Contains(out.String(), "root token revoked") {
				t.Fatalf("substituted root token not revoked and labelled:\n%s", out)
			}
			if a := fv.alarmed("vaultkeeper_root_undecrypted"); !strings.Contains(a, "may be live") {
				t.Fatalf("no alarm: %q", a)
			}
		})
	}
}

// M2: a decrypt failure keeps the encrypted result on disk and alarms.
func TestRootTaskDecryptFailurePreservesResult(t *testing.T) {
	fv := newFakeVault(t)
	vk, _, key := newTestApp(t, fv)
	key.fail = true
	if err := vk.rootTask(context.Background(), &task{name: taskRekeyCancel}); err == nil {
		t.Fatal("decrypt failure reported success")
	}
	files := savedFiles(t, vk)
	if len(files) != 1 {
		t.Fatalf("saved %v", files)
	}
	b, _ := os.ReadFile(files[0])
	if !strings.Contains(string(b), encodedTok) {
		t.Fatal("encrypted result not preserved")
	}
	if info, _ := os.Stat(files[0]); info.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", info.Mode().Perm())
	}
	if fv.alarmed("vaultkeeper_root_undecrypted") == "" {
		t.Fatal("no vaultkeeper_root_undecrypted alarm")
	}
}

// C1: a result line that arrives while our attempt is still collecting
// shares is forged or premature. It is never decrypted; our attempt is
// cancelled.
func TestRootTaskRejectsResultBeforeAttemptConsumed(t *testing.T) {
	fv := newFakeVault(t)
	vk, _, key := newTestApp(t, fv)
	vk.runner = &fakeRunner{fv: fv, premature: true}
	err := vk.rootTask(context.Background(), &task{name: taskRekeyCancel})
	if err == nil || !strings.Contains(err.Error(), "forged") {
		t.Fatalf("err=%v", err)
	}
	if key.decrypted != 0 {
		t.Fatal("premature result decrypted")
	}
	if !fv.saw("DELETE /v1/sys/generate-root/attempt") {
		t.Fatal("our attempt was not cancelled")
	}
}

// H1/M2: a runner that labels its output lines hides the result line from
// the strict parser. The raw output is saved, never lost, and alarmed.
func TestRootTaskPrefixedRunnerOutputSavedRaw(t *testing.T) {
	fv := newFakeVault(t)
	vk, out, key := newTestApp(t, fv)
	vk.runner = &fakeRunner{fv: fv, prefix: "node-c | "}
	err := vk.rootTask(context.Background(), &task{name: taskRekeyCancel})
	if err == nil || !strings.Contains(err.Error(), "CRITICAL") {
		t.Fatalf("err=%v", err)
	}
	if key.decrypted != 0 {
		t.Fatal("decrypted despite unparsed output")
	}
	files := savedFiles(t, vk)
	if len(files) != 1 || !strings.Contains(filepath.Base(files[0]), "raw") {
		t.Fatalf("raw output not saved: %v\n%s", files, out)
	}
	b, _ := os.ReadFile(files[0])
	if !strings.Contains(string(b), "node-c | vaultkeeper-result ") || !strings.Contains(string(b), encodedTok) {
		t.Fatalf("raw file %q", b)
	}
	if fv.alarmed("vaultkeeper_root_undecrypted") == "" {
		t.Fatal("no alarm for a lost result")
	}
}

func TestExecRunnerEnforcesTimeout(t *testing.T) {
	script := filepath.Join(t.TempDir(), "hang.sh")
	os.WriteFile(script, []byte("#!/bin/sh\nexec sleep 30\n"), 0o700)
	r := &ExecRunner{Argv: []string{script}, Timeout: 300 * time.Millisecond, Stderr: io.Discard}
	start := time.Now()
	_, err := r.Contribute(context.Background(), Node{"node-a", 1}, "generate-root")
	if err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("err=%v", err)
	}
	if time.Since(start) > 10*time.Second {
		t.Fatal("timeout not enforced")
	}
}

func TestManualRunnerPromptIsBounded(t *testing.T) {
	huge := strings.Repeat("A", 4*ceremony.MaxResultLine)
	m := &ManualRunner{Out: io.Discard, In: strings.NewReader(huge)}
	got, err := m.PromptResult(context.Background(), Node{"node-a", 1}, "generate-root")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) > ceremony.MaxResultLine+2 {
		t.Fatalf("read %d bytes", len(got))
	}
}
