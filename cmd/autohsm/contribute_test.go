package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/afterdarksys/secretserver-autohsm/internal/alarm"
	"github.com/afterdarksys/secretserver-autohsm/internal/ceremony"
	"github.com/afterdarksys/secretserver-autohsm/internal/config"
	"github.com/afterdarksys/secretserver-autohsm/internal/keysource"
	"github.com/afterdarksys/secretserver-autohsm/internal/vaultclient"
)

const (
	pinnedFP  = "600e44ad55f1d7c04f52946ab051837018556301"
	offlineFP = "151d8ce90777db86be03e5eefb15cc9a4992b487"
	foreignFP = "0123456789abcdef0123456789abcdef01234567"
	nonceA    = "f4fef122-4056-7c7a-0a6d-37707c6a03ec"
	testShare = "c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00c0ffee0001"
)

// fakeVault serves a fixed attempt and update reply and records every request.
type fakeVault struct {
	mu        sync.Mutex
	attempt   string // GET reply
	update    string // PUT .../update reply
	requests  []string
	bodies    [][]byte
	webhooks  [][]byte
	srv, hook *httptest.Server
	ca        string
}

func newFakeVault(t *testing.T, attempt, update string) *fakeVault {
	t.Helper()
	fv := &fakeVault{attempt: attempt, update: update}
	fv.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		fv.mu.Lock()
		fv.requests = append(fv.requests, r.Method+" "+r.URL.Path)
		fv.bodies = append(fv.bodies, b)
		fv.mu.Unlock()
		if r.Method == http.MethodGet {
			io.WriteString(w, fv.attempt)
			return
		}
		io.WriteString(w, fv.update)
	}))
	t.Cleanup(fv.srv.Close)
	fv.hook = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		fv.mu.Lock()
		fv.webhooks = append(fv.webhooks, b)
		fv.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(fv.hook.Close)
	fv.ca = filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(fv.ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: fv.srv.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	return fv
}

func (fv *fakeVault) hooks() [][]byte {
	fv.mu.Lock()
	defer fv.mu.Unlock()
	return append([][]byte(nil), fv.webhooks...)
}

func (fv *fakeVault) writes() []string {
	fv.mu.Lock()
	defer fv.mu.Unlock()
	var out []string
	for _, r := range fv.requests {
		if !strings.HasPrefix(r, http.MethodGet) {
			out = append(out, r)
		}
	}
	return out
}

type contributeHarness struct {
	cfg      *config.Config
	vc       *vaultclient.Client
	key      []byte
	opened   int
	notifier *alarm.Notifier
	stdout   bytes.Buffer
	logs     bytes.Buffer
}

func newHarness(t *testing.T, fv *fakeVault, pins config.VaultkeeperConfig) *contributeHarness {
	t.Helper()
	h := &contributeHarness{key: make([]byte, 32)}
	if _, err := rand.Read(h.key); err != nil {
		t.Fatal(err)
	}
	blob, err := keysource.WrapSoftware(h.key, []byte(testShare), keysource.AAD("node-a", 1))
	if err != nil {
		t.Fatal(err)
	}
	sharePath := filepath.Join(t.TempDir(), "share-1.wrapped")
	if err := os.WriteFile(sharePath, []byte(blob), 0o600); err != nil {
		t.Fatal(err)
	}
	h.cfg = &config.Config{
		NodeID:      "node-a",
		Keys:        config.KeysConfig{Source: "file", Shares: []config.ShareConfig{{Index: 1, Path: sharePath}}},
		Vaultkeeper: pins,
	}
	h.vc, err = vaultclient.New(vaultclient.Config{Address: fv.srv.URL, CACertPath: fv.ca})
	if err != nil {
		t.Fatal(err)
	}
	h.notifier, err = alarm.NewWithClient(fv.hook.URL, fv.hook.Client(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func (h *contributeHarness) run(op string) error {
	log := slog.New(slog.NewTextHandler(&h.logs, nil))
	return contribute(context.Background(), h.cfg, h.vc, func() (keysource.Source, error) {
		h.opened++
		return keysource.NewSoftware(h.key)
	}, op, &h.stdout, h.notifier, log)
}

func pinsBoth() config.VaultkeeperConfig {
	return config.VaultkeeperConfig{PGPFingerprint: pinnedFP, OfflineFingerprint: offlineFP}
}

func grAttempt(fp string) string {
	return `{"started":true,"nonce":"` + nonceA + `","progress":0,"required":3,"pgp_fingerprint":"` + fp + `","otp_length":28}`
}

// rekeyAttempt describes an attempt; verify=true is the only acceptable mode.
func rekeyAttempt(n, threshold int, backup, verify bool, fps []string) string {
	b, _ := json.Marshal(map[string]any{
		"started": true, "nonce": nonceA, "n": n, "t": threshold, "progress": 0, "required": 3,
		"backup": backup, "verification_required": verify, "pgp_fingerprints": fps,
	})
	return string(b)
}

var goodRekeyFPs = []string{pinnedFP, pinnedFP, pinnedFP, pinnedFP, offlineFP}

// Acceptance 1 and 2: the refusal matrix. Every case must refuse with
// ErrRefused, write nothing to Vault, and never open the HSM.
func TestContributeRefusalMatrix(t *testing.T) {
	notStartedGR := `{"started":false,"nonce":"","progress":0,"required":3,"pgp_fingerprint":""}`
	notStartedRekey := `{"started":false,"nonce":"","t":0,"n":0}`
	cases := []struct {
		name    string
		op      string
		attempt string
		pins    config.VaultkeeperConfig
	}{
		{"generate-root: no attempt", ceremony.OpGenerateRoot, notStartedGR, pinsBoth()},
		{"generate-root: OTP attempt (empty fingerprint)", ceremony.OpGenerateRoot, grAttempt(""), pinsBoth()},
		{"generate-root: unpinned fingerprint", ceremony.OpGenerateRoot, grAttempt(foreignFP), pinsBoth()},
		{"generate-root: config has no pin", ceremony.OpGenerateRoot, grAttempt(pinnedFP), config.VaultkeeperConfig{OfflineFingerprint: offlineFP}},
		{"generate-root: malformed nonce", ceremony.OpGenerateRoot, strings.Replace(grAttempt(pinnedFP), nonceA, "not-a-nonce", 1), pinsBoth()},
		{"rekey: no attempt", ceremony.OpRekey, notStartedRekey, pinsBoth()},
		{"rekey: fingerprint not pinned", ceremony.OpRekey, rekeyAttempt(5, 3, false, true, []string{pinnedFP, pinnedFP, pinnedFP, pinnedFP, foreignFP}), pinsBoth()},
		{"rekey: layout out of order", ceremony.OpRekey, rekeyAttempt(5, 3, false, true, []string{offlineFP, pinnedFP, pinnedFP, pinnedFP, pinnedFP}), pinsBoth()},
		{"rekey: n=4", ceremony.OpRekey, rekeyAttempt(4, 3, false, true, goodRekeyFPs[:4]), pinsBoth()},
		{"rekey: n=6", ceremony.OpRekey, rekeyAttempt(6, 3, false, true, append([]string{pinnedFP}, goodRekeyFPs...)), pinsBoth()},
		{"rekey: t=2", ceremony.OpRekey, rekeyAttempt(5, 2, false, true, goodRekeyFPs), pinsBoth()},
		{"rekey: backup=true", ceremony.OpRekey, rekeyAttempt(5, 3, true, true, goodRekeyFPs), pinsBoth()},
		{"rekey: verification not required", ceremony.OpRekey, rekeyAttempt(5, 3, false, false, goodRekeyFPs), pinsBoth()},
		{"rekey: no PGP keys (plaintext shares)", ceremony.OpRekey, rekeyAttempt(5, 3, false, true, nil), pinsBoth()},
		{"rekey: config has no offline pin", ceremony.OpRekey, rekeyAttempt(5, 3, false, true, goodRekeyFPs), config.VaultkeeperConfig{PGPFingerprint: pinnedFP}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fv := newFakeVault(t, tc.attempt, `{}`)
			h := newHarness(t, fv, tc.pins)
			err := h.run(tc.op)
			if !errors.Is(err, ceremony.ErrRefused) {
				t.Fatalf("want refusal, got %v", err)
			}
			if w := fv.writes(); len(w) != 0 {
				t.Fatalf("refused attempt still wrote to Vault: %v", w)
			}
			if h.opened != 0 {
				t.Fatal("HSM was opened for a refused attempt")
			}
			if strings.Contains(h.stdout.String()+h.logs.String(), testShare) {
				t.Fatal("share leaked into output")
			}
			if hooks := fv.hooks(); len(hooks) != 1 || !strings.Contains(string(hooks[0]), `"contribute_refused"`) {
				t.Fatalf("refusal alarm not sent: %q", hooks)
			}
		})
	}
}

func TestContributeGenerateRootSubmitsWithNonce(t *testing.T) {
	fv := newFakeVault(t, grAttempt(strings.ToUpper(pinnedFP)),
		`{"started":true,"nonce":"`+nonceA+`","progress":2,"required":3,"pgp_fingerprint":"`+pinnedFP+`"}`)
	h := newHarness(t, fv, pinsBoth())
	if err := h.run(ceremony.OpGenerateRoot); err != nil {
		t.Fatal(err)
	}
	w := fv.writes()
	if len(w) != 1 || w[0] != "PUT /v1/sys/generate-root/update" {
		t.Fatalf("writes %v", w)
	}
	var body map[string]string
	fv.mu.Lock()
	last := fv.bodies[len(fv.bodies)-1]
	fv.mu.Unlock()
	if err := json.Unmarshal(last, &body); err != nil || body["nonce"] != nonceA || body["key"] != testShare {
		t.Fatalf("update body did not bind share to nonce: %v", err)
	}
	if got := h.stdout.String(); got != "contribute op=generate-root nonce=f4fef122 progress=2/3\n" {
		t.Fatalf("stdout %q", got)
	}
	all := h.stdout.String() + h.logs.String() + string(bytes.Join(fv.hooks(), nil))
	if strings.Contains(all, testShare) || strings.Contains(all, nonceA) {
		t.Fatal("share or full nonce leaked into output/alarm")
	}
}

// The completing node prints only the PGP-encrypted token, re-checked.
func TestContributeFinalSubmitterEmitsEncryptedResult(t *testing.T) {
	enc := "UEdQLWVuY3J5cHRlZC10b2tlbg=="
	fv := newFakeVault(t, grAttempt(pinnedFP),
		`{"started":true,"complete":true,"nonce":"`+nonceA+`","progress":3,"required":3,"pgp_fingerprint":"`+pinnedFP+`","encoded_token":"`+enc+`"}`)
	h := newHarness(t, fv, pinsBoth())
	if err := h.run(ceremony.OpGenerateRoot); err != nil {
		t.Fatal(err)
	}
	r, err := ceremony.FindResult(h.stdout.Bytes())
	if err != nil || r == nil {
		t.Fatalf("no result line: %v\n%s", err, h.stdout.String())
	}
	if r.EncodedToken != enc || r.Nonce != nonceA || r.PGPFingerprint != pinnedFP {
		t.Fatalf("result %+v", r)
	}
}

// Negative: a completion that is not encrypted to the pinned key (only
// possible with a misbehaving Vault) is never forwarded.
func TestContributeWithholdsUnpinnedCompletion(t *testing.T) {
	fv := newFakeVault(t, grAttempt(pinnedFP),
		`{"started":true,"complete":true,"nonce":"`+nonceA+`","progress":3,"required":3,"pgp_fingerprint":"`+foreignFP+`","encoded_token":"QUJD"}`)
	h := newHarness(t, fv, pinsBoth())
	if err := h.run(ceremony.OpGenerateRoot); !errors.Is(err, ceremony.ErrRefused) {
		t.Fatalf("err=%v", err)
	}
	if strings.Contains(h.stdout.String(), ceremony.ResultPrefix) {
		t.Fatal("unpinned completion forwarded")
	}
}

func TestContributeRekeySubmitsAndEmitsResult(t *testing.T) {
	final, _ := json.Marshal(map[string]any{
		"complete": true, "nonce": nonceA, "pgp_fingerprints": goodRekeyFPs,
		"verification_required": true, "verification_nonce": "06060562-47e1-7466-8d71-0b566fdcb424",
		"keys_base64": []string{"QQ==", "Qg==", "Qw==", "RA==", "RQ=="},
		"keys":        []string{"plaintext-must-not-be-decoded"},
	})
	fv := newFakeVault(t, rekeyAttempt(5, 3, false, true, goodRekeyFPs), string(final))
	h := newHarness(t, fv, pinsBoth())
	if err := h.run(ceremony.OpRekey); err != nil {
		t.Fatal(err)
	}
	if w := fv.writes(); len(w) != 1 || w[0] != "PUT /v1/sys/rekey/update" {
		t.Fatalf("writes %v", w)
	}
	r, err := ceremony.FindResult(h.stdout.Bytes())
	if err != nil || r == nil || len(r.KeysBase64) != 5 {
		t.Fatalf("result %+v err %v", r, err)
	}
	if strings.Contains(h.stdout.String(), "plaintext-must-not-be-decoded") {
		t.Fatal("plaintext keys field forwarded")
	}
}

func TestParseContributeArgs(t *testing.T) {
	for _, ok := range [][]string{{"generate-root"}, {"rekey"}, {"rekey", "--config", "/x.yaml"}, {"--config=/x.yaml", "generate-root"}} {
		if _, err := parseContributeArgs(ok); err != nil {
			t.Fatalf("%v rejected: %v", ok, err)
		}
	}
	for _, bad := range [][]string{nil, {"unseal"}, {"generate-root", "rekey"}, {"rekey", "--nonce", "x"}, {"generate-root", "extra"}} {
		if _, err := parseContributeArgs(bad); err == nil {
			t.Fatalf("%v accepted", bad)
		}
	}
}

func installHarness(t *testing.T) (*config.Config, keysource.Source, []byte, string) {
	t.Helper()
	key := make([]byte, 32)
	rand.Read(key)
	src, _ := keysource.NewSoftware(key)
	old, _ := keysource.WrapSoftware(key, []byte("old-share"), keysource.AAD("node-a", 1))
	p := filepath.Join(t.TempDir(), "share-1.wrapped")
	if err := os.WriteFile(p, []byte(old+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{NodeID: "node-a", Keys: config.KeysConfig{Shares: []config.ShareConfig{{Index: 1, Path: p}}}}
	return cfg, src, key, old
}

// wrap --install keeps the previous envelope as .prev, same mode.
func TestInstallKeepsPreviousEnvelope(t *testing.T) {
	cfg, src, key, old := installHarness(t)
	p := cfg.Keys.Shares[0].Path
	env, _ := keysource.WrapSoftware(key, []byte("new-share"), keysource.AAD("node-a", 1))
	if err := installEnvelope(context.Background(), cfg, src, 1, env); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(p)
	prev, _ := os.ReadFile(p + ".prev")
	if strings.TrimSpace(string(got)) != env || strings.TrimSpace(string(prev)) != old {
		t.Fatal("new envelope not installed or old one not kept")
	}
	if info, _ := os.Stat(p + ".prev"); info.Mode().Perm() != 0o600 {
		t.Fatalf(".prev mode %v", info.Mode().Perm())
	}
}

// Negative: an envelope that does not unwrap for this node and index, a
// symlinked share path, and a stale temp file all leave the share untouched.
func TestInstallRefusals(t *testing.T) {
	cfg, src, key, old := installHarness(t)
	p := cfg.Keys.Shares[0].Path
	wrongIdx, _ := keysource.WrapSoftware(key, []byte("new"), keysource.AAD("node-a", 2))
	if err := installEnvelope(context.Background(), cfg, src, 1, wrongIdx); err == nil {
		t.Fatal("envelope for another index installed")
	}
	good, _ := keysource.WrapSoftware(key, []byte("new"), keysource.AAD("node-a", 1))
	stale := filepath.Join(filepath.Dir(p), "."+filepath.Base(p)+".new")
	os.WriteFile(stale, []byte("x"), 0o600)
	if err := installEnvelope(context.Background(), cfg, src, 1, good); err == nil {
		t.Fatal("installed over a stale temp file")
	}
	os.Remove(stale)
	if got, _ := os.ReadFile(p); strings.TrimSpace(string(got)) != old {
		t.Fatal("share changed by a refused install")
	}

	target := filepath.Join(t.TempDir(), "elsewhere")
	os.WriteFile(target, []byte(old), 0o600)
	link := filepath.Join(t.TempDir(), "share-1.wrapped")
	os.Symlink(target, link)
	cfg.Keys.Shares[0].Path = link
	if err := installEnvelope(context.Background(), cfg, src, 1, good); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("symlinked share path accepted: %v", err)
	}
}
