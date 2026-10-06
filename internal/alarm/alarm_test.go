package alarm

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestNewRejectsNonHTTPSWebhook(t *testing.T) {
	for _, rawURL := range []string{
		"http://alerts.example/hook",
		"file:///tmp/hook",
		"alerts.example",
		"https://",
		"https://user:pass@alerts.example/hook",
	} {
		if _, err := New(rawURL, discardLogger()); err == nil {
			t.Fatalf("accepted unsafe webhook URL %q", rawURL)
		}
	}
}

func TestNotifierRejectsRedirects(t *testing.T) {
	n, err := New("https://alerts.example/hook", discardLogger())
	if err != nil {
		t.Fatal(err)
	}
	if err := n.client.CheckRedirect(nil, nil); !errors.Is(err, http.ErrUseLastResponse) {
		t.Fatalf("redirect policy returned %v", err)
	}
}

func TestEmptyWebhookIsNoOp(t *testing.T) {
	n, err := New("", discardLogger())
	if err != nil {
		t.Fatal(err)
	}
	n.SealedDetected(context.Background(), "node-1", true, 3, 5, 1)
}

func TestSealedDetectedPayload(t *testing.T) {
	var got Payload
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method=%s, want POST", r.Method)
		}
		if contentType := r.Header.Get("Content-Type"); contentType != "application/json" {
			t.Errorf("content type=%q", contentType)
		}
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Errorf("decode payload: %v", err)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	n := &Notifier{url: srv.URL, client: srv.Client(), log: discardLogger()}
	n.SealedDetected(context.Background(), "node-1", true, 3, 5, 1)
	if got.Event != "vault_sealed" || got.NodeID != "node-1" || !got.Sealed ||
		got.Threshold != 3 || got.Shares != 5 || got.Progress != 1 || got.Timestamp == "" {
		t.Fatalf("unexpected payload: %+v", got)
	}
	raw, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "key") || strings.Contains(string(raw), "share-") {
		t.Fatalf("payload appears to contain key material: %s", raw)
	}
}

// Regression: a Vault the daemon cannot even reach must still raise the
// alarm. Silently retrying forever without ever notifying anyone repeats the
// "sealed Vault goes unnoticed" failure this package exists to prevent, one
// layer earlier (at the poll itself rather than at a confirmed sealed state).
func TestVaultUnreachablePayload(t *testing.T) {
	var got Payload
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Errorf("decode payload: %v", err)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	n := &Notifier{url: srv.URL, client: srv.Client(), log: discardLogger()}
	n.VaultUnreachable(context.Background(), "node-1", errors.New("dial tcp: connection refused"))
	if got.Event != "vault_unreachable" || got.NodeID != "node-1" || got.Timestamp == "" {
		t.Fatalf("unexpected payload: %+v", got)
	}
	if !strings.Contains(got.Error, "connection refused") {
		t.Fatalf("payload did not carry the poll error: %+v", got)
	}
}

func TestEmptyWebhookVaultUnreachableIsNoOp(t *testing.T) {
	n, err := New("", discardLogger())
	if err != nil {
		t.Fatal(err)
	}
	n.VaultUnreachable(context.Background(), "node-1", errors.New("unreachable"))
}

func TestDaemonFailedPayload(t *testing.T) {
	var got Payload
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Errorf("decode payload: %v", err)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	n := &Notifier{url: srv.URL, client: srv.Client(), log: discardLogger()}
	n.DaemonFailed(context.Background(), "node-1", errors.New("pkcs11 login failed: CKR_PIN_INCORRECT"))
	if got.Event != "autohsm_failed" || got.NodeID != "node-1" || got.Timestamp == "" {
		t.Fatalf("unexpected payload: %+v", got)
	}
	if !strings.Contains(got.Error, "CKR_PIN_INCORRECT") {
		t.Fatalf("payload did not carry the failure: %+v", got)
	}
}

func TestHSMAndStaleSharePayloads(t *testing.T) {
	var got []Payload
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var p Payload
		if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
			t.Errorf("decode payload: %v", err)
		}
		got = append(got, p)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	n := &Notifier{url: srv.URL, client: srv.Client(), log: discardLogger()}
	n.HSMUnavailable(context.Background(), "node-1", errors.New("HSM unavailable: CKR_DEVICE_REMOVED"))
	n.HSMRecovered(context.Background(), "node-1")
	n.SharesStale(context.Background(), "node-1", true, 3, 5, 0, errors.New("vault returned 400 Bad Request: invalid key"))
	want := []string{"hsm_unavailable", "hsm_recovered", "shares_stale"}
	if len(got) != len(want) {
		t.Fatalf("got %d alarms, want %d", len(got), len(want))
	}
	for i, ev := range want {
		if got[i].Event != ev || got[i].NodeID != "node-1" || got[i].Timestamp == "" {
			t.Fatalf("alarm %d: %+v, want event %s", i, got[i], ev)
		}
	}
	if !strings.Contains(got[0].Error, "CKR_DEVICE_REMOVED") || got[1].Error != "" ||
		!strings.Contains(got[2].Error, "invalid key") || got[2].Threshold != 3 || !got[2].Sealed {
		t.Fatalf("payload contents wrong: %+v", got)
	}
}

func TestCeremonyPayloads(t *testing.T) {
	var got []Payload
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var p Payload
		if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
			t.Errorf("decode payload: %v", err)
		}
		got = append(got, p)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	n, err := NewWithClient(srv.URL, srv.Client(), discardLogger())
	if err != nil {
		t.Fatal(err)
	}
	if n.client.CheckRedirect(nil, nil) != http.ErrUseLastResponse {
		t.Fatal("NewWithClient dropped the no-redirect policy")
	}
	n.Contributed(context.Background(), "node-a", "generate-root", "f4fef122", 2, 3)
	n.ContributeRefused(context.Background(), "node-b", "rekey", errors.New("fingerprint not allowlisted"))
	n.Event(context.Background(), "vaultkeeper_keyring_rotated", "vaultkeeper", "term=4")
	if len(got) != 3 {
		t.Fatalf("got %d payloads", len(got))
	}
	if g := got[0]; g.Event != "contribute" || g.Op != "generate-root" || g.Nonce != "f4fef122" || g.Progress != 2 || g.Threshold != 3 {
		t.Fatalf("contribute payload %+v", g)
	}
	if g := got[1]; g.Event != "contribute_refused" || g.NodeID != "node-b" || !strings.Contains(g.Error, "allowlisted") {
		t.Fatalf("refused payload %+v", g)
	}
	if g := got[2]; g.Event != "vaultkeeper_keyring_rotated" || g.Detail != "term=4" {
		t.Fatalf("event payload %+v", g)
	}
}

// Alarm clients never negotiate below TLS 1.3.
func TestAlarmClientsRequireTLS13(t *testing.T) {
	n, _ := New("https://alerts.example/hook", discardLogger())
	m, _ := NewWithClient("https://alerts.example/hook", &http.Client{Transport: &http.Transport{}}, discardLogger())
	for _, x := range []*Notifier{n, m} {
		tr, ok := x.client.Transport.(*http.Transport)
		if !ok || tr.TLSClientConfig == nil || tr.TLSClientConfig.MinVersion != tls.VersionTLS13 {
			t.Fatal("alarm transport does not require TLS 1.3")
		}
	}
}

func TestNewWithClientStillRequiresHTTPS(t *testing.T) {
	if _, err := NewWithClient("http://alerts.example/hook", http.DefaultClient, discardLogger()); err == nil {
		t.Fatal("plaintext webhook accepted")
	}
}
