package alarm

import (
	"context"
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
