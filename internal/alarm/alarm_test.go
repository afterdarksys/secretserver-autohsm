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
