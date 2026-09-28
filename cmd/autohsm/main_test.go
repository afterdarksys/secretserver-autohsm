package main

import (
	"bytes"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/afterdarksys/secretserver-autohsm/internal/keysource"
	"github.com/afterdarksys/secretserver-autohsm/internal/watch"
)

func TestExitCode(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want int
	}{
		{"sealed", sealedError{msg: "sealed"}, exitSealed},
		{"wrapped sealed", fmt.Errorf("status: %w", sealedError{msg: "sealed"}), exitSealed},
		{"terminal", fmt.Errorf("watch: %w", watch.ErrTerminal), exitTerminal},
		{"pin rejected", fmt.Errorf("open: %w", keysource.ErrPINRejected), exitTerminal},
		{"hsm unavailable", fmt.Errorf("open: %w", keysource.ErrHSMUnavailable), 1},
		{"hsm misconfigured", fmt.Errorf("open: %w", keysource.ErrHSMMisconfigured), exitTerminal},
		{"ordinary", errors.New("network down"), 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := exitCode(tt.err); got != tt.want {
				t.Fatalf("exitCode()=%d, want %d", got, tt.want)
			}
		})
	}
}

// Negative: pin_env must be refused for the watch daemon. Unlike pin_file,
// an env-sourced PIN stays visible via /proc/<pid>/environ for the entire
// lifetime of a long-running process.
func TestBuildRejectsPinEnvForWatchDaemon(t *testing.T) {
	const yaml = `
node_id: node-a
vault:
  address: https://vault.example.com:8200
  ca_cert_path: /etc/autohsm/vault-ca.pem
keys:
  source: pkcs11
  pkcs11:
    module_path: /usr/lib/softhsm/libsofthsm2.so
    key_label: autohsm-wrap
    pin_env: AUTOHSM_PIN
  shares:
    - index: 1
      path: /etc/autohsm/share-1.wrapped
`
	p := filepath.Join(t.TempDir(), "autohsm.yaml")
	if err := os.WriteFile(p, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, _, _, err := build(p, true); err == nil || !strings.Contains(err.Error(), "pin_env") {
		t.Fatalf("watch daemon accepted pin_env: %v", err)
	}

	// The same config must still be usable for a short-lived subcommand.
	if _, _, _, err := build(p, false); err == nil || strings.Contains(err.Error(), "pin_env") {
		t.Fatalf("non-daemon build wrongly rejected on pin_env grounds: %v", err)
	}
}

func TestReadShare(t *testing.T) {
	for name, input := range map[string]string{
		"newline": "share-value\n",
		"crlf":    "share-value\r\n",
		"eof":     "share-value",
	} {
		t.Run(name, func(t *testing.T) {
			got, err := readShare(bytes.NewBufferString(input))
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != "share-value" {
				t.Fatalf("got %q", got)
			}
		})
	}
}

func TestReadShareRejectsUnsafeInput(t *testing.T) {
	for name, input := range map[string][]byte{
		"empty":     nil,
		"blank":     []byte("\n"),
		"multiline": []byte("share-one\nshare-two\n"),
		"oversized": bytes.Repeat([]byte{'x'}, maxShareSize+1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := readShare(bytes.NewReader(input)); err == nil {
				t.Fatal("unsafe share input accepted")
			}
		})
	}
}

// status is the cron-monitor entrypoint: it must report seal state without
// opening the HSM. The config below points at a PKCS#11 module and PIN file
// that do not exist, so any attempt to open the key source would fail.
func TestStatusDoesNotOpenHSM(t *testing.T) {
	sealed := true
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/sys/seal-status" {
			t.Errorf("unexpected request %s", r.URL.Path)
		}
		fmt.Fprintf(w, `{"type":"shamir","initialized":true,"sealed":%t,"t":3,"n":5}`, sealed)
	}))
	defer srv.Close()

	dir := t.TempDir()
	ca := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := fmt.Sprintf(`
node_id: node-a
vault:
  address: %s
  ca_cert_path: %s
keys:
  source: pkcs11
  pkcs11:
    module_path: %s
    key_label: autohsm-wrap
    pin_file: %s
  shares:
    - index: 1
      path: %s
`, srv.URL, ca, filepath.Join(dir, "missing-module.so"), filepath.Join(dir, "missing-pin"), filepath.Join(dir, "missing-share"))
	p := filepath.Join(dir, "autohsm.yaml")
	if err := os.WriteFile(p, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := runStatus(p); exitCode(err) != exitSealed {
		t.Fatalf("sealed vault: runStatus()=%v, want exit %d", err, exitSealed)
	}
	sealed = false
	if err := runStatus(p); err != nil {
		t.Fatalf("unsealed vault: runStatus()=%v, want nil", err)
	}
}
