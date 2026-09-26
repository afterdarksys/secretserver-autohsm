package config

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

const validYAML = `
node_id: apps2
vault:
  address: https://apps2.afterdarksys.com:8200
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

func write(t *testing.T, body string, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "autohsm.yaml")
	if err := os.WriteFile(p, []byte(body), mode); err != nil {
		t.Fatal(err)
	}
	// WriteFile is subject to umask; force the mode we asked for.
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadValidConfig(t *testing.T) {
	cfg, err := Load(write(t, validYAML, 0o600))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.NodeID != "apps2" || len(cfg.Keys.Shares) != 1 {
		t.Fatalf("unexpected config: %+v", cfg)
	}
	// Defaults must be applied.
	if cfg.Watch.Interval == 0 || cfg.Vault.Timeout == 0 || cfg.Watch.MaxUnsealAttempts == 0 {
		t.Fatal("defaults not applied")
	}
	if cfg.Vault.RequireTLS13 == nil || !*cfg.Vault.RequireTLS13 {
		t.Fatal("TLS 1.3 must default to required")
	}
}

// Negative: world access or group write access is never allowed. Root-owned
// group-readable files are separately permitted for the dedicated service.
func TestLoadRejectsLoosePermissions(t *testing.T) {
	for _, mode := range []os.FileMode{0o644, 0o604, 0o660, 0o666, 0o777} {
		_, err := Load(write(t, validYAML, mode))
		if err == nil {
			t.Fatalf("accepted config with mode %04o", mode)
		}
		if !strings.Contains(err.Error(), "mode") {
			t.Fatalf("mode %04o: unexpected error %v", mode, err)
		}
	}
}

func TestSecretFileMetadataAcceptsRootServiceGroupMode(t *testing.T) {
	if err := validateSecretFileMetadata(0o640, 0); err != nil {
		t.Fatalf("root-owned 0640 file rejected: %v", err)
	}
	if err := validateSecretFileMetadata(0o640, 1000); err == nil {
		t.Fatal("non-root-owned 0640 file accepted")
	}
}

func TestLoadRejectsNonRegularFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(dir); err == nil {
		t.Fatal("directory accepted as configuration")
	}
}

// Negative: a FIFO at a secret path must be rejected promptly, not block the
// daemon forever waiting for a writer.
func TestOpenSecretFileRejectsFIFOWithoutBlocking(t *testing.T) {
	p := filepath.Join(t.TempDir(), "pin")
	if err := syscall.Mkfifo(p, 0o600); err != nil {
		t.Skipf("mkfifo unavailable: %v", err)
	}
	done := make(chan error, 1)
	go func() {
		f, err := OpenSecretFile(p, "pin_file")
		if f != nil {
			f.Close()
		}
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "not a regular file") {
			t.Fatalf("FIFO accepted or wrong error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("OpenSecretFile blocked on a FIFO")
	}
}

func TestLoadRejectsOversizedConfig(t *testing.T) {
	body := validYAML + "\n# " + strings.Repeat("x", maxConfigSize)
	if _, err := Load(write(t, body, 0o600)); err == nil {
		t.Fatal("oversized configuration accepted")
	}
}

// Negative: a mistyped security setting must be an error, not a silent default.
func TestLoadRejectsUnknownFields(t *testing.T) {
	body := validYAML + "\nunknown_setting: true\n"
	if _, err := Load(write(t, body, 0o600)); err == nil {
		t.Fatal("unknown field accepted")
	}
}

func TestLoadRejectsMultipleYAMLDocuments(t *testing.T) {
	body := validYAML + "\n---\nnode_id: hidden-second-document\n"
	if _, err := Load(write(t, body, 0o600)); err == nil {
		t.Fatal("multiple YAML documents accepted")
	}
}

func TestLoadRejectsUnimplementedMetricsSetting(t *testing.T) {
	body := validYAML + "\nalarm:\n  metrics_addr: 127.0.0.1:9090\n"
	if _, err := Load(write(t, body, 0o600)); err == nil {
		t.Fatal("accepted an unimplemented metrics setting")
	}
}

// Negative: plaintext Vault addresses must be refused — shares would cross the
// network in the clear.
func TestValidateRejectsPlaintextVaultAddress(t *testing.T) {
	body := strings.Replace(validYAML, "https://apps2", "http://apps2", 1)
	if _, err := Load(write(t, body, 0o600)); err == nil {
		t.Fatal("plaintext vault address accepted")
	}
}

// Negative: without a pinned CA there is no way to authenticate Vault.
func TestValidateRequiresCACert(t *testing.T) {
	body := strings.Replace(validYAML, "  ca_cert_path: /etc/autohsm/vault-ca.pem\n", "", 1)
	if _, err := Load(write(t, body, 0o600)); err == nil {
		t.Fatal("missing ca_cert_path accepted")
	}
}

// Negative: the insecure dev key source must never be reachable by omission.
func TestFileSourceRequiresExplicitOptIn(t *testing.T) {
	body := strings.Replace(validYAML, "source: pkcs11", "source: file", 1)
	_, err := Load(write(t, body, 0o600))
	if err == nil {
		t.Fatal("file source accepted without explicit opt-in")
	}
	if !strings.Contains(err.Error(), "allow_insecure_file_source") {
		t.Fatalf("unexpected error: %v", err)
	}

	// With the explicit opt-in it loads (development only).
	body2 := body + "\n  allow_insecure_file_source: true\n"
	if _, err := Load(write(t, body2, 0o600)); err != nil {
		t.Fatalf("explicit opt-in still rejected: %v", err)
	}
}

// Negative: a node with no shares would never unseal — that is a config bug.
func TestValidateRejectsNoShares(t *testing.T) {
	body := strings.Split(validYAML, "  shares:")[0]
	if _, err := Load(write(t, body, 0o600)); err == nil {
		t.Fatal("config with no shares accepted")
	}
}

// Negative: duplicate share indices indicate a copy-paste error that would
// submit the same share twice and never reach threshold.
func TestValidateRejectsDuplicateShareIndex(t *testing.T) {
	body := validYAML + "    - index: 1\n      path: /etc/autohsm/share-1-copy.wrapped\n"
	if _, err := Load(write(t, body, 0o600)); err == nil {
		t.Fatal("duplicate share index accepted")
	}
}

// Negative: exactly one PIN source. Zero is unusable; more than one is ambiguous.
func TestPKCS11RequiresExactlyOnePINSource(t *testing.T) {
	none := strings.Replace(validYAML, "    pin_env: AUTOHSM_PIN\n", "", 1)
	if _, err := Load(write(t, none, 0o600)); err == nil {
		t.Fatal("config with no PIN source accepted")
	}
	two := strings.Replace(validYAML, "    pin_env: AUTOHSM_PIN\n",
		"    pin_env: AUTOHSM_PIN\n    pin_file: /etc/autohsm/pin\n", 1)
	if _, err := Load(write(t, two, 0o600)); err == nil {
		t.Fatal("config with two PIN sources accepted")
	}
}

// Negative: an unknown key source must fail rather than fall back to anything.
func TestValidateRejectsUnknownSource(t *testing.T) {
	body := strings.Replace(validYAML, "source: pkcs11", "source: magic", 1)
	if _, err := Load(write(t, body, 0o600)); err == nil {
		t.Fatal("unknown key source accepted")
	}
}

// Negative: a plaintext alarm webhook would leak operational state.
func TestValidateRejectsPlaintextWebhook(t *testing.T) {
	body := validYAML + "alarm:\n  webhook_url: http://alerts.example/hook\n"
	if _, err := Load(write(t, body, 0o600)); err == nil {
		t.Fatal("plaintext webhook accepted")
	}
}

// Negative: a sub-second poll interval would hammer Vault.
func TestValidateRejectsTinyInterval(t *testing.T) {
	body := validYAML + "watch:\n  interval: 100ms\n"
	if _, err := Load(write(t, body, 0o600)); err == nil {
		t.Fatal("sub-second interval accepted")
	}
}

// Negative: the PIN must not be readable from a loosely-permissioned file.
func TestResolvePINRejectsLoosePINFile(t *testing.T) {
	dir := t.TempDir()
	pinPath := filepath.Join(dir, "pin")
	if err := os.WriteFile(pinPath, []byte("1234\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(pinPath, 0o644); err != nil {
		t.Fatal(err)
	}
	p := PKCS11Config{ModulePath: "m", KeyLabel: "k", PINFile: pinPath}
	if _, err := p.ResolvePIN(); err == nil {
		t.Fatal("read PIN from a world-readable file")
	}

	if err := os.Chmod(pinPath, 0o600); err != nil {
		t.Fatal(err)
	}
	pin, err := p.ResolvePIN()
	if err != nil {
		t.Fatal(err)
	}
	if string(pin) != "1234" {
		t.Fatalf("trailing newline not trimmed: %q", pin)
	}

}

func TestLoadRejectsInlinePIN(t *testing.T) {
	body := strings.Replace(validYAML, "    pin_env: AUTOHSM_PIN", "    pin: secret", 1)
	if _, err := Load(write(t, body, 0o600)); err == nil {
		t.Fatal("inline HSM PIN accepted")
	}
}

func TestResolvePINRejectsEmptyFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "pin")
	if err := os.WriteFile(p, []byte("\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := (PKCS11Config{PINFile: p}).ResolvePIN(); err == nil {
		t.Fatal("empty PIN file accepted")
	}
}
