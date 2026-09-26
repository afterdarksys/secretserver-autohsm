// Asset: autohsm-config
// Purpose: Load and strictly validate autohsm configuration, failing closed on anything ambiguous.
// Threats: Prevents an unsafe daemon from starting at all — loosely protected config,
// plaintext Vault URLs, missing CA pins, or a dev-only key
// source enabled by accident in production. Refuses unknown fields so a typo'd security
// setting is an error rather than a silently ignored default. Does NOT protect the config
// file's contents at rest (that is the filesystem's and the HSM's job).
// Deps: gopkg.in/yaml.v3
// Example: cfg, err := config.Load("/etc/autohsm.yaml")
// Status: tested
// License: proprietary
// Provenance: original
package config

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	ownerOnlyMode   os.FileMode = 0o600
	serviceReadMode os.FileMode = 0o640
	maxConfigSize               = 1 << 20
	maxPINSize                  = 4096
)

// Config is the top-level daemon configuration.
type Config struct {
	// NodeID is an operator-assigned context label bound into each envelope's
	// AAD. It prevents accidental cross-node use but is not hardware identity;
	// actual host separation requires a unique, non-replicated HSM key per node.
	NodeID string `yaml:"node_id"`

	Vault VaultConfig `yaml:"vault"`
	Keys  KeysConfig  `yaml:"keys"`
	Watch WatchConfig `yaml:"watch"`
	Alarm AlarmConfig `yaml:"alarm"`
}

// VaultConfig describes the Vault endpoint to keep unsealed.
type VaultConfig struct {
	Address    string        `yaml:"address"`
	CACertPath string        `yaml:"ca_cert_path"`
	Timeout    time.Duration `yaml:"timeout"`
	// RequireTLS13 defaults to true; set false only for a Vault that cannot
	// negotiate TLS 1.3.
	RequireTLS13 *bool `yaml:"require_tls13"`
}

// KeysConfig selects the key source and the shares this node holds.
type KeysConfig struct {
	// Source is "pkcs11" (production) or "file" (development only).
	Source string `yaml:"source"`

	PKCS11 PKCS11Config `yaml:"pkcs11"`

	// Shares this node is responsible for. Deliberately a list: a node may hold
	// more than one share, but holding >= threshold defeats the whole design.
	Shares []ShareConfig `yaml:"shares"`

	// AllowInsecureFileSource must be explicitly true to permit source: file.
	// This exists so the dev path can never be reached by omission.
	AllowInsecureFileSource bool `yaml:"allow_insecure_file_source"`
}

// ShareConfig locates one wrapped unseal share.
type ShareConfig struct {
	// Index is the share's position in the original split. It is bound into the
	// AEAD additional data, so a share cannot be replayed under another index.
	Index int `yaml:"index"`
	// Path is the file holding the wrapped (HSM-encrypted) share.
	Path string `yaml:"path"`
}

// PKCS11Config describes how to reach the HSM.
type PKCS11Config struct {
	ModulePath string `yaml:"module_path"`
	TokenLabel string `yaml:"token_label"`
	KeyLabel   string `yaml:"key_label"`

	// Exactly one external PIN source must be set. Inline PINs are deliberately
	// unsupported so the main configuration never contains the HSM credential.
	PINFile string `yaml:"pin_file"`
	PINEnv  string `yaml:"pin_env"`
}

// WatchConfig controls the polling loop.
type WatchConfig struct {
	Interval time.Duration `yaml:"interval"`
	// MaxUnsealAttempts bounds consecutive failed unseal cycles before the
	// daemon stops trying and stays loud. Prevents hammering a Vault that is
	// rejecting shares (e.g. wrong keys after a re-init).
	MaxUnsealAttempts int `yaml:"max_unseal_attempts"`
}

// AlarmConfig controls how a sealed Vault is reported.
type AlarmConfig struct {
	// WebhookURL, if set, must be https.
	WebhookURL string `yaml:"webhook_url"`
}

// Load reads, permission-checks, and validates a config file.
func Load(path string) (*Config, error) {
	f, err := OpenSecretFile(path, "config")
	if err != nil {
		return nil, err
	}
	defer f.Close()

	raw, err := ReadBounded(f, maxConfigSize)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	defer wipe(raw)

	var cfg Config
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true) // a mistyped security setting must be an error
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	var trailing any
	if err := dec.Decode(&trailing); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("parse config: multiple YAML documents are not allowed")
		}
		return nil, fmt.Errorf("parse trailing config data: %w", err)
	}

	cfg.applyDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// OpenSecretFile opens path and enforces the trust boundary all autohsm
// secret material (config, PIN, wrapped shares) must meet: a regular file
// that is either owner-only (0600, owned by the user running this process)
// or root-owned and group-readable (0640). Callers outside this package
// (e.g. internal/watch, cmd/autohsm) must use this instead of os.ReadFile
// for any file whose content is or gates key material — the enforcement
// happens on the file the OS already has open, so it cannot be bypassed by
// a TOCTOU swap between check and read.
//
// O_NONBLOCK makes opening a FIFO planted at a secret path return at once so
// the regular-file check can reject it; a plain open would block the daemon
// forever waiting for a writer. It has no effect on reads of regular files.
// Symlinks are followed, but every check applies to the file actually opened,
// so a link can only lead to a file that itself passes the ownership gate.
func OpenSecretFile(path, purpose string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", purpose, err)
	}
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("stat %s: %w", purpose, err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		f.Close()
		return nil, fmt.Errorf("stat %s: cannot determine file owner", purpose)
	}
	if err := validateSecretFileMetadata(info.Mode(), uint32(stat.Uid)); err != nil {
		f.Close()
		return nil, fmt.Errorf("%s %s: %w", purpose, path, err)
	}
	return f, nil
}

func validateSecretFileMetadata(mode os.FileMode, ownerUID uint32) error {
	if !mode.IsRegular() {
		return fmt.Errorf("not a regular file")
	}
	perm := mode.Perm()
	switch perm {
	case ownerOnlyMode:
		if ownerUID != uint32(os.Getuid()) {
			return fmt.Errorf("mode 0600 is allowed only when owned by the running user (uid %d), got uid %d", os.Getuid(), ownerUID)
		}
		return nil
	case serviceReadMode:
		if ownerUID != 0 {
			return fmt.Errorf("mode 0640 is allowed only on a root-owned file")
		}
		return nil
	default:
		return fmt.Errorf("mode %04o; require owner-only 0600 or root-owned 0640", perm)
	}
}

// ReadBounded reads at most limit bytes from r, refusing (and wiping the
// partial read) if the source has more. It reads into ONE buffer allocated up
// front: io.ReadAll grows by reallocating, which would leave earlier partial
// copies of a PIN or share in freed heap memory that can never be wiped.
func ReadBounded(r io.Reader, limit int64) ([]byte, error) {
	buf := make([]byte, limit+1)
	n, err := io.ReadFull(r, buf)
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		wipe(buf)
		return nil, err
	}
	if int64(n) > limit {
		wipe(buf)
		return nil, fmt.Errorf("file exceeds %d bytes", limit)
	}
	return buf[:n], nil
}

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func (c *Config) applyDefaults() {
	if c.Vault.Timeout == 0 {
		c.Vault.Timeout = 10 * time.Second
	}
	if c.Vault.RequireTLS13 == nil {
		t := true
		c.Vault.RequireTLS13 = &t
	}
	if c.Watch.Interval == 0 {
		c.Watch.Interval = 30 * time.Second
	}
	if c.Watch.MaxUnsealAttempts == 0 {
		c.Watch.MaxUnsealAttempts = 5
	}
	if c.Keys.Source == "" {
		c.Keys.Source = "pkcs11"
	}
}

// Validate enforces every invariant the daemon depends on.
func (c *Config) Validate() error {
	if strings.TrimSpace(c.NodeID) == "" {
		return fmt.Errorf("node_id is required (it is bound into each wrapped share)")
	}
	if c.Vault.Address == "" {
		return fmt.Errorf("vault.address is required")
	}
	if !strings.HasPrefix(c.Vault.Address, "https://") {
		return fmt.Errorf("vault.address must be https (refusing to send unseal shares in cleartext)")
	}
	if c.Vault.CACertPath == "" {
		return fmt.Errorf("vault.ca_cert_path is required (this deployment pins a private CA)")
	}
	if c.Vault.Timeout <= 0 {
		return fmt.Errorf("vault.timeout must be positive")
	}
	if c.Watch.Interval < time.Second {
		return fmt.Errorf("watch.interval must be >= 1s, got %s", c.Watch.Interval)
	}
	if c.Watch.MaxUnsealAttempts < 1 {
		return fmt.Errorf("watch.max_unseal_attempts must be >= 1")
	}

	if len(c.Keys.Shares) == 0 {
		return fmt.Errorf("keys.shares is empty: this node would never be able to unseal")
	}
	seen := map[int]bool{}
	for i, s := range c.Keys.Shares {
		if s.Index < 1 {
			return fmt.Errorf("keys.shares[%d].index must be >= 1", i)
		}
		if seen[s.Index] {
			return fmt.Errorf("keys.shares[%d]: duplicate index %d", i, s.Index)
		}
		seen[s.Index] = true
		if strings.TrimSpace(s.Path) == "" {
			return fmt.Errorf("keys.shares[%d].path is required", i)
		}
	}

	switch c.Keys.Source {
	case "pkcs11":
		if err := c.Keys.PKCS11.validate(); err != nil {
			return err
		}
	case "file":
		// Dev-only path: must be opted into explicitly and loudly.
		if !c.Keys.AllowInsecureFileSource {
			return fmt.Errorf(
				"keys.source=file stores shares unprotected on disk; set keys.allow_insecure_file_source: true to accept this (development only)")
		}
	default:
		return fmt.Errorf("keys.source must be \"pkcs11\" or \"file\", got %q", c.Keys.Source)
	}

	if c.Alarm.WebhookURL != "" && !strings.HasPrefix(c.Alarm.WebhookURL, "https://") {
		return fmt.Errorf("alarm.webhook_url must be https")
	}
	return nil
}

func (p PKCS11Config) validate() error {
	if p.ModulePath == "" {
		return fmt.Errorf("keys.pkcs11.module_path is required")
	}
	if p.KeyLabel == "" {
		return fmt.Errorf("keys.pkcs11.key_label is required")
	}
	set := 0
	for _, v := range []string{p.PINFile, p.PINEnv} {
		if v != "" {
			set++
		}
	}
	if set == 0 {
		return fmt.Errorf("one of keys.pkcs11.pin_file or pin_env is required")
	}
	if set > 1 {
		return fmt.Errorf("set exactly one of keys.pkcs11.pin_file or pin_env (got %d)", set)
	}
	return nil
}

// ResolvePIN returns the HSM PIN from whichever source is configured.
// The result is key material: wipe it after use and never log it.
func (p PKCS11Config) ResolvePIN() ([]byte, error) {
	switch {
	case p.PINEnv != "":
		v := os.Getenv(p.PINEnv)
		if v == "" {
			return nil, fmt.Errorf("environment variable %s is empty", p.PINEnv)
		}
		// Best-effort only: this cannot scrub the PIN from /proc/<pid>/environ,
		// which reflects the process's original exec-time environment block for
		// its entire lifetime regardless of Unsetenv. It does stop the value
		// from being re-read via os.Environ() or inherited by a future child
		// process for the remainder of this run.
		os.Unsetenv(p.PINEnv)
		return []byte(v), nil
	case p.PINFile != "":
		f, err := OpenSecretFile(p.PINFile, "pin_file")
		if err != nil {
			return nil, err
		}
		defer f.Close()
		b, err := ReadBounded(f, maxPINSize)
		if err != nil {
			return nil, fmt.Errorf("read pin_file: %w", err)
		}
		pin := bytes.TrimRight(b, "\r\n")
		if len(pin) == 0 {
			wipe(b)
			return nil, fmt.Errorf("pin_file is empty")
		}
		return pin, nil
	}
	return nil, fmt.Errorf("no PIN source configured")
}
