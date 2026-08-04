// Asset: autohsm-config
// Purpose: Load and strictly validate autohsm configuration, failing closed on anything ambiguous.
// Threats: Prevents an unsafe daemon from starting at all — world-readable config holding
// HSM PINs or wrapped shares, plaintext Vault URLs, missing CA pins, or a dev-only key
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
	"fmt"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// requiredMode is the only acceptable permission set for the config file.
// Anything broader can expose the HSM PIN or wrapped share paths.
const requiredMode os.FileMode = 0o600

// Config is the top-level daemon configuration.
type Config struct {
	// NodeID identifies this host. It is bound into the AEAD additional data of
	// every wrapped share, so a share wrapped for one node cannot be unwrapped
	// on another even with the same HSM key.
	NodeID string `yaml:"node_id"`

	Vault  VaultConfig  `yaml:"vault"`
	Keys   KeysConfig   `yaml:"keys"`
	Watch  WatchConfig  `yaml:"watch"`
	Alarm  AlarmConfig  `yaml:"alarm"`
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

	// Exactly one PIN source must be set. PINFile and PINEnv are preferred;
	// PIN inline is supported because the config is already 0600, but it keeps
	// the secret in one more place than necessary.
	PIN     string `yaml:"pin"`
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
	// MetricsAddr, if set, exposes Prometheus-style counters. Bind to
	// localhost unless you have a reason not to.
	MetricsAddr string `yaml:"metrics_addr"`
}

// Load reads, permission-checks, and validates a config file.
func Load(path string) (*Config, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("stat config: %w", err)
	}
	// Fail closed on permissions: the file may hold an HSM PIN.
	if mode := info.Mode().Perm(); mode != requiredMode {
		return nil, fmt.Errorf(
			"config %s has mode %04o, refusing to start (require %04o: it may contain an HSM PIN)",
			path, mode, requiredMode)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	var cfg Config
	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	dec.KnownFields(true) // a mistyped security setting must be an error
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	cfg.applyDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
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
	for _, v := range []string{p.PIN, p.PINFile, p.PINEnv} {
		if v != "" {
			set++
		}
	}
	if set == 0 {
		return fmt.Errorf("one of keys.pkcs11.pin, pin_file, or pin_env is required")
	}
	if set > 1 {
		return fmt.Errorf("set exactly one of keys.pkcs11.pin, pin_file, or pin_env (got %d)", set)
	}
	return nil
}

// ResolvePIN returns the HSM PIN from whichever source is configured.
// The result is key material: wipe it after use and never log it.
func (p PKCS11Config) ResolvePIN() ([]byte, error) {
	switch {
	case p.PIN != "":
		return []byte(p.PIN), nil
	case p.PINEnv != "":
		v := os.Getenv(p.PINEnv)
		if v == "" {
			return nil, fmt.Errorf("environment variable %s is empty", p.PINEnv)
		}
		return []byte(v), nil
	case p.PINFile != "":
		info, err := os.Stat(p.PINFile)
		if err != nil {
			return nil, fmt.Errorf("stat pin_file: %w", err)
		}
		if mode := info.Mode().Perm(); mode != requiredMode {
			return nil, fmt.Errorf("pin_file %s has mode %04o, require %04o", p.PINFile, mode, requiredMode)
		}
		b, err := os.ReadFile(p.PINFile)
		if err != nil {
			return nil, fmt.Errorf("read pin_file: %w", err)
		}
		return []byte(strings.TrimRight(string(b), "\r\n")), nil
	}
	return nil, fmt.Errorf("no PIN source configured")
}
