package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/afterdarksys/secretserver-autohsm/internal/config"
	"github.com/afterdarksys/secretserver-autohsm/internal/vaultclient"
)

const maxConfigSize = 1 << 20

// Config is vaultkeeper's own configuration. It holds no secret: the AppRole
// secret_id lives in its own file, and the operator key lives in gpg.
type Config struct {
	Vault struct {
		Address      string        `yaml:"address"`
		CACertPath   string        `yaml:"ca_cert_path"`
		Timeout      time.Duration `yaml:"timeout"`
		RequireTLS13 *bool         `yaml:"require_tls13"`
	} `yaml:"vault"`

	// OperatorFingerprint is the PGP key generate-root results and node
	// rekey shares are encrypted to. It must equal every node's
	// vaultkeeper.pgp_fingerprint pin.
	OperatorFingerprint string `yaml:"operator_fingerprint"`
	// OfflineFingerprint receives rekey share 5. Its private half is kept
	// off the operator workstation.
	OfflineFingerprint string `yaml:"offline_fingerprint"`
	// GPGPath is the absolute path of the gpg binary (no PATH lookup). gpg
	// runs with vaultkeeper's environment, so GNUPGHOME selects the keyring.
	GPGPath string `yaml:"gpg_path"`

	// Nodes are the autohsm nodes, each holding one share index.
	Nodes []Node `yaml:"nodes"`

	Runner struct {
		// Exec is the argv prefix of the operator's approval-gated fleet
		// runner. {node} and {approval} are substituted per argument; the
		// node command (for example "autohsm contribute generate-root") is
		// appended. Empty means the manual runner: vaultkeeper prints each
		// command and waits for Vault's progress instead.
		Exec []string `yaml:"exec"`
		// Timeout bounds one runner invocation (exec) or the wait for one
		// node's progress (manual).
		Timeout time.Duration `yaml:"timeout"`
	} `yaml:"runner"`
	// PollInterval is how often Vault progress is polled while waiting.
	PollInterval time.Duration `yaml:"poll_interval"`

	// PolicyDir holds <name>.hcl files for the policy-write task.
	PolicyDir string `yaml:"policy_dir"`
	// OutputDir receives vault-share5.<date>.gpg after a rekey.
	OutputDir string `yaml:"output_dir"`
	// StateDir records which ceremony attempts this vaultkeeper started,
	// so status can tell ours from foreign ones.
	StateDir string `yaml:"state_dir"`

	Alarm struct {
		WebhookURL string `yaml:"webhook_url"`
		// CACertPath optionally pins the CA of a webhook receiver behind a
		// private CA (instead of the system roots).
		CACertPath string `yaml:"ca_cert_path"`
	} `yaml:"alarm"`

	// AppRole is used by rotate-keyring and status. Its policy must be
	// limited to update+sudo on sys/rotate and read on sys/key-status.
	AppRole struct {
		Mount        string `yaml:"mount"`
		RoleID       string `yaml:"role_id"`
		SecretIDPath string `yaml:"secret_id_path"`
	} `yaml:"approle"`
}

// Node is one autohsm node and the share index it holds.
type Node struct {
	Name       string `yaml:"name"`
	ShareIndex int    `yaml:"share_index"`
}

var nodeNameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{0,62}$`)

func defaultConfigPath() string {
	if home, err := os.UserHomeDir(); err == nil {
		return filepath.Join(home, ".config", "vaultkeeper", "vaultkeeper.yaml")
	}
	return "/etc/vaultkeeper/vaultkeeper.yaml"
}

// loadConfig reads the config through the same owner/mode gate autohsm uses
// for its own config: the runner argv in it decides what runs on the fleet.
func loadConfig(path string) (*Config, error) {
	f, err := config.OpenSecretFile(path, "vaultkeeper config")
	if err != nil {
		return nil, err
	}
	defer f.Close()
	raw, err := config.ReadBounded(f, maxConfigSize)
	if err != nil {
		return nil, fmt.Errorf("read vaultkeeper config: %w", err)
	}
	var cfg Config
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("parse vaultkeeper config: %w", err)
	}
	var trailing any
	if err := dec.Decode(&trailing); err != io.EOF {
		return nil, fmt.Errorf("parse vaultkeeper config: exactly one YAML document is allowed")
	}
	cfg.applyDefaults()
	if err := cfg.validate(); err != nil {
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
	if c.Runner.Timeout == 0 {
		c.Runner.Timeout = 10 * time.Minute
	}
	if c.PollInterval == 0 {
		c.PollInterval = 2 * time.Second
	}
	if c.AppRole.Mount == "" {
		c.AppRole.Mount = "approle"
	}
	if c.AppRole.SecretIDPath == "" {
		c.AppRole.SecretIDPath = "/etc/vaultkeeper/secret-id"
	}
	if c.StateDir == "" {
		if home, err := os.UserHomeDir(); err == nil {
			c.StateDir = filepath.Join(home, ".local", "state", "vaultkeeper")
		}
	}
	if c.OutputDir == "" {
		if home, err := os.UserHomeDir(); err == nil {
			c.OutputDir = home
		}
	}
}

// validate checks everything that is well-formed-or-absent. Requirements
// specific to one subcommand (nodes for a ceremony, AppRole for rotation)
// are checked by that subcommand, so the vault-host timer config does not
// need to describe the fleet.
func (c *Config) validate() error {
	if !strings.HasPrefix(c.Vault.Address, "https://") {
		return fmt.Errorf("vault.address must be https")
	}
	if c.Vault.CACertPath == "" {
		return fmt.Errorf("vault.ca_cert_path is required (no system-roots fallback)")
	}
	for _, fp := range []*string{&c.OperatorFingerprint, &c.OfflineFingerprint} {
		if *fp == "" {
			continue
		}
		n, err := config.NormalizePGPFingerprint(*fp)
		if err != nil {
			return fmt.Errorf("fingerprint %q: %w", *fp, err)
		}
		*fp = n
	}
	if c.OperatorFingerprint != "" && c.OperatorFingerprint == c.OfflineFingerprint {
		return fmt.Errorf("offline_fingerprint must differ from operator_fingerprint (share 5 must not open with the operator key)")
	}
	names, idx := map[string]bool{}, map[int]bool{}
	for i, n := range c.Nodes {
		if !nodeNameRE.MatchString(n.Name) {
			return fmt.Errorf("nodes[%d].name %q: want lowercase letters, digits, '.' or '-'", i, n.Name)
		}
		if names[n.Name] || idx[n.ShareIndex] {
			return fmt.Errorf("nodes[%d]: duplicate name or share_index", i)
		}
		if n.ShareIndex < 1 || n.ShareIndex > 4 {
			return fmt.Errorf("nodes[%d].share_index must be 1..4 (share 5 is the offline share)", i)
		}
		names[n.Name], idx[n.ShareIndex] = true, true
	}
	if c.GPGPath != "" && !filepath.IsAbs(c.GPGPath) {
		return fmt.Errorf("gpg_path must be absolute, got %q", c.GPGPath)
	}
	if len(c.Runner.Exec) > 0 && c.Runner.Exec[0] == "" {
		return fmt.Errorf("runner.exec[0] must name the runner binary")
	}
	for _, a := range c.Runner.Exec {
		if strings.ContainsAny(a, "\x00\n") {
			return fmt.Errorf("runner.exec arguments must not contain NUL or newline")
		}
	}
	if c.PollInterval < 100*time.Millisecond {
		return fmt.Errorf("poll_interval must be >= 100ms")
	}
	if c.Alarm.WebhookURL != "" && !strings.HasPrefix(c.Alarm.WebhookURL, "https://") {
		return fmt.Errorf("alarm.webhook_url must be https")
	}
	return nil
}

func (c *Config) vaultClient() (*vaultclient.Client, error) {
	return vaultclient.New(vaultclient.Config{
		Address:    c.Vault.Address,
		CACertPath: c.Vault.CACertPath,
		Timeout:    c.Vault.Timeout,
		MinTLS13:   c.Vault.RequireTLS13 != nil && *c.Vault.RequireTLS13,
	})
}

// requireCeremony checks what root-task and rekey need.
func (c *Config) requireCeremony() error {
	if c.OperatorFingerprint == "" {
		return fmt.Errorf("operator_fingerprint is required")
	}
	if c.GPGPath == "" {
		return fmt.Errorf("gpg_path is required (absolute path of gpg)")
	}
	if c.OutputDir == "" {
		return fmt.Errorf("output_dir is required (encrypted results are saved there)")
	}
	if len(c.Nodes) < 3 {
		return fmt.Errorf("at least 3 nodes are required to reach threshold 3, got %d", len(c.Nodes))
	}
	return nil
}
