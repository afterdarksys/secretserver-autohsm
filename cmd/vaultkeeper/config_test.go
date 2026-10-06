package main

import (
	"bufio"
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const baseCfg = `vault:
  address: https://vault.example.com:8200
  ca_cert_path: /etc/vaultkeeper/vault-ca.pem
`

func writeCfg(t *testing.T, body string) string {
	p := filepath.Join(t.TempDir(), "vaultkeeper.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadConfigMinimalForRotateHost(t *testing.T) {
	cfg, err := loadConfig(writeCfg(t, baseCfg+"approle:\n  role_id: r\n"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.AppRole.SecretIDPath != "/etc/vaultkeeper/secret-id" || cfg.AppRole.Mount != "approle" {
		t.Fatalf("defaults %+v", cfg.AppRole)
	}
	if err := cfg.requireCeremony(); err == nil {
		t.Fatal("ceremony allowed without operator key and nodes")
	}
}

func TestLoadConfigRejects(t *testing.T) {
	bad := map[string]string{
		"plaintext vault":     strings.Replace(baseCfg, "https", "http", 1),
		"no CA":               "vault:\n  address: https://v:8200\n",
		"short fingerprint":   baseCfg + "operator_fingerprint: B051837018556301\n",
		"same op and offline": baseCfg + "operator_fingerprint: " + opFP + "\noffline_fingerprint: " + strings.ToUpper(opFP) + "\n",
		"node index 5":        baseCfg + "nodes:\n  - {name: node-a, share_index: 5}\n",
		"duplicate index":     baseCfg + "nodes:\n  - {name: node-a, share_index: 1}\n  - {name: node-b, share_index: 1}\n",
		"node name metachar":  baseCfg + "nodes:\n  - {name: 'node-a;id', share_index: 1}\n",
		"unknown field":       baseCfg + "root_token: nope\n",
		"plaintext webhook":   baseCfg + "alarm:\n  webhook_url: http://alerts.example/hook\n",
		"empty runner binary": baseCfg + "runner:\n  exec: ['', '{node}']\n",
		"two documents":       baseCfg + "---\n" + baseCfg,
		"relative gpg_path":   baseCfg + "gpg_path: gpg\n",
	}
	for name, body := range bad {
		if _, err := loadConfig(writeCfg(t, body)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestLoadConfigRejectsLoosePermissions(t *testing.T) {
	p := writeCfg(t, baseCfg)
	os.Chmod(p, 0o644)
	if _, err := loadConfig(p); err == nil {
		t.Fatal("world-readable config accepted (it decides what runs on the fleet)")
	}
}

func TestManualRunnerPrintsExactCommandAndCannotPipe(t *testing.T) {
	var out bytes.Buffer
	m := &ManualRunner{Out: &out, In: bufio.NewReader(strings.NewReader("")), Approval: "/approvals/ceremony.contract"}
	got, err := m.Contribute(context.Background(), Node{"node-b", 2}, "generate-root")
	if err != nil || got != nil {
		t.Fatalf("manual Contribute = %q, %v", got, err)
	}
	if !strings.Contains(out.String(), "\n    autohsm contribute generate-root\n") || !strings.Contains(out.String(), "node-b") {
		t.Fatalf("command not printed exactly:\n%s", out.String())
	}
	if m.CanPipe() || m.Wrap(context.Background(), Node{"node-b", 2}, []byte("s")) == nil {
		t.Fatal("manual runner claims it can pipe a share")
	}
}

func TestExecRunnerArgvSubstitution(t *testing.T) {
	r := &ExecRunner{Argv: []string{"/usr/local/bin/fleet-run", "--approval={approval}", "--host", "{node}", "--"}, Approval: "/a.contract"}
	got := strings.Join(r.argv(Node{"node-c", 3}, wrapArgs(Node{"node-c", 3})), " ")
	want := "/usr/local/bin/fleet-run --approval=/a.contract --host node-c -- autohsm wrap --index 3 --install"
	if got != want {
		t.Fatalf("argv %q\nwant %q", got, want)
	}
}

// rekey must refuse before touching Vault when the runner cannot deliver
// the new shares (the old shares die the moment Vault rekeys).
func TestRekeyRefusesManualRunnerBeforeStarting(t *testing.T) {
	fv := newFakeVault(t)
	vk, _, _ := newTestApp(t, fv)
	vk.cfg.OfflineFingerprint = foreignFP
	vk.cfg.Nodes = append(vk.cfg.Nodes, Node{"node-d", 4})
	vk.cfg.OutputDir = t.TempDir()
	vk.runner = &ManualRunner{Out: &bytes.Buffer{}, In: bufio.NewReader(strings.NewReader(""))}
	approval := filepath.Join(t.TempDir(), "a")
	os.WriteFile(approval, []byte("x"), 0o600)
	err := vk.cmdRekey(context.Background(), &cliArgs{approval: approval})
	if err == nil || !strings.Contains(err.Error(), "runner.exec") {
		t.Fatalf("err=%v", err)
	}
	if len(fv.calls) != 0 {
		t.Fatalf("vault was contacted: %v", fv.calls)
	}
}
