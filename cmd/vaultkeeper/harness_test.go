package main

// Integration harness: a real Vault binary (file storage, Shamir 5/3, TLS on
// loopback) in a temp dir, four simulated autohsm nodes (real autohsm binary,
// software key source: the same envelope/AAD code path as the HSM source),
// and throwaway GNUPGHOMEs holding generated test keys. Nothing here touches
// a real Vault, host, or keyring. Tests skip, saying why, when `vault` or
// `gpg` is not installed.

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/afterdarksys/secretserver-autohsm/internal/keysource"
	"github.com/afterdarksys/secretserver-autohsm/internal/vaultclient"
)

type testVault struct {
	addr, ca  string
	cmd       *exec.Cmd
	log       *syncBuffer
	http      *http.Client
	initHex   []string
	initB64   []string
	rootToken string
	vc        *vaultclient.Client
	version   string
}

func requireIntegration(t *testing.T) (vaultBin, gpgBin string) {
	t.Helper()
	if testing.Short() {
		t.Skip("integration: skipped under -short")
	}
	// VAULTKEEPER_TEST_VAULT selects a specific Vault binary (for example a
	// verified 1.15 release unpacked in a temp dir) without touching PATH.
	vaultBin = os.Getenv("VAULTKEEPER_TEST_VAULT")
	var err error
	if vaultBin == "" {
		vaultBin, err = exec.LookPath("vault")
		if err != nil {
			t.Skip("integration: SKIPPED, `vault` binary not on PATH and VAULTKEEPER_TEST_VAULT unset (install Vault to run the real-Vault ceremony tests)")
		}
	}
	gpgBin, err = exec.LookPath("gpg")
	if err != nil {
		t.Skip("integration: SKIPPED, `gpg` not on PATH")
	}
	return vaultBin, gpgBin
}

func vaultMajor(t *testing.T, bin string) (int, string) {
	out, err := exec.Command(bin, "version").Output()
	if err != nil {
		t.Fatalf("vault version: %v", err)
	}
	m := regexp.MustCompile(`v(\d+)\.(\d+)\.(\d+)`).FindStringSubmatch(string(out))
	if m == nil {
		t.Fatalf("cannot parse vault version %q", out)
	}
	major, _ := strconv.Atoi(m[1])
	return major, m[0]
}

func selfSignedLoopback(t *testing.T, dir string) (certPath, keyPath string) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: "vault-test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(2 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kd, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPath, keyPath = filepath.Join(dir, "vault.pem"), filepath.Join(dir, "vault-key.pem")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kd}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}

func freePort(t *testing.T) int {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// startVault starts, initialises (5/3) and unseals a disposable Vault.
func startVault(t *testing.T, bin string) *testVault {
	t.Helper()
	dir := t.TempDir()
	cert, key := selfSignedLoopback(t, dir)
	port := freePort(t)
	major, version := vaultMajor(t, bin)
	hcl := fmt.Sprintf(`storage "file" { path = %q }
listener "tcp" {
  address = "127.0.0.1:%d"
  tls_cert_file = %q
  tls_key_file = %q
}
disable_mlock = true
api_addr = "https://127.0.0.1:%d"
`, filepath.Join(dir, "data"), port, cert, key, port)
	if major >= 2 {
		// Vault 2.x authenticates generate-root and rekey by default; 1.x
		// (the layout this design targets) leaves them open. Reproduce 1.x.
		hcl += `enable_unauthenticated_access = ["generate-root", "rekey"]` + "\n"
	}
	cfgPath := filepath.Join(dir, "vault.hcl")
	if err := os.WriteFile(cfgPath, []byte(hcl), 0o600); err != nil {
		t.Fatal(err)
	}
	tv := &testVault{addr: fmt.Sprintf("https://127.0.0.1:%d", port), ca: cert, log: &syncBuffer{}, version: version}
	tv.cmd = exec.Command(bin, "server", "-config="+cfgPath)
	tv.cmd.Stdout, tv.cmd.Stderr = tv.log, tv.log
	if err := tv.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		tv.cmd.Process.Kill()
		tv.cmd.Wait()
	})

	pool := x509.NewCertPool()
	pem, _ := os.ReadFile(cert)
	pool.AppendCertsFromPEM(pem)
	tv.http = &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}}
	var err error
	tv.vc, err = vaultclient.New(vaultclient.Config{Address: tv.addr, CACertPath: cert})
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(30 * time.Second)
	for {
		if _, err := tv.vc.SealStatus(context.Background()); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("vault did not start:\n%s", tv.log.String())
		}
		time.Sleep(200 * time.Millisecond)
	}
	var initResp struct {
		Keys      []string `json:"keys"`
		KeysB64   []string `json:"keys_base64"`
		RootToken string   `json:"root_token"`
	}
	tv.api(t, "", http.MethodPut, "/v1/sys/init", map[string]any{"secret_shares": 5, "secret_threshold": 3}, &initResp, 200)
	tv.initHex, tv.initB64, tv.rootToken = initResp.Keys, initResp.KeysB64, initResp.RootToken
	for i := 0; i < 3; i++ {
		if _, err := tv.vc.SubmitUnsealShare(context.Background(), []byte(tv.initHex[i])); err != nil {
			t.Fatal(err)
		}
	}
	return tv
}

// api is the test's own Vault client for setup and verification (it is the
// harness acting as an administrator, never vaultkeeper).
func (tv *testVault) api(t *testing.T, token, method, path string, body any, out any, wantStatus int) int {
	t.Helper()
	var rdr io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rdr = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, tv.addr+path, rdr)
	if token != "" {
		req.Header.Set("X-Vault-Token", token)
	}
	resp, err := tv.http.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if wantStatus != 0 && resp.StatusCode != wantStatus {
		t.Fatalf("%s %s: status %d, want %d: %s", method, path, resp.StatusCode, wantStatus, raw)
	}
	if out != nil && len(raw) > 0 {
		if err := json.Unmarshal(raw, out); err != nil {
			t.Fatalf("%s %s: decode: %v", method, path, err)
		}
	}
	return resp.StatusCode
}

// rootTokensOtherThan returns accessors of tokens carrying the root policy,
// excluding the given ones.
func (tv *testVault) rootTokensOtherThan(t *testing.T, exclude ...string) []string {
	var list struct {
		Data struct {
			Keys []string `json:"keys"`
		} `json:"data"`
	}
	tv.api(t, tv.rootToken, "LIST", "/v1/auth/token/accessors", nil, &list, 200)
	var out []string
	for _, acc := range list.Data.Keys {
		skip := false
		for _, e := range exclude {
			if acc == e {
				skip = true
			}
		}
		if skip {
			continue
		}
		var info struct {
			Data struct {
				Policies []string `json:"policies"`
			} `json:"data"`
		}
		if tv.api(t, tv.rootToken, http.MethodPost, "/v1/auth/token/lookup-accessor", map[string]string{"accessor": acc}, &info, 0) != 200 {
			continue
		}
		for _, p := range info.Data.Policies {
			if p == "root" {
				out = append(out, acc)
			}
		}
	}
	return out
}

func (tv *testVault) accessorOf(t *testing.T, token string) string {
	var info struct {
		Data struct {
			Accessor string `json:"accessor"`
		} `json:"data"`
	}
	tv.api(t, token, http.MethodGet, "/v1/auth/token/lookup-self", nil, &info, 200)
	return info.Data.Accessor
}

// gpgHome is a throwaway keyring with one generated, passphrase-less
// ed25519/cv25519 test key. The directory is short because gpg-agent's
// socket path must fit in sun_path.
type gpgHome struct {
	dir, bin, fpr string
}

func newGPGHome(t *testing.T, bin, uid string) *gpgHome {
	t.Helper()
	dir, err := os.MkdirTemp("", "vkg")
	if err != nil {
		t.Fatal(err)
	}
	os.Chmod(dir, 0o700)
	h := &gpgHome{dir: dir, bin: bin}
	t.Cleanup(func() {
		c := exec.Command("gpgconf", "--kill", "gpg-agent")
		c.Env = append(os.Environ(), "GNUPGHOME="+dir)
		c.Run()
		os.RemoveAll(dir)
	})
	h.run(t, nil, "--batch", "--pinentry-mode", "loopback", "--passphrase", "", "--quick-gen-key", uid, "ed25519", "sign,cert", "never")
	out := h.run(t, nil, "--with-colons", "--list-keys", uid)
	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(line, "fpr:") {
			h.fpr = strings.ToLower(strings.Split(line, ":")[9])
			break
		}
	}
	if len(h.fpr) != 40 {
		t.Fatalf("no v4 fingerprint for test key: %q", out)
	}
	h.run(t, nil, "--batch", "--pinentry-mode", "loopback", "--passphrase", "", "--quick-add-key", h.fpr, "cv25519", "encr", "never")
	return h
}

func (h *gpgHome) run(t *testing.T, stdin []byte, args ...string) []byte {
	t.Helper()
	c := exec.Command(h.bin, args...)
	c.Env = append(os.Environ(), "GNUPGHOME="+h.dir)
	if stdin != nil {
		c.Stdin = bytes.NewReader(stdin)
	}
	var errb bytes.Buffer
	c.Stderr = &errb
	out, err := c.Output()
	if err != nil {
		t.Fatalf("gpg %v: %v: %s", args, err, errb.String())
	}
	return out
}

// importSecret copies other's secret key into h (the offline key brought
// to the workstation for verify-share5).
func (h *gpgHome) importSecret(t *testing.T, other *gpgHome) {
	sec := other.run(t, nil, "--batch", "--pinentry-mode", "loopback", "--passphrase", "", "--export-secret-keys", other.fpr)
	h.run(t, sec, "--batch", "--pinentry-mode", "loopback", "--passphrase", "", "--import")
}

// importPublic copies other's public key (only) into h.
func (h *gpgHome) importPublic(t *testing.T, other *gpgHome) {
	pub := other.run(t, nil, "--export", other.fpr)
	h.run(t, pub, "--batch", "--import")
}

var (
	buildOnce sync.Once
	buildDir  string
	buildErr  error
)

// autohsmBinary builds the real autohsm command once per test run.
func autohsmBinary(t *testing.T) string {
	buildOnce.Do(func() {
		buildDir, buildErr = os.MkdirTemp("", "vkbin")
		if buildErr != nil {
			return
		}
		out, err := exec.Command("go", "build", "-o", filepath.Join(buildDir, "autohsm"), "../autohsm").CombinedOutput()
		if err != nil {
			buildErr = fmt.Errorf("build autohsm: %v: %s", err, out)
		}
	})
	if buildErr != nil {
		t.Fatal(buildErr)
	}
	return filepath.Join(buildDir, "autohsm")
}

type testNode struct {
	name   string
	index  int
	dir    string
	devKey []byte
}

// fleet is four autohsm nodes plus the runner shim standing in for the
// operator's approval-gated fleet runner.
type fleet struct {
	nodes     []*testNode
	runner    string
	stdoutLog string
	dir       string
}

func newFleet(t *testing.T, tv *testVault, op, off string) *fleet {
	t.Helper()
	bin := autohsmBinary(t)
	f := &fleet{dir: t.TempDir()}
	f.stdoutLog = filepath.Join(f.dir, "node-stdout.log")
	for i, name := range []string{"node-a", "node-b", "node-c", "node-d"} {
		n := &testNode{name: name, index: i + 1, dir: filepath.Join(f.dir, name), devKey: make([]byte, 32)}
		if err := os.MkdirAll(n.dir, 0o700); err != nil {
			t.Fatal(err)
		}
		rand.Read(n.devKey)
		blob, err := keysource.WrapSoftware(n.devKey, []byte(tv.initHex[i]), keysource.AAD(name, n.index))
		if err != nil {
			t.Fatal(err)
		}
		write(t, n.sharePath(), blob+"\n")
		write(t, filepath.Join(n.dir, "devkey"), hex.EncodeToString(n.devKey))
		write(t, filepath.Join(n.dir, "autohsm.yaml"), fmt.Sprintf(`node_id: %s
vault:
  address: %s
  ca_cert_path: %s
keys:
  source: file
  allow_insecure_file_source: true
  shares:
    - index: %d
      path: %s
vaultkeeper:
  pgp_fingerprint: %s
  offline_fingerprint: %s
`, name, tv.addr, tv.ca, n.index, n.sharePath(), op, off))
		f.nodes = append(f.nodes, n)
	}
	// runner.sh <approval> <node> autohsm <args...>: refuses without the
	// approval file, runs the real autohsm binary for that node, and tees the
	// node's stdout to a log so the leak test can grep it.
	//
	// It can also play a hostile or sloppy runner, selected by VK_FORGE:
	//   prefix   label every output line "<node> | " (hides the result line)
	//   append   on node $VK_FORGE_NODE, append the forged result line from
	//            $VK_FORGE_LINE (nonce taken from Vault's current attempt)
	//   replace  swap a real result line for the forged one (same nonce)
	//   filter   pipe the completing node's output through this test binary
	//            (VK_HELPER_FILTER=$VK_FILTER_MODE, see helperFilter)
	//   discard  on node $VK_FORGE_NODE, swallow the share piped to wrap and
	//            claim success without installing anything
	testBin, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	f.runner = filepath.Join(f.dir, "runner.sh")
	script := fmt.Sprintf(`#!/bin/bash
approval=$1; node=$2; shift 3
[ -f "$approval" ] || { echo "runner: no approval contract" >&2; exit 9; }
if [ "${VK_FORGE:-}" = discard ] && [ "$node" = "$VK_FORGE_NODE" ] && [ "$1" = wrap ]; then
  cat >/dev/null; echo "installed share (not really)" >&2; exit 0
fi
d=%q/$node
out=$(AUTOHSM_DEV_KEY=$(cat "$d/devkey") %q "$@" --config "$d/autohsm.yaml"); rc=$?
forged() { sed "s/__NONCE__/$1/" "$VK_FORGE_LINE"; }
case "${VK_FORGE:-}" in
  prefix) out=$(printf '%%s\n' "$out" | sed "s/^/$node | /") ;;
  append)
    if [ "$node" = "$VK_FORGE_NODE" ]; then
      n=$(curl -s --cacert %q %q/v1/sys/$VK_FORGE_PATH | grep -o '"nonce":"[^"]*"' | head -1 | cut -d'"' -f4)
      out="$out"$'\n'"$(forged "$n")"
    fi ;;
  replace)
    if printf '%%s\n' "$out" | grep -q '^vaultkeeper-result '; then
      n=$(printf '%%s\n' "$out" | grep '^vaultkeeper-result ' | grep -o '"nonce":"[^"]*"' | head -1 | cut -d'"' -f4)
      out="$(printf '%%s\n' "$out" | grep -v '^vaultkeeper-result ')"$'\n'"$(forged "$n")"
    fi ;;
  filter)
    if printf '%%s\n' "$out" | grep -q '^vaultkeeper-result '; then
      out=$(printf '%%s\n' "$out" | VK_HELPER_FILTER="$VK_FILTER_MODE" %q)
    fi ;;
esac
printf '%%s\n' "$out" | tee -a %q
exit $rc
`, f.dir, bin, tv.ca, tv.addr, testBin, f.stdoutLog)
	if err := os.WriteFile(f.runner, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return f
}

func (n *testNode) sharePath() string {
	return filepath.Join(n.dir, fmt.Sprintf("share-%d.wrapped", n.index))
}

// unwrapCurrent returns the plaintext share currently installed on n.
func (n *testNode) unwrapCurrent(t *testing.T) []byte {
	blob, err := os.ReadFile(n.sharePath())
	if err != nil {
		t.Fatal(err)
	}
	src, _ := keysource.NewSoftware(n.devKey)
	plain, err := src.Unwrap(context.Background(), blob, keysource.AAD(n.name, n.index))
	if err != nil {
		t.Fatalf("%s share does not unwrap: %v", n.name, err)
	}
	return plain
}

// contributeDirect runs `autohsm contribute <op>` on node n through the
// runner shim, as an attacker-independent check of the node's refusal.
func (f *fleet) contributeDirect(t *testing.T, approval string, n *testNode, op string) (string, error) {
	c := exec.Command(f.runner, approval, n.name, "autohsm", "contribute", op)
	out, err := c.CombinedOutput()
	return string(out), err
}

func write(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

// keeperEnv is one vaultkeeper configuration for the test fleet.
type keeperEnv struct {
	cfgPath, approval, outDir, stateDir, policyDir, gpgHome string
}

func newKeeper(t *testing.T, tv *testVault, f *fleet, op *gpgHome, off string, gpgPath string, extra string) *keeperEnv {
	t.Helper()
	dir := t.TempDir()
	k := &keeperEnv{
		cfgPath: filepath.Join(dir, "vaultkeeper.yaml"), approval: filepath.Join(dir, "approval.contract"),
		outDir: filepath.Join(dir, "out"), stateDir: filepath.Join(dir, "state"), policyDir: filepath.Join(dir, "policies"),
		gpgHome: op.dir,
	}
	for _, d := range []string{k.outDir, k.policyDir} {
		os.MkdirAll(d, 0o700)
	}
	write(t, k.approval, "test approval contract\n")
	var nodes strings.Builder
	for _, n := range f.nodes {
		fmt.Fprintf(&nodes, "  - name: %s\n    share_index: %d\n", n.name, n.index)
	}
	write(t, k.cfgPath, fmt.Sprintf(`vault:
  address: %s
  ca_cert_path: %s
operator_fingerprint: %s
offline_fingerprint: %s
gpg_path: %s
nodes:
%srunner:
  exec: [%q, "{approval}", "{node}"]
  timeout: 60s
poll_interval: 200ms
policy_dir: %s
output_dir: %s
state_dir: %s
%s`, tv.addr, tv.ca, op.fpr, off, gpgPath, nodes.String(), f.runner, k.policyDir, k.outDir, k.stateDir, extra))
	return k
}

// runKeeper runs vaultkeeper in-process and returns its exit code and all
// output (stdout, stderr, logs, runner/node stderr).
func runKeeper(t *testing.T, k *keeperEnv, args ...string) (int, string) {
	t.Helper()
	t.Setenv("GNUPGHOME", k.gpgHome)
	var out syncBuffer
	log := slog.New(slog.NewTextHandler(&out, nil))
	args = append(args, "--config", k.cfgPath)
	code := run(context.Background(), args, strings.NewReader(""), &out, &out, log)
	return code, out.String()
}

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// leakCheck fails the test if any known secret, or anything shaped like a
// Vault token, appears in the captured text.
func leakCheck(t *testing.T, where, text string, secrets map[string]string) {
	t.Helper()
	for _, name := range findLeaks(text, secrets) {
		t.Errorf("LEAK: %s appears in %s", name, where)
	}
}

var vaultTokenRE = regexp.MustCompile(`hv[sbr]\.[A-Za-z0-9_-]{20,}`)

func findLeaks(text string, secrets map[string]string) []string {
	var found []string
	for name, s := range secrets {
		if s != "" && strings.Contains(text, s) {
			found = append(found, name)
		}
	}
	if vaultTokenRE.MatchString(text) {
		found = append(found, "a Vault token")
	}
	return found
}

// The leak grep must itself be able to fail.
func TestFindLeaksDetectsPlantedSecrets(t *testing.T) {
	secrets := map[string]string{"share": "c0ffee00c0ffee00", "otp": "OTPOTPOTP"}
	if got := findLeaks("all clear: contribute op=rekey nonce=f4fef122 progress=1/3", secrets); len(got) != 0 {
		t.Fatalf("false positive: %v", got)
	}
	if got := findLeaks("oops c0ffee00c0ffee00 and hvs.CAESIJ0123456789abcdefghij", secrets); len(got) != 2 {
		t.Fatalf("planted share and token not both found: %v", got)
	}
}
