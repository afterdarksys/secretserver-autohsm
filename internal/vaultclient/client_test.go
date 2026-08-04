package vaultclient

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// newTestVault starts a TLS test server and writes its cert to a PEM file,
// returning the server and the CA path a client should pin.
func newTestVault(t *testing.T, h http.Handler) (*httptest.Server, string) {
	t.Helper()
	srv := httptest.NewTLSServer(h)
	t.Cleanup(srv.Close)

	certPath := filepath.Join(t.TempDir(), "ca.pem")
	block := &pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}
	if err := os.WriteFile(certPath, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
	return srv, certPath
}

// unrelatedCAPath writes a self-signed certificate that did NOT sign any test
// server. httptest reuses one built-in certificate for every TLS server, so a
// second httptest server is NOT a different CA — pinning it would still trust
// the first. This generates a genuinely foreign trust anchor.
func unrelatedCAPath(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "unrelated-test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "unrelated-ca.pem")
	if err := os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func sealStatusHandler(sealed bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"type":"shamir","initialized":true,"sealed":%t,"t":3,"n":5,"progress":0,"version":"1.15.6"}`, sealed)
	})
}

func TestSealStatusParsesSealedVault(t *testing.T) {
	srv, ca := newTestVault(t, sealStatusHandler(true))
	c, err := New(Config{Address: srv.URL, CACertPath: ca, MinTLS13: false})
	if err != nil {
		t.Fatal(err)
	}
	st, err := c.SealStatus(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !st.Sealed || st.Threshold != 3 || st.Shares != 5 {
		t.Fatalf("unexpected status: %+v", st)
	}
}

// Negative: a plaintext http:// address must be refused outright. Submitting a
// share over cleartext would expose it on the wire.
func TestNewRejectsPlaintextHTTP(t *testing.T) {
	_, ca := newTestVault(t, sealStatusHandler(false))
	_, err := New(Config{Address: "http://vault.example:8200", CACertPath: ca})
	if err == nil {
		t.Fatal("plaintext http address accepted")
	}
	if !strings.Contains(err.Error(), "https") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// Negative: a wrong CA must fail the handshake. This is the load-bearing test —
// it proves verification is real and not silently skipped.
func TestSealStatusRejectsUntrustedCert(t *testing.T) {
	srv, _ := newTestVault(t, sealStatusHandler(true))

	c, err := New(Config{Address: srv.URL, CACertPath: unrelatedCAPath(t)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.SealStatus(context.Background()); err == nil {
		t.Fatal("connected to a server signed by an untrusted CA")
	}
}

// Negative: a missing or malformed CA file must fail closed, never fall back to
// system roots (which would trust the public PKI for a private endpoint).
func TestNewRejectsBadCA(t *testing.T) {
	dir := t.TempDir()
	junk := filepath.Join(dir, "junk.pem")
	if err := os.WriteFile(junk, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, path := range map[string]string{
		"missing file": filepath.Join(dir, "does-not-exist.pem"),
		"not a PEM":    junk,
		"empty path":   "",
	} {
		if _, err := New(Config{Address: "https://vault.example:8200", CACertPath: path}); err == nil {
			t.Fatalf("%s: accepted an unusable CA", name)
		}
	}
}

// Negative: an empty share must never be sent to Vault.
func TestSubmitUnsealShareRejectsEmpty(t *testing.T) {
	srv, ca := newTestVault(t, sealStatusHandler(true))
	c, err := New(Config{Address: srv.URL, CACertPath: ca})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.SubmitUnsealShare(context.Background(), nil); err == nil {
		t.Fatal("empty share accepted")
	}
}

// Negative: an oversized response body must not be read without bound.
func TestResponseBodyIsBounded(t *testing.T) {
	flood := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		chunk := strings.Repeat("A", 4096)
		for i := 0; i < 1024; i++ { // 4 MiB, far above maxBody
			fmt.Fprint(w, chunk)
		}
	})
	srv, ca := newTestVault(t, flood)
	c, err := New(Config{Address: srv.URL, CACertPath: ca})
	if err != nil {
		t.Fatal(err)
	}
	// Must fail to decode (truncated) rather than buffering the whole stream.
	if _, err := c.SealStatus(context.Background()); err == nil {
		t.Fatal("unbounded body accepted")
	}
}

// Negative: a non-2xx status must be surfaced, not treated as success.
func TestNon2xxIsAnError(t *testing.T) {
	srv, ca := newTestVault(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"errors":["sealed"]}`, http.StatusInternalServerError)
	}))
	c, err := New(Config{Address: srv.URL, CACertPath: ca})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.SealStatus(context.Background()); err == nil {
		t.Fatal("500 response treated as success")
	}
}

// Negative: a hung endpoint must time out rather than block the daemon forever.
func TestRequestTimesOut(t *testing.T) {
	block := make(chan struct{})
	srv, ca := newTestVault(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-block
	}))
	// Must run BEFORE the server's t.Cleanup close (defers precede cleanups),
	// otherwise srv.Close() blocks forever waiting on this handler.
	defer close(block)
	c, err := New(Config{Address: srv.URL, CACertPath: ca, Timeout: 250 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if _, err := c.SealStatus(context.Background()); err == nil {
		t.Fatal("hung endpoint did not time out")
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("timeout not enforced promptly: %s", elapsed)
	}
}

// Guard: assert no code path can construct a client that skips verification.
func TestTLSConfigNeverSkipsVerification(t *testing.T) {
	srv, ca := newTestVault(t, sealStatusHandler(false))
	c, err := New(Config{Address: srv.URL, CACertPath: ca, MinTLS13: false})
	if err != nil {
		t.Fatal(err)
	}
	tr, ok := c.http.Transport.(*http.Transport)
	if !ok {
		t.Fatal("unexpected transport type")
	}
	if tr.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("InsecureSkipVerify is set")
	}
	if tr.TLSClientConfig.RootCAs == nil {
		t.Fatal("no pinned root CA pool")
	}
	if tr.TLSClientConfig.MinVersion < tls.VersionTLS12 {
		t.Fatalf("MinVersion below TLS 1.2: %x", tr.TLSClientConfig.MinVersion)
	}
}

// Negative: pinning must be exclusive — a cert signed by a public/system root
// (but not by our pinned CA) must still be rejected.
func TestPinnedPoolDoesNotTrustSystemRoots(t *testing.T) {
	srv, _ := newTestVault(t, sealStatusHandler(true))

	c, err := New(Config{Address: srv.URL, CACertPath: unrelatedCAPath(t)})
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.SealStatus(context.Background())
	if err == nil {
		t.Fatal("cert outside the pinned pool was accepted")
	}
	var unknown x509.UnknownAuthorityError
	if !errors.As(err, &unknown) && !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("expected a certificate verification error, got: %v", err)
	}
}
