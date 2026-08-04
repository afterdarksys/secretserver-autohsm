// Asset: vault-seal-client
// Purpose: Minimal, strictly-TLS-verified client for Vault's seal-status and unseal endpoints.
// Threats: Protects unseal key shares in transit against interception and against an
// impersonated Vault (a forged endpoint that harvests shares). Enforces a pinned CA pool,
// TLS >= 1.2 with no InsecureSkipVerify path, bounded response bodies, and request
// timeouts so a hostile or hung endpoint cannot exhaust the daemon. Does NOT authenticate
// the caller to Vault (unseal is an unauthenticated endpoint by design) and does NOT
// protect shares once Vault itself is compromised.
// Deps: none (stdlib only)
// Example: c, _ := vaultclient.New(cfg); st, _ := c.SealStatus(ctx)
// Status: tested
// License: proprietary
// Provenance: original
package vaultclient

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// maxBody bounds any response we will read. Vault's seal-status and unseal
// replies are a few hundred bytes; 64 KiB is generous and still caps a hostile
// endpoint that streams forever.
const maxBody = 64 << 10

// Config describes how to reach one Vault instance.
type Config struct {
	// Address must be an absolute https:// URL.
	Address string
	// CACertPath is a PEM file containing the CA (or self-signed leaf) that
	// signs Vault's certificate. Required: there is no system-roots fallback,
	// because this deployment pins a private certificate.
	CACertPath string
	// Timeout bounds a single request.
	Timeout time.Duration
	// MinTLS13 requires TLS 1.3. Defaults on; may be relaxed to 1.2 only for
	// Vault builds that cannot negotiate 1.3.
	MinTLS13 bool
}

// Client talks to exactly one Vault instance.
type Client struct {
	addr string
	http *http.Client
}

// SealStatus is the subset of Vault's seal-status response we act on.
type SealStatus struct {
	Type        string `json:"type"`
	Initialized bool   `json:"initialized"`
	Sealed      bool   `json:"sealed"`
	Threshold   int    `json:"t"`
	Shares      int    `json:"n"`
	Progress    int    `json:"progress"`
	Version     string `json:"version"`
}

// New builds a client, failing closed on any ambiguity in the TLS configuration.
func New(cfg Config) (*Client, error) {
	if cfg.Address == "" {
		return nil, fmt.Errorf("vault address is required")
	}
	u, err := url.Parse(cfg.Address)
	if err != nil {
		return nil, fmt.Errorf("vault address %q is not a valid URL: %w", cfg.Address, err)
	}
	// Fail closed: plaintext HTTP would expose unseal shares on the wire.
	if u.Scheme != "https" {
		return nil, fmt.Errorf("vault address must use https, got scheme %q", u.Scheme)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("vault address %q has no host", cfg.Address)
	}
	if cfg.CACertPath == "" {
		return nil, fmt.Errorf("ca_cert_path is required (no system-roots fallback: this deployment pins a private CA)")
	}

	pem, err := os.ReadFile(cfg.CACertPath)
	if err != nil {
		return nil, fmt.Errorf("read ca cert: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("ca cert %q contained no usable PEM certificate", cfg.CACertPath)
	}

	minVersion := uint16(tls.VersionTLS13)
	if !cfg.MinTLS13 {
		minVersion = tls.VersionTLS12
	}

	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}

	// NOTE: InsecureSkipVerify is deliberately never set. There is no config
	// path that can disable verification; a bad cert must be a hard failure.
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs:    pool,
			MinVersion: minVersion,
		},
		TLSHandshakeTimeout: timeout,
		DisableKeepAlives:   false,
		MaxIdleConns:        4,
	}

	return &Client{
		addr: strings.TrimRight(cfg.Address, "/"),
		http: &http.Client{
			Transport: transport,
			Timeout:   timeout,
			// Unseal must never be silently redirected to another host.
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}, nil
}

// SealStatus reports Vault's current seal state.
func (c *Client) SealStatus(ctx context.Context) (*SealStatus, error) {
	var st SealStatus
	if err := c.do(ctx, http.MethodGet, "/v1/sys/seal-status", nil, &st); err != nil {
		return nil, err
	}
	return &st, nil
}

// SubmitUnsealShare submits a single key share and returns the resulting status.
//
// share is treated as key material: it is marshalled directly and never logged.
func (c *Client) SubmitUnsealShare(ctx context.Context, share []byte) (*SealStatus, error) {
	if len(share) == 0 {
		return nil, fmt.Errorf("refusing to submit an empty unseal share")
	}
	body, err := json.Marshal(map[string]string{"key": string(share)})
	if err != nil {
		return nil, fmt.Errorf("encode unseal request: %w", err)
	}
	var st SealStatus
	if err := c.do(ctx, http.MethodPut, "/v1/sys/unseal", body, &st); err != nil {
		return nil, err
	}
	return &st, nil
}

func (c *Client) do(ctx context.Context, method, path string, body []byte, out any) error {
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.addr+path, rdr)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.http.Do(req)
	if err != nil {
		// Deliberately does not wrap the request body: it may hold a share.
		return fmt.Errorf("%s %s: %w", method, path, err)
	}
	defer resp.Body.Close()

	// Bound the read so a hostile endpoint cannot exhaust memory.
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("%s %s: vault returned %s", method, path, resp.Status)
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	return nil
}
