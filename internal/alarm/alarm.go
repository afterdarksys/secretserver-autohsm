// Asset: autohsm-alarm
// Purpose: Report a sealed Vault to a webhook so the condition is never silent.
// Threats: Addresses the failure mode that matters most operationally — a sealed Vault
// going unnoticed. Sends only non-secret state (sealed, threshold, progress, node id);
// never key material. Bounds its own behaviour with a timeout and https-only (TLS 1.3) delivery so
// a hung or hostile receiver cannot stall the unseal loop or observe traffic in cleartext.
// Does NOT guarantee delivery: a webhook is best-effort notification, not a substitute for
// an external monitor polling seal-status independently.
// Deps: none (stdlib only)
// Example: a := alarm.New(cfg); a.SealedDetected(ctx, "node-a", status)
// Status: tested
// License: MIT
// Provenance: original
package alarm

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"time"
)

// Notifier posts sealed-state alarms to a webhook.
type Notifier struct {
	url    string
	client *http.Client
	log    *slog.Logger
}

// Payload is the alarm body. Every field is non-secret by construction.
type Payload struct {
	Event     string `json:"event"`
	NodeID    string `json:"node_id"`
	Sealed    bool   `json:"sealed"`
	Threshold int    `json:"threshold"`
	Shares    int    `json:"shares"`
	Progress  int    `json:"progress"`
	// Error is set for vault_unreachable, autohsm_failed, hsm_unavailable and
	// shares_stale events. It carries an error
	// chain built entirely from fmt.Errorf wrapping in this codebase, never
	// key material.
	Error string `json:"error,omitempty"`
	// Op, Nonce and Detail describe vaultkeeper ceremony events. Nonce is at
	// most the first 8 characters of a ceremony nonce, which Vault publishes
	// on an unauthenticated endpoint anyway. None of these ever carry a share,
	// an OTP, or a token.
	Op        string `json:"op,omitempty"`
	Nonce     string `json:"nonce,omitempty"`
	Detail    string `json:"detail,omitempty"`
	Timestamp string `json:"timestamp"`
}

// New builds a notifier. An empty url yields a no-op notifier so callers do not
// need to branch. https is required: alarms traverse the network.
func New(rawURL string, log *slog.Logger) (*Notifier, error) {
	if rawURL == "" {
		return &Notifier{log: log}, nil
	}
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
		return nil, fmt.Errorf("alarm webhook must be an https URL without userinfo, got %q", rawURL)
	}
	return &Notifier{
		url: rawURL,
		client: &http.Client{
			Transport: tls13Transport(nil),
			Timeout:   5 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		log: log,
	}, nil
}

// NewWithClient is New with a caller-supplied HTTP client, for a receiver
// behind a private CA. The https-only URL rule and the no-redirect policy
// still apply.
func NewWithClient(rawURL string, client *http.Client, log *slog.Logger) (*Notifier, error) {
	n, err := New(rawURL, log)
	if err != nil || n.url == "" || client == nil {
		return n, err
	}
	c := *client
	c.CheckRedirect = n.client.CheckRedirect
	switch tr := client.Transport.(type) {
	case nil:
		c.Transport = tls13Transport(nil)
	case *http.Transport:
		c.Transport = tls13Transport(tr)
	default:
		return nil, fmt.Errorf("alarm client transport must be an *http.Transport (TLS 1.3 is enforced on it)")
	}
	if c.Timeout == 0 || c.Timeout > n.client.Timeout {
		c.Timeout = n.client.Timeout
	}
	n.client = &c
	return n, nil
}

// tls13Transport returns a clone of base (or of the default transport) that
// refuses anything below TLS 1.3. Alarms carry no secrets, but they are the
// signal that something is wrong; they should not be downgradable.
func tls13Transport(base *http.Transport) *http.Transport {
	if base == nil {
		base = http.DefaultTransport.(*http.Transport)
	}
	t := base.Clone()
	if t.TLSClientConfig == nil {
		t.TLSClientConfig = &tls.Config{}
	}
	t.TLSClientConfig.MinVersion = tls.VersionTLS13
	return t
}

// SealedDetected fires the alarm. Failures are logged, never fatal: an
// unreachable webhook must not stop the daemon from unsealing.
func (n *Notifier) SealedDetected(ctx context.Context, nodeID string, sealed bool, threshold, shares, progress int) {
	n.post(ctx, Payload{
		Event:     "vault_sealed",
		NodeID:    nodeID,
		Sealed:    sealed,
		Threshold: threshold,
		Shares:    shares,
		Progress:  progress,
	})
}

// VaultUnreachable fires the alarm when a seal-status poll itself fails. A
// Vault the daemon cannot reach is exactly as dangerous as one observed
// sealed -- silently retrying forever without ever alerting anyone would
// repeat the "sealed Vault goes unnoticed" failure this package exists to
// prevent, just one layer earlier.
func (n *Notifier) VaultUnreachable(ctx context.Context, nodeID string, pollErr error) {
	n.post(ctx, Payload{
		Event:  "vault_unreachable",
		NodeID: nodeID,
		Error:  pollErr.Error(),
	})
}

// DaemonFailed fires when the watch daemon is about to exit on an error: the
// HSM could not be opened, the PIN was rejected, shares failed to unwrap until
// the retry budget ran out, or the share layout is unsafe. Once the daemon
// exits nothing else will report a sealed Vault, so the last word must be an
// alarm rather than silence.
func (n *Notifier) DaemonFailed(ctx context.Context, nodeID string, err error) {
	n.post(ctx, Payload{
		Event:  "autohsm_failed",
		NodeID: nodeID,
		Error:  err.Error(),
	})
}

// HSMUnavailable fires once when the HSM session is lost and cannot be
// re-established. The daemon keeps retrying with backoff; it does not
// consume the unseal failure budget while the HSM is down.
func (n *Notifier) HSMUnavailable(ctx context.Context, nodeID string, err error) {
	n.post(ctx, Payload{Event: "hsm_unavailable", NodeID: nodeID, Error: err.Error()})
}

// HSMRecovered fires when a lost HSM session has been re-established.
func (n *Notifier) HSMRecovered(ctx context.Context, nodeID string) {
	n.post(ctx, Payload{Event: "hsm_recovered", NodeID: nodeID})
}

// SharesStale fires when Vault rejects the unseal key material itself (for
// example shares from before a re-initialisation). The daemon stops
// submitting until restarted and repeats this alarm with backoff while Vault
// stays sealed, instead of a vault_sealed alarm on every poll.
func (n *Notifier) SharesStale(ctx context.Context, nodeID string, sealed bool, threshold, shares, progress int, err error) {
	n.post(ctx, Payload{
		Event: "shares_stale", NodeID: nodeID, Sealed: sealed,
		Threshold: threshold, Shares: shares, Progress: progress, Error: err.Error(),
	})
}

// Contributed fires after a node submits its share to a vaultkeeper ceremony.
func (n *Notifier) Contributed(ctx context.Context, nodeID, op, nonce8 string, progress, required int) {
	n.post(ctx, Payload{
		Event: "contribute", NodeID: nodeID, Op: op, Nonce: nonce8,
		Progress: progress, Threshold: required,
	})
}

// ContributeRefused fires when a node refuses a ceremony attempt (no attempt,
// OTP attempt, unpinned key, wrong shape). A refusal nobody expected is the
// signature of someone else trying to harvest shares.
func (n *Notifier) ContributeRefused(ctx context.Context, nodeID, op string, reason error) {
	n.post(ctx, Payload{Event: "contribute_refused", NodeID: nodeID, Op: op, Error: reason.Error()})
}

// Event posts a vaultkeeper event (for example vaultkeeper_foreign_attempt or
// vaultkeeper_keyring_rotated). detail must be non-secret.
func (n *Notifier) Event(ctx context.Context, event, source, detail string) {
	n.post(ctx, Payload{Event: event, NodeID: source, Detail: detail})
}

func (n *Notifier) post(ctx context.Context, p Payload) {
	if n.url == "" {
		return
	}
	p.Timestamp = time.Now().UTC().Format(time.RFC3339)
	body, err := json.Marshal(p)
	if err != nil {
		return
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, n.url, bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := n.client.Do(req)
	if err != nil {
		if n.log != nil {
			n.log.Warn("alarm webhook failed", "error", err)
		}
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 && n.log != nil {
		n.log.Warn("alarm webhook returned non-2xx", "status", resp.Status)
	}
}
