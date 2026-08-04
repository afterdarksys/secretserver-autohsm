// Asset: autohsm-alarm
// Purpose: Report a sealed Vault to a webhook so the condition is never silent.
// Threats: Addresses the failure mode that matters most operationally — a sealed Vault
// going unnoticed. Sends only non-secret state (sealed, threshold, progress, node id);
// never key material. Bounds its own behaviour with a timeout and https-only delivery so
// a hung or hostile receiver cannot stall the unseal loop or observe traffic in cleartext.
// Does NOT guarantee delivery: a webhook is best-effort notification, not a substitute for
// an external monitor polling seal-status independently.
// Deps: none (stdlib only)
// Example: a := alarm.New(cfg); a.SealedDetected(ctx, "apps2", status)
// Status: tested
// License: proprietary
// Provenance: original
package alarm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
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
	Timestamp string `json:"timestamp"`
}

// New builds a notifier. An empty url yields a no-op notifier so callers do not
// need to branch. https is required: alarms traverse the network.
func New(url string, log *slog.Logger) (*Notifier, error) {
	if url == "" {
		return &Notifier{log: log}, nil
	}
	if !strings.HasPrefix(url, "https://") {
		return nil, fmt.Errorf("alarm webhook must be https, got %q", url)
	}
	return &Notifier{
		url:    url,
		client: &http.Client{Timeout: 5 * time.Second},
		log:    log,
	}, nil
}

// SealedDetected fires the alarm. Failures are logged, never fatal: an
// unreachable webhook must not stop the daemon from unsealing.
func (n *Notifier) SealedDetected(ctx context.Context, nodeID string, sealed bool, threshold, shares, progress int) {
	if n.url == "" {
		return
	}
	body, err := json.Marshal(Payload{
		Event:     "vault_sealed",
		NodeID:    nodeID,
		Sealed:    sealed,
		Threshold: threshold,
		Shares:    shares,
		Progress:  progress,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	})
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
