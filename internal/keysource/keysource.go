// Asset: keysource
// Purpose: Interface and wrapped-blob format for retrieving unseal key shares.
// Threats: Defines an AEAD envelope that binds every wrapped share to a specific
// configured node context and share index, preventing accidental relabeling and
// index substitution. The node label is not hardware identity. Does NOT protect
// a share once unwrapped in memory (see secure.Wipe)
// and does NOT prevent an attacker with live HSM access from unwrapping legitimately.
// Deps: none (stdlib only)
// Example: src, _ := keysource.OpenPKCS11(cfg); share, _ := src.Unwrap(ctx, blob, aad)
// Status: tested
// License: MIT
// Provenance: original
package keysource

import (
	"context"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
)

// envelopeVersion prefixes every wrapped blob so the format can evolve without
// ambiguity. A blob with an unknown version is rejected, never guessed at.
const envelopeVersion = "autohsm-v1"

const (
	gcmNonceLen = 12
	gcmTagLen   = 16
)

// Source unwraps a stored share into plaintext key material.
//
// Implementations must never log, cache, or copy the plaintext beyond what the
// caller receives. Callers must wipe the returned buffer.
type Source interface {
	// Unwrap decrypts blob, authenticating it against aad. It must return an
	// error (never partial or unauthenticated plaintext) if authentication fails.
	Unwrap(ctx context.Context, blob []byte, aad []byte) ([]byte, error)
	// Close releases any HSM session.
	Close() error
}

// HealthChecker is implemented by sources whose backing device can go away
// (an HSM). Health re-establishes a lost session when it can and reports
// whether the source is usable.
type HealthChecker interface {
	Health(ctx context.Context) error
}

// AAD builds the additional authenticated data binding a share to one node and
// index. Changing node or index changes the AAD, so the AEAD tag check fails.
// NodeID is a configuration label, not proof that code runs on a physical host.
func AAD(nodeID string, shareIndex int) []byte {
	return []byte(envelopeVersion + "|node=" + nodeID + "|idx=" + strconv.Itoa(shareIndex))
}

// Envelope is the on-disk representation of a wrapped share:
//
//	autohsm-v1.<base64(nonce)>.<base64(ciphertext||tag)>
//
// It carries no secret material of its own; without the HSM key it is inert.
type Envelope struct {
	Nonce      []byte
	Ciphertext []byte
}

// MarshalEnvelope renders an envelope to its on-disk text form.
func MarshalEnvelope(e Envelope) string {
	return envelopeVersion + "." +
		base64.RawStdEncoding.EncodeToString(e.Nonce) + "." +
		base64.RawStdEncoding.EncodeToString(e.Ciphertext)
}

// ParseEnvelope parses the on-disk form, failing closed on anything malformed.
func ParseEnvelope(raw []byte) (Envelope, error) {
	s := strings.TrimSpace(string(raw))
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return Envelope{}, fmt.Errorf("malformed envelope: expected 3 dot-separated fields, got %d", len(parts))
	}
	if parts[0] != envelopeVersion {
		return Envelope{}, fmt.Errorf("unsupported envelope version %q (want %q)", parts[0], envelopeVersion)
	}
	nonce, err := base64.RawStdEncoding.DecodeString(parts[1])
	if err != nil {
		return Envelope{}, fmt.Errorf("decode nonce: %w", err)
	}
	ct, err := base64.RawStdEncoding.DecodeString(parts[2])
	if err != nil {
		return Envelope{}, fmt.Errorf("decode ciphertext: %w", err)
	}
	if len(nonce) != gcmNonceLen {
		return Envelope{}, fmt.Errorf("envelope nonce is %d bytes, require %d", len(nonce), gcmNonceLen)
	}
	if len(ct) <= gcmTagLen {
		return Envelope{}, fmt.Errorf("envelope ciphertext is too short")
	}
	return Envelope{Nonce: nonce, Ciphertext: ct}, nil
}
