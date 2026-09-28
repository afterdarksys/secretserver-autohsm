// Asset: fingerprint
// Purpose: SHA-256 fingerprints so secrets can be referenced in logs without disclosure.
// Threats: Prevents unseal key shares, Vault tokens, and wrapped blobs from being
// written to logs in recoverable form, while still allowing operators to correlate
// "which share" across hosts. Does NOT make a low-entropy secret safe to fingerprint
// (a short or guessable value remains brute-forceable from its digest), and does NOT
// authenticate anything.
// Deps: none
// Example: log.Printf("share %s unwrapped", fingerprint.Of(share))
// Status: tested
// License: MIT
// Provenance: original
package fingerprint

import (
	"crypto/sha256"
	"encoding/hex"
)

// truncatedLen is how many hex characters of the digest are emitted. 16 hex
// chars (64 bits) is ample to correlate entries without widening the surface.
const truncatedLen = 16

// Of returns a short, stable, non-reversible fingerprint of b, suitable for logs.
// The empty input is reported explicitly rather than as a digest, so that an
// accidentally-empty secret is visible in logs instead of looking legitimate.
func Of(b []byte) string {
	if len(b) == 0 {
		return "sha256:<empty>"
	}
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])[:truncatedLen]
}

// OfString is Of for values that are already strings (config identifiers,
// Vault addresses). Do not use it for key material: strings cannot be wiped.
func OfString(s string) string {
	return Of([]byte(s))
}
