// Asset: keysource-software
// Purpose: AES-256-GCM software key source — development and test only, never production.
// Threats: Exercises the exact envelope and AAD binding the HSM path uses, so the
// authentication properties can be tested without a token present. Provides NO
// hardware protection: the wrapping key lives in process memory and (typically) in an
// environment variable, so anyone who can read the host can unwrap every share. It is
// gated behind an explicit opt-in in config for exactly this reason.
// Deps: none (stdlib only)
// Example: src, _ := keysource.NewSoftware(key); share, _ := src.Unwrap(ctx, blob, aad)
// Status: tested
// License: proprietary
// Provenance: original
package keysource

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
)

// softwareKeyLen is fixed at 32 bytes: AES-256 only, no negotiable key sizes.
const softwareKeyLen = 32

type softwareSource struct {
	aead cipher.AEAD
}

// NewSoftware builds a development key source from a 32-byte key.
func NewSoftware(key []byte) (Source, error) {
	if len(key) != softwareKeyLen {
		return nil, fmt.Errorf("software key must be %d bytes (AES-256), got %d", softwareKeyLen, len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("gcm: %w", err)
	}
	return &softwareSource{aead: aead}, nil
}

// Unwrap authenticates and decrypts blob. A tampered ciphertext, a wrong key, or
// mismatched AAD (wrong node or share index) all fail here with no plaintext returned.
func (s *softwareSource) Unwrap(_ context.Context, blob []byte, aad []byte) ([]byte, error) {
	env, err := ParseEnvelope(blob)
	if err != nil {
		return nil, err
	}
	if len(env.Nonce) != s.aead.NonceSize() {
		return nil, fmt.Errorf("nonce is %d bytes, want %d", len(env.Nonce), s.aead.NonceSize())
	}
	plain, err := s.aead.Open(nil, env.Nonce, env.Ciphertext, aad)
	if err != nil {
		// Deliberately opaque: do not reveal whether the key or the AAD was wrong.
		return nil, fmt.Errorf("unwrap failed: share is not authentic for this node and index")
	}
	return plain, nil
}

func (s *softwareSource) Close() error { return nil }

// WrapSoftware produces an envelope for provisioning in development.
// The nonce comes from crypto/rand: never a counter, never time-derived.
func WrapSoftware(key, plaintext, aad []byte) (string, error) {
	if len(plaintext) == 0 {
		return "", fmt.Errorf("refusing to wrap an empty share")
	}
	src, err := NewSoftware(key)
	if err != nil {
		return "", err
	}
	s := src.(*softwareSource)

	nonce := make([]byte, s.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("generate nonce: %w", err)
	}
	ct := s.aead.Seal(nil, nonce, plaintext, aad)
	return MarshalEnvelope(Envelope{Nonce: nonce, Ciphertext: ct}), nil
}
