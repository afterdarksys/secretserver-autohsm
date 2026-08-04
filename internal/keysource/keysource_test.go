package keysource

import (
	"bytes"
	"context"
	"crypto/rand"
	"io"
	"strings"
	"testing"
)

func testKey(t *testing.T) []byte {
	t.Helper()
	k := make([]byte, softwareKeyLen)
	if _, err := io.ReadFull(rand.Reader, k); err != nil {
		t.Fatal(err)
	}
	return k
}

func TestWrapUnwrapRoundTrip(t *testing.T) {
	key := testKey(t)
	share := []byte("bXktdW5zZWFsLWtleS1zaGFyZQ")
	aad := AAD("apps2", 1)

	blob, err := WrapSoftware(key, share, aad)
	if err != nil {
		t.Fatal(err)
	}
	src, err := NewSoftware(key)
	if err != nil {
		t.Fatal(err)
	}
	got, err := src.Unwrap(context.Background(), []byte(blob), aad)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, share) {
		t.Fatal("round-trip produced different plaintext")
	}
}

// Negative: the wrapped blob must not contain the plaintext share.
func TestWrappedBlobDoesNotLeakPlaintext(t *testing.T) {
	key := testKey(t)
	share := []byte("SUPER-SECRET-SHARE-VALUE")
	blob, err := WrapSoftware(key, share, AAD("apps2", 1))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(blob, string(share)) {
		t.Fatal("wrapped blob contains the plaintext share")
	}
}

// Negative: THE load-bearing property. A share wrapped for one node must not
// unwrap on another, even with the identical wrapping key.
func TestUnwrapRejectsWrongNode(t *testing.T) {
	key := testKey(t)
	blob, err := WrapSoftware(key, []byte("share-1"), AAD("apps2", 1))
	if err != nil {
		t.Fatal(err)
	}
	src, _ := NewSoftware(key)
	if _, err := src.Unwrap(context.Background(), []byte(blob), AAD("dr1", 1)); err == nil {
		t.Fatal("share wrapped for apps2 was unwrapped as dr1")
	}
}

// Negative: a share must not be replayable under a different index.
func TestUnwrapRejectsWrongIndex(t *testing.T) {
	key := testKey(t)
	blob, err := WrapSoftware(key, []byte("share-1"), AAD("apps2", 1))
	if err != nil {
		t.Fatal(err)
	}
	src, _ := NewSoftware(key)
	if _, err := src.Unwrap(context.Background(), []byte(blob), AAD("apps2", 2)); err == nil {
		t.Fatal("share wrapped at index 1 was unwrapped at index 2")
	}
}

// Negative: a different wrapping key must not unwrap the share.
func TestUnwrapRejectsWrongKey(t *testing.T) {
	blob, err := WrapSoftware(testKey(t), []byte("share-1"), AAD("apps2", 1))
	if err != nil {
		t.Fatal(err)
	}
	other, _ := NewSoftware(testKey(t))
	if _, err := other.Unwrap(context.Background(), []byte(blob), AAD("apps2", 1)); err == nil {
		t.Fatal("share unwrapped with the wrong key")
	}
}

// Negative: tampering with any byte of the ciphertext must be detected.
func TestUnwrapRejectsTamperedCiphertext(t *testing.T) {
	key := testKey(t)
	aad := AAD("apps2", 1)
	blob, err := WrapSoftware(key, []byte("share-1"), aad)
	if err != nil {
		t.Fatal(err)
	}
	env, err := ParseEnvelope([]byte(blob))
	if err != nil {
		t.Fatal(err)
	}
	env.Ciphertext[0] ^= 0xFF
	src, _ := NewSoftware(key)
	if _, err := src.Unwrap(context.Background(), []byte(MarshalEnvelope(env)), aad); err == nil {
		t.Fatal("tampered ciphertext accepted")
	}
}

// Negative: malformed envelopes must fail closed, not panic or half-parse.
func TestParseEnvelopeRejectsMalformed(t *testing.T) {
	cases := map[string]string{
		"empty":             "",
		"too few fields":    "autohsm-v1.abcd",
		"too many fields":   "autohsm-v1.a.b.c",
		"bad version":       "autohsm-v9.YWJj.YWJj",
		"bad base64 nonce":  "autohsm-v1.!!!!.YWJj",
		"bad base64 cipher": "autohsm-v1.YWJj.!!!!",
		"empty parts":       "autohsm-v1..",
	}
	for name, raw := range cases {
		if _, err := ParseEnvelope([]byte(raw)); err == nil {
			t.Fatalf("%s: malformed envelope accepted", name)
		}
	}
}

// Negative: wrong key sizes must be refused rather than silently padded.
func TestNewSoftwareRejectsBadKeySize(t *testing.T) {
	for _, n := range []int{0, 1, 16, 24, 31, 33, 64} {
		if _, err := NewSoftware(make([]byte, n)); err == nil {
			t.Fatalf("accepted a %d-byte key", n)
		}
	}
}

// Negative: refuse to wrap nothing — an empty share would unseal nothing and
// would look like a working configuration.
func TestWrapRejectsEmptyShare(t *testing.T) {
	if _, err := WrapSoftware(testKey(t), nil, AAD("apps2", 1)); err == nil {
		t.Fatal("empty share wrapped")
	}
}

// Nonces must never repeat across wraps of identical plaintext.
func TestWrapUsesFreshNonce(t *testing.T) {
	key := testKey(t)
	aad := AAD("apps2", 1)
	seen := map[string]bool{}
	for i := 0; i < 50; i++ {
		blob, err := WrapSoftware(key, []byte("same-share"), aad)
		if err != nil {
			t.Fatal(err)
		}
		env, err := ParseEnvelope([]byte(blob))
		if err != nil {
			t.Fatal(err)
		}
		n := string(env.Nonce)
		if seen[n] {
			t.Fatal("nonce reused across wraps")
		}
		seen[n] = true
	}
}
