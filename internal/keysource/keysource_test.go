package keysource

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/miekg/pkcs11"
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

func TestParseEnvelopeRejectsWrongNonceAndShortCiphertext(t *testing.T) {
	for name, env := range map[string]Envelope{
		"short nonce":      {Nonce: make([]byte, 11), Ciphertext: make([]byte, 17)},
		"long nonce":       {Nonce: make([]byte, 13), Ciphertext: make([]byte, 17)},
		"tag only":         {Nonce: make([]byte, 12), Ciphertext: make([]byte, 16)},
		"short ciphertext": {Nonce: make([]byte, 12), Ciphertext: make([]byte, 15)},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseEnvelope([]byte(MarshalEnvelope(env))); err == nil {
				t.Fatal("invalid envelope accepted")
			}
		})
	}
}

func secureKeyAttrs() []*pkcs11.Attribute {
	return []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_VALUE_LEN, uint(32)),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false),
		pkcs11.NewAttribute(pkcs11.CKA_ALWAYS_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_NEVER_EXTRACTABLE, true),
		pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, true),
	}
}

func TestValidateSecretKeyAttributes(t *testing.T) {
	if err := validateSecretKeyAttributes(secureKeyAttrs()); err != nil {
		t.Fatalf("secure AES-256 key rejected: %v", err)
	}

	for name, typ := range map[string]uint{
		"not sensitive":          pkcs11.CKA_SENSITIVE,
		"extractable":            pkcs11.CKA_EXTRACTABLE,
		"not always sensitive":   pkcs11.CKA_ALWAYS_SENSITIVE,
		"previously extractable": pkcs11.CKA_NEVER_EXTRACTABLE,
		"cannot encrypt":         pkcs11.CKA_ENCRYPT,
		"cannot decrypt":         pkcs11.CKA_DECRYPT,
	} {
		t.Run(name, func(t *testing.T) {
			attrs := secureKeyAttrs()
			for _, attr := range attrs {
				if attr.Type == typ {
					attr.Value = []byte{1 - attr.Value[0]}
				}
			}
			if err := validateSecretKeyAttributes(attrs); err == nil {
				t.Fatal("unsafe key attributes accepted")
			}
		})
	}

	attrs := secureKeyAttrs()
	attrs[0] = pkcs11.NewAttribute(pkcs11.CKA_VALUE_LEN, uint(16))
	if err := validateSecretKeyAttributes(attrs); err == nil {
		t.Fatal("AES-128 key accepted")
	}
}

func TestValidateGCMMechanism(t *testing.T) {
	good := pkcs11.MechanismInfo{MinKeySize: 16, MaxKeySize: 32, Flags: pkcs11.CKF_ENCRYPT | pkcs11.CKF_DECRYPT}
	if err := validateGCMMechanism(good); err != nil {
		t.Fatalf("usable AES-GCM mechanism rejected: %v", err)
	}
	for _, bad := range []pkcs11.MechanismInfo{
		{MinKeySize: 16, MaxKeySize: 32, Flags: pkcs11.CKF_ENCRYPT},
		{MinKeySize: 16, MaxKeySize: 24, Flags: pkcs11.CKF_ENCRYPT | pkcs11.CKF_DECRYPT},
		{MinKeySize: 64, MaxKeySize: 64, Flags: pkcs11.CKF_ENCRYPT | pkcs11.CKF_DECRYPT},
	} {
		if err := validateGCMMechanism(bad); err == nil {
			t.Fatalf("unsafe mechanism accepted: %+v", bad)
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

func TestPKCS11ErrorClassification(t *testing.T) {
	for _, code := range []uint{pkcs11.CKR_PIN_INCORRECT, pkcs11.CKR_PIN_LOCKED, pkcs11.CKR_PIN_EXPIRED, pkcs11.CKR_PIN_INVALID, pkcs11.CKR_PIN_LEN_RANGE} {
		err := fmt.Errorf("login: %w", pkcs11.Error(code))
		if !isPINError(err) || isSessionLoss(err) {
			t.Errorf("0x%x must be a PIN error only", code)
		}
	}
	for _, code := range []uint{pkcs11.CKR_SESSION_HANDLE_INVALID, pkcs11.CKR_SESSION_CLOSED, pkcs11.CKR_DEVICE_REMOVED, pkcs11.CKR_TOKEN_NOT_PRESENT, pkcs11.CKR_USER_NOT_LOGGED_IN} {
		if !isSessionLoss(pkcs11.Error(code)) || isPINError(pkcs11.Error(code)) {
			t.Errorf("0x%x must be a session loss only", code)
		}
	}
	// A bad tag must never look like a lost session: that would turn a
	// tampered share into an endless "HSM unavailable" retry.
	for _, code := range []uint{pkcs11.CKR_ENCRYPTED_DATA_INVALID, pkcs11.CKR_GENERAL_ERROR, pkcs11.CKR_FUNCTION_FAILED} {
		if isSessionLoss(pkcs11.Error(code)) || isPINError(pkcs11.Error(code)) {
			t.Errorf("0x%x misclassified", code)
		}
	}
	if isSessionLoss(errors.New("plain")) || isPINError(errors.New("plain")) {
		t.Error("non-PKCS#11 error misclassified")
	}
}

// Negative: once the token rejected the PIN, the source must never log in
// again (no ReadPIN, no C_Login) for the rest of the process.
func TestPINRejectionIsSticky(t *testing.T) {
	reads := 0
	s := &pkcs11Source{pinRejected: true, opts: PKCS11Options{ReadPIN: func() ([]byte, error) {
		reads++
		return []byte("1234"), nil
	}}}
	blob := MarshalEnvelope(Envelope{Nonce: make([]byte, gcmNonceLen), Ciphertext: make([]byte, gcmTagLen+1)})
	if _, err := s.Unwrap(context.Background(), []byte(blob), AAD("n", 1)); !errors.Is(err, ErrPINRejected) {
		t.Fatalf("Unwrap after PIN rejection: %v", err)
	}
	if err := s.Health(context.Background()); !errors.Is(err, ErrPINRejected) {
		t.Fatalf("Health after PIN rejection: %v", err)
	}
	if reads != 0 {
		t.Fatalf("PIN read %d times after rejection, want 0", reads)
	}
}

func TestOpenPKCS11RequiresPINSource(t *testing.T) {
	if _, err := OpenPKCS11(PKCS11Options{ModulePath: "/nonexistent.so", KeyLabel: "k"}); err == nil {
		t.Fatal("OpenPKCS11 accepted a missing PIN source")
	}
}
