// Asset: vaultkeeper-ceremony-policy
// Purpose: The single definition of which generate-root and rekey attempts a node may
// contribute a share to, and of the result line a completing node hands back.
// Threats: Vault's ceremony endpoints can be reachable without authentication, so anyone
// who can reach Vault can start an attempt. This policy makes such an attempt useless:
// a share is released only to an attempt whose result is PGP-encrypted to a pinned key
// (generate-root: exactly the operator key, never an OTP; rekey: exactly 5 new shares in
// the pinned order [operator x4, offline], threshold 3, no backup, and verification
// REQUIRED, so Vault switches only after the new shares are proven).
// Fingerprints are compared in constant time. The result line carries only the
// PGP-encrypted output, re-checked against the same pins before it is emitted. Does NOT
// stop an attacker from cancelling attempts (denial of service), does NOT protect against
// a malicious Vault binary, and does NOT protect the operator's private key.
// Deps: none (stdlib only)
// Example: if err := ceremony.CheckGenerateRoot(st, cfg.Vaultkeeper.PGPFingerprint); err != nil { refuse }
// Status: tested
// License: MIT
// Provenance: original
package ceremony

import (
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/afterdarksys/secretserver-autohsm/internal/vaultclient"
)

// Ceremony operations. These are the only arguments `autohsm contribute`
// accepts.
const (
	OpGenerateRoot = "generate-root"
	OpRekey        = "rekey"
)

// The only rekey shape a node will contribute to: 5 shares, threshold 3.
const (
	RekeyShares    = 5
	RekeyThreshold = 3
)

// ResultPrefix starts the single stdout line a completing node prints. The
// payload is JSON holding only PGP-encrypted material.
const ResultPrefix = "vaultkeeper-result "

// MaxResultLine bounds a result line. Five PGP-encrypted shares are a few KiB.
const MaxResultLine = 64 << 10

// ErrRefused marks a refusal by policy (as opposed to an I/O failure).
var ErrRefused = errors.New("refused")

func refuse(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrRefused, fmt.Sprintf(format, a...))
}

// FingerprintEqual compares two PGP fingerprints case-insensitively in
// constant time. Fingerprints are public, but the rule is uniform.
func FingerprintEqual(a, b string) bool {
	if a == "" || b == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(strings.ToLower(a)), []byte(strings.ToLower(b))) == 1
}

// CheckGenerateRoot decides whether st is an attempt this node may contribute
// to. pinned is the normalized vaultkeeper.pgp_fingerprint.
func CheckGenerateRoot(st *vaultclient.GenerateRootStatus, pinned string) error {
	if pinned == "" {
		return refuse("config has no vaultkeeper.pgp_fingerprint pin")
	}
	if st == nil || !st.Started {
		return refuse("no generate-root attempt is in progress")
	}
	if err := vaultclient.ValidNonce(st.Nonce); err != nil {
		return refuse("generate-root attempt has an unusable nonce")
	}
	if st.PGPFingerprint == "" {
		return refuse("generate-root attempt uses an OTP, not the pinned PGP key")
	}
	if !FingerprintEqual(st.PGPFingerprint, pinned) {
		return refuse("generate-root attempt is encrypted to PGP key %s, which is not the pinned key", st.PGPFingerprint)
	}
	if st.Required < 1 {
		return refuse("generate-root attempt reports no required share count")
	}
	return nil
}

// RekeyLayout is the only rekey key order a node contributes to: shares
// 1-4 to the operator key (re-wrapped onto the nodes), share 5 to the
// offline key.
func RekeyLayout(operator, offline string) []string {
	return []string{operator, operator, operator, operator, offline}
}

// CheckRekey decides whether st is a rekey attempt this node may contribute
// to. operator and offline are the normalized pins.
func CheckRekey(st *vaultclient.RekeyStatus, operator, offline string) error {
	if operator == "" || offline == "" {
		return refuse("config lacks vaultkeeper.pgp_fingerprint or vaultkeeper.offline_fingerprint")
	}
	if st == nil || !st.Started {
		return refuse("no rekey attempt is in progress")
	}
	if err := vaultclient.ValidNonce(st.Nonce); err != nil {
		return refuse("rekey attempt has an unusable nonce")
	}
	if st.Shares != RekeyShares {
		return refuse("rekey attempt wants %d shares, only %d is allowed", st.Shares, RekeyShares)
	}
	if st.Threshold != RekeyThreshold {
		return refuse("rekey attempt wants threshold %d, only %d is allowed", st.Threshold, RekeyThreshold)
	}
	if st.Backup {
		return refuse("rekey attempt has backup=true (Vault would keep a recoverable copy of the new shares)")
	}
	if !st.VerificationRequired {
		return refuse("rekey attempt does not require verification (Vault would switch shares before anyone proved they arrived)")
	}
	if st.VerificationNonce != "" {
		return refuse("rekey attempt has already collected its shares")
	}
	return CheckRekeyLayout(st.PGPFingerprints, operator, offline)
}

// CheckRekeyLayout requires fps to be exactly [operator x4, offline].
func CheckRekeyLayout(fps []string, operator, offline string) error {
	want := RekeyLayout(operator, offline)
	if len(fps) != len(want) {
		return refuse("rekey attempt encrypts %d of %d new shares to PGP keys; all must be", len(fps), RekeyShares)
	}
	for i := range want {
		if !FingerprintEqual(fps[i], want[i]) {
			return refuse("rekey share %d is encrypted to PGP key %q, not the pinned key for that position", i+1, fps[i])
		}
	}
	return nil
}

// Result is what a completing node hands back to the coordinator. Every
// field is either public (op, nonce, fingerprints) or PGP-encrypted.
type Result struct {
	Op              string   `json:"op"`
	Nonce           string   `json:"nonce"`
	EncodedToken    string   `json:"encoded_token,omitempty"`
	PGPFingerprint  string   `json:"pgp_fingerprint,omitempty"`
	KeysBase64      []string `json:"keys_base64,omitempty"`
	PGPFingerprints []string `json:"pgp_fingerprints,omitempty"`
}

// GenerateRootResult builds the result for a completing generate-root
// update, re-checking it against the attempt the node validated.
func GenerateRootResult(final *vaultclient.GenerateRootStatus, nonce, pinned string) (*Result, error) {
	if final == nil || !final.Complete {
		return nil, fmt.Errorf("generate-root reply is not complete")
	}
	if final.Nonce != nonce {
		return nil, refuse("completion nonce does not match the validated attempt")
	}
	if !FingerprintEqual(final.PGPFingerprint, pinned) {
		return nil, refuse("completion is not encrypted to the pinned key")
	}
	if !isBase64(final.EncodedToken) {
		return nil, fmt.Errorf("completion carries no PGP-encrypted token")
	}
	return &Result{Op: OpGenerateRoot, Nonce: nonce, EncodedToken: final.EncodedToken, PGPFingerprint: strings.ToLower(final.PGPFingerprint)}, nil
}

// RekeyResult builds the result for a completing rekey update.
func RekeyResult(final *vaultclient.RekeyStatus, nonce, operator, offline string) (*Result, error) {
	if final == nil || !final.Complete {
		return nil, fmt.Errorf("rekey reply is not complete")
	}
	if final.Nonce != nonce {
		return nil, refuse("completion nonce does not match the validated attempt")
	}
	if !final.VerificationRequired || final.VerificationNonce == "" {
		return nil, refuse("rekey completed without pending verification")
	}
	if err := CheckRekeyLayout(final.PGPFingerprints, operator, offline); err != nil {
		return nil, err
	}
	if len(final.KeysBase64) != RekeyShares {
		return nil, fmt.Errorf("rekey completion carries %d shares, want %d", len(final.KeysBase64), RekeyShares)
	}
	for i, k := range final.KeysBase64 {
		if !isBase64(k) {
			return nil, fmt.Errorf("rekey share %d is not base64", i+1)
		}
	}
	fps := make([]string, len(final.PGPFingerprints))
	for i, fp := range final.PGPFingerprints {
		fps[i] = strings.ToLower(fp)
	}
	return &Result{Op: OpRekey, Nonce: nonce, KeysBase64: final.KeysBase64, PGPFingerprints: fps}, nil
}

func isBase64(s string) bool {
	if s == "" {
		return false
	}
	_, err := base64.StdEncoding.DecodeString(s)
	return err == nil
}

// Line renders r as the single stdout line.
func (r *Result) Line() (string, error) {
	b, err := json.Marshal(r)
	if err != nil {
		return "", err
	}
	return ResultPrefix + string(b), nil
}

// FindResult scans output for the result line and parses it. It returns
// (nil, nil) when there is none. More than one result line is an error.
func FindResult(output []byte) (*Result, error) {
	var found *Result
	for _, line := range strings.Split(string(output), "\n") {
		line = strings.TrimRight(line, "\r")
		if !strings.HasPrefix(line, ResultPrefix) {
			continue
		}
		if found != nil {
			return nil, fmt.Errorf("output holds more than one result line")
		}
		r, err := ParseResult(line)
		if err != nil {
			return nil, err
		}
		found = r
	}
	return found, nil
}

// ParseResult parses one result line strictly.
func ParseResult(line string) (*Result, error) {
	line = strings.TrimSpace(line)
	if len(line) > MaxResultLine {
		return nil, fmt.Errorf("result line exceeds %d bytes", MaxResultLine)
	}
	if !strings.HasPrefix(line, ResultPrefix) {
		return nil, fmt.Errorf("not a %q line", strings.TrimSpace(ResultPrefix))
	}
	dec := json.NewDecoder(strings.NewReader(strings.TrimPrefix(line, ResultPrefix)))
	dec.DisallowUnknownFields()
	var r Result
	if err := dec.Decode(&r); err != nil {
		return nil, fmt.Errorf("parse result line: %w", err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, fmt.Errorf("parse result line: trailing data after the JSON object")
	}
	if r.Op != OpGenerateRoot && r.Op != OpRekey {
		return nil, fmt.Errorf("result line has unknown op %q", r.Op)
	}
	if err := vaultclient.ValidNonce(r.Nonce); err != nil {
		return nil, err
	}
	return &r, nil
}
