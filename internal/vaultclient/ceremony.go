// Asset: vault-ceremony-client
// Purpose: generate-root, rekey, token, and keyring calls for the vaultkeeper ceremonies.
// Threats: Keeps shares bound to one ceremony attempt by always sending the attempt
// nonce with a share, so a share can never land in an attempt that replaced the one
// the caller validated. Builds share, secret_id and token bodies in wipeable buffers,
// never decodes an OTP, and refuses to start a generate-root without a PGP key (no
// OTP path exists here). Does NOT decide whether an attempt is safe to contribute to
// (the caller checks the pinned fingerprints) and does NOT protect a token once the
// caller holds it.
// Deps: none (stdlib only)
// Example: st, _ := c.GenerateRootAttempt(ctx); c.SubmitGenerateRootShare(ctx, share, st.Nonce)
// Status: tested
// License: MIT
// Provenance: original
package vaultclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	"github.com/afterdarksys/secretserver-autohsm/internal/secure"
)

// GenerateRootStatus is Vault's generate-root attempt status. The otp field is
// deliberately not decoded: this package never handles an OTP.
type GenerateRootStatus struct {
	Started  bool   `json:"started"`
	Nonce    string `json:"nonce"`
	Progress int    `json:"progress"`
	Required int    `json:"required"`
	Complete bool   `json:"complete"`
	// EncodedToken is set only on the update that completes the attempt. For a
	// PGP attempt it is the base64 of a PGP message to PGPFingerprint.
	EncodedToken   string `json:"encoded_token"`
	PGPFingerprint string `json:"pgp_fingerprint"`
}

// RekeyStatus is Vault's rekey attempt status, plus the completion fields of
// the final rekey/update reply. The plaintext "keys" field is not decoded.
type RekeyStatus struct {
	Started              bool     `json:"started"`
	Nonce                string   `json:"nonce"`
	Threshold            int      `json:"t"`
	Shares               int      `json:"n"`
	Progress             int      `json:"progress"`
	Required             int      `json:"required"`
	PGPFingerprints      []string `json:"pgp_fingerprints"`
	Backup               bool     `json:"backup"`
	VerificationRequired bool     `json:"verification_required"`
	// VerificationNonce is set once the share-collection phase of a
	// verification-required rekey has completed: Vault holds the new shares
	// but has NOT switched to them until enough of them pass sys/rekey/verify.
	VerificationNonce string `json:"verification_nonce"`
	// Complete and KeysBase64 are set only on the completing update. With PGP
	// keys each entry is a base64 PGP message to PGPFingerprints[i].
	Complete   bool     `json:"complete"`
	KeysBase64 []string `json:"keys_base64"`
}

// RekeyVerifyStatus is Vault's rekey verification status.
type RekeyVerifyStatus struct {
	Started  bool   `json:"started"`
	Nonce    string `json:"nonce"`
	Progress int    `json:"progress"`
	Complete bool   `json:"complete"`
}

// TokenInfo is the non-secret subset of a token lookup.
type TokenInfo struct {
	Accessor     string   `json:"accessor"`
	Policies     []string `json:"policies"`
	TTL          int      `json:"ttl"`
	CreationTime int64    `json:"creation_time"`
	// ExpireTime is nil for a token that never expires (a root token).
	ExpireTime *string `json:"expire_time"`
	// Path is the endpoint that created the token: auth/token/root for
	// init and generate-root, auth/token/create-orphan etc. otherwise.
	Path string `json:"path"`
}

// KeyStatus is the barrier keyring state.
type KeyStatus struct {
	Term        int    `json:"term"`
	InstallTime string `json:"install_time"`
}

// GenerateRootAttempt reads the in-progress generate-root attempt (if any).
func (c *Client) GenerateRootAttempt(ctx context.Context) (*GenerateRootStatus, error) {
	var st GenerateRootStatus
	if err := c.do(ctx, http.MethodGet, "/v1/sys/generate-root/attempt", nil, &st); err != nil {
		return nil, err
	}
	return &st, nil
}

// StartGenerateRoot starts an attempt whose result is encrypted to pgpKeyB64
// (base64 of a binary OpenPGP public key). There is intentionally no OTP mode.
func (c *Client) StartGenerateRoot(ctx context.Context, pgpKeyB64 string) (*GenerateRootStatus, error) {
	if pgpKeyB64 == "" {
		return nil, fmt.Errorf("refusing to start generate-root without a PGP key (OTP attempts are not supported)")
	}
	body, err := json.Marshal(map[string]string{"pgp_key": pgpKeyB64})
	if err != nil {
		return nil, err
	}
	var st GenerateRootStatus
	if err := c.do(ctx, http.MethodPut, "/v1/sys/generate-root/attempt", body, &st); err != nil {
		return nil, err
	}
	return &st, nil
}

// CancelGenerateRoot cancels the current generate-root attempt. token may be
// nil where Vault leaves the endpoint unauthenticated.
func (c *Client) CancelGenerateRoot(ctx context.Context, token []byte) error {
	return c.doToken(ctx, http.MethodDelete, "/v1/sys/generate-root/attempt", token, nil, nil)
}

// SubmitGenerateRootShare submits one unseal share to the attempt identified
// by nonce. Vault rejects the share if the attempt was replaced.
func (c *Client) SubmitGenerateRootShare(ctx context.Context, share []byte, nonce string) (*GenerateRootStatus, error) {
	body, err := shareBody(share, nonce)
	if err != nil {
		return nil, err
	}
	defer secure.Wipe(body)
	var st GenerateRootStatus
	if err := c.do(ctx, http.MethodPut, "/v1/sys/generate-root/update", body, &st); err != nil {
		return nil, err
	}
	return &st, nil
}

// RekeyAttempt reads the in-progress rekey attempt (if any).
func (c *Client) RekeyAttempt(ctx context.Context) (*RekeyStatus, error) {
	var st RekeyStatus
	if err := c.do(ctx, http.MethodGet, "/v1/sys/rekey/init", nil, &st); err != nil {
		return nil, err
	}
	return &st, nil
}

// StartRekey starts a rekey to shares/threshold with one PGP key per new
// share. Backup is always off and verification always on: Vault switches to
// the new shares only after enough of them are proven via VerifyRekeyShare,
// so a lost or substituted result can never strand the old shares.
func (c *Client) StartRekey(ctx context.Context, shares, threshold int, pgpKeysB64 []string) (*RekeyStatus, error) {
	if len(pgpKeysB64) != shares {
		return nil, fmt.Errorf("rekey needs exactly one PGP key per share: %d keys for %d shares", len(pgpKeysB64), shares)
	}
	for i, k := range pgpKeysB64 {
		if k == "" {
			return nil, fmt.Errorf("rekey PGP key %d is empty", i)
		}
	}
	body, err := json.Marshal(map[string]any{
		"secret_shares":        shares,
		"secret_threshold":     threshold,
		"pgp_keys":             pgpKeysB64,
		"backup":               false,
		"require_verification": true,
	})
	if err != nil {
		return nil, err
	}
	var st RekeyStatus
	if err := c.do(ctx, http.MethodPut, "/v1/sys/rekey/init", body, &st); err != nil {
		return nil, err
	}
	return &st, nil
}

// CancelRekey cancels the rekey attempt identified by nonce (current Vault
// releases require the nonce in the body; older ones ignore it). token may be
// nil where Vault leaves the endpoint unauthenticated.
func (c *Client) CancelRekey(ctx context.Context, token []byte, nonce string) error {
	if err := ValidNonce(nonce); err != nil {
		return err
	}
	body, err := json.Marshal(map[string]string{"nonce": nonce})
	if err != nil {
		return err
	}
	return c.doToken(ctx, http.MethodDelete, "/v1/sys/rekey/init", token, body, nil)
}

// SubmitRekeyShare submits one current unseal share to the rekey attempt
// identified by nonce.
func (c *Client) SubmitRekeyShare(ctx context.Context, share []byte, nonce string) (*RekeyStatus, error) {
	body, err := shareBody(share, nonce)
	if err != nil {
		return nil, err
	}
	defer secure.Wipe(body)
	var st RekeyStatus
	if err := c.do(ctx, http.MethodPut, "/v1/sys/rekey/update", body, &st); err != nil {
		return nil, err
	}
	return &st, nil
}

// RekeyVerifyAttempt reads the rekey verification status.
func (c *Client) RekeyVerifyAttempt(ctx context.Context) (*RekeyVerifyStatus, error) {
	var st RekeyVerifyStatus
	if err := c.do(ctx, http.MethodGet, "/v1/sys/rekey/verify", nil, &st); err != nil {
		return nil, err
	}
	return &st, nil
}

// SubmitRekeyVerifyShare submits one NEW share to the verification identified
// by nonce. A wrong share makes Vault reset the verification once it has
// enough shares; Vault keeps the old shares in that case.
func (c *Client) SubmitRekeyVerifyShare(ctx context.Context, share []byte, nonce string) (*RekeyVerifyStatus, error) {
	body, err := shareBody(share, nonce)
	if err != nil {
		return nil, err
	}
	defer secure.Wipe(body)
	var st RekeyVerifyStatus
	if err := c.do(ctx, http.MethodPut, "/v1/sys/rekey/verify", body, &st); err != nil {
		return nil, err
	}
	return &st, nil
}

func shareBody(share []byte, nonce string) ([]byte, error) {
	if len(share) == 0 {
		return nil, fmt.Errorf("refusing to submit an empty share")
	}
	if err := ValidNonce(nonce); err != nil {
		return nil, err
	}
	body, err := marshalKeyRequest(share, nonce)
	if err != nil {
		return nil, fmt.Errorf("encode share request: %w", err)
	}
	return body, nil
}

// ValidNonce accepts only the UUID form Vault uses for ceremony nonces, so a
// nonce can be embedded in a request body without escaping and printed in a
// log without risk of injection.
func ValidNonce(nonce string) error {
	if len(nonce) != 36 {
		return fmt.Errorf("invalid attempt nonce: want a 36-character UUID")
	}
	for i := 0; i < len(nonce); i++ {
		ch := nonce[i]
		switch i {
		case 8, 13, 18, 23:
			if ch != '-' {
				return fmt.Errorf("invalid attempt nonce: want a 36-character UUID")
			}
		default:
			if !(ch >= '0' && ch <= '9' || ch >= 'a' && ch <= 'f') {
				return fmt.Errorf("invalid attempt nonce: want a 36-character UUID")
			}
		}
	}
	return nil
}

// validToken rejects anything that is not a plausible Vault token before it
// is placed in a header. The message never includes the token.
func validToken(token []byte) error {
	if len(token) == 0 || len(token) > 1024 {
		return fmt.Errorf("vault token is empty or oversized")
	}
	for _, b := range token {
		if b <= 0x20 || b >= 0x7f {
			return fmt.Errorf("vault token contains invalid characters")
		}
	}
	return nil
}

// LookupSelf looks up token itself. A revoked token yields a 403 APIError.
func (c *Client) LookupSelf(ctx context.Context, token []byte) (*TokenInfo, error) {
	var resp struct {
		Data TokenInfo `json:"data"`
	}
	if err := c.doToken(ctx, http.MethodGet, "/v1/auth/token/lookup-self", token, nil, &resp); err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// RevokeSelf revokes token (and its children).
func (c *Client) RevokeSelf(ctx context.Context, token []byte) error {
	return c.doToken(ctx, http.MethodPost, "/v1/auth/token/revoke-self", token, nil, nil)
}

// RevokeAccessor revokes the token identified by accessor.
func (c *Client) RevokeAccessor(ctx context.Context, token []byte, accessor string) error {
	body, err := json.Marshal(map[string]string{"accessor": accessor})
	if err != nil {
		return err
	}
	return c.doToken(ctx, http.MethodPost, "/v1/auth/token/revoke-accessor", token, body, nil)
}

// LookupAccessor looks up the token identified by accessor. A revoked
// accessor yields a 400 APIError ("invalid accessor").
func (c *Client) LookupAccessor(ctx context.Context, token []byte, accessor string) (*TokenInfo, error) {
	body, err := json.Marshal(map[string]string{"accessor": accessor})
	if err != nil {
		return nil, err
	}
	var resp struct {
		Data TokenInfo `json:"data"`
	}
	if err := c.doToken(ctx, http.MethodPost, "/v1/auth/token/lookup-accessor", token, body, &resp); err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// WritePolicy writes an ACL policy. name must already be validated by the
// caller; it is path-escaped regardless.
func (c *Client) WritePolicy(ctx context.Context, token []byte, name string, policy []byte) error {
	body, err := json.Marshal(map[string]string{"policy": string(policy)})
	if err != nil {
		return err
	}
	return c.doToken(ctx, http.MethodPut, "/v1/sys/policies/acl/"+url.PathEscape(name), token, body, nil)
}

// Rotate rotates the barrier encryption key (adds a new keyring term).
func (c *Client) Rotate(ctx context.Context, token []byte) error {
	return c.doToken(ctx, http.MethodPut, "/v1/sys/rotate", token, nil, nil)
}

// KeyStatus reads the current keyring term.
func (c *Client) KeyStatus(ctx context.Context, token []byte) (*KeyStatus, error) {
	var resp struct {
		Data KeyStatus `json:"data"`
	}
	if err := c.doToken(ctx, http.MethodGet, "/v1/sys/key-status", token, nil, &resp); err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// AppRoleLogin logs in at auth/<mount>/login and returns the client token in
// a buffer the caller must wipe. secretID is wiped by the caller too; the
// request body holding it is wiped here.
func (c *Client) AppRoleLogin(ctx context.Context, mount, roleID string, secretID []byte) ([]byte, error) {
	if err := validToken([]byte(roleID)); err != nil {
		return nil, fmt.Errorf("approle role_id: %w", err)
	}
	if err := validToken(secretID); err != nil {
		return nil, fmt.Errorf("approle secret_id: %w", err)
	}
	if bytes.ContainsAny(secretID, `"\`) || bytes.ContainsAny([]byte(roleID), `"\`) {
		return nil, fmt.Errorf("approle credentials contain characters that need escaping")
	}
	body := make([]byte, 0, len(roleID)+len(secretID)+32)
	body = append(body, `{"role_id":"`...)
	body = append(body, roleID...)
	body = append(body, `","secret_id":"`...)
	body = append(body, secretID...)
	body = append(body, `"}`...)
	defer secure.Wipe(body)

	// RawMessage keeps the token in a []byte we can wipe instead of a string.
	var resp struct {
		Auth struct {
			ClientToken json.RawMessage `json:"client_token"`
		} `json:"auth"`
	}
	if err := c.doToken(ctx, http.MethodPost, "/v1/auth/"+url.PathEscape(mount)+"/login", nil, body, &resp); err != nil {
		return nil, err
	}
	raw := resp.Auth.ClientToken
	if len(raw) < 3 || raw[0] != '"' || raw[len(raw)-1] != '"' {
		secure.Wipe(raw)
		return nil, fmt.Errorf("approle login returned no client token")
	}
	tok := make([]byte, len(raw)-2)
	copy(tok, raw[1:len(raw)-1])
	secure.Wipe(raw)
	if err := validToken(tok); err != nil {
		secure.Wipe(tok)
		return nil, err
	}
	return tok, nil
}
