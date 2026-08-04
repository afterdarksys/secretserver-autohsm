// Asset: keysource-pkcs11
// Purpose: HSM-backed key source — unwraps unseal shares with an AES-256-GCM key that never leaves the token.
// Threats: Ensures unseal key shares are unrecoverable from stolen disks, backups, or
// filesystem snapshots: the wrapped blobs are inert without the token, and the wrapping
// key is non-extractable. Binds each share to node+index via GCM AAD so a blob cannot be
// replayed on another host. Gives the HSM an audit point and a revocation lever (destroy
// the key). Does NOT defend against an attacker executing code on this host while the
// session is open — they can ask the HSM to unwrap exactly as the daemon does. Auto-unseal
// inherently trades some of Vault's sealed-at-rest guarantee for availability.
// Deps: github.com/miekg/pkcs11
// Example: src, err := keysource.OpenPKCS11(keysource.PKCS11Options{...}); defer src.Close()
// Status: draft — implemented against the PKCS#11 v2.40 AES-GCM interface but NOT yet
// exercised against a live token; run `autohsm selftest` on a host with the module present.
// License: proprietary
// Provenance: original
package keysource

import (
	"context"
	"fmt"
	"sync"

	"github.com/miekg/pkcs11"
)

// gcmTagBits is the authentication tag length requested from the token.
// 128 bits is the full GCM tag; shorter tags weaken forgery resistance.
const gcmTagBits = 128

// PKCS11Options describes how to reach the token and which key to use.
type PKCS11Options struct {
	ModulePath string
	TokenLabel string // optional; if empty, the first token with the key is used
	KeyLabel   string
	PIN        []byte
}

type pkcs11Source struct {
	mu      sync.Mutex
	ctx     *pkcs11.Ctx
	session pkcs11.SessionHandle
	key     pkcs11.ObjectHandle
	closed  bool
}

// OpenPKCS11 initialises the module, logs in, and locates the wrapping key.
// Every failure is terminal: there is deliberately no fallback to software.
func OpenPKCS11(opts PKCS11Options) (Source, error) {
	if opts.ModulePath == "" {
		return nil, fmt.Errorf("pkcs11 module_path is required")
	}
	if opts.KeyLabel == "" {
		return nil, fmt.Errorf("pkcs11 key_label is required")
	}
	if len(opts.PIN) == 0 {
		return nil, fmt.Errorf("pkcs11 PIN is required")
	}

	ctx := pkcs11.New(opts.ModulePath)
	if ctx == nil {
		return nil, fmt.Errorf("failed to load PKCS#11 module %q", opts.ModulePath)
	}
	if err := ctx.Initialize(); err != nil {
		ctx.Destroy()
		return nil, fmt.Errorf("pkcs11 initialize: %w", err)
	}

	cleanup := func() {
		_ = ctx.Finalize()
		ctx.Destroy()
	}

	slots, err := ctx.GetSlotList(true)
	if err != nil {
		cleanup()
		return nil, fmt.Errorf("pkcs11 slot list: %w", err)
	}
	if len(slots) == 0 {
		cleanup()
		return nil, fmt.Errorf("no PKCS#11 tokens present")
	}

	slot, err := selectSlot(ctx, slots, opts.TokenLabel)
	if err != nil {
		cleanup()
		return nil, err
	}

	session, err := ctx.OpenSession(slot, pkcs11.CKF_SERIAL_SESSION)
	if err != nil {
		cleanup()
		return nil, fmt.Errorf("pkcs11 open session: %w", err)
	}
	if err := ctx.Login(session, pkcs11.CKU_USER, string(opts.PIN)); err != nil {
		_ = ctx.CloseSession(session)
		cleanup()
		// The PIN itself is never included in the error.
		return nil, fmt.Errorf("pkcs11 login failed: %w", err)
	}

	key, err := findSecretKey(ctx, session, opts.KeyLabel)
	if err != nil {
		_ = ctx.Logout(session)
		_ = ctx.CloseSession(session)
		cleanup()
		return nil, err
	}

	return &pkcs11Source{ctx: ctx, session: session, key: key}, nil
}

func selectSlot(ctx *pkcs11.Ctx, slots []uint, tokenLabel string) (uint, error) {
	if tokenLabel == "" {
		return slots[0], nil
	}
	for _, s := range slots {
		info, err := ctx.GetTokenInfo(s)
		if err != nil {
			continue
		}
		if trimLabel(info.Label) == tokenLabel {
			return s, nil
		}
	}
	return 0, fmt.Errorf("no token with label %q", tokenLabel)
}

func findSecretKey(ctx *pkcs11.Ctx, session pkcs11.SessionHandle, label string) (pkcs11.ObjectHandle, error) {
	tmpl := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_AES),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
	}
	if err := ctx.FindObjectsInit(session, tmpl); err != nil {
		return 0, fmt.Errorf("pkcs11 find init: %w", err)
	}
	objs, _, err := ctx.FindObjects(session, 2)
	finErr := ctx.FindObjectsFinal(session)
	if err != nil {
		return 0, fmt.Errorf("pkcs11 find: %w", err)
	}
	if finErr != nil {
		return 0, fmt.Errorf("pkcs11 find final: %w", finErr)
	}
	switch len(objs) {
	case 0:
		return 0, fmt.Errorf("no AES secret key labelled %q on token", label)
	case 1:
		return objs[0], nil
	default:
		// Ambiguity is a configuration error: fail closed rather than guess.
		return 0, fmt.Errorf("multiple AES keys labelled %q on token; labels must be unique", label)
	}
}

// Unwrap decrypts the envelope inside the token. Plaintext exists in this
// process only after the token authenticates the ciphertext and AAD.
func (s *pkcs11Source) Unwrap(_ context.Context, blob []byte, aad []byte) ([]byte, error) {
	env, err := ParseEnvelope(blob)
	if err != nil {
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, fmt.Errorf("pkcs11 source is closed")
	}

	params := pkcs11.NewGCMParams(env.Nonce, aad, gcmTagBits)
	defer params.Free()

	mech := []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_GCM, params)}
	if err := s.ctx.DecryptInit(s.session, mech, s.key); err != nil {
		return nil, fmt.Errorf("pkcs11 decrypt init (does the token support CKM_AES_GCM?): %w", err)
	}
	plain, err := s.ctx.Decrypt(s.session, env.Ciphertext)
	if err != nil {
		// Opaque on purpose: do not distinguish wrong-key from wrong-AAD.
		return nil, fmt.Errorf("unwrap failed: share is not authentic for this node and index")
	}
	if len(plain) == 0 {
		return nil, fmt.Errorf("token returned an empty share")
	}
	return plain, nil
}

// WrapPKCS11 encrypts plaintext inside the token, for provisioning.
func (s *pkcs11Source) wrap(nonce, plaintext, aad []byte) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, fmt.Errorf("pkcs11 source is closed")
	}
	params := pkcs11.NewGCMParams(nonce, aad, gcmTagBits)
	defer params.Free()

	mech := []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_GCM, params)}
	if err := s.ctx.EncryptInit(s.session, mech, s.key); err != nil {
		return nil, fmt.Errorf("pkcs11 encrypt init: %w", err)
	}
	ct, err := s.ctx.Encrypt(s.session, plaintext)
	if err != nil {
		return nil, fmt.Errorf("pkcs11 encrypt: %w", err)
	}
	return ct, nil
}

// Wrap produces an envelope using the token's key. Exposed via the CLI so that
// provisioning never requires the wrapping key to leave the HSM.
func Wrap(src Source, nonce, plaintext, aad []byte) (string, error) {
	p, ok := src.(*pkcs11Source)
	if !ok {
		return "", fmt.Errorf("Wrap requires a pkcs11 source")
	}
	if len(plaintext) == 0 {
		return "", fmt.Errorf("refusing to wrap an empty share")
	}
	ct, err := p.wrap(nonce, plaintext, aad)
	if err != nil {
		return "", err
	}
	return MarshalEnvelope(Envelope{Nonce: nonce, Ciphertext: ct}), nil
}

func (s *pkcs11Source) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	_ = s.ctx.Logout(s.session)
	_ = s.ctx.CloseSession(s.session)
	_ = s.ctx.Finalize()
	s.ctx.Destroy()
	return nil
}

func trimLabel(s string) string {
	// Token labels are space-padded to 32 bytes by the spec.
	for len(s) > 0 && (s[len(s)-1] == ' ' || s[len(s)-1] == 0) {
		s = s[:len(s)-1]
	}
	return s
}
