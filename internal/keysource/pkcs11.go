// Asset: keysource-pkcs11
// Purpose: HSM-backed key source — unwraps unseal shares with an AES-256-GCM key that never leaves the token.
// Threats: Ensures unseal key shares are unrecoverable from stolen disks, backups, or
// filesystem snapshots: the wrapped blobs are inert without the token, and the wrapping
// key is non-extractable. Binds each share to configured node context+index via GCM AAD,
// preventing accidental relabeling. Gives the HSM an audit point and a revocation lever (destroy
// the key). Does NOT defend against an attacker executing code on this host while the
// session is open — they can ask the HSM to unwrap exactly as the daemon does. Auto-unseal
// inherently trades some of Vault's sealed-at-rest guarantee for availability.
// Deps: github.com/miekg/pkcs11
// Example: src, err := keysource.OpenPKCS11(keysource.PKCS11Options{...}); defer src.Close()
// Status: tested — PKCS#11 v2.40 AES-GCM interface, exercised against SoftHSM 2.6/2.7 by
// the integration test and scripts/e2e.sh; NOT yet exercised against production hardware,
// so run `autohsm selftest` on the real token before trusting a deployment.
// License: proprietary
// Provenance: original
package keysource

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"
	"unsafe"

	"github.com/afterdarksys/secretserver-autohsm/internal/secure"
	"github.com/miekg/pkcs11"
)

// gcmTagBits is the authentication tag length requested from the token.
// 128 bits is the full GCM tag; shorter tags weaken forgery resistance.
const gcmTagBits = 128

// ErrPINRejected reports that the token refused the PIN (incorrect, locked,
// expired, or invalid). It is terminal: the source never logs in again after
// seeing it, because repeated wrong-PIN attempts count down a hardware token's
// retry counter and can lock or zeroise it.
var ErrPINRejected = errors.New("HSM rejected the PIN")

// ErrHSMUnavailable reports that the token or its session is gone (removed,
// unreachable, session invalidated) and could not be re-established. It is
// transient: a later call retries the connection.
var ErrHSMUnavailable = errors.New("HSM unavailable")

// ErrHSMMisconfigured reports a failure that retrying cannot fix: the module
// cannot be loaded, the token lacks AES-GCM, the key is missing, ambiguous or
// unsafe, or the PIN source is unusable. It is terminal.
var ErrHSMMisconfigured = errors.New("HSM configuration or key is unusable")

// PKCS11Options describes how to reach the token and which key to use.
type PKCS11Options struct {
	ModulePath string
	TokenLabel string // optional; if empty, the first token with the key is used
	KeyLabel   string
	// ReadPIN supplies the user PIN for every login: the initial one and each
	// re-login after a lost session. The source wipes the returned slice
	// immediately after C_Login, so the PIN is not held between logins.
	ReadPIN func() ([]byte, error)
	// DeferUnavailable lets OpenPKCS11 return a disconnected source when the
	// only startup failure is ErrHSMUnavailable (token absent, module cannot
	// initialise, session cannot open). The first Health/Unwrap call then
	// reconnects, so a daemon can start before its HSM and use the same
	// backoff-and-alarm path as a mid-run outage. PIN and configuration
	// failures are still returned.
	DeferUnavailable bool
}

type pkcs11Source struct {
	mu      sync.Mutex
	opts    PKCS11Options
	ctx     *pkcs11.Ctx
	session pkcs11.SessionHandle
	key     pkcs11.ObjectHandle
	// live means ctx/session/key are usable; false forces a reconnect.
	live bool
	// pinRejected is sticky for the life of the process (see ErrPINRejected).
	pinRejected bool
	closed      bool
}

// OpenPKCS11 initialises the module, logs in, and locates the wrapping key.
// Every failure is classified as ErrPINRejected, ErrHSMMisconfigured (both
// terminal) or ErrHSMUnavailable (retryable). There is deliberately no
// fallback to software.
func OpenPKCS11(opts PKCS11Options) (Source, error) {
	if opts.ModulePath == "" {
		return nil, fmt.Errorf("pkcs11 module_path is required")
	}
	if opts.KeyLabel == "" {
		return nil, fmt.Errorf("pkcs11 key_label is required")
	}
	if opts.ReadPIN == nil {
		return nil, fmt.Errorf("pkcs11 PIN source is required")
	}
	s := &pkcs11Source{opts: opts}
	if err := s.connect(); err != nil {
		if opts.DeferUnavailable && errors.Is(err, ErrHSMUnavailable) {
			return s, nil
		}
		return nil, err
	}
	return s, nil
}

// connect performs a full module initialise, login, key lookup and key
// validation. On any failure nothing is left open.
func (s *pkcs11Source) connect() error {
	opts := s.opts
	ctx := pkcs11.New(opts.ModulePath)
	if ctx == nil {
		return fmt.Errorf("%w: failed to load PKCS#11 module %q", ErrHSMMisconfigured, opts.ModulePath)
	}
	if err := ctx.Initialize(); err != nil {
		ctx.Destroy()
		return fmt.Errorf("%w: pkcs11 initialize: %w", ErrHSMUnavailable, err)
	}

	cleanup := func() {
		_ = ctx.Finalize()
		ctx.Destroy()
	}

	slots, err := ctx.GetSlotList(true)
	if err != nil {
		cleanup()
		return fmt.Errorf("%w: pkcs11 slot list: %w", ErrHSMUnavailable, err)
	}
	if len(slots) == 0 {
		cleanup()
		return fmt.Errorf("%w: no PKCS#11 tokens present", ErrHSMUnavailable)
	}

	slot, err := selectSlot(ctx, slots, opts.TokenLabel)
	if err != nil {
		cleanup()
		// The labelled token is not (yet) present: an availability problem.
		return fmt.Errorf("%w: %w", ErrHSMUnavailable, err)
	}
	mechanismInfo, err := ctx.GetMechanismInfo(slot, []*pkcs11.Mechanism{
		pkcs11.NewMechanism(pkcs11.CKM_AES_GCM, nil),
	})
	if err != nil {
		cleanup()
		return fmt.Errorf("%w: pkcs11 token does not support CKM_AES_GCM: %w", ErrHSMMisconfigured, err)
	}
	if err := validateGCMMechanism(mechanismInfo); err != nil {
		cleanup()
		return fmt.Errorf("%w: %w", ErrHSMMisconfigured, err)
	}

	session, err := ctx.OpenSession(slot, pkcs11.CKF_SERIAL_SESSION)
	if err != nil {
		cleanup()
		return fmt.Errorf("%w: pkcs11 open session: %w", ErrHSMUnavailable, err)
	}
	pinBytes, err := opts.ReadPIN()
	if err != nil {
		_ = ctx.CloseSession(session)
		cleanup()
		return fmt.Errorf("%w: read HSM PIN: %w", ErrHSMMisconfigured, err)
	}
	if len(pinBytes) == 0 {
		_ = ctx.CloseSession(session)
		cleanup()
		return fmt.Errorf("%w: pkcs11 PIN is empty", ErrHSMMisconfigured)
	}
	// unsafe.String views the PIN bytes without copying, so the wipe below
	// also erases the memory Login reads from. A plain string(pinBytes)
	// conversion would deep-copy into an unwipeable Go allocation. (The
	// library's own C copy for the call is freed without zeroing; see
	// VALIDATION.md.)
	pin := unsafe.String(unsafe.SliceData(pinBytes), len(pinBytes))
	loginErr := ctx.Login(session, pkcs11.CKU_USER, pin)
	secure.Wipe(pinBytes)
	if loginErr != nil {
		_ = ctx.CloseSession(session)
		cleanup()
		// The PIN itself is never included in the error.
		if isPINError(loginErr) {
			s.pinRejected = true
			return fmt.Errorf("%w (%v); not retrying so a hardware token's retry counter is not exhausted",
				ErrPINRejected, loginErr)
		}
		return fmt.Errorf("%w: pkcs11 login failed: %w", ErrHSMUnavailable, loginErr)
	}

	key, err := findSecretKey(ctx, session, opts.KeyLabel)
	if err != nil {
		_ = ctx.Logout(session)
		_ = ctx.CloseSession(session)
		cleanup()
		// The token is present and logged in, so a missing or ambiguous key
		// is a provisioning error, not an outage.
		return fmt.Errorf("%w: %w", ErrHSMMisconfigured, err)
	}
	if err := validateSecretKey(ctx, session, key); err != nil {
		_ = ctx.Logout(session)
		_ = ctx.CloseSession(session)
		cleanup()
		return fmt.Errorf("%w: pkcs11 key %q is unsafe: %w", ErrHSMMisconfigured, opts.KeyLabel, err)
	}

	s.ctx, s.session, s.key, s.live = ctx, session, key, true
	return nil
}

// disconnect tears down whatever is open; errors are irrelevant because the
// handles are being abandoned either way.
func (s *pkcs11Source) disconnect() {
	if s.ctx == nil {
		return
	}
	_ = s.ctx.Logout(s.session)
	_ = s.ctx.CloseSession(s.session)
	_ = s.ctx.Finalize()
	s.ctx.Destroy()
	s.ctx = nil
	s.live = false
}

// ensureLive reconnects when the session was lost. A rejected PIN is sticky
// and never retried; any other reconnect failure wraps ErrHSMUnavailable.
// Callers must hold s.mu.
func (s *pkcs11Source) ensureLive() error {
	if s.closed {
		return fmt.Errorf("pkcs11 source is closed")
	}
	if s.pinRejected {
		return fmt.Errorf("%w earlier in this process; restart after fixing the PIN", ErrPINRejected)
	}
	if s.live {
		return nil
	}
	s.disconnect()
	if err := s.connect(); err != nil {
		if errors.Is(err, ErrPINRejected) || errors.Is(err, ErrHSMMisconfigured) || errors.Is(err, ErrHSMUnavailable) {
			return err
		}
		return fmt.Errorf("%w: %w", ErrHSMUnavailable, err)
	}
	return nil
}

// isSessionLoss reports PKCS#11 errors meaning the session, login, key handle
// or device went away, as opposed to a bad ciphertext or AAD.
func isSessionLoss(err error) bool {
	var e pkcs11.Error
	if !errors.As(err, &e) {
		return false
	}
	switch uint(e) {
	case pkcs11.CKR_SESSION_HANDLE_INVALID, pkcs11.CKR_SESSION_CLOSED,
		pkcs11.CKR_DEVICE_REMOVED, pkcs11.CKR_DEVICE_ERROR,
		pkcs11.CKR_TOKEN_NOT_PRESENT, pkcs11.CKR_TOKEN_NOT_RECOGNIZED,
		pkcs11.CKR_USER_NOT_LOGGED_IN, pkcs11.CKR_CRYPTOKI_NOT_INITIALIZED,
		pkcs11.CKR_KEY_HANDLE_INVALID, pkcs11.CKR_OBJECT_HANDLE_INVALID:
		return true
	}
	return false
}

// isPINError reports login failures caused by the PIN itself. Retrying these
// burns the token's retry counter.
func isPINError(err error) bool {
	var e pkcs11.Error
	if !errors.As(err, &e) {
		return false
	}
	switch uint(e) {
	case pkcs11.CKR_PIN_INCORRECT, pkcs11.CKR_PIN_LOCKED, pkcs11.CKR_PIN_EXPIRED,
		pkcs11.CKR_PIN_INVALID, pkcs11.CKR_PIN_LEN_RANGE:
		return true
	}
	return false
}

func validateGCMMechanism(info pkcs11.MechanismInfo) error {
	const required = pkcs11.CKF_ENCRYPT | pkcs11.CKF_DECRYPT
	if info.Flags&required != required {
		return fmt.Errorf("pkcs11 CKM_AES_GCM mechanism must support both encrypt and decrypt")
	}
	if info.MinKeySize > 32 || info.MaxKeySize < 32 {
		return fmt.Errorf("pkcs11 CKM_AES_GCM mechanism does not support 32-byte AES keys (range %d..%d)",
			info.MinKeySize, info.MaxKeySize)
	}
	return nil
}

func validateSecretKey(ctx *pkcs11.Ctx, session pkcs11.SessionHandle, key pkcs11.ObjectHandle) error {
	requested := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_VALUE_LEN, nil),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, nil),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, nil),
		pkcs11.NewAttribute(pkcs11.CKA_ALWAYS_SENSITIVE, nil),
		pkcs11.NewAttribute(pkcs11.CKA_NEVER_EXTRACTABLE, nil),
		pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, nil),
		pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, nil),
	}
	attrs, err := ctx.GetAttributeValue(session, key, requested)
	if err != nil {
		return fmt.Errorf("read security attributes: %w", err)
	}
	return validateSecretKeyAttributes(attrs)
}

func validateSecretKeyAttributes(attrs []*pkcs11.Attribute) error {
	byType := make(map[uint][]byte, len(attrs))
	for _, attr := range attrs {
		if attr != nil {
			byType[attr.Type] = attr.Value
		}
	}
	wantLen := pkcs11.NewAttribute(pkcs11.CKA_VALUE_LEN, uint(32)).Value
	if !bytes.Equal(byType[pkcs11.CKA_VALUE_LEN], wantLen) {
		return fmt.Errorf("CKA_VALUE_LEN must be 32 bytes (AES-256)")
	}
	for _, typ := range []uint{
		pkcs11.CKA_SENSITIVE,
		pkcs11.CKA_ALWAYS_SENSITIVE,
		pkcs11.CKA_NEVER_EXTRACTABLE,
		pkcs11.CKA_ENCRYPT,
		pkcs11.CKA_DECRYPT,
	} {
		if !attributeBool(byType[typ]) {
			return fmt.Errorf("attribute 0x%x must be true", typ)
		}
	}
	if value, ok := byType[pkcs11.CKA_EXTRACTABLE]; !ok || len(value) != 1 || value[0] != 0 {
		return fmt.Errorf("CKA_EXTRACTABLE must be false")
	}
	return nil
}

func attributeBool(value []byte) bool {
	return len(value) == 1 && value[0] != 0
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
// process only after the token authenticates the ciphertext and AAD. A lost
// session is re-established once (re-login included) before giving up with
// ErrHSMUnavailable.
func (s *pkcs11Source) Unwrap(_ context.Context, blob []byte, aad []byte) ([]byte, error) {
	env, err := ParseEnvelope(blob)
	if err != nil {
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensureLive(); err != nil {
		return nil, err
	}
	plain, err := s.decrypt(env, aad)
	if err != nil && isSessionLoss(err) {
		s.live = false
		if rerr := s.ensureLive(); rerr != nil {
			return nil, rerr
		}
		plain, err = s.decrypt(env, aad)
		if err != nil && isSessionLoss(err) {
			s.live = false
			return nil, fmt.Errorf("%w: %v", ErrHSMUnavailable, err)
		}
	}
	if err != nil {
		// Opaque on purpose: do not distinguish wrong-key from wrong-AAD.
		return nil, fmt.Errorf("unwrap failed: share is not authentic for this node and index")
	}
	if len(plain) == 0 {
		return nil, fmt.Errorf("token returned an empty share")
	}
	return plain, nil
}

func (s *pkcs11Source) decrypt(env Envelope, aad []byte) ([]byte, error) {
	params := pkcs11.NewGCMParams(env.Nonce, aad, gcmTagBits)
	defer params.Free()
	mech := []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_GCM, params)}
	if err := s.ctx.DecryptInit(s.session, mech, s.key); err != nil {
		return nil, err
	}
	return s.ctx.Decrypt(s.session, env.Ciphertext)
}

// Health verifies the session is still open and logged in, reconnecting if
// it is not. It returns nil, an ErrPINRejected error (terminal), or an
// ErrHSMUnavailable error (retry later).
func (s *pkcs11Source) Health(context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensureLive(); err != nil {
		return err
	}
	info, err := s.ctx.GetSessionInfo(s.session)
	if err == nil && (info.State == pkcs11.CKS_RO_USER_FUNCTIONS || info.State == pkcs11.CKS_RW_USER_FUNCTIONS) {
		return nil
	}
	s.live = false
	return s.ensureLive()
}

// WrapPKCS11 encrypts plaintext inside the token, for provisioning.
func (s *pkcs11Source) wrap(nonce, plaintext, aad []byte) ([]byte, []byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensureLive(); err != nil {
		return nil, nil, err
	}
	params := pkcs11.NewGCMParams(nonce, aad, gcmTagBits)
	defer params.Free()

	mech := []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_GCM, params)}
	if err := s.ctx.EncryptInit(s.session, mech, s.key); err != nil {
		return nil, nil, fmt.Errorf("pkcs11 encrypt init: %w", err)
	}
	ct, err := s.ctx.Encrypt(s.session, plaintext)
	if err != nil {
		return nil, nil, fmt.Errorf("pkcs11 encrypt: %w", err)
	}
	actualNonce := params.IV()
	if len(actualNonce) != 12 {
		return nil, nil, fmt.Errorf("pkcs11 token returned a %d-byte GCM nonce, require 12", len(actualNonce))
	}
	return ct, actualNonce, nil
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
	if len(nonce) != 12 {
		return "", fmt.Errorf("GCM nonce must be 12 bytes, got %d", len(nonce))
	}
	ct, actualNonce, err := p.wrap(nonce, plaintext, aad)
	if err != nil {
		return "", err
	}
	return MarshalEnvelope(Envelope{Nonce: actualNonce, Ciphertext: ct}), nil
}

func (s *pkcs11Source) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	s.disconnect()
	return nil
}

func trimLabel(s string) string {
	// Token labels are space-padded to 32 bytes by the spec.
	for len(s) > 0 && (s[len(s)-1] == ' ' || s[len(s)-1] == 0) {
		s = s[:len(s)-1]
	}
	return s
}
