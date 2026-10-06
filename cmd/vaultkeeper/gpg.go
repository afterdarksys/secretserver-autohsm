package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"os/exec"
	"strings"

	"github.com/afterdarksys/secretserver-autohsm/internal/config"
	"github.com/afterdarksys/secretserver-autohsm/internal/secure"
)

// maxPlaintext bounds decrypted output: a Vault token or an unseal share
// (hex) is well under 1 KiB.
const maxPlaintext = 4096

// GPG shells out to gpg. No OpenPGP implementation lives in this binary: the
// operator's key stays in gpg-agent (passphrase via pinentry today, a card
// touch after the hardware-key upgrade).
//
// gpg inherits vaultkeeper's environment, including GNUPGHOME: the keyring
// used is whichever one that selects (default ~/.gnupg). Path must be
// absolute so a PATH entry cannot substitute another binary.
type GPG struct {
	Path string
	// Operator is the operator key fingerprint, the only key tried for
	// decryption.
	Operator string
}

// noNetwork stops gpg from fetching keys or locating them over the network
// while vaultkeeper drives it.
var noNetwork = []string{"--no-auto-key-retrieve", "--no-auto-key-locate"}

// ExportPublicKey returns the base64 of fpr's binary public key, the form
// Vault's pgp_key / pgp_keys parameters take.
func (g *GPG) ExportPublicKey(ctx context.Context, fpr string) (string, error) {
	var out, errb bytes.Buffer
	args := append([]string{"--batch", "--no-tty"}, noNetwork...)
	args = append(args, "--export", "--export-options", "export-minimal", "--", fpr)
	cmd := exec.CommandContext(ctx, g.Path, args...)
	cmd.Stdout, cmd.Stderr = &out, &limitWriter{w: &errb, n: 4096}
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("gpg --export %s: %w: %s", fpr, err, strings.TrimSpace(errb.String()))
	}
	if out.Len() == 0 {
		return "", fmt.Errorf("gpg has no public key %s", fpr)
	}
	return base64.StdEncoding.EncodeToString(out.Bytes()), nil
}

// Decrypt decrypts one binary PGP message with the operator's key and
// returns the plaintext in a single buffer the caller must wipe. Plaintext
// only ever travels gpg -> pipe -> this buffer; it is never written to disk.
func (g *GPG) Decrypt(ctx context.Context, ciphertext []byte) ([]byte, error) {
	return g.DecryptFor(ctx, g.Operator, ciphertext)
}

// DecryptFor is Decrypt with the secret key restricted to fpr (the offline
// key for verify-share5).
func (g *GPG) DecryptFor(ctx context.Context, fpr string, ciphertext []byte) ([]byte, error) {
	var errb bytes.Buffer
	// --batch keeps gpg from prompting on the TTY itself; gpg-agent's
	// pinentry (or a card touch) still gates the private key.
	if fpr == "" {
		return nil, fmt.Errorf("gpg: key fingerprint not set")
	}
	args := append([]string{"--batch", "--no-tty", "--quiet"}, noNetwork...)
	args = append(args, "--try-secret-key", fpr, "--output", "-", "--decrypt")
	cmd := exec.CommandContext(ctx, g.Path, args...)
	cmd.Stdin = bytes.NewReader(ciphertext)
	cmd.Stderr = &limitWriter{w: &errb, n: 4096}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start gpg: %w", err)
	}
	plain, rerr := config.ReadBounded(stdout, maxPlaintext)
	if rerr != nil {
		// Drain so gpg is never left blocked on a full pipe before Wait.
		io.Copy(io.Discard, stdout)
	}
	werr := cmd.Wait()
	if rerr != nil || werr != nil {
		secure.Wipe(plain)
		if rerr != nil {
			return nil, fmt.Errorf("gpg --decrypt: %w", rerr)
		}
		return nil, fmt.Errorf("gpg --decrypt: %w: %s", werr, strings.TrimSpace(errb.String()))
	}
	trimmed := bytes.TrimSpace(plain)
	if len(trimmed) == 0 {
		secure.Wipe(plain)
		return nil, fmt.Errorf("gpg --decrypt produced no output")
	}
	out := make([]byte, len(trimmed))
	copy(out, trimmed)
	secure.Wipe(plain)
	return out, nil
}

// limitWriter keeps at most n bytes (gpg diagnostics for error messages).
type limitWriter struct {
	w io.Writer
	n int
}

func (l *limitWriter) Write(p []byte) (int, error) {
	if l.n > 0 {
		k := len(p)
		if k > l.n {
			k = l.n
		}
		if _, err := l.w.Write(p[:k]); err != nil {
			return 0, err
		}
		l.n -= k
	}
	return len(p), nil
}
