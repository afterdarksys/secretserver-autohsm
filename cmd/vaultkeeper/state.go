package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/afterdarksys/secretserver-autohsm/internal/vaultclient"
)

// The state directory records the nonce of each ceremony attempt this
// vaultkeeper started, for as long as that ceremony runs. status treats any
// in-progress attempt whose nonce is not recorded here as foreign. Nonces are
// public (Vault serves them on the attempt endpoint), so this is not secret.

func (vk *app) recordAttempt(op, nonce string) error {
	if vk.cfg.StateDir == "" {
		return fmt.Errorf("state_dir is not set")
	}
	if err := os.MkdirAll(vk.cfg.StateDir, 0o700); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(vk.cfg.StateDir, op+".nonce"), []byte(nonce+"\n"), 0o600)
}

func (vk *app) clearAttempt(op string) {
	if vk.cfg.StateDir == "" {
		return
	}
	if err := os.Remove(filepath.Join(vk.cfg.StateDir, op+".nonce")); err != nil && !os.IsNotExist(err) {
		vk.log.Warn("could not clear attempt state", "op", op, "error", err)
	}
}

func (vk *app) ourAttempt(op, nonce string) bool {
	if vk.cfg.StateDir == "" || nonce == "" {
		return false
	}
	b, err := os.ReadFile(filepath.Join(vk.cfg.StateDir, op+".nonce"))
	if err != nil {
		return false
	}
	rec := strings.TrimSpace(string(b))
	return vaultclient.ValidNonce(rec) == nil && rec == nonce
}
