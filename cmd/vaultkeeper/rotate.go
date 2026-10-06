package main

import (
	"bytes"
	"context"
	"fmt"
	"time"

	"github.com/afterdarksys/secretserver-autohsm/internal/config"
	"github.com/afterdarksys/secretserver-autohsm/internal/secure"
)

const maxSecretIDSize = 1024

// appRoleToken logs in with the configured AppRole and returns a token the
// caller must revoke and wipe. The secret_id file must pass the same
// owner/mode gate as autohsm's secrets (0600 owned by the caller, or 0640
// root-owned).
func (vk *app) appRoleToken(ctx context.Context) ([]byte, error) {
	if vk.cfg.AppRole.RoleID == "" {
		return nil, fmt.Errorf("approle.role_id is not configured")
	}
	f, err := config.OpenSecretFile(vk.cfg.AppRole.SecretIDPath, "approle secret_id")
	if err != nil {
		return nil, err
	}
	raw, err := config.ReadBounded(f, maxSecretIDSize)
	f.Close()
	if err != nil {
		return nil, fmt.Errorf("read approle secret_id: %w", err)
	}
	defer secure.Wipe(raw)
	secretID := bytes.TrimSpace(raw)
	if len(secretID) == 0 {
		return nil, fmt.Errorf("approle secret_id file is empty")
	}
	return vk.vc.AppRoleLogin(ctx, vk.cfg.AppRole.Mount, vk.cfg.AppRole.RoleID, secretID)
}

// releaseToken revokes and wipes a short-lived AppRole token.
func (vk *app) releaseToken(token []byte) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := vk.vc.RevokeSelf(ctx, token); err != nil {
		vk.log.Warn("could not revoke approle token (it expires at its TTL)", "error", err)
	}
	secure.Wipe(token)
}

// cmdRotate rotates the barrier key. It needs no root: the AppRole policy
// grants update+sudo on sys/rotate and read on sys/key-status only.
func (vk *app) cmdRotate(ctx context.Context) (err error) {
	defer func() {
		if err != nil {
			vk.notifier.Event(context.Background(), "vaultkeeper_rotate_failed", "vaultkeeper", err.Error())
		}
	}()
	token, err := vk.appRoleToken(ctx)
	if err != nil {
		return fmt.Errorf("approle login: %w", err)
	}
	defer vk.releaseToken(token)

	before, err := vk.vc.KeyStatus(ctx, token)
	if err != nil {
		return fmt.Errorf("key-status: %w", err)
	}
	if err := vk.vc.Rotate(ctx, token); err != nil {
		return fmt.Errorf("rotate: %w", err)
	}
	after, err := vk.vc.KeyStatus(ctx, token)
	if err != nil {
		return fmt.Errorf("key-status after rotate: %w", err)
	}
	if after.Term <= before.Term {
		return fmt.Errorf("keyring term did not advance (%d -> %d)", before.Term, after.Term)
	}
	msg := fmt.Sprintf("term=%d->%d", before.Term, after.Term)
	fmt.Fprintf(vk.out, "keyring rotated: %s\n", msg)
	vk.notifier.Event(ctx, "vaultkeeper_keyring_rotated", "vaultkeeper", msg)
	return nil
}
