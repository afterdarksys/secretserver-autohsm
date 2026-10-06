package main

import (
	"context"
	"fmt"
	"time"

	"github.com/afterdarksys/secretserver-autohsm/internal/ceremony"
)

// cmdStatus reports seal state, keyring term and age, and any ceremony
// attempt in progress. An attempt this vaultkeeper did not start (or one not
// locked to the operator key) raises an alarm and exit code 3.
func (vk *app) cmdStatus(ctx context.Context) int {
	code := exitOK
	seal, err := vk.vc.SealStatus(ctx)
	if err != nil {
		vk.log.Error("seal-status", "error", err)
		return exitFail
	}
	fmt.Fprintf(vk.out, "seal: sealed=%t initialized=%t threshold=%d shares=%d version=%s\n",
		seal.Sealed, seal.Initialized, seal.Threshold, seal.Shares, seal.Version)
	if seal.Sealed {
		code = exitSealed
	}

	if !seal.Sealed {
		if gr, err := vk.vc.GenerateRootAttempt(ctx); err != nil {
			fmt.Fprintf(vk.out, "generate-root: unknown (%v)\n", err)
		} else if gr.Started {
			ours := vk.ourAttempt(ceremony.OpGenerateRoot, gr.Nonce) &&
				ceremony.FingerprintEqual(gr.PGPFingerprint, vk.cfg.OperatorFingerprint)
			fmt.Fprintf(vk.out, "generate-root: IN PROGRESS nonce=%.8s progress=%d/%d pgp_fingerprint=%q ours=%t\n",
				gr.Nonce, gr.Progress, gr.Required, gr.PGPFingerprint, ours)
			if !ours {
				vk.notifier.Event(ctx, "vaultkeeper_foreign_attempt", "vaultkeeper",
					fmt.Sprintf("op=generate-root nonce=%.8s pgp_fingerprint=%q", gr.Nonce, gr.PGPFingerprint))
				code = exitForeign
			}
		} else {
			fmt.Fprintln(vk.out, "generate-root: none")
		}

		if rk, err := vk.vc.RekeyAttempt(ctx); err != nil {
			fmt.Fprintf(vk.out, "rekey: unknown (%v)\n", err)
		} else if rk.Started {
			ours := vk.ourAttempt(ceremony.OpRekey, rk.Nonce)
			fmt.Fprintf(vk.out, "rekey: IN PROGRESS nonce=%.8s progress=%d/%d n=%d t=%d ours=%t\n",
				rk.Nonce, rk.Progress, rk.Required, rk.Shares, rk.Threshold, ours)
			if !ours {
				vk.notifier.Event(ctx, "vaultkeeper_foreign_attempt", "vaultkeeper", fmt.Sprintf("op=rekey nonce=%.8s", rk.Nonce))
				code = exitForeign
			}
		} else {
			fmt.Fprintln(vk.out, "rekey: none")
		}

		if vk.cfg.AppRole.RoleID == "" {
			fmt.Fprintln(vk.out, "keyring: not checked (no approle configured)")
		} else if token, err := vk.appRoleToken(ctx); err != nil {
			fmt.Fprintf(vk.out, "keyring: not checked (approle login: %v)\n", err)
		} else {
			ks, kerr := vk.vc.KeyStatus(ctx, token)
			vk.releaseToken(token)
			if kerr != nil {
				fmt.Fprintf(vk.out, "keyring: unknown (%v)\n", kerr)
			} else {
				age := "unknown"
				if t, perr := time.Parse(time.RFC3339Nano, ks.InstallTime); perr == nil {
					age = fmt.Sprintf("%dd", int(time.Since(t).Hours()/24))
				}
				fmt.Fprintf(vk.out, "keyring: term=%d installed=%s age=%s\n", ks.Term, ks.InstallTime, age)
			}
		}
	}
	// Listing root tokens needs root, so it is a later root-task, and share
	// staleness is visible only on the nodes (autohsm's shares_stale alarm).
	fmt.Fprintln(vk.out, "root tokens: not checked here (needs root; a later allowlisted root-task)")
	fmt.Fprintln(vk.out, "node shares: not checked here (autohsm raises shares_stale on the nodes)")
	return code
}
