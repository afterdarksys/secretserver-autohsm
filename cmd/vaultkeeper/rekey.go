package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"slices"
	"strconv"
	"time"

	"github.com/afterdarksys/secretserver-autohsm/internal/ceremony"
	"github.com/afterdarksys/secretserver-autohsm/internal/secure"
)

// offlineShareIndex is the share that never goes to a node.
const offlineShareIndex = 5

func (vk *app) cmdRekey(ctx context.Context, a *cliArgs) error {
	if err := requireApproval(a.approval); err != nil {
		return err
	}
	if len(a.positional) != 0 {
		return usageError{fmt.Errorf("rekey takes no positional arguments")}
	}
	if err := vk.cfg.requireCeremony(); err != nil {
		return err
	}
	if vk.cfg.OfflineFingerprint == "" {
		return fmt.Errorf("offline_fingerprint is required for rekey (share 5)")
	}
	if len(vk.cfg.Nodes) != ceremony.RekeyShares-1 {
		return fmt.Errorf("rekey needs exactly %d nodes holding share indexes 1..%d, got %d", ceremony.RekeyShares-1, ceremony.RekeyShares-1, len(vk.cfg.Nodes))
	}
	if !vk.runner.CanPipe() {
		// Checked before anything starts: once Vault rekeys, the old shares
		// are dead, so the new ones must be deliverable.
		return fmt.Errorf("rekey must re-wrap shares over stdin: %w", errCannotPipe)
	}
	if info, err := os.Stat(vk.cfg.OutputDir); err != nil || !info.IsDir() {
		return fmt.Errorf("output_dir %q is not a directory", vk.cfg.OutputDir)
	}
	return vk.rekey(ctx, a.shredInit)
}

func (vk *app) rekey(ctx context.Context, shredInit string) error {
	seal, err := vk.vc.SealStatus(ctx)
	if err != nil {
		return err
	}
	if seal.Sealed {
		return fmt.Errorf("vault is sealed; rekey needs an unsealed Vault")
	}
	cur, err := vk.vc.RekeyAttempt(ctx)
	if err != nil {
		return fmt.Errorf("read rekey attempt: %w", err)
	}
	if cur.Started {
		vk.notifier.Event(ctx, "vaultkeeper_foreign_attempt", "vaultkeeper", fmt.Sprintf("op=rekey nonce=%.8s", cur.Nonce))
		return fmt.Errorf("a rekey attempt (nonce %.8s) is already in progress; refusing to start and NOT cancelling it", cur.Nonce)
	}

	op, off := vk.cfg.OperatorFingerprint, vk.cfg.OfflineFingerprint
	opKey, err := vk.gpg.ExportPublicKey(ctx, op)
	if err != nil {
		return err
	}
	offKey, err := vk.gpg.ExportPublicKey(ctx, off)
	if err != nil {
		return err
	}
	// Verification is always required: Vault keeps the old shares until
	// enough new shares have been proven back to it.
	st, err := vk.vc.StartRekey(ctx, ceremony.RekeyShares, ceremony.RekeyThreshold, []string{opKey, opKey, opKey, opKey, offKey})
	if err != nil {
		return fmt.Errorf("start rekey: %w", err)
	}
	nonce := st.Nonce
	if err := ceremony.CheckRekey(st, op, off); err != nil {
		vk.cancelRekeyIfOurs(nonce)
		return fmt.Errorf("vault did not set up the rekey as [operator x4, offline] with verification: %w", err)
	}
	if err := vk.recordAttempt(ceremony.OpRekey, nonce); err != nil {
		vk.cancelRekeyIfOurs(nonce)
		return err
	}
	defer vk.clearAttempt(ceremony.OpRekey)
	vk.log.Info("rekey started", "nonce", nonce[:8], "shares", st.Shares, "threshold", st.Threshold, "verification", st.VerificationRequired)

	res, err := vk.collect(ctx, ceremony.OpRekey, nonce, func(ctx context.Context) (attemptView, error) {
		s, err := vk.vc.RekeyAttempt(ctx)
		if err != nil {
			return attemptView{}, err
		}
		current := s.Started && s.Nonce == nonce
		// Consumed: share collection finished and Vault now waits for
		// verification (it has NOT switched to the new shares yet).
		return attemptView{current: current, done: current && s.VerificationNonce != "", progress: s.Progress, required: s.Required}, nil
	})
	if err != nil {
		// Safe: without verification Vault is still on the old shares.
		vk.cancelRekeyIfOurs(nonce)
		return err
	}
	if lerr := ceremony.CheckRekeyLayout(res.PGPFingerprints, op, off); lerr != nil || len(res.KeysBase64) != ceremony.RekeyShares {
		vk.preserve(res)
		vk.cancelRekeyIfOurs(nonce)
		return fmt.Errorf("rekey result is not [operator x4, offline] with 5 shares; rekey cancelled, Vault keeps the old shares")
	}

	// 1. Persist every encrypted share before anything else happens, and
	// record each file's SHA-256 so later steps trust only these exact files.
	// The ceremony never deletes them; `rekey-cleanup` does, after a drill.
	ts := stamp()
	paths := make([]string, ceremony.RekeyShares)
	state := &rekeyState{Stamp: ts, Nonce: nonce, SHA256: map[string]string{}, VaultVerified: []int{}, Consistent: []int{}}
	for i, b64 := range res.KeysBase64 {
		p, sum, err := vk.writeEncrypted(shareFileName(i+1, ts), b64)
		if err != nil {
			vk.preserve(res)
			vk.cancelRekeyIfOurs(nonce)
			return fmt.Errorf("could not save encrypted share %d (%w); rekey cancelled, Vault keeps the old shares", i+1, err)
		}
		paths[i] = p
		state.SHA256[strconv.Itoa(i+1)] = sum
	}
	if err := vk.writeRekeyState(state); err != nil {
		vk.cancelRekeyIfOurs(nonce)
		return fmt.Errorf("record rekey state (%w); rekey cancelled, Vault keeps the old shares", err)
	}
	fmt.Fprintf(vk.out, "new shares saved PGP-encrypted (1-4: operator key, 5: offline key) in %s, stamp %s\n", vk.cfg.OutputDir, ts)

	// 2. Decrypt node shares 1-4 once; they are used for the consistency
	// proof, verification and delivery, and wiped at the end.
	plain := make([][]byte, ceremony.RekeyShares-1)
	defer func() {
		for _, p := range plain {
			secure.Wipe(p)
		}
	}()
	for i := range plain {
		ct, err := base64.StdEncoding.DecodeString(res.KeysBase64[i])
		if err == nil {
			plain[i], err = vk.gpg.Decrypt(ctx, ct)
		}
		if err != nil {
			vk.cancelRekeyIfOurs(nonce)
			return fmt.Errorf("decrypt new share %d (%w); rekey cancelled, Vault keeps the old shares, files kept in %s", i+1, err, vk.cfg.OutputDir)
		}
	}

	// 3. Before Vault switches: prove share 4 lies on the same polynomial as
	// shares 1-3. Vault's verification never sees share 4, and a completing
	// node could have replaced it. On a mismatch the rekey is cancelled while
	// Vault is still on the old shares.
	if err := sharesConsistent(plain); err != nil {
		cancelled := vk.cancelRekeyIfOurs(nonce)
		vk.notifier.Event(context.WithoutCancel(ctx), "vaultkeeper_rekey_inconsistent", "vaultkeeper",
			fmt.Sprintf("stamp=%s share 4 inconsistent with shares 1-3 before verify; rekey cancelled=%t", ts, cancelled))
		if !cancelled {
			return fmt.Errorf("CRITICAL: share 4 is not consistent with shares 1-3 (%v) and the rekey could not be cancelled; "+
				"check Vault now. Files kept in %s (stamp %s)", err, vk.cfg.OutputDir, ts)
		}
		return fmt.Errorf("CRITICAL: share 4 is not consistent with shares 1-3 (%v); before verify; rekey cancelled, Vault keeps the old "+
			"shares, nothing delivered. Files kept in %s (stamp %s)", err, vk.cfg.OutputDir, ts)
	}

	// 4. Verify shares 1-3 with Vault. Only now does Vault switch, and only
	// to shares that open with the operator key and that share 4 agrees with.
	if err := vk.verifyRekey(ctx, plain[:ceremony.RekeyThreshold]); err != nil {
		if vk.cancelRekeyIfOurs(nonce) {
			return fmt.Errorf("rekey verification failed (%w); rekey cancelled, Vault keeps the old shares, nodes untouched; "+
				"the share files of the cancelled rekey are kept in %s and open nothing", err, vk.cfg.OutputDir)
		}
		return fmt.Errorf("CRITICAL: rekey verification did not confirm (%w) and the attempt is no longer pending; "+
			"check Vault before anything else. Encrypted new shares are kept in %s", err, vk.cfg.OutputDir)
	}
	state.VaultVerified, state.Consistent = []int{1, 2, 3}, []int{4}
	if err := vk.writeRekeyState(state); err != nil {
		// Vault has switched; nothing is lost (files on disk), but the
		// proof record is needed by verify-share5 and rekey-cleanup.
		vk.log.Error("could not record the rekey proof; deliver from the share files", "error", err)
	}
	fmt.Fprintln(vk.out, "share 4 consistent with shares 1-3; Vault verified shares 1-3 and now uses the new shares")
	fmt.Fprintln(vk.out, "share 5 is UNVERIFIED (run verify-share5 with the offline key)")

	// 5. Deliver. Interruptible: every share is already on disk, so a
	// cancel here loses nothing. A node's selftest is the node's own claim
	// and gates nothing below.
	nodes := slices.Clone(vk.cfg.Nodes)
	slices.SortFunc(nodes, func(a, b Node) int { return a.ShareIndex - b.ShareIndex })
	var failed []Node
	for _, n := range nodes {
		if ctx.Err() != nil {
			failed = append(failed, n)
			continue
		}
		if err := vk.runner.Wrap(ctx, n, plain[n.ShareIndex-1]); err != nil {
			vk.log.Error("re-wrap failed", "node", n.Name, "index", n.ShareIndex, "error", err)
			failed = append(failed, n)
			continue
		}
		if err := vk.runner.Selftest(ctx, n); err != nil {
			vk.log.Error("selftest failed after re-wrap", "node", n.Name, "error", err)
			failed = append(failed, n)
			continue
		}
		fmt.Fprintf(vk.out, "node %s: share %d re-wrapped, node reports selftest OK\n", n.Name, n.ShareIndex)
	}
	reported := len(nodes) - len(failed)
	for _, n := range failed {
		fmt.Fprintf(vk.out, "node %s NOT delivered; re-wrap it from %s (PGP-encrypted to the operator key)\n", n.Name, paths[n.ShareIndex-1])
	}

	if shredInit != "" {
		if err := vk.shredGate(vk.cfg.OutputDir, ts); err != nil {
			fmt.Fprintf(vk.out, "NOT shredding %s: %v. After verify-share5 and an unseal drill, use rekey-cleanup %s --shred-init-file\n", shredInit, err, ts)
		} else if err := shred(shredInit); err != nil {
			vk.log.Error("shred of old init file failed", "path", shredInit, "error", err)
		} else {
			fmt.Fprintf(vk.out, "shredded old init file %s\n", shredInit)
		}
	}
	fmt.Fprintf(vk.out, "next: unseal drill with the node shares, `vaultkeeper verify-share5 %s` where the offline key is available, then `vaultkeeper rekey-cleanup %s`. All share files are kept until then.\n",
		paths[ceremony.RekeyShares-1], ts)
	vk.notifier.Event(context.WithoutCancel(ctx), "vaultkeeper_rekey_unconfirmed", "vaultkeeper",
		fmt.Sprintf("stamp=%s vault_verified=1-3 consistent=4 share5=UNVERIFIED nodes_reported_ok=%d/%d init_shredded=false; unseal drill, verify-share5 and rekey-cleanup pending",
			ts, reported, len(nodes)))
	if ctx.Err() != nil {
		return fmt.Errorf("interrupted during delivery (%d/%d nodes done); nothing is lost, see the share files above: %w", reported, len(nodes), ctx.Err())
	}
	if len(failed) > 0 {
		return fmt.Errorf("rekey completed but %d node(s) failed re-wrap/selftest (%d/%d OK)", len(failed), reported, len(nodes))
	}
	return nil
}

// verifyRekey proves the new shares to Vault via sys/rekey/verify. A forged
// or substituted result fails here, before Vault switches.
func (vk *app) verifyRekey(ctx context.Context, shares [][]byte) error {
	vs, err := vk.vc.RekeyVerifyAttempt(ctx)
	if err != nil {
		return fmt.Errorf("read rekey verification: %w", err)
	}
	if !vs.Started {
		return fmt.Errorf("no rekey verification is pending")
	}
	complete := false
	for i := 0; i < len(shares) && !complete; i++ {
		st, err := vk.vc.SubmitRekeyVerifyShare(ctx, shares[i], vs.Nonce)
		if err != nil {
			return fmt.Errorf("vault rejected the new shares: %w", err)
		}
		complete = st.Complete
	}
	if !complete {
		return fmt.Errorf("verification did not complete with %d shares", len(shares))
	}
	after, err := vk.vc.RekeyAttempt(ctx)
	if err != nil {
		return fmt.Errorf("confirm rekey: %w", err)
	}
	if after.Started {
		return fmt.Errorf("rekey still pending after verification")
	}
	return nil
}

// writeEncrypted writes a base64 PGP message as binary to output_dir, 0600,
// refusing to overwrite anything, and returns the file's SHA-256 (hex).
func (vk *app) writeEncrypted(name, b64 string) (string, string, error) {
	ct, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return "", "", err
	}
	p, err := vk.saveFile(name, ct)
	if err != nil {
		return "", "", err
	}
	sum := sha256.Sum256(ct)
	return p, hex.EncodeToString(sum[:]), nil
}

// shred overwrites a file with zeroes, syncs, and removes it. On
// copy-on-write or journaling filesystems (APFS, ZFS, btrfs) the old blocks
// may survive; this removes the file and its obvious copy, not every trace.
func shred(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", path)
	}
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	zero := make([]byte, 4096)
	for left := info.Size(); left > 0; {
		n := int64(len(zero))
		if left < n {
			n = left
		}
		if _, err := f.Write(zero[:n]); err != nil {
			f.Close()
			return err
		}
		left -= n
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Remove(path)
}

// cancelRekeyIfOurs cancels the rekey only if it is still the one we
// started, and reports whether it did. A pending rekey (including one waiting
// for verification) has not switched Vault's shares, so cancelling is safe.
func (vk *app) cancelRekeyIfOurs(nonce string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cur, err := vk.vc.RekeyAttempt(ctx)
	if err != nil || !cur.Started || cur.Nonce != nonce {
		return false
	}
	if err := vk.vc.CancelRekey(ctx, nil, nonce); err != nil {
		vk.log.Warn("could not cancel our rekey attempt", "nonce", nonce[:8], "error", err)
		return false
	}
	vk.log.Info("cancelled our rekey attempt; Vault keeps the old shares", "nonce", nonce[:8])
	return true
}
