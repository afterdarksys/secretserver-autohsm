package main

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/afterdarksys/secretserver-autohsm/internal/ceremony"
	"github.com/afterdarksys/secretserver-autohsm/internal/config"
	"github.com/afterdarksys/secretserver-autohsm/internal/secure"
	"github.com/afterdarksys/secretserver-autohsm/internal/shamir"
)

// After a rekey, the operator's output_dir holds, per stamp:
//
//	vault-share<i>.<stamp>.gpg    shares 1-4 (operator key), 5 (offline key)
//	vault-rekey.<stamp>.json      SHA-256 of each share file (recorded when it was
//	                              written) and what was PROVEN: 1-3 by Vault, 4 by
//	                              local math
//	vault-share5.<stamp>.verified written by verify-share5 (sha256 of share 5)
//
// Nothing here is a plaintext share. Deleting shares 1-4 and shredding the
// old init file are separate, gated steps (rekey-cleanup), never part of the
// ceremony, and never gated on a node's own selftest report.

var stampRE = regexp.MustCompile(`^[0-9]{8}T[0-9]{6}\.[0-9]{9}Z$`)

func shareFileName(i int, ts string) string { return fmt.Sprintf("vault-share%d.%s.gpg", i, ts) }

func stateFileName(ts string) string { return "vault-rekey." + ts + ".json" }

func share5MarkerName(ts string) string { return "vault-share5." + ts + ".verified" }

// rekeyState records what the ceremony proved. Only proof counts: Vault's
// verification of shares 1-3 and the local consistency proof of share 4.
type rekeyState struct {
	Stamp string `json:"stamp"`
	Nonce string `json:"nonce"`
	// SHA256 maps share index ("1".."5") to the hex SHA-256 of its file as
	// written by the ceremony. Every later read must match it.
	SHA256        map[string]string `json:"sha256"`
	VaultVerified []int             `json:"vault_verified"`
	Consistent    []int             `json:"consistent"`
}

// writeRekeyState writes (or atomically replaces) the state file, 0600.
func (vk *app) writeRekeyState(st *rekeyState) error {
	b, err := json.Marshal(st)
	if err != nil {
		return err
	}
	tmp := "." + stateFileName(st.Stamp) + ".new"
	p, err := vk.saveFile(tmp, append(b, '\n'))
	if err != nil {
		return err
	}
	if err := os.Rename(p, filepath.Join(vk.cfg.OutputDir, stateFileName(st.Stamp))); err != nil {
		os.Remove(p)
		return err
	}
	return nil
}

// readShareFile returns share file i of the rekey only if its SHA-256
// matches the one recorded when the ceremony wrote it (constant time).
func readShareFile(dir string, st *rekeyState, i int) ([]byte, error) {
	b, err := readSmallFile(filepath.Join(dir, shareFileName(i, st.Stamp)))
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(b)
	if subtle.ConstantTimeCompare([]byte(hex.EncodeToString(sum[:])), []byte(st.SHA256[strconv.Itoa(i)])) != 1 {
		return nil, fmt.Errorf("share file %d changed since the ceremony wrote it", i)
	}
	return b, nil
}

// provenState loads the state for ts from dir and requires shares 1-3
// Vault-verified and share 4 consistent.
func provenState(dir, ts string) (*rekeyState, error) {
	if !stampRE.MatchString(ts) {
		return nil, fmt.Errorf("invalid rekey stamp %q", ts)
	}
	b, err := readSmallFile(filepath.Join(dir, stateFileName(ts)))
	if err != nil {
		return nil, fmt.Errorf("rekey state: %w", err)
	}
	var st rekeyState
	if err := json.Unmarshal(b, &st); err != nil {
		return nil, fmt.Errorf("rekey state: %w", err)
	}
	if st.Stamp != ts || !slices.Equal(st.VaultVerified, []int{1, 2, 3}) || !slices.Equal(st.Consistent, []int{4}) {
		return nil, fmt.Errorf("rekey %s did not prove shares 1-4 (vault_verified=%v consistent=%v)", ts, st.VaultVerified, st.Consistent)
	}
	for i := 1; i <= ceremony.RekeyShares; i++ {
		if h := st.SHA256[strconv.Itoa(i)]; len(h) != 2*sha256.Size {
			return nil, fmt.Errorf("rekey %s state has no file hash for share %d", ts, i)
		}
	}
	return &st, nil
}

// shredGate allows shredding the old init file only when shares 1-3 were
// verified by Vault, share 4 is consistent with them, and share 5 has been
// verified by verify-share5 (and the file is unchanged since).
func (vk *app) shredGate(dir, ts string) error {
	st, err := provenState(dir, ts)
	if err != nil {
		return err
	}
	marker, err := readSmallFile(filepath.Join(dir, share5MarkerName(ts)))
	if err != nil {
		return fmt.Errorf("share 5 is UNVERIFIED (run verify-share5 where the offline key is available)")
	}
	share5, err := readShareFile(dir, st, 5)
	if err != nil {
		return fmt.Errorf("share 5 file: %w", err)
	}
	sum := sha256.Sum256(share5)
	if subtle.ConstantTimeCompare([]byte(strings.TrimSpace(string(marker))), []byte(hex.EncodeToString(sum[:]))) != 1 {
		return fmt.Errorf("share 5 file changed since it was verified")
	}
	return nil
}

func readSmallFile(p string) ([]byte, error) {
	info, err := os.Lstat(p)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", p)
	}
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return config.ReadBounded(f, ceremony.MaxResultLine)
}

// sharesConsistent hex-decodes the decrypted shares (Vault hands PGP rekey
// shares out hex-encoded) and requires every 3-subset containing the first
// share to combine to the same secret.
func sharesConsistent(hexShares [][]byte) error {
	parts := make([][]byte, len(hexShares))
	defer func() {
		for _, p := range parts {
			secure.Wipe(p)
		}
	}()
	for i, h := range hexShares {
		parts[i] = make([]byte, hex.DecodedLen(len(h)))
		if _, err := hex.Decode(parts[i], h); err != nil {
			return fmt.Errorf("share %d is not hex", i+1)
		}
	}
	return shamir.Consistent(parts, ceremony.RekeyThreshold)
}

// cmdVerifyShare5 decrypts share 5 with the offline key and shares 1-3 with
// the operator key, and proves share 5 lies on their polynomial.
func (vk *app) cmdVerifyShare5(ctx context.Context, a *cliArgs) error {
	if len(a.positional) != 1 {
		return usageError{fmt.Errorf("verify-share5 takes the path of vault-share5.<stamp>.gpg")}
	}
	if vk.cfg.OperatorFingerprint == "" || vk.cfg.OfflineFingerprint == "" || vk.cfg.GPGPath == "" {
		return fmt.Errorf("verify-share5 needs operator_fingerprint, offline_fingerprint and gpg_path")
	}
	path, err := filepath.Abs(a.positional[0])
	if err != nil {
		return err
	}
	dir, base := filepath.Split(path)
	ts := strings.TrimSuffix(strings.TrimPrefix(base, "vault-share5."), ".gpg")
	if base != shareFileName(5, ts) || !stampRE.MatchString(ts) {
		return usageError{fmt.Errorf("%s is not a vault-share5.<stamp>.gpg file", base)}
	}
	st, err := provenState(dir, ts)
	if err != nil {
		return fmt.Errorf("refusing: %w", err)
	}
	shares := make([][]byte, 4)
	defer func() {
		for _, s := range shares {
			secure.Wipe(s)
		}
	}()
	// Every file must match its recorded hash before any is decrypted.
	idxs := []int{1, 2, 3, 5}
	cts := make([][]byte, len(idxs))
	for i, idx := range idxs {
		if cts[i], err = readShareFile(dir, st, idx); err != nil {
			return fmt.Errorf("refusing: share %d: %w", idx, err)
		}
	}
	for i, idx := range idxs {
		fpr := vk.cfg.OperatorFingerprint
		if idx == 5 {
			fpr = vk.cfg.OfflineFingerprint
		}
		if shares[i], err = vk.gpg.DecryptFor(ctx, fpr, cts[i]); err != nil {
			return fmt.Errorf("decrypt share %d: %w", idx, err)
		}
	}
	if err := sharesConsistent(shares); err != nil {
		vk.notifier.Event(ctx, "vaultkeeper_rekey_inconsistent", "vaultkeeper", "stamp="+ts+" share 5 is not consistent with shares 1-3")
		return fmt.Errorf("CRITICAL: share 5 is NOT consistent with the Vault-verified shares 1-3 (%v); it is not a backup", err)
	}
	ct5, err := readShareFile(dir, st, 5)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(ct5)
	if _, err := vk.saveFileIn(dir, share5MarkerName(ts), []byte(hex.EncodeToString(sum[:])+"\n")); err != nil {
		return fmt.Errorf("record share 5 verification: %w", err)
	}
	fmt.Fprintf(vk.out, "share 5 VERIFIED: consistent with the Vault-verified shares 1-3 (stamp %s)\n", ts)
	return nil
}

// cmdRekeyCleanup removes the operator-encrypted node shares 1-4 of a rekey
// after a fresh check that Vault is unsealed and the operator's confirmation
// of an unseal drill with the new node shares; optionally it shreds the old
// init file behind the full proof gate. Share 5 is always kept.
func (vk *app) cmdRekeyCleanup(ctx context.Context, a *cliArgs) error {
	if len(a.positional) != 1 {
		return usageError{fmt.Errorf("rekey-cleanup takes the rekey stamp")}
	}
	ts := a.positional[0]
	dir := vk.cfg.OutputDir
	st, err := provenState(dir, ts)
	if err != nil {
		return fmt.Errorf("refusing: %w", err)
	}
	// Delete only the exact files the ceremony wrote.
	for i := 1; i < ceremony.RekeyShares; i++ {
		if _, err := readShareFile(dir, st, i); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("refusing: %w", err)
		}
	}
	if a.shredInit != "" {
		if err := vk.shredGate(dir, ts); err != nil {
			return fmt.Errorf("refusing to shred %s: %w", a.shredInit, err)
		}
	}
	seal, err := vk.vc.SealStatus(ctx)
	if err != nil {
		return err
	}
	if seal.Sealed {
		return fmt.Errorf("refusing: Vault is sealed right now")
	}
	if err := confirmDrill(vk.in, vk.out); err != nil {
		return fmt.Errorf("refusing: %w", err)
	}
	for i := 1; i < ceremony.RekeyShares; i++ {
		p := filepath.Join(dir, shareFileName(i, ts))
		if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
			return err
		}
		fmt.Fprintf(vk.out, "removed %s\n", p)
	}
	if a.shredInit != "" {
		if err := shred(a.shredInit); err != nil {
			return fmt.Errorf("shred %s: %w", a.shredInit, err)
		}
		fmt.Fprintf(vk.out, "shredded old init file %s\n", a.shredInit)
	}
	fmt.Fprintf(vk.out, "kept %s\n", filepath.Join(dir, shareFileName(5, ts)))
	return nil
}

const drillPhrase = "unseal drill passed"

// confirmDrill asks the operator, on a terminal, to confirm an unseal drill.
// A variable so tests can stand in for the terminal.
var confirmDrill = func(in io.Reader, out io.Writer) error {
	f, ok := in.(*os.File)
	if !ok {
		return fmt.Errorf("confirmation needs a terminal on stdin")
	}
	info, err := f.Stat()
	if err != nil || info.Mode()&os.ModeCharDevice == 0 {
		return fmt.Errorf("confirmation needs a terminal on stdin")
	}
	fmt.Fprintf(out, "Before cleaning up, prove the NEW node shares unseal Vault. Sealing Vault needs root, so the\n"+
		"practical drill is restarting the Vault process (an OUTAGE) and watching the autohsm nodes unseal it.\n"+
		"vaultkeeper cannot check this; your answer is only an acknowledgement.\nType %q to confirm: ", drillPhrase)
	buf := make([]byte, 128)
	n, _ := f.Read(buf)
	if strings.TrimSpace(string(buf[:n])) != drillPhrase {
		return fmt.Errorf("unseal drill not confirmed")
	}
	return nil
}
