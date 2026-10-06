package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"github.com/afterdarksys/secretserver-autohsm/internal/config"
	"github.com/afterdarksys/secretserver-autohsm/internal/fingerprint"
	"github.com/afterdarksys/secretserver-autohsm/internal/keysource"
	"github.com/afterdarksys/secretserver-autohsm/internal/secure"
)

// installEnvelope atomically replaces the configured wrapped-share file for
// index with envelope (used by vaultkeeper rekey, which pipes the new share
// over stdin so it never touches disk in plaintext). The envelope is first
// proven to unwrap for this node and index. The replacement keeps the old
// file's owner, group and mode, so it passes the same secret-file gate.
//
// The previous envelope is kept as <path>.prev (a hard link to the old file,
// so the same owner and mode) instead of being destroyed: if the new share
// turns out to be wrong, the old one is still there to put back.
//
// The share path must be a regular file, not a symlink. A leftover
// .<name>.new from an interrupted install makes this fail closed; inspect and
// remove it by hand, then re-run.
func installEnvelope(ctx context.Context, cfg *config.Config, src keysource.Source, index int, envelope string) error {
	path := ""
	for _, s := range cfg.Keys.Shares {
		if s.Index == index {
			path = s.Path
		}
	}
	if path == "" {
		return fmt.Errorf("--install: share index %d is not configured for node %q", index, cfg.NodeID)
	}

	plain, err := src.Unwrap(ctx, []byte(envelope), keysource.AAD(cfg.NodeID, index))
	if err != nil {
		return fmt.Errorf("--install: new envelope does not unwrap: %w", err)
	}
	secure.Wipe(plain)

	if li, err := os.Lstat(path); err != nil {
		return fmt.Errorf("--install: existing share file: %w", err)
	} else if !li.Mode().IsRegular() {
		return fmt.Errorf("--install: %s is not a regular file (symlinks are refused)", path)
	}
	prev := path + ".prev"
	if li, err := os.Lstat(prev); err == nil && !li.Mode().IsRegular() {
		return fmt.Errorf("--install: %s exists and is not a regular file", prev)
	}

	old, err := config.OpenSecretFile(path, fmt.Sprintf("share %d", index))
	if err != nil {
		return fmt.Errorf("--install: existing share file: %w", err)
	}
	info, err := old.Stat()
	old.Close()
	if err != nil {
		return err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("--install: cannot determine owner of %s", path)
	}

	tmp := filepath.Join(filepath.Dir(path), "."+filepath.Base(path)+".new")
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, info.Mode().Perm())
	if err != nil {
		return fmt.Errorf("--install: create temp file: %w", err)
	}
	cleanup := func() { os.Remove(tmp) }
	if _, err := f.WriteString(envelope + "\n"); err != nil {
		f.Close()
		cleanup()
		return err
	}
	if int(st.Uid) != os.Getuid() || int(st.Gid) != os.Getgid() {
		if err := f.Chown(int(st.Uid), int(st.Gid)); err != nil {
			f.Close()
			cleanup()
			return fmt.Errorf("--install: chown: %w", err)
		}
	}
	if err := f.Chmod(info.Mode().Perm()); err != nil {
		f.Close()
		cleanup()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		cleanup()
		return err
	}
	if err := f.Close(); err != nil {
		cleanup()
		return err
	}
	// Keep the old envelope: <path>.prev becomes a second name for the old
	// inode before the rename replaces <path>.
	if err := os.Remove(prev); err != nil && !os.IsNotExist(err) {
		cleanup()
		return fmt.Errorf("--install: remove old %s: %w", prev, err)
	}
	if err := os.Link(path, prev); err != nil {
		cleanup()
		return fmt.Errorf("--install: keep previous envelope: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		cleanup()
		return fmt.Errorf("--install: rename: %w", err)
	}
	// Persist the rename. A failure here does not undo the install, so it is
	// reported rather than returned.
	if d, err := os.Open(filepath.Dir(path)); err == nil {
		if err := d.Sync(); err != nil {
			fmt.Fprintf(os.Stderr, "warning: fsync %s: %v\n", filepath.Dir(path), err)
		}
		d.Close()
	}
	fmt.Fprintf(os.Stderr, "installed share %d for node %q at %s (%s); previous envelope kept at %s\n",
		index, cfg.NodeID, path, fingerprint.OfString(envelope), prev)
	return nil
}
