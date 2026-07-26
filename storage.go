package vault

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gofrs/flock"
)

const (
	// vaultLockTimeout bounds how long a process waits for another process to
	// finish its read-modify-write cycle before giving up.
	vaultLockTimeout = 10 * time.Second
	// vaultLockRetry is how often the lock is re-attempted while waiting.
	vaultLockRetry = 50 * time.Millisecond
	// vaultDirMode keeps the vault directory owner-only. Secrets live here, so
	// the group-readable 0750 the providers used before is too permissive.
	vaultDirMode = 0700
	// vaultFileMode keeps the vault file owner-only.
	vaultFileMode = 0600
)

// resolveVaultPath builds the on-disk path for a vault file and proves it stays
// inside storagePath.
//
// filepath.Clean does not sanitize an ID embedded in a filename, it *resolves*
// it: Clean("vault-../../../tmp/evil.enc") is "../tmp/evil.enc", because the
// first ".." pops the literal "vault-.." element and the rest survive. Joining
// that onto the storage directory escapes it, so a crafted vault ID could make
// save() overwrite an arbitrary file. IDs are validated, and the result is then
// checked against the base directory as a belt-and-braces second gate.
func resolveVaultPath(storagePath, id, ext string) (string, error) {
	if err := ValidateVaultID(id); err != nil {
		return "", err
	}

	base, err := expandPath(storagePath)
	if err != nil {
		return "", fmt.Errorf("invalid vault storage path %q: %w", storagePath, err)
	}

	full := filepath.Join(base, fmt.Sprintf("%s-%s.%s", vaultFileBase, id, ext))

	rel, err := filepath.Rel(base, full)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", NewVaultPathError(full)
	}

	return full, nil
}

// readVaultFile reads a vault file from disk.
//
// The boolean reports whether the file exists. Only a genuinely absent file
// permits a caller to initialize a fresh vault; an existing but zero-length file
// is reported as corrupt. Treating "empty" as "absent" is how a truncated vault
// used to be silently reinitialized and then overwritten by the constructor,
// destroying every secret without reporting an error.
func readVaultFile(path string) ([]byte, bool, error) {
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, false, nil
		}
		// Anything else -- a permissions problem, an I/O error -- must not be
		// reported as "not found", which callers reasonably read as "create a
		// new one".
		return nil, false, fmt.Errorf("failed to read vault file %s: %w", path, err)
	}

	if len(data) == 0 {
		return nil, true, fmt.Errorf(
			"%w: vault file %s is empty; refusing to overwrite it. "+
				"Restore it from a backup, or delete it to start a new vault",
			ErrVaultCorrupt, path,
		)
	}

	return data, true, nil
}

// writeVaultFileAtomic writes data to path via a temp file and a rename.
func writeVaultFileAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, vaultDirMode); err != nil {
		return fmt.Errorf("failed to create vault directory: %w", err)
	}

	// A random name via os.CreateTemp (which uses O_EXCL) rather than a fixed
	// "<path>.tmp". The fixed name let two concurrent savers truncate each
	// other's partial write, and let a pre-planted symlink at that predictable
	// path redirect the write -- os.WriteFile follows symlinks and does not
	// apply the 0600 mode to an already-existing target.
	tmp, err := os.CreateTemp(dir, ".vault-*")
	if err != nil {
		return fmt.Errorf("failed to create temp vault file: %w", err)
	}
	tmpName := tmp.Name()

	discard := func() {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
	}

	if err := tmp.Chmod(vaultFileMode); err != nil {
		discard()
		return fmt.Errorf("failed to set vault file permissions: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		discard()
		return fmt.Errorf("failed to write temp vault file: %w", err)
	}
	// Flush to stable storage before the rename. Without this, a crash can leave
	// the renamed file present but zero-length -- exactly the corrupt state
	// readVaultFile now has to reject.
	if err := tmp.Sync(); err != nil {
		discard()
		return fmt.Errorf("failed to flush vault file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("failed to close temp vault file: %w", err)
	}

	if err := os.Rename(tmpName, path); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("failed to move vault file into place: %w", err)
	}

	syncDir(dir)
	return nil
}

// syncDir flushes a directory entry so a completed rename survives a crash.
// Best effort: not all platforms or filesystems support fsync on a directory
// (Windows in particular), and by this point the data is already in place, so
// there is nothing a caller could do with the error.
func syncDir(dir string) {
	d, err := os.Open(filepath.Clean(dir))
	if err != nil {
		return
	}
	defer func() { _ = d.Close() }()
	_ = d.Sync()
}

// withVaultLock runs fn while holding an exclusive advisory lock on the vault.
//
// The per-instance RWMutex only serializes goroutines sharing one provider
// value. It does nothing about a second provider in the same process, or -- the
// common case -- a second `flow secret set` running concurrently. Because every
// save rewrites the whole file from an in-memory snapshot, two unsynchronized
// writers silently lose one of the two updates.
func withVaultLock(vaultPath string, fn func() error) error {
	if err := os.MkdirAll(filepath.Dir(vaultPath), vaultDirMode); err != nil {
		return fmt.Errorf("failed to create vault directory: %w", err)
	}

	lock := flock.New(vaultPath + ".lock")
	ctx, cancel := context.WithTimeout(context.Background(), vaultLockTimeout)
	defer cancel()

	locked, err := lock.TryLockContext(ctx, vaultLockRetry)
	if err != nil {
		return fmt.Errorf("failed to acquire vault lock for %s: %w", vaultPath, err)
	}
	if !locked {
		return fmt.Errorf("timed out waiting for the vault lock on %s", vaultPath)
	}
	defer func() { _ = lock.Unlock() }()

	return fn()
}
