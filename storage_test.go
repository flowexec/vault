package vault_test

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/flowexec/vault"
)

const testVaultID = "v1"

func unencryptedConfig(dir string) *vault.Config {
	return &vault.Config{
		ID:          testVaultID,
		Type:        vault.ProviderTypeUnencrypted,
		Unencrypted: &vault.UnencryptedConfig{StoragePath: dir},
	}
}

func vaultFilePath(dir string) string {
	return filepath.Join(dir, fmt.Sprintf("vault-%s.json", testVaultID))
}

// A zero-length vault file used to be read as "no vault here", which made the
// constructor initialize a fresh one and immediately save over it -- destroying
// every secret and reporting success.
func TestEmptyVaultFileIsRejectedRatherThanOverwritten(t *testing.T) {
	dir := t.TempDir()
	path := vaultFilePath(dir)

	if err := os.WriteFile(path, []byte{}, 0600); err != nil {
		t.Fatalf("failed to seed empty vault file: %v", err)
	}

	_, err := vault.NewUnencryptedVault(unencryptedConfig(dir))
	if err == nil {
		t.Fatal("NewUnencryptedVault() accepted an empty vault file, want an error")
	}
	if !errors.Is(err, vault.ErrVaultCorrupt) {
		t.Errorf("error = %v, want ErrVaultCorrupt", err)
	}

	// The crucial part: the file must be left exactly as it was.
	info, statErr := os.Stat(path)
	if statErr != nil {
		t.Fatalf("vault file disappeared: %v", statErr)
	}
	if info.Size() != 0 {
		t.Errorf("vault file was rewritten (size %d), want it left untouched", info.Size())
	}
}

// A truncated vault must not be silently replaced with an empty one either.
func TestTruncatedVaultFileIsNotSilentlyReinitialized(t *testing.T) {
	dir := t.TempDir()

	v, err := vault.NewUnencryptedVault(unencryptedConfig(dir))
	if err != nil {
		t.Fatalf("NewUnencryptedVault() error = %v", err)
	}
	if err := v.SetSecret("keep-me", vault.NewSecretValue([]byte("value"))); err != nil {
		t.Fatalf("SetSecret() error = %v", err)
	}

	path := vaultFilePath(dir)
	if err := os.WriteFile(path, []byte("{not json"), 0600); err != nil {
		t.Fatalf("failed to corrupt vault file: %v", err)
	}

	if _, err := vault.NewUnencryptedVault(unencryptedConfig(dir)); err == nil {
		t.Fatal("NewUnencryptedVault() accepted a corrupt vault file, want an error")
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read vault file: %v", err)
	}
	if string(data) != "{not json" {
		t.Errorf("corrupt vault file was overwritten with %q", string(data))
	}
}

// Every save rewrites the whole file from an in-memory snapshot taken when the
// provider was built. Two providers writing without a shared lock silently lose
// one of the two updates -- the per-instance RWMutex does nothing here.
func TestConcurrentWritesFromSeparateProvidersDoNotLoseUpdates(t *testing.T) {
	dir := t.TempDir()

	if _, err := vault.NewUnencryptedVault(unencryptedConfig(dir)); err != nil {
		t.Fatalf("NewUnencryptedVault() error = %v", err)
	}

	const writers = 8
	var wg sync.WaitGroup
	errs := make(chan error, writers)

	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			// A separate provider instance per writer: distinct in-memory state,
			// so only the cross-process file lock can serialize them.
			v, err := vault.NewUnencryptedVault(unencryptedConfig(dir))
			if err != nil {
				errs <- fmt.Errorf("writer %d: open: %w", n, err)
				return
			}
			key := fmt.Sprintf("key-%d", n)
			if err := v.SetSecret(key, vault.NewSecretValue([]byte("value"))); err != nil {
				errs <- fmt.Errorf("writer %d: set: %w", n, err)
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("%v", err)
	}

	final, err := vault.NewUnencryptedVault(unencryptedConfig(dir))
	if err != nil {
		t.Fatalf("reopen error = %v", err)
	}
	keys, err := final.ListSecrets()
	if err != nil {
		t.Fatalf("ListSecrets() error = %v", err)
	}
	if len(keys) != writers {
		t.Errorf("vault holds %d secrets (%v), want all %d -- updates were lost", len(keys), keys, writers)
	}
}

func TestAtomicWriteLeavesNoTempFilesAndKeepsModeOwnerOnly(t *testing.T) {
	dir := t.TempDir()

	v, err := vault.NewUnencryptedVault(unencryptedConfig(dir))
	if err != nil {
		t.Fatalf("NewUnencryptedVault() error = %v", err)
	}
	for i := 0; i < 5; i++ {
		if err := v.SetSecret(fmt.Sprintf("k%d", i), vault.NewSecretValue([]byte("v"))); err != nil {
			t.Fatalf("SetSecret() error = %v", err)
		}
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir() error = %v", err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".vault-") || strings.HasSuffix(e.Name(), ".tmp") {
			t.Errorf("temp file %q was left behind", e.Name())
		}
	}

	info, err := os.Stat(vaultFilePath(dir))
	if err != nil {
		t.Fatalf("Stat() error = %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Errorf("vault file mode = %o, want 0600", perm)
	}
}

// A fixed "<path>.tmp" name meant os.WriteFile would follow a symlink planted
// there and write the vault contents through it.
func TestAtomicWriteDoesNotFollowAPlantedTempSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(t.TempDir(), "victim.txt")
	if err := os.WriteFile(target, []byte("original"), 0600); err != nil {
		t.Fatalf("failed to create target: %v", err)
	}

	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	if err := os.Symlink(target, vaultFilePath(dir)+".tmp"); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	v, err := vault.NewUnencryptedVault(unencryptedConfig(dir))
	if err != nil {
		t.Fatalf("NewUnencryptedVault() error = %v", err)
	}
	if err := v.SetSecret("k", vault.NewSecretValue([]byte("secret"))); err != nil {
		t.Fatalf("SetSecret() error = %v", err)
	}

	data, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if string(data) != "original" {
		t.Errorf("the planted symlink was followed: target now holds %q", string(data))
	}
}

func TestLocalProvidersReportClosedRatherThanPanicking(t *testing.T) {
	dir := t.TempDir()

	v, err := vault.NewUnencryptedVault(unencryptedConfig(dir))
	if err != nil {
		t.Fatalf("NewUnencryptedVault() error = %v", err)
	}
	if err := v.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	// Every one of these dereferenced a nil state before the guards were added.
	if _, err := v.GetSecret("k"); !errors.Is(err, vault.ErrVaultClosed) {
		t.Errorf("GetSecret() after Close = %v, want ErrVaultClosed", err)
	}
	if err := v.SetSecret("k", vault.NewSecretValue([]byte("v"))); !errors.Is(err, vault.ErrVaultClosed) {
		t.Errorf("SetSecret() after Close = %v, want ErrVaultClosed", err)
	}
	if err := v.DeleteSecret("k"); !errors.Is(err, vault.ErrVaultClosed) {
		t.Errorf("DeleteSecret() after Close = %v, want ErrVaultClosed", err)
	}
	if _, err := v.ListSecrets(); !errors.Is(err, vault.ErrVaultClosed) {
		t.Errorf("ListSecrets() after Close = %v, want ErrVaultClosed", err)
	}
	if _, err := v.HasSecret("k"); !errors.Is(err, vault.ErrVaultClosed) {
		t.Errorf("HasSecret() after Close = %v, want ErrVaultClosed", err)
	}
	if _, err := v.Metadata(); !errors.Is(err, vault.ErrVaultClosed) {
		t.Errorf("Metadata() after Close = %v, want ErrVaultClosed", err)
	}
}
