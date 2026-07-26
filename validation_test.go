package vault_test

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/flowexec/vault"
)

// A vault ID is interpolated into a filename, and filepath.Clean *resolves*
// traversal rather than sanitizing it: Clean("vault-../../../tmp/evil.enc")
// yields "../tmp/evil.enc", which escapes the storage directory once joined.
func TestVaultIDCannotEscapeTheStorageDirectory(t *testing.T) {
	hostile := []string{
		"../../../tmp/evil",
		"..",
		"../sibling",
		"a/b",
		`a\b`,
		".hidden",
		"-leading-dash",
		"has space",
		"semi;colon",
		"",
	}

	for _, id := range hostile {
		t.Run(id, func(t *testing.T) {
			dir := t.TempDir()
			_, err := vault.NewUnencryptedVault(&vault.Config{
				ID:          id,
				Type:        vault.ProviderTypeUnencrypted,
				Unencrypted: &vault.UnencryptedConfig{StoragePath: dir},
			})
			if err == nil {
				t.Fatalf("vault ID %q was accepted, want rejection", id)
			}
		})
	}
}

// The traversal is only interesting if it would otherwise have written outside
// the storage directory, so assert that directly.
func TestTraversalVaultIDWritesNothingOutsideStorage(t *testing.T) {
	base := t.TempDir()
	storage := filepath.Join(base, "storage")
	if err := os.MkdirAll(storage, 0700); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}

	_, err := vault.NewUnencryptedVault(&vault.Config{
		ID:          "../escaped",
		Type:        vault.ProviderTypeUnencrypted,
		Unencrypted: &vault.UnencryptedConfig{StoragePath: storage},
	})
	if err == nil {
		t.Fatal("a traversing vault ID was accepted")
	}

	entries, err := os.ReadDir(base)
	if err != nil {
		t.Fatalf("ReadDir() error = %v", err)
	}
	for _, e := range entries {
		if e.Name() != "storage" {
			t.Errorf("something was written outside the storage directory: %q", e.Name())
		}
	}
}

func TestValidateSecretKey(t *testing.T) {
	valid := []string{"key", "my-key", "my_key", "my.key", "a1", "A.B-C_d"}
	for _, key := range valid {
		if err := vault.ValidateSecretKey(key); err != nil {
			t.Errorf("ValidateSecretKey(%q) = %v, want nil", key, err)
		}
	}

	invalid := []struct {
		key, why string
	}{
		{"", "empty"},
		{"has space", "space"},
		{"has/slash", "path separator"},
		{"semi;colon", "shell metacharacter"},
		{"$(id)", "command substitution"},
		// A leading dash makes the key look like an option to any backend CLI
		// the external provider shells out to.
		{"-f", "leading dash"},
		{"--vault", "leading dash"},
		// "." and ".." are path elements; the external provider passes keys to
		// tools like pass where they address entries within a store.
		{".", "current directory"},
		{"..", "parent directory"},
	}
	for _, tc := range invalid {
		if err := vault.ValidateSecretKey(tc.key); err == nil {
			t.Errorf("ValidateSecretKey(%q) = nil, want rejection (%s)", tc.key, tc.why)
		}
	}
}

// New() returned the concrete typed pointer even on error, which Go wraps in a
// non-nil interface. `if provider != nil` then passed and the next call
// panicked on a nil receiver.
func TestNewReturnsATrulyNilProviderOnError(t *testing.T) {
	provider, _, err := vault.New("test", vault.WithProvider(vault.ProviderTypeAge))
	if err == nil {
		t.Fatal("expected an error for an age vault with no configuration")
	}
	if provider != nil {
		t.Errorf("New() returned a non-nil Provider (%T) alongside an error", provider)
	}
}

func TestNewRejectsUnsupportedProviderType(t *testing.T) {
	provider, _, err := vault.New("test", vault.WithProvider("nope"))
	if err == nil {
		t.Fatal("expected an error for an unsupported provider type")
	}
	if provider != nil {
		t.Errorf("New() returned a non-nil Provider (%T) alongside an error", provider)
	}
	if !errors.Is(err, vault.ErrInvalidConfig) {
		t.Errorf("error = %v, want ErrInvalidConfig", err)
	}
}

// The masked String() must apply to a dereferenced copy too. With a pointer
// receiver, fmt.Sprintf("%v", *secret) fell outside the method set and printed
// the raw bytes.
func TestSecretMasksItselfEvenWhenDereferenced(t *testing.T) {
	secret := vault.NewSecretValue([]byte("top-secret-value"))

	for name, rendered := range map[string]string{
		"pointer":      fmt.Sprintf("%v", secret),
		"dereferenced": fmt.Sprintf("%v", *secret),
	} {
		if strings.Contains(rendered, "top-secret-value") {
			t.Errorf("%s formatting leaked the secret: %s", name, rendered)
		}
	}
}

// WithLocalPath switched on the provider type the moment it ran, so it was a
// silent no-op unless WithProvider happened to be passed first -- surfacing
// later as a confusing "storage path is required".
func TestWithLocalPathIsOrderIndependent(t *testing.T) {
	t.Run("path before provider", func(t *testing.T) {
		dir := t.TempDir()
		_, cfg, err := vault.New("v1",
			vault.WithLocalPath(dir),
			vault.WithProvider(vault.ProviderTypeUnencrypted),
		)
		if err != nil {
			t.Fatalf("New() error = %v", err)
		}
		if cfg.Unencrypted == nil || cfg.Unencrypted.StoragePath != dir {
			t.Errorf("storage path was not applied: %+v", cfg.Unencrypted)
		}
	})

	t.Run("provider before path", func(t *testing.T) {
		dir := t.TempDir()
		_, cfg, err := vault.New("v1",
			vault.WithProvider(vault.ProviderTypeUnencrypted),
			vault.WithLocalPath(dir),
		)
		if err != nil {
			t.Fatalf("New() error = %v", err)
		}
		if cfg.Unencrypted == nil || cfg.Unencrypted.StoragePath != dir {
			t.Errorf("storage path was not applied: %+v", cfg.Unencrypted)
		}
	})
}

// The version field was written on every save but never read back, so a vault
// from a future format would have been parsed as though it were current.
func TestNewerVaultVersionIsRejected(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "vault-v1.json")

	if err := os.WriteFile(path, []byte(`{"version":99,"id":"v1","secrets":{}}`), 0600); err != nil {
		t.Fatalf("failed to seed vault file: %v", err)
	}

	_, err := vault.NewUnencryptedVault(&vault.Config{
		ID:          "v1",
		Type:        vault.ProviderTypeUnencrypted,
		Unencrypted: &vault.UnencryptedConfig{StoragePath: dir},
	})
	if err == nil {
		t.Fatal("a newer vault format version was accepted")
	}
	if !errors.Is(err, vault.ErrVaultCorrupt) {
		t.Errorf("error = %v, want ErrVaultCorrupt", err)
	}
}

func TestSecretZeroClearsTheBuffer(t *testing.T) {
	secret := vault.NewSecretValue([]byte("top-secret-value"))
	secret.Zero()

	if got := secret.PlainTextString(); got != "" {
		t.Errorf("PlainTextString() after Zero() = %q, want empty", got)
	}
	if got := secret.Bytes(); len(got) != 0 {
		t.Errorf("Bytes() after Zero() = %v, want empty", got)
	}
}
