package vault_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/flowexec/vault"
)

// A vault config carries the provider's command templates and environment
// values, and its presence alone discloses which secret backends a user has
// configured. The file was already 0600, but the directory SaveConfigJSON
// created for it was group-readable.
func TestSaveConfigJSONWritesOwnerOnly(t *testing.T) {
	dir := t.TempDir()
	nested := filepath.Join(dir, "configs")
	path := filepath.Join(nested, "myvault.json")

	cfg := vault.Config{
		ID:          "myvault",
		Type:        vault.ProviderTypeUnencrypted,
		Unencrypted: &vault.UnencryptedConfig{StoragePath: dir},
	}
	if err := vault.SaveConfigJSON(cfg, path); err != nil {
		t.Fatalf("SaveConfigJSON() error = %v", err)
	}

	fileInfo, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat(file) error = %v", err)
	}
	if perm := fileInfo.Mode().Perm(); perm != 0600 {
		t.Errorf("config file mode = %o, want 0600", perm)
	}

	dirInfo, err := os.Stat(nested)
	if err != nil {
		t.Fatalf("Stat(dir) error = %v", err)
	}
	if perm := dirInfo.Mode().Perm(); perm != 0700 {
		t.Errorf("config directory mode = %o, want 0700", perm)
	}
}
