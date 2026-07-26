package vault_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/flowexec/vault"
)

func TestLinkRoundTrip(t *testing.T) {
	provider := newTestProvider(t, validExternalConfig())

	if err := provider.Link("aws-key", "op://Team/AWS/access_key_id"); err != nil {
		t.Fatalf("Link() error = %v", err)
	}

	ref, err := provider.Reference("aws-key")
	if err != nil {
		t.Fatalf("Reference() error = %v", err)
	}
	if want := "op://Team/AWS/access_key_id"; ref != want {
		t.Errorf("Reference() = %q, want %q", ref, want)
	}

	links, err := provider.Links()
	if err != nil {
		t.Fatalf("Links() error = %v", err)
	}
	if len(links) != 1 || links["aws-key"] != "op://Team/AWS/access_key_id" {
		t.Errorf("Links() = %v, want one entry for aws-key", links)
	}
}

// Two fields of one item, addressed separately. This is the case the previous
// design could not express at all: it hardcoded the password field.
func TestLinkAddressesIndividualFieldsOfOneItem(t *testing.T) {
	provider := newTestProvider(t, validExternalConfig())

	for alias, ref := range map[string]string{
		"aws-access-key": "op://Team/AWS/access_key_id",
		"aws-secret-key": "op://Team/AWS/secret_access_key",
	} {
		if err := provider.Link(alias, ref); err != nil {
			t.Fatalf("Link(%q) error = %v", alias, err)
		}
	}

	links, err := provider.Links()
	if err != nil {
		t.Fatalf("Links() error = %v", err)
	}
	if links["aws-access-key"] == links["aws-secret-key"] {
		t.Fatal("both aliases resolved to the same reference")
	}
	if links["aws-secret-key"] != "op://Team/AWS/secret_access_key" {
		t.Errorf("aws-secret-key = %q, want the secret_access_key field", links["aws-secret-key"])
	}
}

func TestLinkReplacesAnExistingLink(t *testing.T) {
	provider := newTestProvider(t, validExternalConfig())

	if err := provider.Link("k", "old/path"); err != nil {
		t.Fatalf("Link() error = %v", err)
	}
	if err := provider.Link("k", "new/path"); err != nil {
		t.Fatalf("Link() error = %v", err)
	}

	ref, err := provider.Reference("k")
	if err != nil {
		t.Fatalf("Reference() error = %v", err)
	}
	if ref != "new/path" {
		t.Errorf("Reference() = %q, want %q", ref, "new/path")
	}
}

func TestUnlinkUnknownKeyIsAnError(t *testing.T) {
	provider := newTestProvider(t, validExternalConfig())
	if err := provider.Unlink("never-linked"); !errors.Is(err, vault.ErrSecretNotFound) {
		t.Errorf("Unlink() error = %v, want ErrSecretNotFound", err)
	}
}

// The registry outlives the process: a link made by one provider must be visible
// to the next one opened over the same storage.
func TestLinksPersistAcrossProviders(t *testing.T) {
	dir := t.TempDir()

	cfg := validExternalConfig()
	cfg.StoragePath = dir
	first := newTestProvider(t, cfg)
	if err := first.Link("k", "a/b"); err != nil {
		t.Fatalf("Link() error = %v", err)
	}

	cfg2 := validExternalConfig()
	cfg2.StoragePath = dir
	second := newTestProvider(t, cfg2)

	ref, err := second.Reference("k")
	if err != nil {
		t.Fatalf("Reference() from a second provider error = %v", err)
	}
	if ref != "a/b" {
		t.Errorf("Reference() = %q, want %q", ref, "a/b")
	}
}

// The registry is not secret material, but it enumerates the name and location
// of every secret in use, which is not something to leave world-readable.
func TestRegistryFileIsOwnerOnly(t *testing.T) {
	dir := t.TempDir()
	cfg := validExternalConfig()
	cfg.StoragePath = dir

	provider := newTestProvider(t, cfg)
	if err := provider.Link("k", "a/b"); err != nil {
		t.Fatalf("Link() error = %v", err)
	}

	matches, err := filepath.Glob(filepath.Join(dir, "*links.json"))
	if err != nil || len(matches) != 1 {
		t.Fatalf("expected exactly one registry file in %s, found %v (err %v)", dir, matches, err)
	}

	info, err := os.Stat(matches[0])
	if err != nil {
		t.Fatalf("Stat() error = %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("registry mode = %o, want 600", perm)
	}
}

// The safety floor. Each of these would change the meaning of the command the
// reference is substituted into, and the pattern is deliberately permissive here
// to prove the floor is what rejects them rather than the provider's own shape
// check.
func TestLinkRejectsUnsafeReferences(t *testing.T) {
	cfg := validExternalConfig()
	cfg.ReferencePattern = ".*"

	for _, reference := range []string{
		"",
		"a'; rm -rf /; '",
		`a"b`,
		"a`id`b",
		"a$(id)b",
		"a$HOME",
		`a\b`,
		"a\nb",
		"a\rb",
		"a\x00b",
		"-rf",
		"--vault",
		"../../etc/passwd",
		"a/../../../etc/passwd",
	} {
		provider := newTestProvider(t, cfg)
		err := provider.Link("k", reference)
		if err == nil {
			t.Errorf("Link(%q) was accepted, want rejection", reference)
			continue
		}
		if !errors.Is(err, vault.ErrInvalidReference) {
			t.Errorf("Link(%q) error = %v, want ErrInvalidReference", reference, err)
		}
	}
}

func TestLinkRejectsAnOverlongReference(t *testing.T) {
	provider := newTestProvider(t, validExternalConfig())
	long := ""
	for i := 0; i < 3000; i++ {
		long += "a"
	}
	if err := provider.Link("k", long); !errors.Is(err, vault.ErrInvalidReference) {
		t.Errorf("Link(<3000 chars>) error = %v, want ErrInvalidReference", err)
	}
}

// The pattern catches a reference that is safe but wrong for this provider, so
// a typo fails at link time rather than at read time.
func TestLinkAppliesTheProviderReferencePattern(t *testing.T) {
	cfg := validExternalConfig()
	cfg.ReferencePattern = `^op://[^/]+/[^/]+/[^/]+$`

	provider := newTestProvider(t, cfg)

	if err := provider.Link("ok", "op://Team/AWS/access_key_id"); err != nil {
		t.Errorf("Link() on a well-formed op reference error = %v", err)
	}
	err := provider.Link("bad", "just-a-name")
	if !errors.Is(err, vault.ErrInvalidReference) {
		t.Errorf("Link() on a malformed reference error = %v, want ErrInvalidReference", err)
	}
}

// A registry is a file on disk, so a reference can arrive by hand-editing rather
// than through Link. The floor has to be applied on the way out too, because
// that is the point where the reference reaches a shell.
func TestHandEditedUnsafeReferenceIsRejectedOnRead(t *testing.T) {
	dir := t.TempDir()
	cfg := validExternalConfig()
	cfg.StoragePath = dir

	provider := newTestProvider(t, cfg)
	if err := provider.Link("k", "safe/path"); err != nil {
		t.Fatalf("Link() error = %v", err)
	}

	matches, _ := filepath.Glob(filepath.Join(dir, "*links.json"))
	if len(matches) != 1 {
		t.Fatalf("expected one registry file, found %v", matches)
	}
	tampered := `{"version":1,"links":{"k":"a$(id)b"}}`
	if err := os.WriteFile(matches[0], []byte(tampered), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	rec := &execCapture{}
	provider.SetExecutionFunc(capturingExec(rec, "value", nil))

	_, err := provider.GetSecret("k")
	if !errors.Is(err, vault.ErrInvalidReference) {
		t.Errorf("GetSecret() on a tampered reference = %v, want ErrInvalidReference", err)
	}
	if rec.calls != 0 {
		t.Errorf("ran %d commands with a tampered reference, want 0", rec.calls)
	}
}

// Every write rewrites the whole registry file, so an unsynchronised
// read-modify-write silently drops another writer's link. The lock has to span
// the read as well as the write.
func TestConcurrentLinksDoNotLoseEntries(t *testing.T) {
	dir := t.TempDir()
	const writers = 8

	var wg sync.WaitGroup
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			// A separate provider per goroutine: sharing one would be serialised
			// by its own mutex and would not exercise the file lock at all.
			cfg := validExternalConfig()
			cfg.StoragePath = dir
			provider, err := vault.NewExternalVaultProvider(&vault.Config{
				ID: "test-vault", Type: vault.ProviderTypeExternal, External: cfg,
			})
			if err != nil {
				t.Errorf("NewExternalVaultProvider() error = %v", err)
				return
			}
			if err := provider.Link(fmt.Sprintf("key-%d", i), fmt.Sprintf("path/%d", i)); err != nil {
				t.Errorf("Link() error = %v", err)
			}
		}(i)
	}
	wg.Wait()

	cfg := validExternalConfig()
	cfg.StoragePath = dir
	provider := newTestProvider(t, cfg)
	links, err := provider.Links()
	if err != nil {
		t.Fatalf("Links() error = %v", err)
	}
	if len(links) != writers {
		t.Errorf("registry holds %d links, want %d -- concurrent writes were lost: %v",
			len(links), writers, links)
	}
}

// A registry written by a newer version of the library must not be parsed as
// though it were the current format.
func TestRegistryFromANewerVersionIsRejected(t *testing.T) {
	dir := t.TempDir()
	cfg := validExternalConfig()
	cfg.StoragePath = dir

	provider := newTestProvider(t, cfg)
	if err := provider.Link("k", "a/b"); err != nil {
		t.Fatalf("Link() error = %v", err)
	}

	matches, _ := filepath.Glob(filepath.Join(dir, "*links.json"))
	if err := os.WriteFile(matches[0], []byte(`{"version":99,"links":{}}`), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	if _, err := provider.Links(); !errors.Is(err, vault.ErrVaultCorrupt) {
		t.Errorf("Links() on a future-version registry = %v, want ErrVaultCorrupt", err)
	}
}

func TestMigrateLegacyLinks(t *testing.T) {
	cfg := validExternalConfig()
	cfg.LegacyList = vault.CommandConfig{CommandTemplate: "list-them"}

	provider := newTestProvider(t, cfg)
	// "team/db/password" is a name a legacy backend can report but which was
	// never a valid key, so it is skipped rather than failing the migration.
	provider.SetExecutionFunc(capturingExec(&execCapture{},
		"api-key\nlegacy-token\nteam/db/password\n", nil))

	migrated, err := provider.MigrateLegacyLinks()
	if err != nil {
		t.Fatalf("MigrateLegacyLinks() error = %v", err)
	}
	if want := []string{"api-key", "legacy-token"}; !equalStrings(migrated, want) {
		t.Errorf("MigrateLegacyLinks() = %v, want %v", migrated, want)
	}

	ref, err := provider.Reference("api-key")
	if err != nil {
		t.Fatalf("Reference() error = %v", err)
	}
	if ref != "api-key" {
		t.Errorf("migrated reference = %q, want the key itself (%q)", ref, "api-key")
	}
}

// Migration must be repeatable, and must never overwrite a link someone has
// already re-pointed at where the secret actually lives.
func TestMigrateLegacyLinksPreservesExistingLinks(t *testing.T) {
	cfg := validExternalConfig()
	cfg.LegacyList = vault.CommandConfig{CommandTemplate: "list-them"}

	provider := newTestProvider(t, cfg)
	if err := provider.Link("api-key", "op://Team/Service/api_key"); err != nil {
		t.Fatalf("Link() error = %v", err)
	}
	provider.SetExecutionFunc(capturingExec(&execCapture{}, "api-key\n", nil))

	migrated, err := provider.MigrateLegacyLinks()
	if err != nil {
		t.Fatalf("MigrateLegacyLinks() error = %v", err)
	}
	if len(migrated) != 0 {
		t.Errorf("MigrateLegacyLinks() = %v, want nothing migrated", migrated)
	}

	ref, _ := provider.Reference("api-key")
	if ref != "op://Team/Service/api_key" {
		t.Errorf("existing link was overwritten: %q", ref)
	}
}

func TestMigrateLegacyLinksWithoutALegacyListIsAnError(t *testing.T) {
	provider := newTestProvider(t, validExternalConfig())
	if _, err := provider.MigrateLegacyLinks(); !errors.Is(err, vault.ErrInvalidConfig) {
		t.Errorf("MigrateLegacyLinks() error = %v, want ErrInvalidConfig", err)
	}
}

// A pre-v0.4.0 config still unmarshals rather than failing at load, and reports
// which of its commands are now inert.
func TestLegacyConfigLoadsAndReportsInertCommands(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "legacy.json")
	legacy := `{
	  "id": "legacy",
	  "type": "external",
	  "external": {
	    "get":    { "cmd": "pass show {{key}}" },
	    "set":    { "cmd": "pass insert {{key}}" },
	    "delete": { "cmd": "pass rm {{key}}" },
	    "list":   { "cmd": "pass ls" },
	    "exists": { "cmd": "test -f {{key}}" }
	  }
	}`
	if err := os.WriteFile(path, []byte(legacy), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	cfg, err := vault.LoadConfigJSON(path)
	if err != nil {
		t.Fatalf("LoadConfigJSON() on a legacy config error = %v", err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() on a legacy config error = %v", err)
	}

	inert := cfg.External.LegacyWriteCommands()
	if want := []string{"set", "delete", "list", "exists"}; !equalStrings(inert, want) {
		t.Errorf("LegacyWriteCommands() = %v, want %v", inert, want)
	}
}

// A closed vault must not still be mutating files on disk.
func TestUnlinkAfterCloseIsRejected(t *testing.T) {
	provider := linkedProvider(t, validExternalConfig(), "k", "a/b")
	if err := provider.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if err := provider.Unlink("k"); !errors.Is(err, vault.ErrVaultClosed) {
		t.Errorf("Unlink() after Close = %v, want ErrVaultClosed", err)
	}
}

var _ = context.Background
