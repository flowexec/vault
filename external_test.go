package vault_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/flowexec/vault"
)

// validExternalConfig returns a config that satisfies ExternalConfig.Validate.
// Only a get command is mandatory now: an external vault reads through to a
// provider and never writes to it.
func validExternalConfig() *vault.ExternalConfig {
	return &vault.ExternalConfig{
		Get: vault.CommandConfig{CommandTemplate: "vault kv get -format=json {{ref}}"},
	}
}

// newTestProvider builds a provider over a throwaway storage directory, so each
// test gets its own link registry.
func newTestProvider(t *testing.T, cfg *vault.ExternalConfig) *vault.ExternalVaultProvider {
	t.Helper()
	if cfg.StoragePath == "" {
		cfg.StoragePath = t.TempDir()
	}
	provider, err := vault.NewExternalVaultProvider(&vault.Config{
		ID:       "test-vault",
		Type:     vault.ProviderTypeExternal,
		External: cfg,
	})
	if err != nil {
		t.Fatalf("Failed to create provider: %v", err)
	}
	return provider
}

// linkedProvider builds a provider with key already pointing at reference.
func linkedProvider(
	t *testing.T, cfg *vault.ExternalConfig, key, reference string,
) *vault.ExternalVaultProvider {
	t.Helper()
	provider := newTestProvider(t, cfg)
	if err := provider.Link(key, reference); err != nil {
		t.Fatalf("Link(%q, %q) error = %v", key, reference, err)
	}
	return provider
}

// execCapture records what the provider actually asked the shell to run. The
// older mockCommandContext observes neither cmd nor input, so it cannot catch a
// provider rendering the wrong template or running a command it should not.
type execCapture struct {
	cmd, input, dir string
	env             []string
	calls           int
}

func capturingExec(c *execCapture, out string, err error) func(
	context.Context, string, string, string, []string,
) (string, error) {
	return func(_ context.Context, cmd, input, dir string, envList []string) (string, error) {
		c.cmd, c.input, c.dir, c.env = cmd, input, dir, envList
		c.calls++
		return out, err
	}
}

func TestNewExternalVaultProvider(t *testing.T) {
	tests := []struct {
		name    string
		config  *vault.Config
		wantErr bool
	}{
		{
			name: "valid config",
			config: &vault.Config{
				ID:   "test-vault",
				Type: vault.ProviderTypeExternal,
				External: func() *vault.ExternalConfig {
					c := validExternalConfig()
					c.StoragePath = t.TempDir()
					return c
				}(),
			},
		},
		{
			name: "missing external config",
			config: &vault.Config{
				ID:   "test-vault",
				Type: vault.ProviderTypeExternal,
			},
			wantErr: true,
		},
		{
			name: "missing get template",
			config: &vault.Config{
				ID:       "test-vault",
				Type:     vault.ProviderTypeExternal,
				External: &vault.ExternalConfig{StoragePath: t.TempDir()},
			},
			wantErr: true,
		},
		{
			// A vault with nowhere to keep its registry cannot resolve a single
			// key, so this must fail at construction rather than at first read.
			name: "missing storage path",
			config: &vault.Config{
				ID:       "test-vault",
				Type:     vault.ProviderTypeExternal,
				External: validExternalConfig(),
			},
			wantErr: true,
		},
		{
			name: "invalid timeout",
			config: &vault.Config{
				ID:   "test-vault",
				Type: vault.ProviderTypeExternal,
				External: func() *vault.ExternalConfig {
					c := validExternalConfig()
					c.StoragePath = t.TempDir()
					c.Timeout = "not-a-duration"
					return c
				}(),
			},
			wantErr: true,
		},
		{
			name: "invalid reference pattern",
			config: &vault.Config{
				ID:   "test-vault",
				Type: vault.ProviderTypeExternal,
				External: func() *vault.ExternalConfig {
					c := validExternalConfig()
					c.StoragePath = t.TempDir()
					c.ReferencePattern = "([unclosed"
					return c
				}(),
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider, err := vault.NewExternalVaultProvider(tt.config)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewExternalVaultProvider() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				return
			}
			if provider == nil {
				t.Fatal("NewExternalVaultProvider() returned nil provider")
			}
			if provider.ID() != tt.config.ID {
				t.Errorf("NewExternalVaultProvider() ID = %v, want %v", provider.ID(), tt.config.ID)
			}
		})
	}
}

// An external vault never receives a secret value, so a template asking for one
// can only ever render empty. Rejecting it beats silently reading the wrong
// thing, and the check also still guards the old injection sink on any config
// carried over from before v0.4.0.
func TestConfigRejectsSecretValueInCommandTemplates(t *testing.T) {
	for _, tmpl := range []string{
		"vault kv get {{ref}} value={{value}}",
		"vault kv get {{ref}} value={{ value }}",
		"vault kv get {{ref}} pw={{password}}",
	} {
		cfg := validExternalConfig()
		cfg.StoragePath = t.TempDir()
		cfg.Get.CommandTemplate = tmpl

		_, err := vault.NewExternalVaultProvider(&vault.Config{
			ID: "test-vault", Type: vault.ProviderTypeExternal, External: cfg,
		})
		if err == nil {
			t.Errorf("template %q was accepted, want rejection", tmpl)
			continue
		}
		if !errors.Is(err, vault.ErrInvalidConfig) {
			t.Errorf("template %q: error = %v, want ErrInvalidConfig", tmpl, err)
		}
	}
}

// The whole point of the registry: the command addresses the provider's path,
// not the local alias.
func TestGetSecret_RendersTheReferenceNotTheKey(t *testing.T) {
	cfg := validExternalConfig()
	cfg.Get.CommandTemplate = "op read '{{ref}}'"

	provider := linkedProvider(t, cfg, "aws-key", "op://Team/AWS/access_key_id")
	rec := &execCapture{}
	provider.SetExecutionFunc(capturingExec(rec, "value", nil))

	if _, err := provider.GetSecret("aws-key"); err != nil {
		t.Fatalf("GetSecret() error = %v", err)
	}

	if want := "op read 'op://Team/AWS/access_key_id'"; rec.cmd != want {
		t.Errorf("cmd = %q, want %q", rec.cmd, want)
	}
}

// Both variables are available: {{ref}} for the provider, {{key}} for the alias.
func TestGetSecret_TemplateSeesBothKeyAndReference(t *testing.T) {
	cfg := validExternalConfig()
	cfg.Get.CommandTemplate = "get {{key}} from {{ref}}"

	provider := linkedProvider(t, cfg, "alias", "some/path")
	rec := &execCapture{}
	provider.SetExecutionFunc(capturingExec(rec, "v", nil))

	if _, err := provider.GetSecret("alias"); err != nil {
		t.Fatalf("GetSecret() error = %v", err)
	}
	if want := "get alias from some/path"; rec.cmd != want {
		t.Errorf("cmd = %q, want %q", rec.cmd, want)
	}
}

// An unlinked key is answered from the registry alone. Spawning a provider
// process to be told about a name the vault never knew is wasted work, and for
// 1Password it would raise a biometric prompt for a key that cannot resolve.
func TestGetSecret_UnknownKeyRunsNoCommand(t *testing.T) {
	provider := newTestProvider(t, validExternalConfig())
	rec := &execCapture{}
	provider.SetExecutionFunc(capturingExec(rec, "value", nil))

	_, err := provider.GetSecret("never-linked")
	if !errors.Is(err, vault.ErrSecretNotFound) {
		t.Errorf("GetSecret() error = %v, want ErrSecretNotFound", err)
	}
	if rec.calls != 0 {
		t.Errorf("ran %d commands for an unlinked key, want 0", rec.calls)
	}
}

// A link whose target has since been removed in the provider is a broken link,
// not a mystery failure.
func TestGetSecret_NotFoundPatternMarksABrokenLink(t *testing.T) {
	cfg := validExternalConfig()
	cfg.NotFoundPattern = "ParameterNotFound"

	provider := linkedProvider(t, cfg, "k", "/prod/db/password")
	provider.SetExecutionFunc(capturingExec(&execCapture{},
		"ParameterNotFound: nope", fmt.Errorf("exit status 254")))

	_, err := provider.GetSecret("k")
	if !errors.Is(err, vault.ErrSecretNotFound) {
		t.Errorf("GetSecret() error = %v, want ErrSecretNotFound", err)
	}
	if !strings.Contains(err.Error(), "/prod/db/password") {
		t.Errorf("error %v does not name the reference that failed", err)
	}
}

func TestSetSecret_IsRejected(t *testing.T) {
	provider := newTestProvider(t, validExternalConfig())
	rec := &execCapture{}
	provider.SetExecutionFunc(capturingExec(rec, "", nil))

	err := provider.SetSecret("k", vault.NewSecretValue([]byte("v")))
	if !errors.Is(err, vault.ErrReadOnly) {
		t.Errorf("SetSecret() error = %v, want ErrReadOnly", err)
	}
	if rec.calls != 0 {
		t.Errorf("ran %d commands, want 0", rec.calls)
	}
}

// The safety property this design exists for: removing a secret from the vault
// must not be able to destroy the data it points at.
func TestDeleteSecret_UnlinksAndRunsNoCommand(t *testing.T) {
	provider := linkedProvider(t, validExternalConfig(), "k", "team/db/password")
	rec := &execCapture{}
	provider.SetExecutionFunc(capturingExec(rec, "", nil))

	if err := provider.DeleteSecret("k"); err != nil {
		t.Fatalf("DeleteSecret() error = %v", err)
	}
	if rec.calls != 0 {
		t.Errorf("DeleteSecret ran %d commands against the provider, want 0", rec.calls)
	}

	exists, err := provider.HasSecret("k")
	if err != nil {
		t.Fatalf("HasSecret() error = %v", err)
	}
	if exists {
		t.Error("HasSecret() = true after delete, want false")
	}
}

func TestDeleteSecret_UnknownKeyIsAnError(t *testing.T) {
	provider := newTestProvider(t, validExternalConfig())
	if err := provider.DeleteSecret("nope"); !errors.Is(err, vault.ErrSecretNotFound) {
		t.Errorf("DeleteSecret() error = %v, want ErrSecretNotFound", err)
	}
}

// The vault lists what has been linked into it, not the provider's inventory.
func TestListSecrets_ReturnsLinkedKeysSorted(t *testing.T) {
	provider := newTestProvider(t, validExternalConfig())
	rec := &execCapture{}
	provider.SetExecutionFunc(capturingExec(rec, "SHOULD NOT BE USED", nil))

	for key, ref := range map[string]string{
		"zeta": "a/z", "alpha": "a/a", "mid": "a/m",
	} {
		if err := provider.Link(key, ref); err != nil {
			t.Fatalf("Link() error = %v", err)
		}
	}

	keys, err := provider.ListSecrets()
	if err != nil {
		t.Fatalf("ListSecrets() error = %v", err)
	}
	if want := []string{"alpha", "mid", "zeta"}; !equalStrings(keys, want) {
		t.Errorf("ListSecrets() = %v, want %v", keys, want)
	}
	if rec.calls != 0 {
		t.Errorf("ListSecrets ran %d commands, want 0", rec.calls)
	}
}

// A boolean must not cost a provider round trip: callers use HasSecret on paths
// that do not expect to block on the network or on a biometric prompt.
func TestHasSecret_IsARegistryLookup(t *testing.T) {
	provider := linkedProvider(t, validExternalConfig(), "linked", "a/b")
	rec := &execCapture{}
	provider.SetExecutionFunc(capturingExec(rec, "", fmt.Errorf("should not run")))

	for _, tc := range []struct {
		key  string
		want bool
	}{{"linked", true}, {"absent", false}} {
		got, err := provider.HasSecret(tc.key)
		if err != nil {
			t.Fatalf("HasSecret(%q) error = %v", tc.key, err)
		}
		if got != tc.want {
			t.Errorf("HasSecret(%q) = %v, want %v", tc.key, got, tc.want)
		}
	}
	if rec.calls != 0 {
		t.Errorf("HasSecret ran %d commands, want 0", rec.calls)
	}
}

func TestExternalVaultProvider_Metadata(t *testing.T) {
	t.Run("successful retrieval", func(t *testing.T) {
		cfg := validExternalConfig()
		cfg.Metadata.CommandTemplate = "vault status"

		provider := newTestProvider(t, cfg)
		provider.SetExecutionFunc(capturingExec(&execCapture{}, "vault is healthy", nil))

		metadata, err := provider.Metadata()
		if err != nil {
			t.Fatalf("Metadata() error = %v", err)
		}
		if metadata.RawData != "vault is healthy" {
			t.Errorf("Metadata().RawData = %v, want %v", metadata.RawData, "vault is healthy")
		}
	})

	t.Run("not configured is not an error", func(t *testing.T) {
		provider := newTestProvider(t, validExternalConfig())
		metadata, err := provider.Metadata()
		if err != nil {
			t.Fatalf("Metadata() error = %v", err)
		}
		if metadata.RawData != "" {
			t.Errorf("Metadata().RawData = %v, want empty", metadata.RawData)
		}
	})

	// Previously every failure path returned an empty Metadata{}, so a broken
	// command, a timeout and "not configured" were indistinguishable.
	t.Run("command failure surfaces as an error", func(t *testing.T) {
		cfg := validExternalConfig()
		cfg.Metadata.CommandTemplate = "vault status"

		provider := newTestProvider(t, cfg)
		provider.SetExecutionFunc(capturingExec(&execCapture{}, "", fmt.Errorf("command failed")))

		if _, err := provider.Metadata(); err == nil {
			t.Error("Metadata() error = nil, want the command failure to surface")
		}
	})
}

func TestClosedProviderReturnsErrVaultClosed(t *testing.T) {
	cfg := validExternalConfig()
	cfg.Metadata.CommandTemplate = "status"

	provider := linkedProvider(t, cfg, "k", "a/b")
	provider.SetExecutionFunc(capturingExec(&execCapture{}, "ok", nil))
	if err := provider.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	if _, err := provider.GetSecret("k"); !errors.Is(err, vault.ErrVaultClosed) {
		t.Errorf("GetSecret() after Close = %v, want ErrVaultClosed", err)
	}
	if err := provider.SetSecret("k", vault.NewSecretValue([]byte("v"))); !errors.Is(err, vault.ErrVaultClosed) {
		t.Errorf("SetSecret() after Close = %v, want ErrVaultClosed", err)
	}
	if err := provider.DeleteSecret("k"); !errors.Is(err, vault.ErrVaultClosed) {
		t.Errorf("DeleteSecret() after Close = %v, want ErrVaultClosed", err)
	}
	if _, err := provider.ListSecrets(); !errors.Is(err, vault.ErrVaultClosed) {
		t.Errorf("ListSecrets() after Close = %v, want ErrVaultClosed", err)
	}
	if _, err := provider.HasSecret("k"); !errors.Is(err, vault.ErrVaultClosed) {
		t.Errorf("HasSecret() after Close = %v, want ErrVaultClosed", err)
	}
	if _, err := provider.Metadata(); !errors.Is(err, vault.ErrVaultClosed) {
		t.Errorf("Metadata() after Close = %v, want ErrVaultClosed", err)
	}
	if err := provider.Link("k2", "a/c"); !errors.Is(err, vault.ErrVaultClosed) {
		t.Errorf("Link() after Close = %v, want ErrVaultClosed", err)
	}
	if _, err := provider.Links(); !errors.Is(err, vault.ErrVaultClosed) {
		t.Errorf("Links() after Close = %v, want ErrVaultClosed", err)
	}
}

// Exercises the real execute(), not a mock. stderr merged into stdout on success
// concatenates backend warnings onto the secret value itself.
func TestExecute_StderrIsNotMergedIntoTheSecret(t *testing.T) {
	cfg := validExternalConfig()
	cfg.Get.CommandTemplate = "printf 'the-secret'; printf 'gpg: WARNING: unsafe permissions' 1>&2"

	provider := linkedProvider(t, cfg, "k", "a/b")

	secret, err := provider.GetSecret("k")
	if err != nil {
		t.Fatalf("GetSecret() error = %v", err)
	}
	if got := secret.PlainTextString(); got != "the-secret" {
		t.Errorf("GetSecret() = %q, want %q (stderr leaked into the value)", got, "the-secret")
	}
}

// End-to-end through the real shell: a reference is substituted into a command a
// shell then parses, so the quoting has to survive contact with real data.
func TestGetSecret_ReferenceReachesTheRealShellIntact(t *testing.T) {
	cfg := validExternalConfig()
	cfg.Get.CommandTemplate = "printf '%s' '{{ref}}'"

	for _, reference := range []string{
		"op://Team/AWS/access_key_id",
		"team/db/password",
		"/prod/service-a/api key",
		"path/with*glob?chars",
		"trailing/space ",
	} {
		provider := newTestProvider(t, cfg)
		if err := provider.Link("k", reference); err != nil {
			t.Fatalf("Link(%q) error = %v", reference, err)
		}

		secret, err := provider.GetSecret("k")
		if err != nil {
			t.Fatalf("GetSecret() for %q error = %v", reference, err)
		}
		if got := secret.PlainTextString(); got != reference {
			t.Errorf("reference reached the shell as %q, want %q", got, reference)
		}
	}
}

// expandEnv used to mutate the shared config map while callers held only a read
// lock, which is an unrecoverable "concurrent map writes" fault. Run with -race.
func TestConcurrentReadsDoNotRaceOnEnvironment(t *testing.T) {
	cfg := validExternalConfig()
	cfg.Metadata.CommandTemplate = "status"
	cfg.Environment = map[string]string{
		"HOME_REF": "$HOME",
		"LITERAL":  "$(tty)",
		"PLAIN":    "value",
	}

	provider := linkedProvider(t, cfg, "k", "a/b")
	// Reads are concurrent by design, so the exec func must be stateless here --
	// a shared execCapture would itself race and mask what we are testing.
	provider.SetExecutionFunc(func(
		_ context.Context, _, _, _ string, _ []string,
	) (string, error) {
		return "value", nil
	})

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = provider.GetSecret("k")
			_, _ = provider.ListSecrets()
			_, _ = provider.HasSecret("k")
			_, _ = provider.Metadata()
		}()
	}
	wg.Wait()

	// The config map itself must be unchanged: expansion returns a new map.
	if got := cfg.Environment["LITERAL"]; got != "$(tty)" {
		t.Errorf("config Environment was mutated: LITERAL = %q, want %q", got, "$(tty)")
	}
}

// GetSecret used to TrimSpace the command's output, so a secret with deliberate
// leading or trailing whitespace was stored correctly by the backend and came
// back mangled. Only the single trailing newline a command adds is removed.
func TestGetSecret_PreservesDeliberateWhitespace(t *testing.T) {
	for _, tc := range []struct {
		name, stdout, want string
	}{
		{"leading space", " value\n", " value"},
		{"trailing space", "value \n", "value "},
		{"only spaces", "   \n", "   "},
		{"tabs", "\tvalue\t\n", "\tvalue\t"},
		{"internal newlines", "line1\nline2\n", "line1\nline2"},
		{"no trailing newline", "value", "value"},
		{"crlf", "value\r\n", "value"},
		{"empty", "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			provider := linkedProvider(t, validExternalConfig(), "k", "a/b")
			provider.SetExecutionFunc(func(
				_ context.Context, _, _, _ string, _ []string,
			) (string, error) {
				return tc.stdout, nil
			})

			secret, err := provider.GetSecret("k")
			if err != nil {
				t.Fatalf("GetSecret() error = %v", err)
			}
			if got := secret.PlainTextString(); got != tc.want {
				t.Errorf("GetSecret() = %q, want %q", got, tc.want)
			}
		})
	}
}

// Metadata still tidies its output; only the secret value is verbatim.
func TestMetadataStillTrims(t *testing.T) {
	cfg := validExternalConfig()
	cfg.Metadata.CommandTemplate = "status"

	provider := newTestProvider(t, cfg)
	provider.SetExecutionFunc(func(
		_ context.Context, _, _, _ string, _ []string,
	) (string, error) {
		return "  account 1234  \n", nil
	})

	md, err := provider.Metadata()
	if err != nil {
		t.Fatalf("Metadata() error = %v", err)
	}
	if md.RawData != "account 1234" {
		t.Errorf("Metadata().RawData = %q, want %q", md.RawData, "account 1234")
	}
}

func equalStrings(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}
