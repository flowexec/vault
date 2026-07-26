package vault_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/flowexec/vault"
)

const testSecretValue = "s3cr3t"

// validExternalConfig returns a config that satisfies ExternalConfig.Validate.
// Get and Set command templates are mandatory, so every fixture needs them even
// when the test only exercises another operation.
func validExternalConfig() *vault.ExternalConfig {
	return &vault.ExternalConfig{
		Get: vault.CommandConfig{CommandTemplate: "vault kv get -format=json {{key}}"},
		Set: vault.CommandConfig{CommandTemplate: "vault kv put {{key}}"},
	}
}

func newTestProvider(t *testing.T, cfg *vault.ExternalConfig) *vault.ExternalVaultProvider {
	t.Helper()
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

// execCapture records what the provider actually asked the shell to run. The
// older mockCommandContext observes neither cmd nor input, so it cannot catch a
// provider rendering the wrong template or leaking a secret into a command.
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
				ID:       "test-vault",
				Type:     vault.ProviderTypeExternal,
				External: validExternalConfig(),
			},
			wantErr: false,
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
			name: "missing get and set templates",
			config: &vault.Config{
				ID:       "test-vault",
				Type:     vault.ProviderTypeExternal,
				External: &vault.ExternalConfig{},
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
					c.Timeout = "not-a-duration"
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

// A secret interpolated into a command template is a command-injection sink: the
// rendered string is parsed and run by a shell and the template engine does no
// quoting. Configs that try must be rejected at load, not silently accepted.
func TestConfigRejectsSecretValueInCommandTemplates(t *testing.T) {
	for _, tmpl := range []string{
		"vault kv put {{key}} value={{value}}",
		"vault kv put {{key}} value={{ value }}",
		"vault kv put {{key}} pw={{password}}",
	} {
		cfg := validExternalConfig()
		cfg.Set.CommandTemplate = tmpl

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

func TestSetSecret_ValueTravelsOverStdinNotTheCommand(t *testing.T) {
	cfg := validExternalConfig()
	cfg.Set.CommandTemplate = "store {{key}}"
	cfg.Set.InputTemplate = "{{ value }}"
	// A Get input template that must NOT be used for the set operation.
	cfg.Get.InputTemplate = "WRONG-TEMPLATE"

	provider := newTestProvider(t, cfg)
	rec := &execCapture{}
	provider.SetExecutionFunc(capturingExec(rec, "", nil))

	if err := provider.SetSecret("test-key", vault.NewSecretValue([]byte(testSecretValue))); err != nil {
		t.Fatalf("SetSecret() error = %v", err)
	}

	if rec.input != testSecretValue {
		t.Errorf("stdin = %q, want %q (set input template was not rendered)", rec.input, testSecretValue)
	}
	if strings.Contains(rec.cmd, testSecretValue) {
		t.Errorf("secret leaked into the command string: %q", rec.cmd)
	}
	if rec.cmd != "store test-key" {
		t.Errorf("cmd = %q, want %q", rec.cmd, "store test-key")
	}
}

// A value containing shell metacharacters must round-trip byte-exact. Before the
// fix, "p@$$w0rd" had $$ expanded to the PID and a different secret was stored.
func TestSetSecret_ValueWithShellMetacharactersIsUntouched(t *testing.T) {
	for _, value := range []string{
		`p@$$w0rd`,
		`correct horse battery`,
		`hunter2; echo pwned`,
		"back`tick`",
		`quote'and"quote`,
		"multi\nline",
	} {
		cfg := validExternalConfig()
		cfg.Set.CommandTemplate = "store {{key}}"
		cfg.Set.InputTemplate = "{{ value }}"

		provider := newTestProvider(t, cfg)
		rec := &execCapture{}
		provider.SetExecutionFunc(capturingExec(rec, "", nil))

		if err := provider.SetSecret("k", vault.NewSecretValue([]byte(value))); err != nil {
			t.Fatalf("SetSecret(%q) error = %v", value, err)
		}
		if rec.input != value {
			t.Errorf("stdin = %q, want %q", rec.input, value)
		}
		if strings.Contains(rec.cmd, value) {
			t.Errorf("value %q leaked into command %q", value, rec.cmd)
		}
	}
}

func TestSetSecret_InputTemplateSeesTheKey(t *testing.T) {
	cfg := validExternalConfig()
	cfg.Set.CommandTemplate = "store"
	cfg.Set.InputTemplate = "{{ key }}:{{ value }}"

	provider := newTestProvider(t, cfg)
	rec := &execCapture{}
	provider.SetExecutionFunc(capturingExec(rec, "", nil))

	if err := provider.SetSecret("my-key", vault.NewSecretValue([]byte(testSecretValue))); err != nil {
		t.Fatalf("SetSecret() error = %v", err)
	}
	if want := "my-key:" + testSecretValue; rec.input != want {
		t.Errorf("stdin = %q, want %q", rec.input, want)
	}
}

// Each operation must render its own input template. All of these previously
// rendered Get's template instead.
func TestOperationsRenderTheirOwnInputTemplate(t *testing.T) {
	t.Run("delete", func(t *testing.T) {
		cfg := validExternalConfig()
		cfg.Get.InputTemplate = "WRONG"
		cfg.Delete.CommandTemplate = "rm {{key}}"
		cfg.Delete.InputTemplate = "delete:{{ input }}"

		provider := newTestProvider(t, cfg)
		rec := &execCapture{}
		provider.SetExecutionFunc(capturingExec(rec, "", nil))

		if err := provider.DeleteSecret("k"); err != nil {
			t.Fatalf("DeleteSecret() error = %v", err)
		}
		if rec.input != "delete:k" {
			t.Errorf("stdin = %q, want %q", rec.input, "delete:k")
		}
	})

	t.Run("list", func(t *testing.T) {
		cfg := validExternalConfig()
		cfg.Get.InputTemplate = "WRONG"
		cfg.List.CommandTemplate = "ls"
		cfg.List.InputTemplate = "list-input"

		provider := newTestProvider(t, cfg)
		rec := &execCapture{}
		provider.SetExecutionFunc(capturingExec(rec, "a\nb", nil))

		if _, err := provider.ListSecrets(); err != nil {
			t.Fatalf("ListSecrets() error = %v", err)
		}
		if rec.input != "list-input" {
			t.Errorf("stdin = %q, want %q", rec.input, "list-input")
		}
	})

	// Metadata previously gated on List's input template, so a configured
	// metadata input was ignored unless list.input happened to be set too.
	t.Run("metadata", func(t *testing.T) {
		cfg := validExternalConfig()
		cfg.Metadata.CommandTemplate = "status"
		cfg.Metadata.InputTemplate = "meta-input"

		provider := newTestProvider(t, cfg)
		rec := &execCapture{}
		provider.SetExecutionFunc(capturingExec(rec, "ok", nil))

		if _, err := provider.Metadata(); err != nil {
			t.Fatalf("Metadata() error = %v", err)
		}
		if rec.input != "meta-input" {
			t.Errorf("stdin = %q, want %q", rec.input, "meta-input")
		}
	})
}

// Configs written against the old behaviour set only Get.InputTemplate; that
// must keep working.
func TestGetInputTemplateBackCompat(t *testing.T) {
	cfg := validExternalConfig()
	cfg.Get.InputTemplate = "{{ input }}"

	provider := newTestProvider(t, cfg)
	rec := &execCapture{}
	provider.SetExecutionFunc(capturingExec(rec, "value", nil))

	if _, err := provider.GetSecret("my-key"); err != nil {
		t.Fatalf("GetSecret() error = %v", err)
	}
	if rec.input != "my-key" {
		t.Errorf("stdin = %q, want %q", rec.input, "my-key")
	}
}

func TestExternalVaultProvider_GetSecret(t *testing.T) {
	tests := []struct {
		name          string
		key           string
		out           string
		execErr       error
		wantSecret    string
		wantErr       bool
		errorContains string
	}{
		{name: "successful get", key: "test-key", out: "secret-value", wantSecret: "secret-value"},
		{
			name: "command fails", key: "test-key", execErr: fmt.Errorf("command failed"),
			wantErr: true, errorContains: "failed to get secret",
		},
		{name: "invalid key", key: "", wantErr: true, errorContains: "invalid secret key"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider := newTestProvider(t, validExternalConfig())
			provider.SetExecutionFunc(capturingExec(&execCapture{}, tt.out, tt.execErr))

			secret, err := provider.GetSecret(tt.key)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetSecret() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil {
				if tt.errorContains != "" && !strings.Contains(err.Error(), tt.errorContains) {
					t.Errorf("GetSecret() error = %v, want error containing %v", err, tt.errorContains)
				}
				return
			}
			if secret.PlainTextString() != tt.wantSecret {
				t.Errorf("GetSecret() secret = %v, want %v", secret.PlainTextString(), tt.wantSecret)
			}
		})
	}
}

func TestExternalVaultProvider_ListSecrets(t *testing.T) {
	tests := []struct {
		name        string
		out         string
		execErr     error
		wantSecrets []string
		wantErr     bool
	}{
		{name: "successful list", out: "secret1\nsecret2\nsecret3", wantSecrets: []string{"secret1", "secret2", "secret3"}},
		{name: "empty list", out: "", wantSecrets: []string{}},
		{name: "command fails", execErr: fmt.Errorf("command failed"), wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validExternalConfig()
			cfg.List.CommandTemplate = "vault kv list"

			provider := newTestProvider(t, cfg)
			provider.SetExecutionFunc(capturingExec(&execCapture{}, tt.out, tt.execErr))

			secrets, err := provider.ListSecrets()
			if (err != nil) != tt.wantErr {
				t.Errorf("ListSecrets() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				return
			}
			if len(secrets) != len(tt.wantSecrets) {
				t.Fatalf("ListSecrets() returned %d secrets, want %d", len(secrets), len(tt.wantSecrets))
			}
			for i, secret := range secrets {
				if secret != tt.wantSecrets[i] {
					t.Errorf("ListSecrets() secret[%d] = %v, want %v", i, secret, tt.wantSecrets[i])
				}
			}
		})
	}
}

func TestExternalVaultProvider_HasSecret(t *testing.T) {
	tests := []struct {
		name       string
		key        string
		execErr    error
		wantExists bool
	}{
		{name: "secret exists", key: "existing-key", wantExists: true},
		{name: "secret does not exist", key: "nonexistent-key", execErr: fmt.Errorf("not found"), wantExists: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validExternalConfig()
			cfg.Exists.CommandTemplate = "vault kv get {{key}}"

			provider := newTestProvider(t, cfg)
			provider.SetExecutionFunc(capturingExec(&execCapture{}, "some-value", tt.execErr))

			exists, err := provider.HasSecret(tt.key)
			if err != nil {
				t.Fatalf("HasSecret() error = %v", err)
			}
			if exists != tt.wantExists {
				t.Errorf("HasSecret() = %v, want %v", exists, tt.wantExists)
			}
		})
	}
}

// NotFoundPattern separates "absent" from "the backend is broken". Without it,
// an expired session reports the secret as simply missing.
func TestHasSecret_NotFoundPatternDistinguishesRealFailures(t *testing.T) {
	cfg := validExternalConfig()
	cfg.Exists.CommandTemplate = "check {{key}}"
	cfg.NotFoundPattern = "ParameterNotFound"

	t.Run("absent", func(t *testing.T) {
		provider := newTestProvider(t, cfg)
		provider.SetExecutionFunc(capturingExec(&execCapture{}, "", fmt.Errorf("ParameterNotFound: nope")))

		exists, err := provider.HasSecret("k")
		if err != nil {
			t.Fatalf("HasSecret() error = %v", err)
		}
		if exists {
			t.Error("HasSecret() = true, want false")
		}
	})

	t.Run("real failure surfaces", func(t *testing.T) {
		provider := newTestProvider(t, cfg)
		provider.SetExecutionFunc(capturingExec(&execCapture{}, "", fmt.Errorf("ExpiredToken: session expired")))

		if _, err := provider.HasSecret("k"); err == nil {
			t.Error("HasSecret() error = nil, want the expired-session error to surface")
		}
	})
}

// HasSecret with no exists command delegates to the get path. Doing that through
// the exported GetSecret would take a second read lock, which deadlocks if a
// writer arrives in between, because sync.RWMutex is not reentrant.
func TestHasSecret_WithoutExistsCommandDoesNotDeadlock(t *testing.T) {
	provider := newTestProvider(t, validExternalConfig())
	provider.SetExecutionFunc(capturingExec(&execCapture{}, "value", nil))

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 50; i++ {
			_, _ = provider.HasSecret("k")
		}
	}()
	// Contend with writers so a queued writer sits between the two read locks.
	for i := 0; i < 50; i++ {
		_ = provider.SetSecret("k", vault.NewSecretValue([]byte("v")))
	}
	<-done
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
	cfg.List.CommandTemplate = "ls"
	cfg.Metadata.CommandTemplate = "status"

	provider := newTestProvider(t, cfg)
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
}

// Exercises the real execute(), not a mock. stderr merged into stdout on success
// concatenates backend warnings onto the secret value itself.
func TestExecute_StderrIsNotMergedIntoTheSecret(t *testing.T) {
	cfg := validExternalConfig()
	cfg.Get.CommandTemplate = "printf 'the-secret'; printf 'gpg: WARNING: unsafe permissions' 1>&2"

	provider := newTestProvider(t, cfg)

	secret, err := provider.GetSecret("k")
	if err != nil {
		t.Fatalf("GetSecret() error = %v", err)
	}
	if got := secret.PlainTextString(); got != "the-secret" {
		t.Errorf("GetSecret() = %q, want %q (stderr leaked into the value)", got, "the-secret")
	}
}

// End-to-end through the real shell, not a mock: a secret full of shell
// metacharacters must survive a set/get round trip byte-exact. This is the
// behaviour the injection fix exists to guarantee.
func TestExternalProvider_RoundTripThroughRealShell(t *testing.T) {
	dir := t.TempDir()
	store := filepath.Join(dir, "secret.txt")

	cfg := &vault.ExternalConfig{
		Get: vault.CommandConfig{CommandTemplate: "cat '" + store + "'"},
		Set: vault.CommandConfig{
			CommandTemplate: "cat > '" + store + "'",
			InputTemplate:   "{{ value }}",
		},
	}
	provider := newTestProvider(t, cfg)

	for _, value := range []string{
		`p@$$w0rd`,
		`correct horse battery`,
		`hunter2; echo pwned > ` + filepath.Join(dir, "injected"),
		"back`echo tick`",
		`quote'and"quote`,
		`glob*star?`,
		`$(id)`,
		`${HOME}`,
	} {
		if err := provider.SetSecret("k", vault.NewSecretValue([]byte(value))); err != nil {
			t.Fatalf("SetSecret(%q) error = %v", value, err)
		}

		secret, err := provider.GetSecret("k")
		if err != nil {
			t.Fatalf("GetSecret() after setting %q error = %v", value, err)
		}
		if got := secret.PlainTextString(); got != value {
			t.Errorf("round trip: got %q, want %q", got, value)
		}
	}

	// The injection attempt above must not have run.
	if _, err := os.Stat(filepath.Join(dir, "injected")); !os.IsNotExist(err) {
		t.Error("command injection succeeded: the payload created a file")
	}
}

// expandEnv used to mutate the shared config map while callers held only a read
// lock, which is an unrecoverable "concurrent map writes" fault. Run with -race.
func TestConcurrentGetSecretDoesNotRaceOnEnvironment(t *testing.T) {
	cfg := validExternalConfig()
	cfg.Environment = map[string]string{
		"HOME_REF": "$HOME",
		"LITERAL":  "$(tty)",
		"PLAIN":    "value",
	}

	provider := newTestProvider(t, cfg)
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
			_, _ = provider.Metadata()
		}()
	}
	wg.Wait()

	// The config map itself must be unchanged: expansion returns a new map.
	if got := cfg.Environment["LITERAL"]; got != "$(tty)" {
		t.Errorf("config Environment was mutated: LITERAL = %q, want %q", got, "$(tty)")
	}
}
