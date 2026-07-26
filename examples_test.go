package vault_test

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/flowexec/vault"
)

// sampleReference is a reference of the shape each shipped example expects,
// used to prove the config's reference pattern accepts a realistic value and
// that the rendered command addresses it.
var sampleReference = map[string]string{
	"aws-ssm.json":   "/prod/db/password",
	"1password.json": "op://Team/AWS/access_key_id",
	"bitwarden.json": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
	"pass.json":      "team/db/password",
}

// Every config shipped under examples/providers must load, validate, accept a
// realistic reference and render its operations. Nothing previously exercised
// these files, which is how three of them came to interpolate the secret
// straight into a shell command and how the pass example's set shipped broken.
func TestShippedExampleProvidersAreUsable(t *testing.T) {
	files, err := filepath.Glob("examples/providers/*.json")
	if err != nil {
		t.Fatalf("Glob() error = %v", err)
	}
	if len(files) == 0 {
		t.Fatal("no example provider configs found")
	}

	for _, file := range files {
		t.Run(filepath.Base(file), func(t *testing.T) {
			reference, ok := sampleReference[filepath.Base(file)]
			if !ok {
				t.Fatalf("no sample reference defined for %s; add one so its pattern is covered", file)
			}

			cfg, err := vault.LoadConfigJSON(file)
			if err != nil {
				t.Fatalf("LoadConfigJSON() error = %v", err)
			}

			// The examples deliberately omit storage_path: a config authored for
			// distribution does not know where the consuming tool keeps vault
			// state. Supplying it here is exactly what that tool does.
			cfg.External.StoragePath = t.TempDir()

			provider, err := vault.NewExternalVaultProvider(&cfg)
			if err != nil {
				t.Fatalf("config was rejected: %v", err)
			}

			var (
				lastCmd string
				nextOut string
			)
			provider.SetExecutionFunc(func(
				_ context.Context, cmd, _, _ string, _ []string,
			) (string, error) {
				lastCmd = cmd
				return nextOut, nil
			})

			if err := provider.Link("test-key", reference); err != nil {
				t.Fatalf("Link(%q) was rejected by this provider's reference pattern: %v", reference, err)
			}

			nextOut = "the-secret"
			secretValue, err := provider.GetSecret("test-key")
			if err != nil {
				t.Fatalf("GetSecret() error = %v", err)
			}
			if secretValue.PlainTextString() != "the-secret" {
				t.Errorf("GetSecret() = %q, want %q", secretValue.PlainTextString(), "the-secret")
			}
			// The command must address the provider's own path, not the alias.
			if !strings.Contains(lastCmd, reference) {
				t.Errorf("get command %q does not carry the reference %q", lastCmd, reference)
			}
			if strings.Contains(lastCmd, "{{") {
				t.Errorf("get command %q left an unrendered template", lastCmd)
			}

			keys, err := provider.ListSecrets()
			if err != nil {
				t.Fatalf("ListSecrets() error = %v", err)
			}
			if len(keys) != 1 || keys[0] != "test-key" {
				t.Errorf("ListSecrets() = %v, want [test-key]", keys)
			}

			nextOut = `{"Account":"123456789012","Arn":"arn:aws:iam::123456789012:user/dev"}`
			if _, err := provider.Metadata(); err != nil {
				t.Errorf("Metadata() error = %v", err)
			}
		})
	}
}

// A read-through vault must not ship a write command, and must not carry a
// construct the rendering pipeline would silently mangle.
func TestShippedExampleProvidersAreReadOnly(t *testing.T) {
	files, _ := filepath.Glob("examples/providers/*.json")

	for _, file := range files {
		t.Run(filepath.Base(file), func(t *testing.T) {
			cfg, err := vault.LoadConfigJSON(file)
			if err != nil {
				t.Fatalf("LoadConfigJSON() error = %v", err)
			}

			if inert := cfg.External.LegacyWriteCommands(); len(inert) != 0 {
				t.Errorf("example still defines write-era commands %v, which are never executed", inert)
			}

			if cfg.External.ReferencePattern == "" {
				t.Error("example defines no reference_pattern, so a mistyped reference fails only at read time")
			}

			for name, op := range map[string]vault.CommandConfig{
				"get":      cfg.External.Get,
				"metadata": cfg.External.Metadata,
			} {
				if op.CommandTemplate == "" {
					continue
				}
				// A backtick anywhere breaks the expression template, which
				// wraps expressions in backticks itself.
				if strings.Contains(op.CommandTemplate, "`") {
					t.Errorf("%s command contains a backtick, which the template engine cannot carry", name)
				}
			}
		})
	}
}
