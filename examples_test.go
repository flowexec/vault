package vault_test

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/flowexec/vault"
)

// Every config shipped under examples/providers must load, validate, and render
// each of its operations. Nothing previously exercised these files, which is how
// three of them came to interpolate the secret straight into a shell command and
// how the pass example's stdin-based set shipped permanently broken.
func TestShippedExampleProvidersAreUsable(t *testing.T) {
	files, err := filepath.Glob("examples/providers/*.json")
	if err != nil {
		t.Fatalf("Glob() error = %v", err)
	}
	if len(files) == 0 {
		t.Fatal("no example provider configs found")
	}

	const secret = "s3cr3t-$(id)-'quoted'"

	// Sample backend output per provider, shaped the way that CLI actually
	// responds, so the output templates are genuinely exercised rather than
	// handed something they happen to tolerate.
	sampleOutput := map[string]struct{ list, metadata string }{
		"aws-ssm.json": {
			list:     `{"Parameters":[{"Name":"/alpha"},{"Name":"/beta"}]}`,
			metadata: `{"Account":"123456789012","Arn":"arn:aws:iam::123456789012:user/dev"}`,
		},
		"1password.json": {
			list:     `[{"title":"alpha"},{"title":"beta"}]`,
			metadata: `dev@example.com`,
		},
		"bitwarden.json": {
			list:     `[{"name":"alpha"},{"name":"beta"}]`,
			metadata: `{"status":"unlocked"}`,
		},
		"pass.json": {
			list:     "alpha\nbeta",
			metadata: "AAAA1111",
		},
	}

	for _, file := range files {
		t.Run(filepath.Base(file), func(t *testing.T) {
			samples, ok := sampleOutput[filepath.Base(file)]
			if !ok {
				t.Fatalf("no sample output defined for %s; add one so its templates are covered", file)
			}

			cfg, err := vault.LoadConfigJSON(file)
			if err != nil {
				t.Fatalf("LoadConfigJSON() error = %v", err)
			}

			provider, err := vault.NewExternalVaultProvider(&cfg)
			if err != nil {
				t.Fatalf("config was rejected: %v", err)
			}

			var (
				lastCmd   string
				lastInput string
				nextOut   string
			)
			provider.SetExecutionFunc(func(
				_ context.Context, cmd, input, _ string, _ []string,
			) (string, error) {
				lastCmd, lastInput = cmd, input
				return nextOut, nil
			})

			// Set: the secret must reach stdin and never the command string.
			if err := provider.SetSecret("test-key", vault.NewSecretValue([]byte(secret))); err != nil {
				t.Fatalf("SetSecret() error = %v", err)
			}
			if lastInput != secret {
				t.Errorf("set stdin = %q, want the secret %q", lastInput, secret)
			}
			if strings.Contains(lastCmd, secret) {
				t.Errorf("the secret leaked into the set command: %q", lastCmd)
			}

			// Every other configured operation must render without error.
			nextOut = "the-secret"
			secretValue, err := provider.GetSecret("test-key")
			if err != nil {
				t.Errorf("GetSecret() error = %v", err)
			} else if secretValue.PlainTextString() != "the-secret" {
				t.Errorf("GetSecret() = %q, want %q", secretValue.PlainTextString(), "the-secret")
			}

			nextOut = ""
			if err := provider.DeleteSecret("test-key"); err != nil {
				t.Errorf("DeleteSecret() error = %v", err)
			}

			nextOut = samples.list
			keys, err := provider.ListSecrets()
			if err != nil {
				t.Errorf("ListSecrets() error = %v", err)
			} else if len(keys) != 2 || keys[0] != "alpha" || keys[1] != "beta" {
				t.Errorf("ListSecrets() = %v, want [alpha beta]", keys)
			}

			nextOut = ""
			if _, err := provider.HasSecret("test-key"); err != nil {
				t.Errorf("HasSecret() error = %v", err)
			}

			nextOut = samples.metadata
			if _, err := provider.Metadata(); err != nil {
				t.Errorf("Metadata() error = %v", err)
			}
		})
	}
}

// The rendered commands must not carry template or shell hazards that the
// rendering pipeline would silently mangle.
func TestShippedExampleProvidersRenderCleanCommands(t *testing.T) {
	files, _ := filepath.Glob("examples/providers/*.json")

	for _, file := range files {
		t.Run(filepath.Base(file), func(t *testing.T) {
			cfg, err := vault.LoadConfigJSON(file)
			if err != nil {
				t.Fatalf("LoadConfigJSON() error = %v", err)
			}

			for name, op := range map[string]vault.CommandConfig{
				"get":      cfg.External.Get,
				"set":      cfg.External.Set,
				"delete":   cfg.External.Delete,
				"list":     cfg.External.List,
				"exists":   cfg.External.Exists,
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
