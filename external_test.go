package vault_test

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/flowexec/vault"
)

// mockCommandContext creates mock commands for testing
func mockCommandContext(
	outputs map[string]string,
	errors map[string]error,
) func(ctx context.Context, cmd, input, dir string, envList []string) (string, error) {
	return func(ctx context.Context, cmd, input, dir string, envList []string) (string, error) {
		for _, output := range outputs {
			return output, nil
		}

		for range errors {
			return "", fmt.Errorf("mock error")
		}

		return "mock", nil
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
				External: &vault.ExternalConfig{
					Get: vault.CommandConfig{
						CommandTemplate: "vault kv get -format=json {{key}}",
					},
					Set: vault.CommandConfig{
						CommandTemplate: "vault kv put {{key}} value={{value}}",
					},
				},
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider, err := vault.NewExternalVaultProvider(tt.config)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewExternalVaultProvider() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && provider == nil {
				t.Error("NewExternalVaultProvider() returned nil provider")
			}
			if !tt.wantErr && provider.ID() != tt.config.ID {
				t.Errorf("NewExternalVaultProvider() ID = %v, want %v", provider.ID(), tt.config.ID)
			}
		})
	}
}

func TestExternalVaultProvider_GetSecret(t *testing.T) {
	config := &vault.Config{
		ID:   "test-vault",
		Type: vault.ProviderTypeExternal,
		External: &vault.ExternalConfig{
			Get: vault.CommandConfig{
				CommandTemplate: "vault kv get -format=json {{key}}",
			},
		},
	}

	provider, err := vault.NewExternalVaultProvider(config)
	if err != nil {
		t.Fatalf("Failed to create provider: %v", err)
	}

	tests := []struct {
		name          string
		key           string
		mockOutputs   map[string]string
		mockErrors    map[string]error
		wantSecret    string
		wantErr       bool
		errorContains string
	}{
		{
			name: "successful get",
			key:  "test-key",
			mockOutputs: map[string]string{
				"vault kv get -format=json test-key": "secret-value",
			},
			wantSecret: "secret-value",
			wantErr:    false,
		},
		{
			name: "command fails",
			key:  "test-key",
			mockErrors: map[string]error{
				"vault kv get -format=json test-key": fmt.Errorf("command failed"),
			},
			wantErr:       true,
			errorContains: "failed to get secret",
		},
		{
			name:          "invalid key",
			key:           "",
			wantErr:       true,
			errorContains: "invalid secret key",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testProvider := provider
			if tt.name == "get operation not configured" {
				testConfig := &vault.Config{
					ID:       "test-vault",
					Type:     vault.ProviderTypeExternal,
					External: &vault.ExternalConfig{},
				}
				var err error
				testProvider, err = vault.NewExternalVaultProvider(testConfig)
				if err != nil {
					t.Fatalf("Failed to create test provider: %v", err)
				}
			}

			testProvider.SetExecutionFunc(mockCommandContext(tt.mockOutputs, tt.mockErrors))

			secret, err := testProvider.GetSecret(tt.key)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetSecret() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if err != nil && tt.errorContains != "" {
				if !strings.Contains(err.Error(), tt.errorContains) {
					t.Errorf("GetSecret() error = %v, want error containing %v", err, tt.errorContains)
				}
				return
			}

			if !tt.wantErr && secret.PlainTextString() != tt.wantSecret {
				t.Errorf("GetSecret() secret = %v, want %v", secret.PlainTextString(), tt.wantSecret)
			}
		})
	}
}

func TestExternalVaultProvider_SetSecret(t *testing.T) {
	config := &vault.Config{
		ID:   "test-vault",
		Type: vault.ProviderTypeExternal,
		External: &vault.ExternalConfig{
			Set: vault.CommandConfig{
				CommandTemplate: "vault kv put {{key}} value={{value}}",
			},
		},
	}

	provider, err := vault.NewExternalVaultProvider(config)
	if err != nil {
		t.Fatalf("Failed to create provider: %v", err)
	}

	tests := []struct {
		name          string
		key           string
		value         string
		mockOutputs   map[string]string
		mockErrors    map[string]error
		wantErr       bool
		errorContains string
	}{
		{
			name:  "successful set",
			key:   "test-key",
			value: "test-value",
			mockOutputs: map[string]string{
				"vault kv put test-key value=test-value": "success",
			},
			wantErr: false,
		},
		{
			name:  "command fails",
			key:   "test-key",
			value: "test-value",
			mockErrors: map[string]error{
				"vault kv put test-key value=test-value": fmt.Errorf("command failed"),
			},
			wantErr:       true,
			errorContains: "failed to set secret",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testProvider := provider
			testProvider.SetExecutionFunc(mockCommandContext(tt.mockOutputs, tt.mockErrors))

			secret := vault.NewSecretValue([]byte(tt.value))
			err := testProvider.SetSecret(tt.key, secret)
			if (err != nil) != tt.wantErr {
				t.Errorf("SetSecret() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if err != nil && tt.errorContains != "" {
				if !strings.Contains(err.Error(), tt.errorContains) {
					t.Errorf("SetSecret() error = %v, want error containing %v", err, tt.errorContains)
				}
			}
		})
	}
}

func TestExternalVaultProvider_ListSecrets(t *testing.T) {
	config := &vault.Config{
		ID:   "test-vault",
		Type: vault.ProviderTypeExternal,
		External: &vault.ExternalConfig{
			List: vault.CommandConfig{
				CommandTemplate: "vault kv list",
			},
		},
	}

	provider, err := vault.NewExternalVaultProvider(config)
	if err != nil {
		t.Fatalf("Failed to create provider: %v", err)
	}

	tests := []struct {
		name        string
		mockOutputs map[string]string
		mockErrors  map[string]error
		wantSecrets []string
		wantErr     bool
	}{
		{
			name: "successful list",
			mockOutputs: map[string]string{
				"vault kv list": "secret1\nsecret2\nsecret3",
			},
			wantSecrets: []string{"secret1", "secret2", "secret3"},
			wantErr:     false,
		},
		{
			name: "empty list",
			mockOutputs: map[string]string{
				"vault kv list": "",
			},
			wantSecrets: []string{},
			wantErr:     false,
		},
		{
			name: "command fails",
			mockErrors: map[string]error{
				"vault kv list": fmt.Errorf("command failed"),
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testProvider := provider
			testProvider.SetExecutionFunc(mockCommandContext(tt.mockOutputs, tt.mockErrors))

			secrets, err := testProvider.ListSecrets()
			if (err != nil) != tt.wantErr {
				t.Errorf("ListSecrets() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				if len(secrets) != len(tt.wantSecrets) {
					t.Errorf("ListSecrets() returned %d secrets, want %d", len(secrets), len(tt.wantSecrets))
					return
				}
				for i, secret := range secrets {
					if secret != tt.wantSecrets[i] {
						t.Errorf("ListSecrets() secret[%d] = %v, want %v", i, secret, tt.wantSecrets[i])
					}
				}
			}
		})
	}
}

func TestExternalVaultProvider_HasSecret(t *testing.T) {
	config := &vault.Config{
		ID:   "test-vault",
		Type: vault.ProviderTypeExternal,
		External: &vault.ExternalConfig{
			Exists: vault.CommandConfig{
				CommandTemplate: "vault kv get {{key}}",
			},
		},
	}

	provider, err := vault.NewExternalVaultProvider(config)
	if err != nil {
		t.Fatalf("Failed to create provider: %v", err)
	}

	tests := []struct {
		name        string
		key         string
		mockOutputs map[string]string
		mockErrors  map[string]error
		wantExists  bool
		wantErr     bool
	}{
		{
			name: "secret exists",
			key:  "existing-key",
			mockOutputs: map[string]string{
				"vault kv get existing-key": "some-value",
			},
			wantExists: true,
			wantErr:    false,
		},
		{
			name: "secret does not exist",
			key:  "nonexistent-key",
			mockErrors: map[string]error{
				"vault kv get nonexistent-key": fmt.Errorf("not found"),
			},
			wantExists: false,
			wantErr:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testProvider := provider
			testProvider.SetExecutionFunc(mockCommandContext(tt.mockOutputs, tt.mockErrors))

			exists, err := testProvider.HasSecret(tt.key)
			if (err != nil) != tt.wantErr {
				t.Errorf("HasSecret() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if exists != tt.wantExists {
				t.Errorf("HasSecret() = %v, want %v", exists, tt.wantExists)
			}
		})
	}
}

func TestExternalVaultProvider_Metadata(t *testing.T) {
	tests := []struct {
		name        string
		config      *vault.ExternalConfig
		mockOutputs map[string]string
		mockErrors  map[string]error
		wantRawData string
	}{
		{
			name: "successful metadata retrieval",
			config: &vault.ExternalConfig{
				Metadata: vault.CommandConfig{
					CommandTemplate: "vault status",
				},
			},
			mockOutputs: map[string]string{
				"vault status": "vault is healthy",
			},
			wantRawData: "vault is healthy",
		},
		{
			name:        "no metadata command configured",
			config:      &vault.ExternalConfig{},
			wantRawData: "",
		},
		{
			name: "metadata command fails",
			config: &vault.ExternalConfig{
				Metadata: vault.CommandConfig{
					CommandTemplate: "vault status",
				},
			},
			mockErrors: map[string]error{
				"vault status": fmt.Errorf("command failed"),
			},
			wantRawData: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &vault.Config{
				ID:       "test-vault",
				Type:     vault.ProviderTypeExternal,
				External: tt.config,
			}

			provider, err := vault.NewExternalVaultProvider(config)
			if err != nil {
				t.Fatalf("Failed to create provider: %v", err)
			}

			testProvider := provider
			testProvider.SetExecutionFunc(mockCommandContext(tt.mockOutputs, tt.mockErrors))

			metadata := testProvider.Metadata()
			if metadata.RawData != tt.wantRawData {
				t.Errorf("Metadata().RawData = %v, want %v", metadata.RawData, tt.wantRawData)
			}
		})
	}
}
