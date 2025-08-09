package vault_test

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/flowexec/vault"
)

func TestUnencryptedVault_New(t *testing.T) {
	tempDir := t.TempDir()

	vlt, cfg, err := vault.New("test-vault",
		vault.WithProvider(vault.ProviderTypeUnencrypted),
		vault.WithUnencryptedPath(tempDir),
	)
	if err != nil {
		t.Fatalf("Failed to create unencrypted vault: %v", err)
	}
	defer vlt.Close()

	if vlt.ID() != "test-vault" {
		t.Errorf("Expected vault ID 'test-vault', got '%s'", vlt.ID())
	}

	if cfg.Type != vault.ProviderTypeUnencrypted {
		t.Errorf("Expected provider type '%s', got '%s'", vault.ProviderTypeUnencrypted, cfg.Type)
	}

	if cfg.Unencrypted == nil {
		t.Fatal("Expected unencrypted config to be set")
	}

	if cfg.Unencrypted.StoragePath != tempDir {
		t.Errorf("Expected storage path '%s', got '%s'", tempDir, cfg.Unencrypted.StoragePath)
	}
}

func TestUnencryptedVault_SecretOperations(t *testing.T) {
	tempDir := t.TempDir()

	vlt, _, err := vault.New("test-vault",
		vault.WithProvider(vault.ProviderTypeUnencrypted),
		vault.WithUnencryptedPath(tempDir),
	)
	if err != nil {
		t.Fatalf("Failed to create unencrypted vault: %v", err)
	}
	defer vlt.Close()

	// Test setting a secret
	testKey := "test-key"
	testValue := "test-value"
	secret := vault.NewSecretValue([]byte(testValue))

	err = vlt.SetSecret(testKey, secret)
	if err != nil {
		t.Fatalf("Failed to set secret: %v", err)
	}

	// Test getting the secret
	retrievedSecret, err := vlt.GetSecret(testKey)
	if err != nil {
		t.Fatalf("Failed to get secret: %v", err)
	}

	if retrievedSecret.PlainTextString() != testValue {
		t.Errorf("Expected secret value '%s', got '%s'", testValue, retrievedSecret.PlainTextString())
	}

	// Test HasSecret
	exists, err := vlt.HasSecret(testKey)
	if err != nil {
		t.Fatalf("Failed to check if secret exists: %v", err)
	}
	if !exists {
		t.Error("Expected secret to exist")
	}

	// Test ListSecrets
	secrets, err := vlt.ListSecrets()
	if err != nil {
		t.Fatalf("Failed to list secrets: %v", err)
	}
	if len(secrets) != 1 {
		t.Errorf("Expected 1 secret, got %d", len(secrets))
	}
	if secrets[0] != testKey {
		t.Errorf("Expected secret key '%s', got '%s'", testKey, secrets[0])
	}

	// Test deleting the secret
	err = vlt.DeleteSecret(testKey)
	if err != nil {
		t.Fatalf("Failed to delete secret: %v", err)
	}

	// Verify secret is gone
	exists, err = vlt.HasSecret(testKey)
	if err != nil {
		t.Fatalf("Failed to check if secret exists after deletion: %v", err)
	}
	if exists {
		t.Error("Expected secret to not exist after deletion")
	}

	// Test getting non-existent secret
	_, err = vlt.GetSecret(testKey)
	if !errors.Is(err, vault.ErrSecretNotFound) {
		t.Errorf("Expected ErrSecretNotFound, got %v", err)
	}

	// Test deleting non-existent secret
	err = vlt.DeleteSecret(testKey)
	if !errors.Is(err, vault.ErrSecretNotFound) {
		t.Errorf("Expected ErrSecretNotFound when deleting non-existent secret, got %v", err)
	}
}

func TestUnencryptedVault_FileFormat(t *testing.T) {
	tempDir := t.TempDir()

	vlt, _, err := vault.New("test-vault",
		vault.WithProvider(vault.ProviderTypeUnencrypted),
		vault.WithUnencryptedPath(tempDir),
	)
	if err != nil {
		t.Fatalf("Failed to create unencrypted vault: %v", err)
	}
	defer vlt.Close()

	// Set multiple secrets
	secrets := map[string]string{
		"API_KEY":      "secret-api-key",
		"DATABASE_URL": "postgresql://user:pass@host:5432/db",
		"DEBUG":        "true",
		"QUOTED_VALUE": "value with spaces",
	}

	for key, value := range secrets {
		err = vlt.SetSecret(key, vault.NewSecretValue([]byte(value)))
		if err != nil {
			t.Fatalf("Failed to set secret %s: %v", key, err)
		}
	}

	// Read the file directly to verify JSON format
	vaultFilePath := filepath.Join(tempDir, "vault-test-vault.json")
	content, err := os.ReadFile(vaultFilePath)
	if err != nil {
		t.Fatalf("Failed to read vault file: %v", err)
	}

	contentStr := string(content)
	t.Logf("Vault file content:\n%s", contentStr)

	// Parse the JSON to verify structure
	var vaultData map[string]interface{}
	if err := json.Unmarshal(content, &vaultData); err != nil {
		t.Fatalf("Expected valid JSON format, got parse error: %v", err)
	}

	// Verify required fields exist
	if vaultData["id"] != "test-vault" {
		t.Errorf("Expected vault ID 'test-vault', got %v", vaultData["id"])
	}
	if vaultData["version"] != float64(1) {
		t.Errorf("Expected version 1, got %v", vaultData["version"])
	}

	// Verify metadata exists
	metadata, metadataExists := vaultData["metadata"].(map[string]interface{})
	if !metadataExists {
		t.Fatal("Expected metadata field in vault file")
	}
	if _, createdExists := metadata["created"]; !createdExists {
		t.Error("Expected created timestamp in metadata")
	}
	if _, lastModifiedExists := metadata["lastModified"]; !lastModifiedExists {
		t.Error("Expected lastModified timestamp in metadata")
	}

	// Verify secrets are properly stored
	secretsData, secretsExists := vaultData["secrets"].(map[string]interface{})
	if !secretsExists {
		t.Fatal("Expected secrets field in vault file")
	}

	for key, expectedValue := range secrets {
		actualValue, valueExists := secretsData[key]
		if !valueExists {
			t.Errorf("Expected secret key '%s' to be present", key)
			continue
		}
		if actualValue != expectedValue {
			t.Errorf("Expected secret value '%s' for key '%s', got '%v'", expectedValue, key, actualValue)
		}
	}
}

func TestUnencryptedVault_Persistence(t *testing.T) {
	tempDir := t.TempDir()

	// Create first vault instance and add a secret
	vault1, _, err := vault.New("test-vault",
		vault.WithProvider(vault.ProviderTypeUnencrypted),
		vault.WithUnencryptedPath(tempDir),
	)
	if err != nil {
		t.Fatalf("Failed to create first vault: %v", err)
	}

	testKey := "persistent-key"
	testValue := "persistent-value"
	err = vault1.SetSecret(testKey, vault.NewSecretValue([]byte(testValue)))
	if err != nil {
		t.Fatalf("Failed to set secret in first vault: %v", err)
	}
	vault1.Close()

	// Create second vault instance with same configuration
	vault2, _, err := vault.New("test-vault",
		vault.WithProvider(vault.ProviderTypeUnencrypted),
		vault.WithUnencryptedPath(tempDir),
	)
	if err != nil {
		t.Fatalf("Failed to create second vault: %v", err)
	}
	defer vault2.Close()

	// Verify secret persists
	retrievedSecret, err := vault2.GetSecret(testKey)
	if err != nil {
		t.Fatalf("Failed to get secret from second vault: %v", err)
	}

	if retrievedSecret.PlainTextString() != testValue {
		t.Errorf("Expected persisted secret value '%s', got '%s'", testValue, retrievedSecret.PlainTextString())
	}

	// Verify metadata is preserved
	metadata := vault2.Metadata()
	if metadata.Created.IsZero() {
		t.Error("Expected creation time to be preserved")
	}
	if metadata.LastModified.IsZero() {
		t.Error("Expected last modified time to be preserved")
	}
}

func TestUnencryptedVault_Metadata(t *testing.T) {
	tempDir := t.TempDir()

	vlt, _, err := vault.New("test-vault",
		vault.WithProvider(vault.ProviderTypeUnencrypted),
		vault.WithUnencryptedPath(tempDir),
	)
	if err != nil {
		t.Fatalf("Failed to create vault: %v", err)
	}
	defer vlt.Close()

	metadata := vlt.Metadata()
	if metadata.Created.IsZero() {
		t.Error("Expected creation time to be set")
	}
	if metadata.LastModified.IsZero() {
		t.Error("Expected last modified time to be set")
	}

	// Add a secret and verify last modified time is updated
	oldModified := metadata.LastModified
	time.Sleep(10 * time.Millisecond) // Ensure some time passes

	err = vlt.SetSecret("test-key", vault.NewSecretValue([]byte("test-value")))
	if err != nil {
		t.Fatalf("Failed to set secret: %v", err)
	}

	newMetadata := vlt.Metadata()
	if !newMetadata.LastModified.After(oldModified) {
		t.Error("Expected last modified time to be updated after setting secret")
	}
}

func TestUnencryptedVault_SortedOutput(t *testing.T) {
	tempDir := t.TempDir()

	vlt, _, err := vault.New("test-vault",
		vault.WithProvider(vault.ProviderTypeUnencrypted),
		vault.WithUnencryptedPath(tempDir),
	)
	if err != nil {
		t.Fatalf("Failed to create vault: %v", err)
	}
	defer vlt.Close()

	// Add secrets in non-alphabetical order
	secretKeys := []string{"zebra", "alpha", "beta", "gamma"}
	for _, key := range secretKeys {
		err = vlt.SetSecret(key, vault.NewSecretValue([]byte("value-"+key)))
		if err != nil {
			t.Fatalf("Failed to set secret %s: %v", key, err)
		}
	}

	// List secrets and verify they are sorted
	listedKeys, err := vlt.ListSecrets()
	if err != nil {
		t.Fatalf("Failed to list secrets: %v", err)
	}

	expectedOrder := []string{"alpha", "beta", "gamma", "zebra"}
	if len(listedKeys) != len(expectedOrder) {
		t.Fatalf("Expected %d keys, got %d", len(expectedOrder), len(listedKeys))
	}

	for i, expected := range expectedOrder {
		if listedKeys[i] != expected {
			t.Errorf("Expected key at position %d to be '%s', got '%s'", i, expected, listedKeys[i])
		}
	}

	// Verify JSON format maintains sorted order (JSON doesn't guarantee key order,
	// but our implementation should maintain sorted keys in memory)
	vaultFilePath := filepath.Join(tempDir, "vault-test-vault.json")
	content, err := os.ReadFile(vaultFilePath)
	if err != nil {
		t.Fatalf("Failed to read vault file: %v", err)
	}

	// Parse JSON to verify secrets are present
	var vaultData map[string]interface{}
	if err := json.Unmarshal(content, &vaultData); err != nil {
		t.Fatalf("Expected valid JSON format, got parse error: %v", err)
	}

	secretsData, secretsExists := vaultData["secrets"].(map[string]interface{})
	if !secretsExists {
		t.Fatal("Expected secrets field in JSON")
	}

	// Verify all expected keys are present in the JSON
	for _, expectedKey := range expectedOrder {
		if _, keyExists := secretsData[expectedKey]; !keyExists {
			t.Errorf("Expected secret key '%s' to be present in JSON", expectedKey)
		}
	}
}
