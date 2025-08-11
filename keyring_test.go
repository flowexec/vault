package vault_test

import (
	"errors"
	"testing"

	"github.com/zalando/go-keyring"

	"github.com/flowexec/vault"
)

const testKeyringService = "flowexec-vault-test"

func TestKeyringVault_New(t *testing.T) {
	keyring.MockInit()
	vlt, cfg, err := vault.New("test-keyring-vault",
		vault.WithProvider(vault.ProviderTypeKeyring),
		vault.WithKeyringService(testKeyringService),
	)
	if err != nil {
		t.Fatalf("Failed to create keyring vault: %v", err)
	}
	defer vlt.Close()

	if vlt.ID() != "test-keyring-vault" {
		t.Errorf("Expected vault ID 'test-keyring-vault', got '%s'", vlt.ID())
	}

	if cfg.Type != vault.ProviderTypeKeyring {
		t.Errorf("Expected provider type '%s', got '%s'", vault.ProviderTypeKeyring, cfg.Type)
	}

	if cfg.Keyring == nil {
		t.Fatal("Expected keyring config to be set")
	}

	if cfg.Keyring.Service != testKeyringService {
		t.Errorf("Expected service name '%s', got '%s'", testKeyringService, cfg.Keyring.Service)
	}
}

func TestKeyringVault_SecretOperations(t *testing.T) {
	keyring.MockInit()
	vlt, _, err := vault.New("test-keyring-vault",
		vault.WithProvider(vault.ProviderTypeKeyring),
		vault.WithKeyringService(testKeyringService),
	)
	if err != nil {
		t.Fatalf("Failed to create keyring vault: %v", err)
	}
	defer func() {
		secrets, _ := vlt.ListSecrets()
		for _, key := range secrets {
			_ = vlt.DeleteSecret(key)
		}
		vlt.Close()
	}()

	// Test setting a secret
	testKey := "test-keyring-key"
	testValue := "test-keyring-value"
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

func TestKeyringVault_MultipleSecrets(t *testing.T) {
	keyring.MockInit()
	vlt, _, err := vault.New("test-keyring-vault-multiple",
		vault.WithProvider(vault.ProviderTypeKeyring),
		vault.WithKeyringService(testKeyringService),
	)
	if err != nil {
		t.Fatalf("Failed to create keyring vault: %v", err)
	}
	defer func() {
		// Clean up any remaining secrets before closing
		secrets, _ := vlt.ListSecrets()
		for _, key := range secrets {
			_ = vlt.DeleteSecret(key)
		}
		vlt.Close()
	}()

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

	// Verify all secrets can be retrieved
	for key, expectedValue := range secrets {
		secret, err := vlt.GetSecret(key)
		if err != nil {
			t.Fatalf("Failed to get secret %s: %v", key, err)
		}
		if secret.PlainTextString() != expectedValue {
			t.Errorf("Expected secret value '%s' for key '%s', got '%s'", expectedValue, key, secret.PlainTextString())
		}
	}

	// Test ListSecrets returns all keys in sorted order
	listedKeys, err := vlt.ListSecrets()
	if err != nil {
		t.Fatalf("Failed to list secrets: %v", err)
	}

	expectedKeys := []string{"API_KEY", "DATABASE_URL", "DEBUG", "QUOTED_VALUE"}
	if len(listedKeys) != len(expectedKeys) {
		t.Errorf("Expected %d secrets, got %d", len(expectedKeys), len(listedKeys))
	}

	for i, expectedKey := range expectedKeys {
		if i >= len(listedKeys) {
			t.Errorf("Expected key '%s' at position %d, but list is too short", expectedKey, i)
			continue
		}
		if listedKeys[i] != expectedKey {
			t.Errorf("Expected key '%s' at position %d, got '%s'", expectedKey, i, listedKeys[i])
		}
	}

	// Clean up - delete all secrets
	for key := range secrets {
		err = vlt.DeleteSecret(key)
		if err != nil {
			t.Fatalf("Failed to delete secret %s: %v", key, err)
		}
	}

	// Verify all secrets are gone
	listedKeys, err = vlt.ListSecrets()
	if err != nil {
		t.Fatalf("Failed to list secrets after cleanup: %v", err)
	}
	if len(listedKeys) != 0 {
		t.Errorf("Expected 0 secrets after cleanup, got %d", len(listedKeys))
	}
}

func TestKeyringVault_Persistence(t *testing.T) {
	keyring.MockInit()
	testKey := "persistent-keyring-key"
	testValue := "persistent-keyring-value"

	// Create first vault instance and add a secret
	vault1, _, err := vault.New("test-keyring-persistence",
		vault.WithProvider(vault.ProviderTypeKeyring),
		vault.WithKeyringService(testKeyringService),
	)
	if err != nil {
		t.Fatalf("Failed to create first vault: %v", err)
	}

	err = vault1.SetSecret(testKey, vault.NewSecretValue([]byte(testValue)))
	if err != nil {
		t.Fatalf("Failed to set secret in first vault: %v", err)
	}
	vault1.Close()

	// Create second vault instance with same configuration
	vault2, _, err := vault.New("test-keyring-persistence",
		vault.WithProvider(vault.ProviderTypeKeyring),
		vault.WithKeyringService(testKeyringService),
	)
	if err != nil {
		t.Fatalf("Failed to create second vault: %v", err)
	}
	defer func() {
		// Clean up
		_ = vault2.DeleteSecret(testKey)
		vault2.Close()
	}()

	// Verify secret persists
	retrievedSecret, err := vault2.GetSecret(testKey)
	if err != nil {
		t.Fatalf("Failed to get secret from second vault: %v", err)
	}

	if retrievedSecret.PlainTextString() != testValue {
		t.Errorf("Expected persisted secret value '%s', got '%s'", testValue, retrievedSecret.PlainTextString())
	}

	// Verify metadata is accessible
	metadata := vault2.Metadata()
	if metadata.Created.IsZero() {
		t.Error("Expected creation time to be set")
	}
	if metadata.LastModified.IsZero() {
		t.Error("Expected last modified time to be set")
	}
}

func TestKeyringVault_Metadata(t *testing.T) {
	keyring.MockInit()
	vlt, _, err := vault.New("test-keyring-metadata",
		vault.WithProvider(vault.ProviderTypeKeyring),
		vault.WithKeyringService(testKeyringService),
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

	err = vlt.SetSecret("test-key", vault.NewSecretValue([]byte("test-value")))
	if err != nil {
		t.Fatalf("Failed to set secret: %v", err)
	}

	newMetadata := vlt.Metadata()
	if !newMetadata.LastModified.After(oldModified) {
		t.Error("Expected last modified time to be updated after setting secret")
	}

	// Clean up
	_ = vlt.DeleteSecret("test-key")
}

func TestKeyringVault_InvalidKeyValidation(t *testing.T) {
	keyring.MockInit()
	vlt, _, err := vault.New("test-keyring-validation",
		vault.WithProvider(vault.ProviderTypeKeyring),
		vault.WithKeyringService(testKeyringService),
	)
	if err != nil {
		t.Fatalf("Failed to create vault: %v", err)
	}
	defer vlt.Close()

	// Test empty key
	err = vlt.SetSecret("", vault.NewSecretValue([]byte("value")))
	if err == nil {
		t.Error("Expected error when setting secret with empty key")
	}

	_, err = vlt.GetSecret("")
	if err == nil {
		t.Error("Expected error when getting secret with empty key")
	}

	err = vlt.DeleteSecret("")
	if err == nil {
		t.Error("Expected error when deleting secret with empty key")
	}

	_, err = vlt.HasSecret("")
	if err == nil {
		t.Error("Expected error when checking secret with empty key")
	}
}

func TestKeyringVault_SortedOutput(t *testing.T) {
	keyring.MockInit()
	vlt, _, err := vault.New("test-keyring-sorted",
		vault.WithProvider(vault.ProviderTypeKeyring),
		vault.WithKeyringService(testKeyringService),
	)
	if err != nil {
		t.Fatalf("Failed to create vault: %v", err)
	}
	defer func() {
		// Clean up any remaining secrets before closing
		secrets, _ := vlt.ListSecrets()
		for _, key := range secrets {
			_ = vlt.DeleteSecret(key)
		}
		vlt.Close()
	}()

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
}
