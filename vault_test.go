package vault_test

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jahvon/vault"
)

func TestVaultInterface(t *testing.T) {
	tests := []struct {
		name     string
		provider vault.ProviderType
		setup    func(t *testing.T, dir string) vault.Provider
	}{
		{
			name:     "AES256 Vault",
			provider: vault.ProviderTypeAES256,
			setup:    setupAESVault,
		},
		{
			name:     "Age Vault",
			provider: vault.ProviderTypeAge,
			setup:    setupAgeVault,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tempDir := t.TempDir()

			v := tt.setup(t, tempDir)
			defer v.Close()

			testBasicOperations(t, v)
			testSecretOperations(t, v)
			testPersistence(t, v, tt.provider, tempDir)
		})
	}
}

func setupAESVault(t *testing.T, dir string) vault.Provider {
	// Only generate a new key if one isn't already set
	if os.Getenv(vault.DefaultVaultKeyEnv) == "" {
		key, err := vault.GenerateEncryptionKey()
		if err != nil {
			t.Fatalf("Failed to generate test key: %v", err)
		}
		t.Setenv(vault.DefaultVaultKeyEnv, key)
	}

	v, err := vault.New("test-aes",
		vault.WithProvider(vault.ProviderTypeAES256),
		vault.WithAESPath(dir),
		vault.WithAESKeyFromEnv(vault.DefaultVaultKeyEnv),
	)
	if err != nil {
		t.Fatalf("Failed to create AES vault: %v", err)
	}

	return v
}

func setupAgeVault(t *testing.T, dir string) vault.Provider {
	testIdentity := "AGE-SECRET-KEY-1LC563A3EG4TLDL5EQE0YP5ZSJW8NADURXLZ8WVM00DMKG60URRNQ5TRZH0"
	testRecipient := "age1wnhg53pg2qfsfxwvxvlg6pygw5uzwcyhj2dqhg0k83fvjexf9pzsxqdvs0"

	keyFile := filepath.Join(dir, "test-key.txt")
	err := os.WriteFile(keyFile, []byte(testIdentity), 0600)
	if err != nil {
		t.Fatalf("Failed to write test key file: %v", err)
	}

	v, err := vault.New("test-age",
		vault.WithProvider(vault.ProviderTypeAge),
		vault.WithAgePath(dir),
		vault.WithAgeIdentityFromFile(keyFile),
		vault.WithAgeRecipients(testRecipient),
	)
	if err != nil {
		t.Fatalf("Failed to create Age vault: %v", err)
	}

	return v
}

func testBasicOperations(t *testing.T, v vault.Provider) {
	id := v.ID()
	if id == "" {
		t.Error("Vault ID should not be empty")
	}

	secrets, err := v.ListSecrets()
	if err != nil {
		t.Fatalf("Failed to list secrets: %v", err)
	}
	if len(secrets) != 0 {
		t.Errorf("New vault should have 0 secrets, got %d", len(secrets))
	}

	exists, err := v.HasSecret("nonexistent")
	if err != nil {
		t.Fatalf("Failed to check secret existence: %v", err)
	}
	if exists {
		t.Error("HasSecret should return false for nonexistent secret")
	}

	_, err = v.GetSecret("nonexistent")
	if !errors.Is(err, vault.ErrSecretNotFound) {
		t.Errorf("Expected ErrSecretNotFound, got: %v", err)
	}
}

func testSecretOperations(t *testing.T, v vault.Provider) {
	testCases := []struct {
		key   string
		value string
	}{
		{"api-key", "my-secret-api-key"},
		{"db-password", "super-secret-password"},
		{"special-chars", "!@#$%^&*()_+-={}[]|\\:;\"'<>?,./ ~`"},
		{"unicode", "🔐 secret with emoji 🚀"},
		{"empty", ""},
	}

	for _, tc := range testCases {
		secret := vault.NewSecretValue([]byte(tc.value))
		err := v.SetSecret(tc.key, secret)
		if err != nil {
			t.Fatalf("Failed to set secret %s: %v", tc.key, err)
		}
	}

	// Verify all secrets can be retrieved
	for _, tc := range testCases {
		secret, err := v.GetSecret(tc.key)
		if err != nil {
			t.Fatalf("Failed to get secret %s: %v", tc.key, err)
		}
		if secret.PlainTextString() != tc.value {
			t.Errorf("Secret %s: expected %q, got %q", tc.key, tc.value, secret.PlainTextString())
		}

		// Test HasSecret
		exists, err := v.HasSecret(tc.key)
		if err != nil {
			t.Fatalf("Failed to check secret %s existence: %v", tc.key, err)
		}
		if !exists {
			t.Errorf("HasSecret should return true for %s", tc.key)
		}
	}

	// Test ListSecrets
	secrets, err := v.ListSecrets()
	if err != nil {
		t.Fatalf("Failed to list secrets: %v", err)
	}
	if len(secrets) != len(testCases) {
		t.Errorf("Expected %d secrets, got %d", len(testCases), len(secrets))
	}

	// Verify all expected keys are present
	keyMap := make(map[string]bool)
	for _, key := range secrets {
		keyMap[key] = true
	}
	for _, tc := range testCases {
		if !keyMap[tc.key] {
			t.Errorf("Missing secret key: %s", tc.key)
		}
	}

	// Test updating existing secret
	newSecret := vault.NewSecretValue([]byte("updated-value"))
	err = v.SetSecret("api-key", newSecret)
	if err != nil {
		t.Fatalf("Failed to update secret: %v", err)
	}

	retrievedSecret, err := v.GetSecret("api-key")
	if err != nil {
		t.Fatalf("Failed to get updated secret: %v", err)
	}
	if retrievedSecret.PlainTextString() != "updated-value" {
		t.Errorf("Updated secret: expected 'updated-value', got %q", retrievedSecret.PlainTextString())
	}

	// Test DeleteSecret
	err = v.DeleteSecret("api-key")
	if err != nil {
		t.Fatalf("Failed to delete secret: %v", err)
	}

	_, err = v.GetSecret("api-key")
	if !errors.Is(err, vault.ErrSecretNotFound) {
		t.Errorf("Expected ErrSecretNotFound after deletion, got: %v", err)
	}

	exists, err := v.HasSecret("api-key")
	if err != nil {
		t.Fatalf("Failed to check deleted secret existence: %v", err)
	}
	if exists {
		t.Error("HasSecret should return false for deleted secret")
	}

	// Verify list count decreased
	secrets, err = v.ListSecrets()
	if err != nil {
		t.Fatalf("Failed to list secrets after deletion: %v", err)
	}
	if len(secrets) != len(testCases)-1 {
		t.Errorf("Expected %d secrets after deletion, got %d", len(testCases)-1, len(secrets))
	}

	// Test deleting nonexistent secret
	err = v.DeleteSecret("nonexistent")
	if !errors.Is(err, vault.ErrSecretNotFound) {
		t.Errorf("Expected ErrSecretNotFound when deleting nonexistent secret, got: %v", err)
	}
}

func testPersistence(t *testing.T, v vault.Provider, provider vault.ProviderType, dir string) {
	// Store a test secret
	testSecret := vault.NewSecretValue([]byte("persistence-test"))
	err := v.SetSecret("persist-test", testSecret)
	if err != nil {
		t.Fatalf("Failed to set persistence test secret: %v", err)
	}

	// Close the vault
	err = v.Close()
	if err != nil {
		t.Fatalf("Failed to close vault: %v", err)
	}

	// Verify encrypted file exists
	var pattern string
	switch provider {
	case vault.ProviderTypeAES256:
		pattern = "*.enc"
	case vault.ProviderTypeAge:
		pattern = "*.age"
	}

	files, err := filepath.Glob(filepath.Join(dir, pattern))
	if err != nil {
		t.Fatalf("Failed to find vault files: %v", err)
	}
	if len(files) == 0 {
		t.Fatalf("No encrypted vault file found (pattern: %s)", pattern)
	}

	// Recreate vault and verify secret persisted
	var newVault vault.Provider
	switch provider {
	case vault.ProviderTypeAES256:
		newVault = setupAESVault(t, dir)
	case vault.ProviderTypeAge:
		newVault = setupAgeVault(t, dir)
	}
	defer newVault.Close()

	retrievedSecret, err := newVault.GetSecret("persist-test")
	if err != nil {
		t.Fatalf("Failed to get persisted secret: %v", err)
	}
	if retrievedSecret.PlainTextString() != "persistence-test" {
		t.Errorf("Persisted secret: expected 'persistence-test', got %q", retrievedSecret.PlainTextString())
	}

	// Test that Metadata is preserved
	metadata := newVault.Metadata()
	if metadata.Created.IsZero() {
		t.Error("Metadata creation time should not be zero")
	}
	if metadata.LastModified.IsZero() {
		t.Error("Metadata last modified time should not be zero")
	}
	if metadata.Created.After(metadata.LastModified) {
		t.Error("Metadata creation time should not be after last modified time")
	}
	if metadata.LastModified.Before(metadata.Created) {
		t.Error("Metadata last modified time should not be before creation time")
	}
}

func TestSecretValidation(t *testing.T) {
	tempDir := t.TempDir()
	v := setupAESVault(t, tempDir)
	defer v.Close()

	// Test invalid secret keys
	invalidKeys := []string{
		"", // empty
		"key with spaces",
		"key/with/slashes",
		"key\\with\\backslashes",
		"key\nwith\nnewlines",
		"key\twith\ttabs",
	}

	for _, key := range invalidKeys {
		secret := vault.NewSecretValue([]byte("test"))
		err := v.SetSecret(key, secret)
		if err == nil {
			t.Errorf("Expected error for invalid key %q, but got none", key)
		}
	}

	// Test valid keys
	validKeys := []string{
		"simple-key",
		"key_with_underscores",
		"key-with-dashes",
		"key123",
		"UPPERCASE",
		"mixedCase",
		"key.with.dots",
	}

	for _, key := range validKeys {
		secret := vault.NewSecretValue([]byte("test"))
		err := v.SetSecret(key, secret)
		if err != nil {
			t.Errorf("Expected no error for valid key %q, but got: %v", key, err)
		}
	}
}

func TestConcurrentAccess(t *testing.T) {
	tempDir := t.TempDir()
	v := setupAESVault(t, tempDir)
	defer v.Close()

	// Test concurrent reads and writes
	done := make(chan bool)
	errs := make(chan error, 10)

	// Concurrent writers
	for i := 0; i < 5; i++ {
		go func(id int) {
			for j := 0; j < 10; j++ {
				key := fmt.Sprintf("key-%d-%d", id, j)
				value := fmt.Sprintf("value-%d-%d", id, j)
				secret := vault.NewSecretValue([]byte(value))
				if err := v.SetSecret(key, secret); err != nil {
					errs <- err
					return
				}
			}
			done <- true
		}(i)
	}

	// Concurrent readers
	for i := 0; i < 3; i++ {
		go func() {
			for j := 0; j < 20; j++ {
				_, _ = v.ListSecrets() // Don't care about errors here since secrets are being added concurrently
				time.Sleep(time.Millisecond)
			}
			done <- true
		}()
	}

	// Wait for all goroutines
	for i := 0; i < 8; i++ {
		select {
		case err := <-errs:
			t.Fatalf("Concurrent operation failed: %v", err)
		case <-done:
			// Success
		case <-time.After(10 * time.Second):
			t.Fatal("Concurrent test timed out")
		}
	}
}
