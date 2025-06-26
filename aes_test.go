package vault_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jahvon/vault"
	"github.com/jahvon/vault/crypto"
)

func TestAESKeyGeneration(t *testing.T) {
	key1, err := vault.GenerateEncryptionKey()
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}
	if key1 == "" {
		t.Error("Generated key should not be empty")
	}

	key2, err := vault.GenerateEncryptionKey()
	if err != nil {
		t.Fatalf("Failed to generate second key: %v", err)
	}
	if key1 == key2 {
		t.Error("Generated keys should be unique")
	}

	err = vault.ValidateEncryptionKey(key1)
	if err != nil {
		t.Errorf("Valid key failed validation: %v", err)
	}

	err = vault.ValidateEncryptionKey("invalid-key")
	if err == nil {
		t.Error("Invalid key should fail validation")
	}
}

func TestAESKeyResolver(t *testing.T) {
	tempDir := t.TempDir()

	// Test key from environment
	testKey, err := vault.GenerateEncryptionKey()
	if err != nil {
		t.Fatalf("Failed to generate test key: %v", err)
	}

	t.Setenv("TEST_AES_KEY", testKey)

	resolver := vault.NewKeyResolver([]vault.KeySource{
		{Type: "env", Name: "TEST_AES_KEY"},
	})

	keys, err := resolver.ResolveKeys()
	if err != nil {
		t.Fatalf("Failed to resolve keys: %v", err)
	}
	if len(keys) != 1 {
		t.Errorf("Expected 1 key, got %d", len(keys))
	}
	if keys[0] != testKey {
		t.Errorf("Expected key %s, got %s", testKey, keys[0])
	}

	// Test key from file
	keyFile := filepath.Join(tempDir, "test-key.txt")
	err = os.WriteFile(keyFile, []byte(testKey), 0600)
	if err != nil {
		t.Fatalf("Failed to write key file: %v", err)
	}

	resolver = vault.NewKeyResolver([]vault.KeySource{
		{Type: "file", Path: keyFile},
	})

	keys, err = resolver.ResolveKeys()
	if err != nil {
		t.Fatalf("Failed to resolve keys from file: %v", err)
	}
	if len(keys) != 1 {
		t.Errorf("Expected 1 key from file, got %d", len(keys))
	}
	if keys[0] != testKey {
		t.Errorf("Expected key from file %s, got %s", testKey, keys[0])
	}

	// Test multiple sources
	resolver = vault.NewKeyResolver([]vault.KeySource{
		{Type: "env", Name: "NONEXISTENT_KEY"},
		{Type: "file", Path: keyFile},
		{Type: "env", Name: "TEST_AES_KEY"},
	})

	keys, err = resolver.ResolveKeys()
	if err != nil {
		t.Fatalf("Failed to resolve keys from multiple sources: %v", err)
	}
	if len(keys) != 2 { // Should find both the file and env key
		t.Errorf("Expected 2 keys from multiple sources, got %d", len(keys))
	}
}

func TestAESKeyResolverDecryption(t *testing.T) {
	// Generate test keys
	workingKey, err := vault.GenerateEncryptionKey()
	if err != nil {
		t.Fatalf("Failed to generate working key: %v", err)
	}

	wrongKey, err := vault.GenerateEncryptionKey()
	if err != nil {
		t.Fatalf("Failed to generate wrong key: %v", err)
	}

	// Encrypt test data with working key
	testData := "test secret data"
	encryptedData, err := crypto.EncryptValue(workingKey, testData)
	if err != nil {
		t.Fatalf("Failed to encrypt test data: %v", err)
	}

	// Set up resolver with wrong key first, then right key
	t.Setenv("WRONG_KEY", wrongKey)
	t.Setenv("WORKING_KEY", workingKey)

	resolver := vault.NewKeyResolver([]vault.KeySource{
		{Type: "env", Name: "WRONG_KEY"},
		{Type: "env", Name: "WORKING_KEY"},
	})

	// Test TryDecrypt - should succeed with working key
	decryptedData, usedKey, err := resolver.TryDecrypt(encryptedData)
	if err != nil {
		t.Fatalf("Failed to decrypt with resolver: %v", err)
	}
	if decryptedData != testData {
		t.Errorf("Expected decrypted data %s, got %s", testData, decryptedData)
	}
	if usedKey != workingKey {
		t.Errorf("Expected working key %s, got %s", workingKey, usedKey)
	}

	// Test with no working keys
	resolver = vault.NewKeyResolver([]vault.KeySource{
		{Type: "env", Name: "WRONG_KEY"},
	})

	_, _, err = resolver.TryDecrypt(encryptedData)
	if err == nil {
		t.Error("Expected decryption to fail with wrong key only")
	}
}

func TestAESVaultCreation(t *testing.T) {
	tempDir := t.TempDir()

	// Test creating vault without AES config
	_, err := vault.NewAES256Vault(&vault.Config{
		ID:   "test",
		Type: vault.ProviderTypeAES256,
	})
	if err == nil {
		t.Error("Expected error when creating vault without AES config")
	}

	// Test creating vault with valid config
	testKey, err := vault.GenerateEncryptionKey()
	if err != nil {
		t.Fatalf("Failed to generate test key: %v", err)
	}

	t.Setenv("TEST_VAULT_KEY", testKey)

	config := &vault.Config{
		ID:   "test-vault",
		Type: vault.ProviderTypeAES256,
		Aes: &vault.AesConfig{
			StoragePath: tempDir,
			KeySource: []vault.KeySource{
				{Type: "env", Name: "TEST_VAULT_KEY"},
			},
		},
	}

	v, err := vault.NewAES256Vault(config)
	if err != nil {
		t.Fatalf("Failed to create AES vault: %v", err)
	}
	defer v.Close()

	if v.ID() != "test-vault" {
		t.Errorf("Expected vault ID 'test-vault', got %s", v.ID())
	}

	// Verify vault file was created
	expectedFile := filepath.Join(tempDir, "vault-test-vault.enc")
	if _, err := os.Stat(expectedFile); os.IsNotExist(err) {
		t.Errorf("Expected vault file %s was not created", expectedFile)
	}
}

func TestAESVaultKeyResolution(t *testing.T) {
	tempDir := t.TempDir()

	// Create vault with first key
	key1, err := vault.GenerateEncryptionKey()
	if err != nil {
		t.Fatalf("Failed to generate key1: %v", err)
	}

	t.Setenv("VAULT_KEY_1", key1)

	config := &vault.Config{
		ID:   "test-multi-key",
		Type: vault.ProviderTypeAES256,
		Aes: &vault.AesConfig{
			StoragePath: tempDir,
			KeySource: []vault.KeySource{
				{Type: "env", Name: "VAULT_KEY_1"},
			},
		},
	}

	vault1, err := vault.NewAES256Vault(config)
	if err != nil {
		t.Fatalf("Failed to create vault with key1: %v", err)
	}

	// Add a secret
	secret := vault.NewSecretValue([]byte("test-secret"))
	err = vault1.SetSecret("test-key", secret)
	if err != nil {
		t.Fatalf("Failed to set secret: %v", err)
	}
	_ = vault1.Close()

	// Now create a new key and try to access vault with multiple key sources
	key2, err := vault.GenerateEncryptionKey()
	if err != nil {
		t.Fatalf("Failed to generate key2: %v", err)
	}

	t.Setenv("VAULT_KEY_2", key2)

	// Configure vault with wrong key first, then right key
	config.Aes.KeySource = []vault.KeySource{
		{Type: "env", Name: "VAULT_KEY_2"}, // Wrong key first
		{Type: "env", Name: "VAULT_KEY_1"}, // Right key second
	}

	vault2, err := vault.NewAES256Vault(config)
	if err != nil {
		t.Fatalf("Failed to create vault with multiple keys: %v", err)
	}
	defer vault2.Close()

	// Should be able to retrieve the secret using the second key
	retrievedSecret, err := vault2.GetSecret("test-key")
	if err != nil {
		t.Fatalf("Failed to get secret with multiple key sources: %v", err)
	}
	if retrievedSecret.PlainTextString() != "test-secret" {
		t.Errorf("Expected 'test-secret', got %s", retrievedSecret.PlainTextString())
	}
}

func TestAESVaultFileFormat(t *testing.T) {
	tempDir := t.TempDir()

	testKey, err := vault.GenerateEncryptionKey()
	if err != nil {
		t.Fatalf("Failed to generate test key: %v", err)
	}
	t.Setenv("FILE_FORMAT_KEY", testKey)

	config := &vault.Config{
		ID:   "format-test",
		Type: vault.ProviderTypeAES256,
		Aes: &vault.AesConfig{
			StoragePath: tempDir,
			KeySource: []vault.KeySource{
				{Type: "env", Name: "FILE_FORMAT_KEY"},
			},
		},
	}

	vault1, err := vault.NewAES256Vault(config)
	if err != nil {
		t.Fatalf("Failed to create vault: %v", err)
	}

	_ = vault1.SetSecret("key1", vault.NewSecretValue([]byte("value1")))
	_ = vault1.SetSecret("key2", vault.NewSecretValue([]byte("value2")))
	_ = vault1.Close()

	vaultFile := filepath.Join(tempDir, "vault-format-test.enc")
	data, err := os.ReadFile(vaultFile)
	if err != nil {
		t.Fatalf("Failed to read vault file: %v", err)
	}

	if len(data) == 0 {
		t.Error("Vault file should not be empty")
	}

	// Verify the file is encrypted (should not contain plain text)
	dataStr := string(data)
	if strings.Contains(dataStr, "key1") ||
		strings.Contains(dataStr, "value1") ||
		strings.Contains(dataStr, "key2") ||
		strings.Contains(dataStr, "value2") {
		t.Error("Vault file should not contain plain text secrets")
	}

	// Verify file can be decrypted by creating new vault
	vault2, err := vault.NewAES256Vault(config)
	if err != nil {
		t.Fatalf("Failed to recreate vault: %v", err)
	}
	defer vault2.Close()

	secret1, err := vault2.GetSecret("key1")
	if err != nil {
		t.Fatalf("Failed to decrypt secret: %v", err)
	}
	if secret1.PlainTextString() != "value1" {
		t.Errorf("Expected 'value1', got %s", secret1.PlainTextString())
	}
}

func TestAESDefaultKeySource(t *testing.T) {
	// Test that KeyResolver works with default sources when nil is provided
	// This is a behavioral test rather than testing internal implementation
	testKey, err := vault.GenerateEncryptionKey()
	if err != nil {
		t.Fatalf("Failed to generate test key: %v", err)
	}
	t.Setenv(vault.DefaultVaultKeyEnv, testKey)

	resolver := vault.NewKeyResolver(nil)
	keys, err := resolver.ResolveKeys()
	if err != nil {
		t.Fatalf("Failed to resolve keys with default source: %v", err)
	}

	if len(keys) != 1 {
		t.Errorf("Expected 1 key from default source, got %d", len(keys))
	}
	if keys[0] != testKey {
		t.Errorf("Expected key %s, got %s", testKey, keys[0])
	}
}
