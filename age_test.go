package vault_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/flowexec/vault"
)

func TestAgeIdentityResolver(t *testing.T) {
	tempDir := t.TempDir()

	testIdentity := "AGE-SECRET-KEY-1LC563A3EG4TLDL5EQE0YP5ZSJW8NADURXLZ8WVM00DMKG60URRNQ5TRZH0"
	t.Setenv("TEST_AGE_IDENTITY", testIdentity)

	resolver := vault.NewIdentityResolver([]vault.IdentitySource{
		{Type: "env", Name: "TEST_AGE_IDENTITY"},
	})

	identities, err := resolver.ResolveIdentities()
	if err != nil {
		t.Fatalf("Failed to resolve identities: %v", err)
	}
	if len(identities) != 1 {
		t.Errorf("Expected 1 identity, got %d", len(identities))
	}

	// Test identity from file
	keyFile := filepath.Join(tempDir, "test-identity.txt")
	err = os.WriteFile(keyFile, []byte(testIdentity), 0600)
	if err != nil {
		t.Fatalf("Failed to write identity file: %v", err)
	}

	resolver = vault.NewIdentityResolver([]vault.IdentitySource{
		{Type: "file", Path: keyFile},
	})

	identities, err = resolver.ResolveIdentities()
	if err != nil {
		t.Fatalf("Failed to resolve identities from file: %v", err)
	}
	if len(identities) != 1 {
		t.Errorf("Expected 1 identity from file, got %d", len(identities))
	}

	// Test multiple sources
	resolver = vault.NewIdentityResolver([]vault.IdentitySource{
		{Type: "env", Name: "NONEXISTENT_IDENTITY"},
		{Type: "file", Path: keyFile},
		{Type: "env", Name: "TEST_AGE_IDENTITY"},
	})

	identities, err = resolver.ResolveIdentities()
	if err != nil {
		t.Fatalf("Failed to resolve identities from multiple sources: %v", err)
	}
	if len(identities) != 2 { // Should find both the file and env identity
		t.Errorf("Expected 2 identities from multiple sources, got %d", len(identities))
	}
}

func TestAgeIdentityResolverErrors(t *testing.T) {
	// Test invalid identity
	t.Setenv("INVALID_AGE_IDENTITY", "not-a-valid-age-key")

	resolver := vault.NewIdentityResolver([]vault.IdentitySource{
		{Type: "env", Name: "INVALID_AGE_IDENTITY"},
	})

	identities, err := resolver.ResolveIdentities()
	if err == nil {
		t.Error("Expected error when no valid identities found")
	}
	if len(identities) != 0 {
		t.Errorf("Expected 0 identities for invalid key, got %d", len(identities))
	}

	// Test nonexistent file
	resolver = vault.NewIdentityResolver([]vault.IdentitySource{
		{Type: "file", Path: "/nonexistent/path/key.txt"},
	})

	_, err = resolver.ResolveIdentities()
	if err == nil {
		t.Error("Expected error for nonexistent file")
	}

	// Test empty file path
	resolver = vault.NewIdentityResolver([]vault.IdentitySource{
		{Type: "file", Path: ""},
	})

	_, err = resolver.ResolveIdentities()
	if err == nil {
		t.Error("Expected error for empty file path")
	}

	// Test no valid identities
	resolver = vault.NewIdentityResolver([]vault.IdentitySource{
		{Type: "env", Name: "NONEXISTENT_KEY"},
	})

	_, err = resolver.ResolveIdentities()
	if err == nil {
		t.Error("Expected error when no valid identities found")
	}
}

func TestAgeVaultCreation(t *testing.T) {
	tempDir := t.TempDir()

	// Test creating vault without Age config
	_, err := vault.NewAgeVault(&vault.Config{
		ID:   "test",
		Type: vault.ProviderTypeAge,
	})
	if err == nil {
		t.Error("Expected error when creating vault without Age config")
	}

	testIdentity := "AGE-SECRET-KEY-1LC563A3EG4TLDL5EQE0YP5ZSJW8NADURXLZ8WVM00DMKG60URRNQ5TRZH0"
	testRecipient := "age1wnhg53pg2qfsfxwvxvlg6pygw5uzwcyhj2dqhg0k83fvjexf9pzsxqdvs0"
	keyFile := filepath.Join(tempDir, "test-key.txt")
	err = os.WriteFile(keyFile, []byte(testIdentity), 0600)
	if err != nil {
		t.Fatalf("Failed to write identity file: %v", err)
	}

	config := &vault.Config{
		ID:   "test-age-vault",
		Type: vault.ProviderTypeAge,
		Age: &vault.AgeConfig{
			StoragePath: tempDir,
			IdentitySources: []vault.IdentitySource{
				{Type: "file", Path: keyFile},
			},
			Recipients: []string{testRecipient},
		},
	}

	v, err := vault.NewAgeVault(config)
	if err != nil {
		t.Fatalf("Failed to create Age vault: %v", err)
	}
	defer v.Close()

	if v.ID() != "test-age-vault" {
		t.Errorf("Expected vault ID 'test-age-vault', got %s", v.ID())
	}

	// Verify vault file was created
	expectedFile := filepath.Join(tempDir, "vault-test-age-vault.age")
	if _, err := os.Stat(expectedFile); os.IsNotExist(err) {
		t.Errorf("Expected vault file %s was not created", expectedFile)
	}
}

func TestAgeVaultRecipientManagement(t *testing.T) {
	tempDir := t.TempDir()

	testIdentity := "AGE-SECRET-KEY-1LC563A3EG4TLDL5EQE0YP5ZSJW8NADURXLZ8WVM00DMKG60URRNQ5TRZH0"
	testRecipient1 := "age1wnhg53pg2qfsfxwvxvlg6pygw5uzwcyhj2dqhg0k83fvjexf9pzsxqdvs0"
	testRecipient2 := "age1u7rkgxlu26y68m3ky0aesxtls9g33zy5zcy0wuehtwua6lssmpus4xszw6"
	keyFile := filepath.Join(tempDir, "test-key.txt")
	err := os.WriteFile(keyFile, []byte(testIdentity), 0600)
	if err != nil {
		t.Fatalf("Failed to write identity file: %v", err)
	}

	config := &vault.Config{
		ID:   "recipient-test",
		Type: vault.ProviderTypeAge,
		Age: &vault.AgeConfig{
			StoragePath: tempDir,
			IdentitySources: []vault.IdentitySource{
				{Type: "file", Path: keyFile},
			},
			Recipients: []string{testRecipient1},
		},
	}

	v, err := vault.NewAgeVault(config)
	if err != nil {
		t.Fatalf("Failed to create Age vault: %v", err)
	}
	defer v.Close()

	// Test initial recipients
	recipients, err := v.ListRecipients()
	if err != nil {
		t.Fatalf("Failed to list recipients: %v", err)
	}
	if len(recipients) != 1 {
		t.Errorf("Expected 1 initial recipient, got %d", len(recipients))
	}
	if recipients[0] != testRecipient1 {
		t.Errorf("Expected recipient %s, got %s", testRecipient1, recipients[0])
	}

	// Test adding recipient
	err = v.AddRecipient(testRecipient2)
	if err != nil {
		t.Fatalf("Failed to add recipient: %v", err)
	}

	recipients, err = v.ListRecipients()
	if err != nil {
		t.Fatalf("Failed to list recipients after add: %v", err)
	}
	if len(recipients) != 2 {
		t.Errorf("Expected 2 recipients after add, got %d", len(recipients))
	}

	// Test adding duplicate recipient (should not fail)
	err = v.AddRecipient(testRecipient1)
	if err != nil {
		t.Fatalf("Failed to add duplicate recipient: %v", err)
	}

	recipients, err = v.ListRecipients()
	if err != nil {
		t.Fatalf("Failed to list recipients after duplicate add: %v", err)
	}
	if len(recipients) != 2 { // Should still be 2, duplicate doesn't increase count
		t.Errorf("Expected 2 recipients after duplicate add, got %d", len(recipients))
	}

	// Test removing recipient (should succeed now that we have 2)
	err = v.RemoveRecipient(testRecipient2)
	if err != nil {
		t.Fatalf("Failed to remove recipient: %v", err)
	}

	recipients, err = v.ListRecipients()
	if err != nil {
		t.Fatalf("Failed to list recipients after remove: %v", err)
	}
	if len(recipients) != 1 {
		t.Errorf("Expected 1 recipient after remove, got %d", len(recipients))
	}

	// Test removing the last recipient (should fail)
	err = v.RemoveRecipient(testRecipient1)
	if err == nil {
		t.Error("Expected error when removing the last recipient")
	}

	// Test removing nonexistent recipient
	err = v.RemoveRecipient("age1nonexistent123456789")
	if err == nil {
		t.Error("Expected error when removing nonexistent recipient")
	}
}

func TestAgeVaultInvalidRecipient(t *testing.T) {
	tempDir := t.TempDir()

	testIdentity := "AGE-SECRET-KEY-1LC563A3EG4TLDL5EQE0YP5ZSJW8NADURXLZ8WVM00DMKG60URRNQ5TRZH0"
	keyFile := filepath.Join(tempDir, "test-key.txt")
	err := os.WriteFile(keyFile, []byte(testIdentity), 0600)
	if err != nil {
		t.Fatalf("Failed to write identity file: %v", err)
	}

	config := &vault.Config{
		ID:   "invalid-recipient-test",
		Type: vault.ProviderTypeAge,
		Age: &vault.AgeConfig{
			StoragePath: tempDir,
			IdentitySources: []vault.IdentitySource{
				{Type: "file", Path: keyFile},
			},
			Recipients: []string{"invalid-recipient-key"},
		},
	}

	// Should fail during vault creation due to invalid recipient
	_, err = vault.NewAgeVault(config)
	if err == nil {
		t.Error("Expected error when creating vault with invalid recipient")
	}
}

func TestAgeVaultFileFormat(t *testing.T) {
	tempDir := t.TempDir()

	testIdentity := "AGE-SECRET-KEY-1LC563A3EG4TLDL5EQE0YP5ZSJW8NADURXLZ8WVM00DMKG60URRNQ5TRZH0"
	testRecipient := "age1wnhg53pg2qfsfxwvxvlg6pygw5uzwcyhj2dqhg0k83fvjexf9pzsxqdvs0"

	keyFile := filepath.Join(tempDir, "test-key.txt")
	err := os.WriteFile(keyFile, []byte(testIdentity), 0600)
	if err != nil {
		t.Fatalf("Failed to write identity file: %v", err)
	}

	config := &vault.Config{
		ID:   "format-test",
		Type: vault.ProviderTypeAge,
		Age: &vault.AgeConfig{
			StoragePath: tempDir,
			IdentitySources: []vault.IdentitySource{
				{Type: "file", Path: keyFile},
			},
			Recipients: []string{testRecipient},
		},
	}

	vault1, err := vault.NewAgeVault(config)
	if err != nil {
		t.Fatalf("Failed to create vault: %v", err)
	}

	_ = vault1.SetSecret("key1", vault.NewSecretValue([]byte("value1")))
	_ = vault1.SetSecret("key2", vault.NewSecretValue([]byte("value2")))
	_ = vault1.Close()

	// Verify the encrypted file exists and has content
	vaultFile := filepath.Join(tempDir, "vault-format-test.age")
	data, err := os.ReadFile(vaultFile)
	if err != nil {
		t.Fatalf("Failed to read vault file: %v", err)
	}

	if len(data) == 0 {
		t.Error("Vault file should not be empty")
	}

	// Verify the file starts with age format header
	dataStr := string(data)
	if !strings.HasPrefix(dataStr, "age-encryption.org/v1") {
		t.Error("Age vault file should start with age format header")
	}

	// Verify the file is encrypted (should not contain plain text)
	if strings.Contains(dataStr, "key1") ||
		strings.Contains(dataStr, "value1") ||
		strings.Contains(dataStr, "key2") ||
		strings.Contains(dataStr, "value2") {
		t.Error("Age vault file should not contain plain text secrets")
	}

	// Verify file can be decrypted by creating new vault
	vault2, err := vault.NewAgeVault(config)
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

func TestAgeVaultNoRecipients(t *testing.T) {
	tempDir := t.TempDir()

	testIdentity := "AGE-SECRET-KEY-1LC563A3EG4TLDL5EQE0YP5ZSJW8NADURXLZ8WVM00DMKG60URRNQ5TRZH0"
	keyFile := filepath.Join(tempDir, "test-key.txt")
	err := os.WriteFile(keyFile, []byte(testIdentity), 0600)
	if err != nil {
		t.Fatalf("Failed to write identity file: %v", err)
	}

	config := &vault.Config{
		ID:   "no-recipients-test",
		Type: vault.ProviderTypeAge,
		Age: &vault.AgeConfig{
			StoragePath: tempDir,
			IdentitySources: []vault.IdentitySource{
				{Type: "file", Path: keyFile},
			},
			Recipients: []string{},
		},
	}

	_, err = vault.NewAgeVault(config)
	if err == nil {
		t.Error("Expected error when creating vault with no recipients")
	}
}

func TestAgeVaultPathExpansion(t *testing.T) {
	tempDir := t.TempDir()

	testIdentity := "AGE-SECRET-KEY-1LC563A3EG4TLDL5EQE0YP5ZSJW8NADURXLZ8WVM00DMKG60URRNQ5TRZH0"
	relativeKeyFile := "./test-key.txt"

	// Change to temp dir so relative path works
	oldDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Failed to get working directory: %v", err)
	}
	defer os.Chdir(oldDir)

	err = os.Chdir(tempDir)
	if err != nil {
		t.Fatalf("Failed to change to temp directory: %v", err)
	}

	err = os.WriteFile(relativeKeyFile, []byte(testIdentity), 0600)
	if err != nil {
		t.Fatalf("Failed to write identity file: %v", err)
	}

	testRecipient := "age1wnhg53pg2qfsfxwvxvlg6pygw5uzwcyhj2dqhg0k83fvjexf9pzsxqdvs0"
	config := &vault.Config{
		ID:   "path-expansion-test",
		Type: vault.ProviderTypeAge,
		Age: &vault.AgeConfig{
			StoragePath: tempDir,
			IdentitySources: []vault.IdentitySource{
				{Type: "file", Path: relativeKeyFile},
			},
			Recipients: []string{testRecipient},
		},
	}

	v, err := vault.NewAgeVault(config)
	if err != nil {
		t.Fatalf("Failed to create vault with relative path: %v", err)
	}
	defer v.Close()

	err = v.SetSecret("test", vault.NewSecretValue([]byte("value")))
	if err != nil {
		t.Fatalf("Failed to set secret with relative path identity: %v", err)
	}
}
