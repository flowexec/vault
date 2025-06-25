package vault

import (
	"fmt"
	"os"
	"strings"

	"github.com/jahvon/vault/crypto"
)

const (
	EncryptionKeyEnvVar = "VAULT_ENCRYPTION_KEY"
)

type KeyResolver struct {
	sources []KeySource
}

func NewKeyResolver(sources []KeySource) *KeyResolver {
	if len(sources) == 0 {
		sources = []KeySource{
			{Type: envSource, Name: EncryptionKeyEnvVar},
		}
	}
	return &KeyResolver{
		sources: sources,
	}
}

func (r *KeyResolver) ResolveKeys() ([]string, error) {
	var keys []string

	for _, source := range r.sources {
		switch source.Type {
		case envSource:
			if key := r.fromEnvironment(source.Name); key != "" {
				keys = append(keys, key)
			}
		case fileSource:
			if key, err := r.fromFile(source.Path); err == nil && key != "" {
				keys = append(keys, key)
			}
		}
	}

	if len(keys) == 0 {
		return nil, fmt.Errorf("no encryption keys found")
	}

	return keys, nil
}

func (r *KeyResolver) TryDecrypt(encryptedData string) (string, string, error) {
	keys, err := r.ResolveKeys()
	if err != nil {
		return "", "", err
	}

	for _, key := range keys {
		decryptedData, err := crypto.DecryptValue(key, encryptedData)
		if err != nil {
			continue // Key validation failed (bad base64, etc.)
		}

		// For CFB mode, we need additional validation since it always "succeeds"
		// We expect the data to be valid UTF-8 and likely YAML/JSON structure
		if isLikelyValidDecryption(decryptedData) {
			return decryptedData, key, nil
		}
	}

	return "", "", fmt.Errorf("failed to decrypt data with any available key")
}

// isLikelyValidDecryption checks if the decrypted data looks valid
func isLikelyValidDecryption(data string) bool {
	// Check if it's valid UTF-8
	if !isValidUTF8(data) {
		return false
	}

	// Check if it contains a reasonable amount of printable characters
	printableCount := 0
	for _, r := range data {
		if r >= 32 && r <= 126 || r == '\n' || r == '\t' || r == '\r' {
			printableCount++
		}
	}

	// If most characters are printable, it's likely valid
	return len(data) == 0 || float64(printableCount)/float64(len(data)) > 0.8
}

func isValidUTF8(s string) bool {
	for i, r := range s {
		if r == '\uFFFD' && len(s[i:]) > 0 {
			return false
		}
	}
	return true
}

func (r *KeyResolver) fromEnvironment(envVar string) string {
	if envVar == "" {
		envVar = EncryptionKeyEnvVar
	}

	return os.Getenv(envVar)
}

func (r *KeyResolver) fromFile(path string) (string, error) {
	if path == "" {
		return "", fmt.Errorf("key file path cannot be empty")
	}

	expandedPath := expandPath(path)
	keyBytes, err := os.ReadFile(expandedPath)
	if err != nil {
		return "", fmt.Errorf("failed to read key file %s: %w", expandedPath, err)
	}

	return strings.TrimSpace(string(keyBytes)), nil
}
