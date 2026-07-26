package vault

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/flowexec/vault/crypto"
)

type KeyResolver struct {
	sources []KeySource
}

func NewKeyResolver(sources []KeySource) *KeyResolver {
	if len(sources) == 0 {
		sources = []KeySource{
			{Type: envSource, Name: DefaultVaultKeyEnv},
		}
	}
	return &KeyResolver{
		sources: sources,
	}
}

func (r *KeyResolver) ResolveKeys() ([]string, error) {
	var keys []string
	var failures []string

	for _, source := range r.sources {
		switch source.Type {
		case envSource:
			if key := r.fromEnvironment(source.Name); key != "" {
				keys = append(keys, key)
			} else {
				failures = append(failures, fmt.Sprintf("env %s: not set or empty", source.Name))
			}
		case fileSource:
			// Errors here used to be discarded outright (`err == nil &&`), so a
			// typo'd path, a permissions problem or a truncated key file all
			// surfaced as the generic "no encryption keys found" -- or worse,
			// silently fell through to a different source.
			key, err := r.fromFile(source.Path)
			switch {
			case err != nil:
				failures = append(failures, fmt.Sprintf("file %s: %v", source.Path, err))
			case key == "":
				failures = append(failures, fmt.Sprintf("file %s: is empty", source.Path))
			default:
				keys = append(keys, key)
			}
		}
	}

	if len(keys) == 0 {
		if len(failures) > 0 {
			return nil, fmt.Errorf("%w: no encryption keys found (%s)", ErrNoAccess, strings.Join(failures, "; "))
		}
		return nil, fmt.Errorf("%w: no encryption keys found", ErrNoAccess)
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
			continue // try the next key
		}
		return decryptedData, key, nil
	}

	return "", "", fmt.Errorf("%w: failed to decrypt data with any available key", ErrDecryptionFailed)
}

func (r *KeyResolver) fromEnvironment(envVar string) string {
	if envVar == "" {
		envVar = DefaultVaultKeyEnv
	}

	return os.Getenv(envVar)
}

func (r *KeyResolver) fromFile(path string) (string, error) {
	if path == "" {
		return "", fmt.Errorf("key file path cannot be empty")
	}

	expandedPath, err := expandPath(path)
	if err != nil {
		return "", fmt.Errorf("failed to expand key file path %s: %w", path, err)
	}

	keyBytes, err := os.ReadFile(filepath.Clean(expandedPath))
	if err != nil {
		return "", fmt.Errorf("failed to read key file %s: %w", expandedPath, err)
	}

	return strings.TrimSpace(string(keyBytes)), nil
}
