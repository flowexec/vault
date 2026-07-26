package vault

import (
	"fmt"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/flowexec/vault/crypto"
)

const (
	aesCurrentVaultVersion = 1
	aesVaultFileExt        = "enc"
)

// AESState represents the state of the local AES256 vault.
type AESState struct {
	Metadata `yaml:"metadata"`

	Version int               `json:"version"`
	ID      string            `yaml:"id"`
	Secrets map[string]string `yaml:"secrets"`
}

// AES256Vault manages operations on an instance of a local vault backed by AES256 symmetric encryption.
type AES256Vault struct {
	mu       sync.RWMutex
	id       string
	fullPath string

	state    *AESState
	resolver *KeyResolver
	dek      string
}

// GenerateEncryptionKey generates a new AES encryption key
func GenerateEncryptionKey() (string, error) {
	return crypto.GenerateKey()
}

// DeriveEncryptionKey derives an AES encryption key from a passphrase
func DeriveEncryptionKey(passphrase, sal string) (string, string, error) {
	key, salt, err := crypto.DeriveKey([]byte(passphrase), []byte(sal))
	if err != nil {
		return "", "", fmt.Errorf("failed to derive encryption key: %w", err)
	}
	return key, salt, nil
}

// ValidateEncryptionKey checks if a key is valid by attempting to encrypt/decrypt test data
func ValidateEncryptionKey(key string) error {
	testData := "test-validation-data"
	encrypted, err := crypto.EncryptValue(key, testData)
	if err != nil {
		return fmt.Errorf("key validation failed during encryption: %w", err)
	}

	decrypted, err := crypto.DecryptValue(key, encrypted)
	if err != nil {
		return fmt.Errorf("key validation failed during decryption: %w", err)
	}

	if decrypted != testData {
		return fmt.Errorf("key validation failed: decrypted data does not match")
	}

	return nil
}

func NewAES256Vault(cfg *Config) (*AES256Vault, error) {
	if cfg.Aes == nil {
		return nil, fmt.Errorf("AES configuration is required")
	}

	path := filepath.Join(
		filepath.Clean(cfg.Aes.StoragePath),
		filepath.Clean(fmt.Sprintf("%s-%s.%s", vaultFileBase, cfg.ID, aesVaultFileExt)),
	)

	vault := &AES256Vault{
		id:       cfg.ID,
		fullPath: path,
		resolver: NewKeyResolver(cfg.Aes.KeySource),
	}

	if err := vault.load(); err != nil {
		return nil, fmt.Errorf("failed to load vault: %w", err)
	}

	if vault.state == nil {
		if err := vault.init(); err != nil {
			return nil, fmt.Errorf("failed to initialize vault: %w", err)
		}
	}

	return vault, nil
}

func (v *AES256Vault) init() error {
	keys, err := v.resolver.ResolveKeys()
	if err != nil {
		return fmt.Errorf("no encryption key available for new vault: %w", err)
	}
	v.dek = keys[0]

	now := time.Now()
	v.state = &AESState{
		Version: aesCurrentVaultVersion,
		ID:      v.id,
		Metadata: Metadata{
			Created:      now,
			LastModified: now,
		},
		Secrets: make(map[string]string),
	}

	return withVaultLock(v.fullPath, v.save)
}

// load retrieves the AESState from the vault file, decrypts it, and unmarshals it into an AESState struct.
func (v *AES256Vault) load() error {
	data, exists, err := readVaultFile(v.fullPath)
	if err != nil {
		return err
	}
	if !exists {
		return nil
	}

	// try to decrypt the vault file using available keys
	dataStr, key, err := v.resolver.TryDecrypt(string(data))
	if err != nil {
		return err
	}
	v.dek = key

	var state AESState
	if err := yaml.Unmarshal([]byte(dataStr), &state); err != nil {
		return fmt.Errorf("failed to unmarshal vault state: %w", err)
	}
	v.state = &state
	return nil
}

// save encrypts and writes the vault contents to disk
func (v *AES256Vault) save() error {
	if v.state == nil {
		return ErrVaultClosed
	}

	if v.dek == "" {
		return fmt.Errorf("no encryption key available for saving")
	}

	v.state.LastModified = time.Now()
	data, err := yaml.Marshal(v.state)
	if err != nil {
		return fmt.Errorf("failed to marshal vault state: %w", err)
	}
	encryptedDataStr, err := crypto.EncryptValue(v.dek, string(data))
	if err != nil {
		return fmt.Errorf("failed to encrypt vault state: %w", err)
	}

	return writeVaultFileAtomic(v.fullPath, []byte(encryptedDataStr))
}

// mutate runs a read-modify-write cycle under the cross-process vault lock.
//
// Reloading inside the lock is the point: in-memory state is a snapshot taken
// when the provider was constructed, and every save rewrites the whole file.
// Writing that snapshot back without refreshing silently discards whatever
// another process stored in the meantime.
func (v *AES256Vault) mutate(apply func() error) error {
	return withVaultLock(v.fullPath, func() error {
		if err := v.load(); err != nil {
			return err
		}
		if err := apply(); err != nil {
			return err
		}
		return v.save()
	})
}

func (v *AES256Vault) ID() string {
	return v.id
}

func (v *AES256Vault) Metadata() (Metadata, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()

	if v.state == nil {
		return Metadata{}, ErrVaultClosed
	}
	return v.state.Metadata, nil
}

func (v *AES256Vault) GetSecret(key string) (Secret, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()

	if err := ValidateSecretKey(key); err != nil {
		return nil, err
	}
	if v.state == nil {
		return nil, ErrVaultClosed
	}

	value, exists := v.state.Secrets[key]
	if !exists {
		return nil, ErrSecretNotFound
	}

	return NewSecretValue([]byte(value)), nil
}

func (v *AES256Vault) SetSecret(key string, secret Secret) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	if err := ValidateSecretKey(key); err != nil {
		return err
	}
	if v.state == nil {
		return ErrVaultClosed
	}

	return v.mutate(func() error {
		if v.state.Secrets == nil {
			v.state.Secrets = make(map[string]string)
		}
		v.state.Secrets[key] = secret.PlainTextString()
		return nil
	})
}

func (v *AES256Vault) DeleteSecret(key string) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	if err := ValidateSecretKey(key); err != nil {
		return err
	}
	if v.state == nil {
		return ErrVaultClosed
	}

	// The existence check runs inside mutate, after the reload, so it sees the
	// current on-disk contents rather than a stale snapshot.
	return v.mutate(func() error {
		if _, exists := v.state.Secrets[key]; !exists {
			return ErrSecretNotFound
		}
		delete(v.state.Secrets, key)
		return nil
	})
}

func (v *AES256Vault) ListSecrets() ([]string, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()

	if v.state == nil {
		return nil, ErrVaultClosed
	}

	keys := make([]string, 0, len(v.state.Secrets))
	for k := range v.state.Secrets {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys, nil
}

func (v *AES256Vault) HasSecret(key string) (bool, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()

	if err := ValidateSecretKey(key); err != nil {
		return false, err
	}
	if v.state == nil {
		return false, ErrVaultClosed
	}

	_, exists := v.state.Secrets[key]
	return exists, nil
}

func (v *AES256Vault) Close() error {
	// clear the secret state from memory
	v.mu.Lock()
	defer v.mu.Unlock()

	v.dek = ""
	v.state = nil

	return nil
}
