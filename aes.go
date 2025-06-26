package vault

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/jahvon/vault/crypto"
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

	return v.save()
}

// load retrieves the AESState from the vault file, decrypts it, and unmarshals it into an AESState struct.
func (v *AES256Vault) load() error {
	data, err := os.ReadFile(filepath.Clean(v.fullPath))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("%w: failed to read vault file %s: %w", ErrVaultNotFound, v.fullPath, err)
	}

	if len(data) == 0 {
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
		return nil
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

	// write to the file atomically
	if err := os.MkdirAll(filepath.Dir(v.fullPath), 0750); err != nil {
		return fmt.Errorf("failed to create vault directory: %w", err)
	}
	tempFile := v.fullPath + ".tmp"
	if err := os.WriteFile(tempFile, []byte(encryptedDataStr), 0600); err != nil {
		return fmt.Errorf("failed to write temp vault file: %w", err)
	}

	if err := os.Rename(tempFile, v.fullPath); err != nil {
		_ = os.Remove(tempFile)
		return fmt.Errorf("failed to move vault file: %w", err)
	}

	return nil
}

func (v *AES256Vault) ID() string {
	return v.id
}

func (v *AES256Vault) Metadata() Metadata {
	v.mu.RLock()
	defer v.mu.RUnlock()

	if v.state == nil {
		return Metadata{}
	}
	return v.state.Metadata
}

func (v *AES256Vault) GetSecret(key string) (Secret, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()

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

	if v.state.Secrets == nil {
		v.state.Secrets = make(map[string]string)
	}

	v.state.Secrets[key] = secret.PlainTextString()
	return v.save()
}

func (v *AES256Vault) DeleteSecret(key string) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	_, exists := v.state.Secrets[key]
	if !exists {
		return ErrSecretNotFound
	}

	delete(v.state.Secrets, key)
	return v.save()
}

func (v *AES256Vault) ListSecrets() ([]string, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()

	keys := make([]string, 0, len(v.state.Secrets))
	for k := range v.state.Secrets {
		keys = append(keys, k)
	}
	return keys, nil
}

func (v *AES256Vault) HasSecret(key string) (bool, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()

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
