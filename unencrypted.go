package vault

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

const (
	unencryptedCurrentVaultVersion = 1
	unencryptedVaultFileExt        = "json"
)

// UnencryptedState represents the state of the unencrypted vault.
type UnencryptedState struct {
	Metadata `json:"metadata"`

	Version int               `json:"version"`
	ID      string            `json:"id"`
	Secrets map[string]string `json:"secrets"`
}

// UnencryptedVault manages operations on an instance of an unencrypted vault that stores secrets in JSON format.
type UnencryptedVault struct {
	mu       sync.RWMutex
	id       string
	fullPath string

	state *UnencryptedState
}

func NewUnencryptedVault(cfg *Config) (*UnencryptedVault, error) {
	if cfg.Unencrypted == nil {
		return nil, fmt.Errorf("unencrypted configuration is required")
	}

	path := filepath.Join(
		filepath.Clean(cfg.Unencrypted.StoragePath),
		filepath.Clean(fmt.Sprintf("%s-%s.%s", vaultFileBase, cfg.ID, unencryptedVaultFileExt)),
	)

	vault := &UnencryptedVault{
		id:       cfg.ID,
		fullPath: path,
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

func (v *UnencryptedVault) init() error {
	now := time.Now()
	v.state = &UnencryptedState{
		Version: unencryptedCurrentVaultVersion,
		ID:      v.id,
		Metadata: Metadata{
			Created:      now,
			LastModified: now,
		},
		Secrets: make(map[string]string),
	}

	return v.save()
}

// load retrieves the vault contents from the file and parses it into the state.
func (v *UnencryptedVault) load() error {
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

	// Parse the JSON format
	var state UnencryptedState
	if err := json.Unmarshal(data, &state); err != nil {
		return fmt.Errorf("failed to parse vault file: %w", err)
	}

	v.state = &state
	return nil
}

// save writes the vault contents to disk in JSON format
func (v *UnencryptedVault) save() error {
	if v.state == nil {
		return nil
	}

	v.state.LastModified = time.Now()

	// Marshal to JSON with indentation for readability
	data, err := json.MarshalIndent(v.state, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal vault state: %w", err)
	}

	// Write to file atomically
	if err := os.MkdirAll(filepath.Dir(v.fullPath), 0750); err != nil {
		return fmt.Errorf("failed to create vault directory: %w", err)
	}

	tempFile := v.fullPath + ".tmp"
	if err := os.WriteFile(tempFile, data, 0600); err != nil {
		return fmt.Errorf("failed to write temp vault file: %w", err)
	}

	if err := os.Rename(tempFile, v.fullPath); err != nil {
		_ = os.Remove(tempFile)
		return fmt.Errorf("failed to move vault file: %w", err)
	}

	return nil
}

func (v *UnencryptedVault) ID() string {
	return v.id
}

func (v *UnencryptedVault) Metadata() Metadata {
	v.mu.RLock()
	defer v.mu.RUnlock()

	if v.state == nil {
		return Metadata{}
	}
	return v.state.Metadata
}

func (v *UnencryptedVault) GetSecret(key string) (Secret, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()

	value, exists := v.state.Secrets[key]
	if !exists {
		return nil, ErrSecretNotFound
	}

	return NewSecretValue([]byte(value)), nil
}

func (v *UnencryptedVault) SetSecret(key string, secret Secret) error {
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

func (v *UnencryptedVault) DeleteSecret(key string) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	_, exists := v.state.Secrets[key]
	if !exists {
		return ErrSecretNotFound
	}

	delete(v.state.Secrets, key)
	return v.save()
}

func (v *UnencryptedVault) ListSecrets() ([]string, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()

	keys := make([]string, 0, len(v.state.Secrets))
	for k := range v.state.Secrets {
		keys = append(keys, k)
	}

	// Sort for deterministic output
	sort.Strings(keys)
	return keys, nil
}

func (v *UnencryptedVault) HasSecret(key string) (bool, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()

	_, exists := v.state.Secrets[key]
	return exists, nil
}

func (v *UnencryptedVault) Close() error {
	// clear the secret state from memory
	v.mu.Lock()
	defer v.mu.Unlock()

	v.state = nil

	return nil
}
