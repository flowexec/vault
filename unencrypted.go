package vault

import (
	"encoding/json"
	"fmt"
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

	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	path, err := resolveVaultPath(cfg.Unencrypted.StoragePath, cfg.ID, unencryptedVaultFileExt)
	if err != nil {
		return nil, err
	}

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

	return withVaultLock(v.fullPath, v.save)
}

// load retrieves the vault contents from the file and parses it into the state.
func (v *UnencryptedVault) load() error {
	data, exists, err := readVaultFile(v.fullPath)
	if err != nil {
		return err
	}
	if !exists {
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
		return ErrVaultClosed
	}

	v.state.LastModified = time.Now()

	// Marshal to JSON with indentation for readability
	data, err := json.MarshalIndent(v.state, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal vault state: %w", err)
	}

	return writeVaultFileAtomic(v.fullPath, data)
}

// mutate runs a read-modify-write cycle under the cross-process vault lock.
// See AES256Vault.mutate for why the reload inside the lock is required.
func (v *UnencryptedVault) mutate(apply func() error) error {
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

func (v *UnencryptedVault) ID() string {
	return v.id
}

func (v *UnencryptedVault) Metadata() (Metadata, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()

	if v.state == nil {
		return Metadata{}, ErrVaultClosed
	}
	return v.state.Metadata, nil
}

func (v *UnencryptedVault) GetSecret(key string) (Secret, error) {
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

func (v *UnencryptedVault) SetSecret(key string, secret Secret) error {
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

func (v *UnencryptedVault) DeleteSecret(key string) error {
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

func (v *UnencryptedVault) ListSecrets() ([]string, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()

	if v.state == nil {
		return nil, ErrVaultClosed
	}

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

	if err := ValidateSecretKey(key); err != nil {
		return false, err
	}
	if v.state == nil {
		return false, ErrVaultClosed
	}

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
