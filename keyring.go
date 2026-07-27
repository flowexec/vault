package vault

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/zalando/go-keyring"
)

// KeyringVault manages operations on a keyring-based vault that stores secrets in the system keyring.
type KeyringVault struct {
	mu      sync.RWMutex
	id      string
	service string

	metadata Metadata
}

func NewKeyringVault(cfg *Config) (*KeyringVault, error) {
	if cfg.Keyring == nil {
		return nil, fmt.Errorf("keyring configuration is required")
	}

	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	vault := &KeyringVault{
		id:      cfg.ID,
		service: cfg.Keyring.Service,
	}

	// Only a genuinely absent record means "new vault". Treating every error as
	// absence meant a locked keychain, a DBus failure or a dismissed prompt made
	// initMetadata() write a fresh record over the real Created timestamp.
	if err := vault.loadMetadata(); err != nil {
		if !errors.Is(err, keyring.ErrNotFound) {
			return nil, fmt.Errorf("failed to read keyring vault metadata: %w", err)
		}
		if err := vault.initMetadata(); err != nil {
			return nil, fmt.Errorf("failed to initialize keyring vault metadata: %w", err)
		}
	}

	return vault, nil
}

// Keyring entry names are a flat namespace shared by every vault using the same
// service, so the components are length-prefixed to make them unambiguous.
// Plain "%s-secret-%s" collided: vault "a" with key "b-secret-c" and vault
// "a-secret-b" with key "c" both produced "a-secret-b-secret-c", letting one
// vault silently read, overwrite or delete another's secret.
func (v *KeyringVault) namespaced(kind, key string) string {
	return fmt.Sprintf("%d:%s:%s:%s", len(v.id), v.id, kind, key)
}

// legacyNamespaced reproduces the pre-v0.3.0 entry name.
//
// Renaming the entries fixed a real collision but made every secret in an
// existing keyring vault unreachable: the data is still in the OS keyring, just
// under the old name. Reads fall back to this, and the next write migrates the
// entry, so an existing vault keeps working without the user re-entering
// anything.
func (v *KeyringVault) legacyNamespaced(kind, key string) string {
	if key == "" {
		return fmt.Sprintf("%s-%s", v.id, kind)
	}
	return fmt.Sprintf("%s-%s-%s", v.id, kind, key)
}

// get reads an entry, falling back to the pre-v0.3.0 name.
//
// Whether the value came from a legacy entry is deliberately not reported. It
// would only be useful for deciding to migrate, and set already deletes the
// legacy entry unconditionally, so the migration happens on the next write
// either way.
func (v *KeyringVault) get(kind, key string) (string, error) {
	data, err := keyring.Get(v.service, v.namespaced(kind, key))
	if err == nil {
		return data, nil
	}
	if !errors.Is(err, keyring.ErrNotFound) {
		return "", err
	}

	data, legacyErr := keyring.Get(v.service, v.legacyNamespaced(kind, key))
	if legacyErr != nil {
		// Report the miss against the current name; the legacy lookup is an
		// implementation detail and its error would only confuse.
		return "", err
	}
	return data, nil
}

// set writes an entry under the current name and removes any legacy entry it
// supersedes, so the rename completes on first write rather than leaving two
// copies of a secret in the keyring.
func (v *KeyringVault) set(kind, key, value string) error {
	if err := keyring.Set(v.service, v.namespaced(kind, key), value); err != nil {
		return err
	}
	_ = keyring.Delete(v.service, v.legacyNamespaced(kind, key))
	return nil
}

// remove deletes both the current and legacy entries so a delete cannot leave
// the old copy behind to reappear on the next read.
func (v *KeyringVault) remove(kind, key string) error {
	err := keyring.Delete(v.service, v.namespaced(kind, key))
	legacyErr := keyring.Delete(v.service, v.legacyNamespaced(kind, key))
	if err != nil && errors.Is(err, keyring.ErrNotFound) && legacyErr == nil {
		return nil
	}
	return err
}

func (v *KeyringVault) initMetadata() error {
	now := time.Now()
	v.metadata = Metadata{
		Created:      now,
		LastModified: now,
	}

	return v.saveMetadata()
}

func (v *KeyringVault) loadMetadata() error {
	data, err := v.get("metadata", "")
	if err != nil {
		return err
	}

	var metadata Metadata
	if err := json.Unmarshal([]byte(data), &metadata); err != nil {
		return fmt.Errorf("failed to unmarshal metadata: %w", err)
	}

	v.metadata = metadata
	return nil
}

func (v *KeyringVault) saveMetadata() error {
	v.metadata.LastModified = time.Now()

	data, err := json.Marshal(v.metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	return v.set("metadata", "", string(data))
}

func (v *KeyringVault) loadSecretsList() ([]string, error) {
	data, err := v.get("secrets-list", "")
	if err != nil {
		if errors.Is(err, keyring.ErrNotFound) {
			return []string{}, nil
		}
		return nil, err
	}

	var secrets []string
	if err := json.Unmarshal([]byte(data), &secrets); err != nil {
		return nil, fmt.Errorf("failed to unmarshal secrets list: %w", err)
	}

	return secrets, nil
}

func (v *KeyringVault) saveSecretsList(secrets []string) error {
	data, err := json.Marshal(secrets)
	if err != nil {
		return fmt.Errorf("failed to marshal secrets list: %w", err)
	}

	return v.set("secrets-list", "", string(data))
}

func (v *KeyringVault) addSecretToList(key string) error {
	secrets, err := v.loadSecretsList()
	if err != nil {
		return err
	}

	// Check if secret already exists in list
	for _, s := range secrets {
		if s == key {
			return nil // Already exists
		}
	}

	secrets = append(secrets, key)
	sort.Strings(secrets)

	return v.saveSecretsList(secrets)
}

func (v *KeyringVault) removeSecretFromList(key string) error {
	secrets, err := v.loadSecretsList()
	if err != nil {
		return err
	}

	// Remove the secret from the list
	for i, s := range secrets {
		if s == key {
			secrets = append(secrets[:i], secrets[i+1:]...)
			break
		}
	}

	return v.saveSecretsList(secrets)
}

func (v *KeyringVault) ID() string {
	return v.id
}

func (v *KeyringVault) Metadata() (Metadata, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()

	return v.metadata, nil
}

func (v *KeyringVault) GetSecret(key string) (Secret, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()

	if err := ValidateSecretKey(key); err != nil {
		return nil, err
	}

	data, err := v.get("secret", key)
	if err != nil {
		if errors.Is(err, keyring.ErrNotFound) {
			return nil, ErrSecretNotFound
		}
		return nil, fmt.Errorf("failed to get secret from keyring: %w", err)
	}

	return NewSecretValue([]byte(data)), nil
}

func (v *KeyringVault) SetSecret(key string, secret Secret) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	if err := ValidateSecretKey(key); err != nil {
		return err
	}

	if err := v.set("secret", key, secret.PlainTextString()); err != nil {
		return fmt.Errorf("failed to set secret in keyring: %w", err)
	}

	if err := v.addSecretToList(key); err != nil {
		return fmt.Errorf("failed to update secrets list: %w", err)
	}

	return v.saveMetadata()
}

func (v *KeyringVault) DeleteSecret(key string) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	if err := ValidateSecretKey(key); err != nil {
		return err
	}

	// Check if secret exists first
	_, err := v.get("secret", key)
	if err != nil {
		if errors.Is(err, keyring.ErrNotFound) {
			return ErrSecretNotFound
		}
		return fmt.Errorf("failed to check secret existence: %w", err)
	}

	if err := v.remove("secret", key); err != nil {
		return fmt.Errorf("failed to delete secret from keyring: %w", err)
	}

	if err := v.removeSecretFromList(key); err != nil {
		return fmt.Errorf("failed to update secrets list: %w", err)
	}

	return v.saveMetadata()
}

func (v *KeyringVault) ListSecrets() ([]string, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()

	secrets, err := v.loadSecretsList()
	if err != nil {
		return nil, fmt.Errorf("failed to load secrets list: %w", err)
	}

	// Return a copy to prevent external modification
	result := make([]string, len(secrets))
	copy(result, secrets)

	return result, nil
}

func (v *KeyringVault) HasSecret(key string) (bool, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()

	if err := ValidateSecretKey(key); err != nil {
		return false, err
	}

	_, err := v.get("secret", key)
	if err != nil {
		if errors.Is(err, keyring.ErrNotFound) {
			return false, nil
		}
		return false, fmt.Errorf("failed to check secret existence: %w", err)
	}

	return true, nil
}

func (v *KeyringVault) Close() error {
	// Keyring doesn't need explicit cleanup
	// Just clear the in-memory metadata
	v.mu.Lock()
	defer v.mu.Unlock()

	v.metadata = Metadata{}

	return nil
}
