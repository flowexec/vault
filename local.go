package vault

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"filippo.io/age"
)

const (
	currentVaultVersion = 1
	vaultFileBase       = "vault"
	vaultFileExt        = ".age"
)

type Metadata struct {
	Created      time.Time `json:"created"`
	LastModified time.Time `json:"lastModified"`
}

// LocalSecret represents an encrypted secret with its metadata
type LocalSecret struct {
	Metadata `json:"metadata"`

	Encrypted   []byte `json:"encrypted"`
	Nonce       []byte `json:"nonce"`
	Description string `json:"description,omitempty"`
}

// LocalState represents the state of the local vault
type LocalState struct {
	Metadata `json:"metadata"`

	Version    int               `json:"version"`
	ID         string            `json:"id"`
	Recipients []string          `json:"recipients"`
	Secrets    map[string]string `json:"secrets"`
}

// LocalVault manages operations on an instance of a local vault
type LocalVault struct {
	mu       sync.RWMutex
	id       string
	fullPath string

	cfg      *LocalConfig
	state    *LocalState
	resolver *IdentityResolver

	identities []age.Identity
	recipients []age.Recipient
}

func NewLocalVault(cfg *Config) (*LocalVault, error) {
	path := filepath.Join(
		filepath.Clean(cfg.Local.StoragePath),
		filepath.Clean(fmt.Sprintf("%s-%s.%s", vaultFileBase, cfg.ID, vaultFileExt)),
	)

	vault := &LocalVault{
		mu:       sync.RWMutex{},
		fullPath: path,
		id:       cfg.ID,
		cfg:      cfg.Local,
		resolver: NewIdentityResolver(cfg.Local.IdentitySources),
	}

	ids, err := vault.resolver.ResolveIdentities()
	if err != nil {
		return nil, fmt.Errorf("failed to resolve identities: %w", err)
	}
	vault.identities = ids

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

func (v *LocalVault) init() error {
	now := time.Now()
	v.state = &LocalState{
		Version: currentVaultVersion,
		ID:      v.id,
		Metadata: Metadata{
			Created:      now,
			LastModified: now,
		},
		Recipients: v.cfg.Recipients,
		Secrets:    make(map[string]string),
	}

	for _, recipientKey := range v.cfg.Recipients {
		if err := v.addRecipientToState(recipientKey); err != nil {
			return fmt.Errorf("failed to add initial recipient %s: %w", recipientKey, err)
		}
	}

	if len(v.state.Recipients) == 0 {
		// what to do...
		return fmt.Errorf("no recipients available for encryption, please add at least one recipient")
	}

	if err := v.parseRecipients(); err != nil {
		return fmt.Errorf("failed to parse recipients: %w", err)
	}

	return v.save()
}

// load reads the vault file and decrypts its contents
func (v *LocalVault) load() error {
	data, err := os.ReadFile(v.fullPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("failed to read vault file: %w", err)
	}

	if len(data) == 0 {
		return nil
	}

	// decrypt the vault file using age
	r, err := age.Decrypt(bytes.NewReader(data), v.identities...)
	if err != nil {
		return fmt.Errorf("failed to decrypt vault file - do you have the right key?: %w", err)
	}

	var state LocalState
	if err := json.NewDecoder(r).Decode(&state); err != nil {
		return fmt.Errorf("failed to unmarshal vault state: %w", err)
	}

	// store the state and recipients on the LocalVault obj
	v.state = &state
	if err := v.parseRecipients(); err != nil {
		return fmt.Errorf("failed to parse recipients: %w", err)
	}

	return nil
}

// save encrypts and writes the vault contents to disk
func (v *LocalVault) save() error {
	if len(v.recipients) == 0 {
		return fmt.Errorf("no recipients available for encryption")
	}

	v.state.Metadata.LastModified = time.Now()
	data, err := json.Marshal(v.state)
	if err != nil {
		return fmt.Errorf("failed to marshal vault state: %w", err)
	}

	var buf bytes.Buffer
	// encrypt the entire file using age
	w, err := age.Encrypt(&buf, v.recipients...)
	if err != nil {
		return fmt.Errorf("failed to create age encryptor: %w", err)
	}
	if _, err := w.Write(data); err != nil {
		return fmt.Errorf("failed to encrypt data: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("failed to finalize encryption: %w", err)
	}

	// write to the file atomically
	if err := os.MkdirAll(filepath.Dir(v.fullPath), 0755); err != nil {
		return fmt.Errorf("failed to create vault directory: %w", err)
	}
	tempFile := v.fullPath + ".tmp"
	if err := os.WriteFile(tempFile, buf.Bytes(), 0600); err != nil {
		return fmt.Errorf("failed to write temp vault file: %w", err)
	}

	if err := os.Rename(tempFile, v.fullPath); err != nil {
		_ = os.Remove(tempFile) // Clean up on failure
		return fmt.Errorf("failed to move vault file: %w", err)
	}

	return nil
}

func (v *LocalVault) ID() string {
	return v.id
}

func (v *LocalVault) GetSecret(key string) (Secret, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()

	value, exists := v.state.Secrets[key]
	if !exists {
		return nil, ErrSecretNotFound
	}

	return NewSecretValue([]byte(value)), nil
}

func (v *LocalVault) SetSecret(key string, value Secret) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	if v.state.Secrets == nil {
		v.state.Secrets = make(map[string]string)
	}

	v.state.Secrets[key] = value.String()
	return v.save()
}

func (v *LocalVault) DeleteSecret(key string) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	_, exists := v.state.Secrets[key]
	if !exists {
		return ErrSecretNotFound
	}

	delete(v.state.Secrets, key)
	return v.save()
}

func (v *LocalVault) ListSecrets() ([]string, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()

	keys := make([]string, 0, len(v.state.Secrets))
	for k := range v.state.Secrets {
		keys = append(keys, k)
	}
	return keys, nil
}

func (v *LocalVault) HasSecret(key string) (bool, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()

	_, exists := v.state.Secrets[key]
	return exists, nil
}

func (v *LocalVault) Close() error {
	// do i need to do anything here?
	return nil
}

func (v *LocalVault) AddRecipient(publicKey string) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	if err := v.addRecipientToState(publicKey); err != nil {
		return err
	}
	if err := v.parseRecipients(); err != nil {
		return fmt.Errorf("failed to parse recipients: %w", err)
	}

	return v.save()
}

func (v *LocalVault) RemoveRecipient(publicKey string) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	found := false
	for i, rec := range v.state.Recipients {
		if rec == publicKey {
			v.state.Recipients = append(v.state.Recipients[:i], v.state.Recipients[i+1:]...)
			found = true
			break
		}
	}

	if !found {
		return fmt.Errorf("recipient %s not found", publicKey)
	}

	if err := v.parseRecipients(); err != nil {
		return fmt.Errorf("failed to parse recipients: %w", err)
	}

	return v.save()
}

func (v *LocalVault) ListRecipients() ([]string, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()

	recipients := make([]string, len(v.state.Recipients))
	copy(recipients, v.state.Recipients) // prevent modification of internal state
	return recipients, nil
}
