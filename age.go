package vault

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"sync"
	"time"

	"filippo.io/age"
)

const (
	ageCurrentVaultVersion = 1
	ageVaultFileExt        = "age"
)

// AgeState represents the state of the local age vault
type AgeState struct {
	Metadata `json:"metadata"`

	Version    int               `json:"version"`
	ID         string            `json:"id"`
	Recipients []string          `json:"recipients"`
	Secrets    map[string]string `json:"secrets"`
}

// AgeVault manages operations on an instance of a local vault backed by age encryption.
type AgeVault struct {
	mu       sync.RWMutex
	id       string
	fullPath string

	cfg      *AgeConfig
	state    *AgeState
	resolver *IdentityResolver

	identities []age.Identity
	recipients []age.Recipient
}

func NewAgeVault(cfg *Config) (*AgeVault, error) {
	if cfg.Age == nil {
		return nil, fmt.Errorf("age configuration is required")
	}

	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	path, err := resolveVaultPath(cfg.Age.StoragePath, cfg.ID, ageVaultFileExt)
	if err != nil {
		return nil, err
	}

	vault := &AgeVault{
		mu:       sync.RWMutex{},
		fullPath: path,
		id:       cfg.ID,
		cfg:      cfg.Age,
		resolver: NewIdentityResolver(cfg.Age.IdentitySources),
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

func (v *AgeVault) init() error {
	now := time.Now()
	v.state = &AgeState{
		Version: ageCurrentVaultVersion,
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
		return fmt.Errorf("no recipients available for encryption, please add at least one recipient")
	}

	// Creating a vault encrypted only to someone else's key produces a file
	// that cannot be opened again -- including by the process that just wrote
	// it. Catch that here rather than at the next load.
	if !v.canDecryptWith(v.state.Recipients) {
		return fmt.Errorf(
			"%w: none of the configured recipients match your identity, "+
				"so the vault would be unreadable as soon as it is written",
			ErrInvalidRecipient,
		)
	}

	if err := v.parseRecipients(); err != nil {
		return fmt.Errorf("failed to parse recipients: %w", err)
	}

	return withVaultLock(v.fullPath, v.save)
}

// load reads the vault file and decrypts its contents
func (v *AgeVault) load() error {
	data, exists, err := readVaultFile(v.fullPath)
	if err != nil {
		return err
	}
	if !exists {
		return nil
	}

	r, err := age.Decrypt(bytes.NewReader(data), v.identities...)
	if err != nil {
		return fmt.Errorf("failed to decrypt vault file - do you have the right key?: %w", err)
	}

	var state AgeState
	if err := json.NewDecoder(r).Decode(&state); err != nil {
		return fmt.Errorf("failed to unmarshal vault state: %w", err)
	}

	v.state = &state
	if err := v.parseRecipients(); err != nil {
		return fmt.Errorf("failed to parse recipients: %w", err)
	}

	return nil
}

// save encrypts and writes the vault contents to disk
func (v *AgeVault) save() error {
	if v.state == nil {
		return ErrVaultClosed
	}

	if len(v.recipients) == 0 {
		return fmt.Errorf("no recipients available for encryption")
	}

	v.state.LastModified = time.Now()
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
		return fmt.Errorf("failed to encrypt AESState: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("failed to finalize encryption: %w", err)
	}

	return writeVaultFileAtomic(v.fullPath, buf.Bytes())
}

// mutate runs a read-modify-write cycle under the cross-process vault lock.
// See AES256Vault.mutate for why the reload inside the lock is required.
func (v *AgeVault) mutate(apply func() error) error {
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

func (v *AgeVault) ID() string {
	return v.id
}

func (v *AgeVault) Metadata() (Metadata, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()

	if v.state == nil {
		return Metadata{}, ErrVaultClosed
	}
	return v.state.Metadata, nil
}

func (v *AgeVault) GetSecret(key string) (Secret, error) {
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

func (v *AgeVault) SetSecret(key string, value Secret) error {
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
		v.state.Secrets[key] = value.PlainTextString()
		return nil
	})
}

func (v *AgeVault) DeleteSecret(key string) error {
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

func (v *AgeVault) ListSecrets() ([]string, error) {
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

func (v *AgeVault) HasSecret(key string) (bool, error) {
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

// canDecryptWith reports whether any resolved identity appears in recipients.
// Encrypting to a set that excludes your own key produces a vault you can never
// reopen, and a single mistyped public key is enough to do it.
func (v *AgeVault) canDecryptWith(recipients []string) bool {
	own := make(map[string]struct{}, len(v.identities))
	for _, id := range v.identities {
		if x, ok := id.(*age.X25519Identity); ok {
			own[x.Recipient().String()] = struct{}{}
		}
	}
	if len(own) == 0 {
		// An identity type we cannot map to a recipient string; do not block on
		// a check we are unable to perform.
		return true
	}

	for _, r := range recipients {
		if _, ok := own[r]; ok {
			return true
		}
	}
	return false
}

func (v *AgeVault) Close() error {
	// clear the secret state from memory
	v.mu.Lock()
	defer v.mu.Unlock()

	v.state = nil
	v.recipients = nil
	v.identities = nil

	return nil
}

func (v *AgeVault) AddRecipient(publicKey string) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	if v.state == nil {
		return ErrVaultClosed
	}

	return v.mutate(func() error {
		if err := v.addRecipientToState(publicKey); err != nil {
			return err
		}
		return v.parseRecipients()
	})
}

func (v *AgeVault) RemoveRecipient(publicKey string) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	if v.state == nil {
		return ErrVaultClosed
	}

	return v.mutate(func() error {
		// Don't allow removing the last recipient
		if len(v.state.Recipients) <= 1 {
			return fmt.Errorf("cannot remove the last recipient - at least one recipient is required for encryption")
		}

		remaining := make([]string, 0, len(v.state.Recipients))
		found := false
		for _, rec := range v.state.Recipients {
			if rec == publicKey {
				found = true
				continue
			}
			remaining = append(remaining, rec)
		}

		if !found {
			return fmt.Errorf("recipient %s not found", publicKey)
		}

		// Refusing here is the difference between "you removed a colleague" and
		// "you locked yourself out permanently". The previous check only
		// guarded the *last* recipient, not your own.
		if !v.canDecryptWith(remaining) {
			return fmt.Errorf(
				"%w: removing %s would leave no recipient matching your identity, "+
					"making the vault permanently unreadable",
				ErrInvalidRecipient, publicKey,
			)
		}

		// Commit to state only once the new set is known to parse, so a failure
		// cannot leave in-memory recipients inconsistent with what is on disk.
		previous := v.state.Recipients
		v.state.Recipients = remaining
		if err := v.parseRecipients(); err != nil {
			v.state.Recipients = previous
			return fmt.Errorf("failed to parse recipients: %w", err)
		}
		return nil
	})
}

func (v *AgeVault) ListRecipients() ([]string, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()

	if v.state == nil {
		return nil, ErrVaultClosed
	}

	recipients := make([]string, len(v.state.Recipients))
	copy(recipients, v.state.Recipients) // prevent modification of internal state
	return recipients, nil
}
