package vault

import (
	"fmt"
	"os"
	"strings"

	"filippo.io/age"
)

type IdentityResolver struct {
	sources []IdentitySource
}

func NewIdentityResolver(sources []IdentitySource) *IdentityResolver {
	if len(sources) == 0 {
		sources = []IdentitySource{
			{Type: envSource, Name: DefaultVaultKeyEnv},
		}
	}
	return &IdentityResolver{sources: sources}
}

func (r *IdentityResolver) ResolveIdentities() ([]age.Identity, error) {
	var identities []age.Identity

	for _, source := range r.sources {
		switch source.Type {
		case envSource:
			if id := r.fromEnvironment(source.Name); id != nil {
				identities = append(identities, id)
			}
		case fileSource:
			if id, err := r.fromFile(source.Path); err != nil {
				return nil, fmt.Errorf("failed to read identity from file %s: %w", source.Path, err)
			} else if id != nil {
				identities = append(identities, id)
			}
		}
	}

	if len(identities) == 0 {
		return nil, fmt.Errorf("%w: no valid identities found", ErrNoAccess)
	}

	return identities, nil
}

func (r *IdentityResolver) fromEnvironment(envVar string) age.Identity {
	if envVar == "" {
		envVar = DefaultVaultKeyEnv
	}

	keyStr := os.Getenv(envVar)
	if keyStr == "" {
		return nil
	}

	identity, err := age.ParseX25519Identity(keyStr)
	if err != nil {
		return nil
	}

	return identity
}

func (r *IdentityResolver) fromFile(path string) (age.Identity, error) {
	if path == "" {
		return nil, fmt.Errorf("identity file path cannot be empty")
	}

	expandedPath, err := expandPath(path)
	if err != nil {
		return nil, fmt.Errorf("failed to expand identity file path %s: %w", path, err)
	}

	keyBytes, err := os.ReadFile(expandedPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read identity file %s: %w", expandedPath, err)
	}

	identity, err := age.ParseX25519Identity(strings.TrimSpace(string(keyBytes)))
	if err != nil {
		return nil, fmt.Errorf("invalid identity in file %s: %w", expandedPath, err)
	}

	return identity, nil
}

func (v *AgeVault) addRecipientToState(publicKey string) error {
	_, err := age.ParseX25519Recipient(publicKey)
	if err != nil {
		return fmt.Errorf("%w: invalid recipient key: %w", ErrInvalidRecipient, err)
	}

	for _, existing := range v.state.Recipients {
		if existing == publicKey {
			return nil
		}
	}

	v.state.Recipients = append(v.state.Recipients, publicKey)
	return nil
}

func (v *AgeVault) parseRecipients() error {
	v.recipients = make([]age.Recipient, 0, len(v.state.Recipients))

	for _, recipientStr := range v.state.Recipients {
		recipient, err := age.ParseX25519Recipient(recipientStr)
		if err != nil {
			return fmt.Errorf("%w: invalid recipient %s: %w", ErrInvalidRecipient, recipientStr, err)
		}
		v.recipients = append(v.recipients, recipient)
	}

	return nil
}
