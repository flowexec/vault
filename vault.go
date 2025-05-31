package vault

import (
	"fmt"
)

type Provider interface {
	GetSecret(key string) (Secret, error)
	SetSecret(key string, value Secret) error
	DeleteSecret(key string) error
	ListSecrets() ([]string, error)
	HasSecret(key string) (bool, error)

	// ID returns a unique identifier for this vault instance
	ID() string
	Close() error
}

type Option func(*Config)

// New creates a new vault instance with the provided ID and options
func New(id string, opts ...Option) (Provider, error) {
	config := &Config{ID: id}
	for _, opt := range opts {
		opt(config)
	}
	if err := config.Validate(); err != nil {
		return nil, err
	}

	switch config.Type {
	case ProviderTypeLocal:
		return NewLocalVault(config)
	case ProviderTypeExternal:
		return nil, fmt.Errorf("external vault provider not implemented yet")
	}
	return nil, fmt.Errorf("unsupported vault type: %s", config.Type)
}

// WithProvider sets the vault provider type
func WithProvider(provider ProviderType) Option {
	return func(c *Config) {
		c.Type = provider
	}
}

// WithLocalPath sets the local vault storage fullPath
func WithLocalPath(path string) Option {
	return func(c *Config) {
		if c.Local == nil {
			c.Local = &LocalConfig{}
		}
		c.Local.StoragePath = path
	}
}

// WithLocalIdentityFromEnv specifies to retrieve the key from an environment variable for local vaults
func WithLocalIdentityFromEnv(envVar string) Option {
	return func(c *Config) {
		if c.Local == nil {
			c.Local = &LocalConfig{}
		}
		if len(c.Local.IdentitySources) == 0 {
			c.Local.IdentitySources = make([]IdentitySource, 0)
		}
		c.Local.IdentitySources = append(
			c.Local.IdentitySources,
			IdentitySource{Type: "env", Name: envVar},
		)
	}
}

// WithLocalIdentityFromFile specifies to retrieve the key from a file for local vaults
func WithLocalIdentityFromFile(path string) Option {
	return func(c *Config) {
		if c.Local == nil {
			c.Local = &LocalConfig{}
		}
		if len(c.Local.IdentitySources) == 0 {
			c.Local.IdentitySources = make([]IdentitySource, 0)
		}
		c.Local.IdentitySources = append(
			c.Local.IdentitySources,
			IdentitySource{Type: "file", Path: path},
		)
	}
}

// WithRecipients sets the recipients for local vaults
func WithRecipients(recipients ...string) Option {
	return func(c *Config) {
		if c.Local == nil {
			c.Local = &LocalConfig{}
		}
		// if len(c.Local.Recipients) == 0 {
		// 	c.Local.Recipients = make([]string, len(recipients))
		// }
		c.Local.Recipients = append(c.Local.Recipients, recipients...)
	}
}

// WithExternalConfig sets the external vault configuration. FOR TESTING PURPOSES ONLY.
// TODO: break this down when the external provider is fully impelemented
func WithExternalConfig(cfg *ExternalConfig) Option {
	return func(c *Config) {
		c.Type = ProviderTypeExternal
		c.External = cfg
	}
}

type RecipientManager interface {
	AddRecipient(identity string) error
	RemoveRecipient(identity string) error
	ListRecipients() ([]string, error)
}

func HasRecipientManagement(v Provider) (RecipientManager, bool) {
	rm, ok := v.(RecipientManager)
	return rm, ok
}
