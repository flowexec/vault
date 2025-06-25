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
	case ProviderTypeAge:
		return NewAgeVault(config)
	case ProviderTypeAES256:
		return NewAES256Vault(config)
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

// WithAgePath sets the age vault storage path
func WithAgePath(path string) Option {
	return func(c *Config) {
		if c.Age == nil {
			c.Age = &AgeConfig{}
		}
		c.Age.StoragePath = path
	}
}

// WithAESPath sets the AES vault storage path
func WithAESPath(path string) Option {
	return func(c *Config) {
		if c.Aes == nil {
			c.Aes = &AesConfig{}
		}
		c.Aes.StoragePath = path
	}
}

// WithLocalPath sets the local vault storage path (works for both Age and AES based on provider type)
func WithLocalPath(path string) Option {
	return func(c *Config) {
		//nolint:exhaustive
		switch c.Type {
		case ProviderTypeAge:
			if c.Age == nil {
				c.Age = &AgeConfig{}
			}
			c.Age.StoragePath = path
		case ProviderTypeAES256:
			if c.Aes == nil {
				c.Aes = &AesConfig{}
			}
			c.Aes.StoragePath = path
		}
	}
}

// WithAgeIdentityFromEnv specifies to retrieve the age identity from an environment variable
func WithAgeIdentityFromEnv(envVar string) Option {
	return func(c *Config) {
		if c.Age == nil {
			c.Age = &AgeConfig{}
		}
		if len(c.Age.IdentitySources) == 0 {
			c.Age.IdentitySources = make([]IdentitySource, 0)
		}
		c.Age.IdentitySources = append(
			c.Age.IdentitySources,
			IdentitySource{Type: "env", Name: envVar},
		)
	}
}

// WithAgeIdentityFromFile specifies to retrieve the age identity from a file
func WithAgeIdentityFromFile(path string) Option {
	return func(c *Config) {
		if c.Age == nil {
			c.Age = &AgeConfig{}
		}
		if len(c.Age.IdentitySources) == 0 {
			c.Age.IdentitySources = make([]IdentitySource, 0)
		}
		c.Age.IdentitySources = append(
			c.Age.IdentitySources,
			IdentitySource{Type: "file", Path: path},
		)
	}
}

// WithAESKeyFromEnv specifies to retrieve the AES key from an environment variable
func WithAESKeyFromEnv(envVar string) Option {
	return func(c *Config) {
		if c.Aes == nil {
			c.Aes = &AesConfig{}
		}
		if len(c.Aes.KeySource) == 0 {
			c.Aes.KeySource = make([]KeySource, 0)
		}
		c.Aes.KeySource = append(
			c.Aes.KeySource,
			KeySource{Type: "env", Name: envVar},
		)
	}
}

// WithAESKeyFromFile specifies to retrieve the AES key from a file
func WithAESKeyFromFile(path string) Option {
	return func(c *Config) {
		if c.Aes == nil {
			c.Aes = &AesConfig{}
		}
		if len(c.Aes.KeySource) == 0 {
			c.Aes.KeySource = make([]KeySource, 0)
		}
		c.Aes.KeySource = append(
			c.Aes.KeySource,
			KeySource{Type: "file", Path: path},
		)
	}
}

// WithAgeRecipients sets the recipients for age vaults
func WithAgeRecipients(recipients ...string) Option {
	return func(c *Config) {
		if c.Age == nil {
			c.Age = &AgeConfig{}
		}
		// if len(c.Age.Recipients) == 0 {
		// 	c.Age.Recipients = make([]string, len(recipients))
		// }
		c.Age.Recipients = append(c.Age.Recipients, recipients...)
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
