package vault

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

type ProviderType string

const (
	ProviderTypeAES256      ProviderType = "aes256"
	ProviderTypeAge         ProviderType = "age"
	ProviderTypeExternal    ProviderType = "external"
	ProviderTypeUnencrypted ProviderType = "unencrypted"
)

type Config struct {
	ID          string             `json:"id"`
	Type        ProviderType       `json:"type"`
	Age         *AgeConfig         `json:"age,omitempty"`
	Aes         *AesConfig         `json:"aes,omitempty"`
	External    *ExternalConfig    `json:"external,omitempty"`
	Unencrypted *UnencryptedConfig `json:"unencrypted,omitempty"`
}

func (c *Config) Validate() error {
	if c.ID == "" {
		return fmt.Errorf("%w: vault ID is required", ErrInvalidConfig)
	}

	switch c.Type {
	case ProviderTypeAge:
		if c.Age == nil {
			return fmt.Errorf("%w: age configuration required for the age vault provider", ErrInvalidConfig)
		}
		return c.Age.Validate()
	case ProviderTypeAES256:
		if c.Aes == nil {
			return fmt.Errorf("%w: aes configuration required for the aes256 vault provider", ErrInvalidConfig)
		}
		return c.Aes.Validate()
	case ProviderTypeExternal:
		if c.External == nil {
			return fmt.Errorf("%w: external configuration required for external vault", ErrInvalidConfig)
		}
		return c.External.Validate()
	case ProviderTypeUnencrypted:
		if c.Unencrypted == nil {
			return fmt.Errorf("%w: unencrypted configuration required for unencrypted vault provider", ErrInvalidConfig)
		}
		return c.Unencrypted.Validate()
	default:
		return fmt.Errorf("%w: unsupported vault type: %s", ErrInvalidConfig, c.Type)
	}
}

// SaveConfigJSON saves the vault configuration to a file in JSON format
func SaveConfigJSON(config Config, path string) error {
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	if err := os.WriteFile(filepath.Clean(path), data, 0600); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}

// LoadConfigJSON loads the vault configuration from a file in JSON format
func LoadConfigJSON(path string) (Config, error) {
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return Config{}, fmt.Errorf("failed to read config file: %w", err)
	}

	var config Config
	if err := json.Unmarshal(data, &config); err != nil {
		return Config{}, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	return config, nil
}

// IdentitySource represents a source for the local vault identity keys
type IdentitySource struct {
	// Type of identity source
	// Must be one of: "env", "file"
	Type string `json:"type"`
	// Path to the identity file (for "file" type)
	Path string `json:"fullPath,omitempty"`
	// Environment variable name (for "env" type)
	Name string `json:"name,omitempty"`
}

// AgeConfig contains local (age-based) vault configuration
type AgeConfig struct {
	// Storage location for the vault file
	StoragePath string `json:"storage_path"`

	// Identity sources for decryption (in order of preference)
	IdentitySources []IdentitySource `json:"identity_sources,omitempty"`

	// Recipients who can decrypt secrets
	Recipients []string `json:"recipients,omitempty"`
}

func (c *AgeConfig) Validate() error {
	if c.StoragePath == "" {
		return fmt.Errorf("%w: storage path is required for age vault", ErrInvalidConfig)
	}
	if len(c.IdentitySources) == 0 {
		return fmt.Errorf("%w: at least one identity source is required for age vault", ErrInvalidConfig)
	}
	for _, source := range c.IdentitySources {
		if source.Type != envSource && source.Type != fileSource {
			return fmt.Errorf("%w: invalid identity source type: %s", ErrInvalidConfig, source.Type)
		}
		if source.Type == fileSource && source.Path == "" {
			return fmt.Errorf("%w: path is required for file identity source", ErrInvalidConfig)
		}
		if source.Type == envSource && source.Name == "" {
			return fmt.Errorf("%w: name is required for env identity source", ErrInvalidConfig)
		}
	}
	return nil
}

// KeySource represents a source for the local vault encryption keys
type KeySource struct {
	// Type of data encryption key source
	// Must be one of: "env", "file"
	Type string `json:"type"`
	// Path to the identity file (for "file" type)
	Path string `json:"fullPath,omitempty"`
	// Environment variable name (for "env" type)
	Name string `json:"name,omitempty"`
}

// AesConfig contains local (AES256-based) vault configuration
type AesConfig struct {
	// Storage location for the vault file
	StoragePath string `json:"storage_path"`
	// DEK sources for decryption (in order of preference)
	KeySource []KeySource `json:"key_sources,omitempty"`
}

func (c *AesConfig) Validate() error {
	if c.StoragePath == "" {
		return fmt.Errorf("%w: storage path is required for AES vault", ErrInvalidConfig)
	}
	if len(c.KeySource) == 0 {
		return fmt.Errorf("%w: at least one key source is required for AES vault", ErrInvalidConfig)
	}
	for _, source := range c.KeySource {
		if source.Type != envSource && source.Type != fileSource {
			return fmt.Errorf("%w: invalid key source type: %s", ErrInvalidConfig, source.Type)
		}
		if source.Type == fileSource && source.Path == "" {
			return fmt.Errorf("%w: path is required for file key source", ErrInvalidConfig)
		}
		if source.Type == envSource && source.Name == "" {
			return fmt.Errorf("%w: name is required for env key source", ErrInvalidConfig)
		}
	}
	return nil
}

// CommandSet defines the command templates for external vault operations
type CommandSet struct {
	Get    string `json:"get"`
	Set    string `json:"set"`
	Delete string `json:"delete"`
	List   string `json:"list"`
	Exists string `json:"exists,omitempty"`
}

// ExternalConfig contains external (cli command-based) vault configuration
type ExternalConfig struct {
	// Command templates for operations
	Commands CommandSet `json:"commands"`

	// Environment variables for commands
	Environment map[string]string `json:"environment,omitempty"`

	// Timeout for command execution
	Timeout time.Duration `json:"timeout,omitempty"`

	// WorkingDir for command execution
	WorkingDir string `json:"working_dir,omitempty"`
}

func (c *ExternalConfig) Validate() error {
	if c.Commands.Get == "" || c.Commands.Set == "" {
		return fmt.Errorf("%w: get and set commands are required for external vault", ErrInvalidConfig)
	}
	return nil
}

// UnencryptedConfig contains unencrypted (plain text) vault configuration
type UnencryptedConfig struct {
	// Storage location for the vault file
	StoragePath string `json:"storage_path"`
}

func (c *UnencryptedConfig) Validate() error {
	if c.StoragePath == "" {
		return fmt.Errorf("%w: storage path is required for unencrypted vault", ErrInvalidConfig)
	}
	return nil
}
