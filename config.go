package vault

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"time"
)

type ProviderType string

const (
	ProviderTypeAES256      ProviderType = "aes256"
	ProviderTypeAge         ProviderType = "age"
	ProviderTypeExternal    ProviderType = "external"
	ProviderTypeKeyring     ProviderType = "keyring"
	ProviderTypeUnencrypted ProviderType = "unencrypted"
)

type Config struct {
	ID          string             `json:"id"`
	Type        ProviderType       `json:"type"`
	Age         *AgeConfig         `json:"age,omitempty"`
	Aes         *AesConfig         `json:"aes,omitempty"`
	External    *ExternalConfig    `json:"external,omitempty"`
	Keyring     *KeyringConfig     `json:"keyring,omitempty"`
	Unencrypted *UnencryptedConfig `json:"unencrypted,omitempty"`

	// pendingLocalPath holds a WithLocalPath value until the provider type is
	// known. Unexported so it never reaches the serialized config.
	pendingLocalPath string
}

func (c *Config) Validate() error {
	// The ID becomes part of a filename and of keyring entry names, so it needs
	// a real charset check, not just a non-empty check.
	if err := ValidateVaultID(c.ID); err != nil {
		return err
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
	case ProviderTypeKeyring:
		if c.Keyring == nil {
			return fmt.Errorf("%w: keyring configuration required for keyring vault provider", ErrInvalidConfig)
		}
		return c.Keyring.Validate()
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

	// Owner-only, matching the vault storage directory. A vault config carries
	// the provider's command templates and environment values, and its presence
	// alone discloses which secret backends a user has configured; there is no
	// reason for it to be group-readable when the file itself is 0600.
	if err := os.MkdirAll(filepath.Dir(path), vaultDirMode); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	if err := os.WriteFile(filepath.Clean(path), data, vaultFileMode); err != nil {
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

// CommandConfig represents a command template to be executed with its arguments
type CommandConfig struct {
	// CommandTemplate for building command arguments
	CommandTemplate string `json:"cmd"`
	// OutputTemplate for parsing command output
	OutputTemplate string `json:"output,omitempty"`
	// InputTemplate for providing input to the command
	InputTemplate string `json:"input,omitempty"`
}

// SourceRef records which generator produced a configuration. The library never
// interprets it; it exists so a tool that renders configs from presets can
// recognise its own output later and re-run preset-specific work (a readiness
// check, a discovery browse) against an already-created vault.
type SourceRef struct {
	Name   string            `json:"name"`
	Values map[string]string `json:"values,omitempty"`
}

// ExternalConfig contains external (cli command-based) vault configuration.
//
// An external vault is a read-through registry, not a store. It holds a set of
// links -- an alias paired with a reference the provider's CLI understands, such
// as an op:// URI, a pass entry path or an SSM parameter name -- and resolves
// them by running Get. It never writes secret material anywhere.
//
// That is why there is only a get command here. Writing through to a provider
// meant either interpolating the secret into a shell command or handing it to a
// CLI as an argv element, and it meant a delete that destroyed real data. Both
// are gone: a secret is created in the tool that owns it, and removing a link
// removes only the link.
type ExternalConfig struct {
	// Get resolves a reference to a secret value. Its command template receives
	// {{ ref }} (the reference) and {{ key }} (the alias).
	Get CommandConfig `json:"get,omitempty"`
	// Metadata CommandConfig for the metadata operation
	Metadata CommandConfig `json:"metadata,omitempty"`

	// StoragePath is the directory holding this vault's link registry.
	//
	// Not required by Validate: a config authored by hand or rendered from a
	// preset does not know where the consuming tool keeps vault state, so the
	// tool fills this in before constructing the provider. It is required at
	// construction, where a missing value is a real error rather than a
	// half-configured file on disk.
	StoragePath string `json:"storage_path,omitempty"`

	// ReferencePattern constrains what a reference may look like for this
	// provider, as a regular expression. It is a usability gate that catches a
	// mistyped reference at link time rather than at read time; the safety rules
	// in validateReference apply regardless of what it permits.
	ReferencePattern string `json:"reference_pattern,omitempty"`

	// Source records which preset generated this config, for the generator's own
	// use. Opaque to the library.
	Source *SourceRef `json:"source,omitempty"`

	// Environment variables for commands
	Environment map[string]string `json:"environment,omitempty"`

	// Timeout duration string for command execution
	Timeout string `json:"timeout,omitempty"`

	// WorkingDir for command execution
	WorkingDir string `json:"working_dir,omitempty"`

	// NotFoundPattern is matched against a failing command's error output to tell
	// "this secret does not exist" apart from a real failure (an expired session,
	// a network error, a permissions problem). Without it, any non-zero exit is
	// read as absence. Example: "ParameterNotFound".
	NotFoundPattern string `json:"not_found_pattern,omitempty"`

	// Legacy write-era fields. Parsed so a pre-v0.4.0 config still unmarshals
	// instead of failing at load, and reported as inert by Validate. Set and
	// Delete are never executed. List is read by MigrateLegacyLinks, which is the
	// one place a legacy config still has something useful to say: it can name
	// the keys that used to exist so they can be seeded as links.
	LegacySet           CommandConfig `json:"set,omitempty"`
	LegacyDelete        CommandConfig `json:"delete,omitempty"`
	LegacyList          CommandConfig `json:"list,omitempty"`
	LegacyListSeparator string        `json:"separator,omitempty"`
	LegacyExists        CommandConfig `json:"exists,omitempty"`
}

// LegacyWriteCommands returns the names of the inert write-era commands present
// in this config, so a caller can tell the user they are being ignored.
func (c *ExternalConfig) LegacyWriteCommands() []string {
	var found []string
	for _, op := range []struct {
		name string
		tmpl string
	}{
		{"set", c.LegacySet.CommandTemplate},
		{"delete", c.LegacyDelete.CommandTemplate},
		{"list", c.LegacyList.CommandTemplate},
		{"exists", c.LegacyExists.CommandTemplate},
	} {
		if op.tmpl != "" {
			found = append(found, op.name)
		}
	}
	return found
}

// timeoutDuration parses the configured timeout. An empty timeout means no limit.
func (c *ExternalConfig) timeoutDuration() (time.Duration, error) {
	if c.Timeout == "" {
		return 0, nil
	}
	return time.ParseDuration(c.Timeout)
}

// secretValueRefs matches a template action referencing the secret value. These
// are rejected in command templates: the rendered command is executed by a shell
// and the template engine performs no quoting, so interpolating a secret there is
// a command-injection sink and silently corrupts values containing shell
// metacharacters. Secrets must travel over stdin via an input template.
var secretValueRefs = regexp.MustCompile(`{{[^}]*\b(value|password)\b[^}]*}}`)

func (c *ExternalConfig) Validate() error {
	if c.Get.CommandTemplate == "" {
		return fmt.Errorf("%w: a get command template is required for an external vault", ErrInvalidConfig)
	}

	cmdTemplates := map[string]string{
		"get":      c.Get.CommandTemplate,
		"metadata": c.Metadata.CommandTemplate,
	}
	for op, tmpl := range cmdTemplates {
		// An external vault no longer carries secret material into a command, so
		// this can only fire on a hand-written template. Keep the check: the
		// rendered command is run by a shell with no quoting, and a template that
		// still asks for the value would silently render it empty rather than
		// failing, which is a worse outcome than a clear rejection.
		if secretValueRefs.MatchString(tmpl) {
			return fmt.Errorf(
				"%w: the %s command template references a secret value. External vaults are "+
					"read-through and never receive one, so this can only render empty",
				ErrInvalidConfig, op,
			)
		}
	}

	if c.ReferencePattern != "" {
		if _, err := regexp.Compile(c.ReferencePattern); err != nil {
			return fmt.Errorf("%w: invalid reference_pattern %q: %w", ErrInvalidConfig, c.ReferencePattern, err)
		}
	}

	if _, err := c.timeoutDuration(); err != nil {
		return fmt.Errorf("%w: invalid timeout duration %q: %w", ErrInvalidConfig, c.Timeout, err)
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

// KeyringConfig contains keyring vault configuration
type KeyringConfig struct {
	// Service name used for keyring operations
	Service string `json:"service"`
}

func (c *KeyringConfig) Validate() error {
	if c.Service == "" {
		return fmt.Errorf("%w: service name is required for keyring vault", ErrInvalidConfig)
	}
	return nil
}
