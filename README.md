# Vault

<p>
    <a href="https://img.shields.io/github/v/release/flowexec/vault"><img src="https://img.shields.io/github/v/release/flowexec/vault" alt="GitHub release"></a>
    <a href="https://pkg.go.dev/github.com/flowexec/vault"><img src="https://pkg.go.dev/badge/github.com/flowexec/vault.svg" alt="Go Reference"></a>
</p>

A flexible Go library for secure secret management with multiple backend providers. Made for [flow](https://github.com/jahvon/flow) but can be used independently.

## Features

- **Multiple Provider Support**: Choose from local encrypted storage, system keyring, or external CLI tools
- **Pluggable Architecture**: Easy to extend with custom providers
- **Type Safety**: Strong typing for secrets with secure memory handling
- **Thread Safe**: Concurrent access protection with read/write mutexes
- **Comprehensive API**: Full CRUD operations plus metadata and existence checks

## Upgrading to v0.3.0

v0.3.0 is a security and correctness release. It contains breaking changes, each
of which replaces behaviour that failed silently:

| Change | Why | What to do |
|---|---|---|
| `Provider.Metadata()` returns `(Metadata, error)` | Every failure previously returned an empty struct, so a broken command, a timeout and "not configured" were indistinguishable | Handle the new error |
| External configs referencing `{{value}}`/`{{password}}` in a `cmd` are rejected | The value was interpolated into a shell command with no quoting — a command-injection sink that also corrupted ordinary passwords | Move the secret to an `InputTemplate` (stdin) |
| An existing but zero-length vault file is an error | It was read as "no vault here", so the constructor initialized and immediately overwrote it, destroying every secret | Restore from backup, or delete the file to start fresh |
| Operations on a closed vault return `ErrVaultClosed` | They dereferenced nil state and panicked | Nothing, unless you relied on the panic |
| Vault IDs are charset-validated | An ID is interpolated into a filename, and `filepath.Clean` *resolves* traversal rather than sanitizing it | Use IDs matching `^[a-zA-Z0-9][a-zA-Z0-9-_.]*$` |
| Encryption keys must be exactly 32 bytes | `aes.NewCipher` also accepts 16 and 24, silently downgrading an "AES256" vault to AES-128/192 | Regenerate short keys |
| `DeriveKey` returns a parameter-tagged salt | Changing the scrypt cost would otherwise silently change every derived key | Pass the returned salt back verbatim rather than base64-decoding it first |

Local vault files written by earlier versions are read without migration.

## Quick Start

```go
package main

import (
    "fmt"
    "github.com/flowexec/vault"
)

func main() {
    // Create a new AES vault
    v, err := vault.New("my-vault",
        vault.WithProvider(vault.ProviderTypeAES256),
        vault.WithLocalPath("/path/to/vault/storage"),
        vault.WithAESKeyFromEnv("VAULT_KEY"),
    )
    if err != nil {
        panic(err)
    }
    defer v.Close()

    // Store a secret
    secret := vault.NewSecretValue([]byte("my-secret-value"))
    err = v.SetSecret("api-key", secret)
    if err != nil {
        panic(err)
    }

    // Retrieve a secret
    retrieved, err := v.GetSecret("api-key")
    if err != nil {
        panic(err)
    }
    fmt.Println("Secret:", retrieved.PlainTextString())
}
```

## Provider Types

### Local Encrypted Providers

#### AES256 Provider
Stores secrets in an AES-256 encrypted file with configurable key sources.

```go
provider, _, err := vault.New("my-vault",
    vault.WithProvider(vault.ProviderTypeAES256),
    vault.WithAESPath("~/.config/flow/vaults"), // a directory, not a file
)
```

**Key Generation:**
```go
key, err := vault.GenerateEncryptionKey()
// Store this key securely (environment variable, HSM, etc.)
```

#### Age Provider
Uses the [age encryption tool](https://age-encryption.org/) with public key cryptography.

```go
provider, _, err := vault.New("my-vault", 
    vault.WithProvider(vault.ProviderTypeAge),
    vault.WithAgePath("~/.config/flow/vaults"), // a directory, not a file
)
```

**Key Generation:**
```bash
age-keygen -o ~/.age/identity.txt
# Add recipients to vault configuration
```

#### Keyring Provider
Integrates with the operating system's secure keyring.

```go
provider, _, err := vault.New("my-vault",
    vault.WithProvider(vault.ProviderTypeKeyring),
    vault.WithKeyringService("my-app-secrets"),
)
```

No additional setup required - uses OS authentication.

#### Unencrypted Provider
Stores secrets in plain text JSON files.

```go
provider, _, err := vault.New("my-vault",
    vault.WithProvider(vault.ProviderTypeUnencrypted), 
    vault.WithUnencryptedPath("~/.config/flow/vaults"), // a directory, not a file
)
```

### External CLI Providers

#### External Provider
Integrates with any CLI tool for secret management. Supports popular tools like Bitwarden, 1Password, HashiCorp Vault, AWS SSM, and more.

```go
config := &vault.Config{
    ID: "bitwarden",
    Type: vault.ProviderTypeExternal,
    External: &vault.ExternalConfig{
        Get: vault.CommandConfig{
            CommandTemplate: "bw get password '{{key}}'",
        },
        Set: vault.CommandConfig{
            CommandTemplate: "bw create item",
            // The secret is piped to the command's stdin, never placed in it.
            InputTemplate: "{{value}}",
        },
        // ... other operations
    },
}

provider, err := vault.NewExternalVaultProvider(config)
```

> **The secret value is not available to command templates.** A rendered command
> is parsed and run by a shell and the template engine does no quoting, so
> interpolating a secret there is a command-injection sink and silently corrupts
> any value containing shell metacharacters (`p@$$w0rd` has `$$` replaced by the
> process ID; `correct horse battery` word-splits to `correct`). Configurations
> referencing `{{value}}` or `{{password}}` in a `cmd` are rejected at load —
> use an `InputTemplate` instead.

**External Provider Examples**

Ready-to-use configurations for popular CLI tools are available in the [`examples/`](./examples/) directory:

- **[Bitwarden](./examples/providers/bitwarden.json)**
- **[1Password](./examples/providers/1password.json)**
- **[AWS SSM](./examples/providers/aws-ssm.json)**
- **[pass](./examples/providers/pass.json)**

See the [examples README](./examples/README.md) for detailed setup instructions.

## Usage

### Basic Operations

```go
// Store a secret
secret := vault.NewSecretValue([]byte("my-secret-value"))
err = provider.SetSecret("api-key", secret)

// Retrieve the secret
retrieved, err := provider.GetSecret("api-key")
fmt.Println("Secret:", retrieved.PlainTextString())

// List all secrets
secrets, _ := provider.ListSecrets()

// Check if secret exists
exists, _ := provider.HasSecret("api-key")

// Get vault metadata
metadata, err := provider.Metadata()
```

### Configuration from File

```go
// Load configuration from JSON
config, err := vault.LoadConfigJSON("vault-config.json") 
provider, _, err := vault.New(config.ID, vault.WithProvider(config.Type))
```
