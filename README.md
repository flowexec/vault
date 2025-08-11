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
    vault.WithAESPath("~/secrets.vault"),
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
    vault.WithAgePath("~/secrets.age"),
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
    vault.WithUnencryptedPath("~/dev-secrets.json"),
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
            CommandTemplate: "bw get password {{key}}",
        },
        Set: vault.CommandConfig{
            CommandTemplate: "bw create item --name {{key}} --password {{value}}",
        },
        // ... other operations
    },
}

provider, err := vault.NewExternalVaultProvider(config)
```

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
metadata := provider.Metadata()
```

### Configuration from File

```go
// Load configuration from JSON
config, err := vault.LoadConfigJSON("vault-config.json") 
provider, _, err := vault.New(config.ID, vault.WithProvider(config.Type))
```
