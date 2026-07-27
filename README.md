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

Reads secrets that live in another tool — 1Password, pass, AWS SSM, Bitwarden —
through that tool's CLI.

An external vault is a **read-through registry, not a store**. It holds a set of
*links*: a key you choose, paired with a *reference* the provider understands.
Reading a key resolves its reference and runs the get command. Nothing is ever
written back.

```go
config := &vault.Config{
    ID:   "work",
    Type: vault.ProviderTypeExternal,
    External: &vault.ExternalConfig{
        Get: vault.CommandConfig{
            CommandTemplate: "op read --no-newline '{{ref}}'",
        },
        // Where the link registry is kept.
        StoragePath: "~/.config/flow/vaults",
        // Catches a mistyped reference at link time rather than at read time.
        ReferencePattern: `^op://[^/]+/[^/]+/[^/]+$`,
    },
}

provider, _ := vault.NewExternalVaultProvider(config)

// Point a key at something that already exists. Note the field on the end:
// one item's several credentials are addressed individually.
links := provider.(vault.ReferenceVault)
_ = links.Link("aws-access-key", "op://Team/AWS/access_key_id")
_ = links.Link("aws-secret-key", "op://Team/AWS/secret_access_key")

secret, _ := provider.GetSecret("aws-access-key")
```

Because the key is a local alias, you never have to reorganise the store you are
pointing at, and because a reference names a field, one item's several
credentials are individually reachable.

> **Reads only.** `SetSecret` returns `ErrReadOnly`, and `DeleteSecret` removes
> the *link* — the secret in the provider is untouched. Create secrets in the
> tool that owns them.
>
> This is deliberate. Writing through meant handing the value to a provider CLI,
> and none of them accept one safely: 1Password takes it as an argv assignment,
> visible to every process on the machine. It also meant a delete that destroyed
> real data, and a set that rebuilt an item from scratch, dropping whatever else
> was on it.

References are validated before they reach a shell — no quotes, backticks, `$`,
backslashes, control characters, leading dashes or `..` segments — on the way in
*and* on the way out, since a registry is a file that can be hand-edited.

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
