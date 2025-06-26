# Vault

A Go package for secure secret storage with multiple encryption backends. Made for [flow](https://github.com/jahvon/flow) but can be used independently.

## Quick Start

```go
package main

import (
    "fmt"
    "github.com/jahvon/vault"
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

## Providers

### AES256 Provider

Symmetric encryption using AES-256. Best for when you want a single encryption key shared across users / systems.

**Key Generation:**
```go
key, err := vault.GenerateEncryptionKey()
if err != nil {
    panic(err)
}
// Store this key securely and configure vault to use it
```

### Age Provider

Asymmetric encryption using the [age encryption format](https://github.com/FiloSottile/age). Best for when you may have multiple users or need the ability to add/remove recipients.

**Key Generation:**
```bash
# Generate age key pair - see https://github.com/FiloSottile/age for details
age-keygen -o key.txt
# Public key: age1ql3blv6a5y...
# Private key in key.txt
```

## Encrypted Files

Both vault types create a single encrypted file at the specified path:

- **AES256**: `vault-{id}.enc` 
- **Age**: `vault-{id}.age`
