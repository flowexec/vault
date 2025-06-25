# Vault

A Go package for secure secret storage with multiple encryption backends.

## Overview

The vault package provides a unified interface for storing and retrieving encrypted secrets. It supports multiple encryption providers with different security models and use cases.

## Installation

```bash
go get github.com/jahvon/vault
```

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

Symmetric encryption using AES-256. Best for single-user scenarios or when all users can share the same key.

**Features:**
- Single shared encryption key
- Fast encryption/decryption
- Smaller encrypted files
- Simple key management

**Configuration:**
```go
v, err := vault.New("my-vault",
    vault.WithProvider(vault.ProviderTypeAES256),
    vault.WithAESPath("/path/to/storage"),
    vault.WithAESKeyFromEnv("VAULT_ENCRYPTION_KEY"),
    // or vault.WithAESKeyFromFile("~/.vault/key"),
)
```

**Key Generation:**
```go
key, err := vault.GenerateEncryptionKey()
if err != nil {
    panic(err)
}
// Store this key securely and configure vault to use it
```

### Age Provider

Modern asymmetric encryption using the [age encryption format](https://age-encryption.org/). Best for multi-user scenarios or when you need to add/remove recipients.

**Features:**
- Multiple recipients with separate keys
- No shared secrets to distribute
- Add/remove users without re-encrypting
- Modern cryptographic primitives

**Configuration:**
```go
v, err := vault.New("my-vault",
    vault.WithProvider(vault.ProviderTypeAge),
    vault.WithAgePath("/path/to/storage"),
    vault.WithAgeIdentityFromEnv("AGE_PRIVATE_KEY"),
    vault.WithRecipients("age1ql3blv6a5y..."), // public keys
)
```

**Key Generation:**
```bash
# Generate age key pair
age-keygen -o key.txt
# Public key: age1ql3blv6a5y...
# Private key in key.txt
```

## Key Differences: AES vs Age

| Feature | AES256 | Age |
|---------|--------|-----|
| **Encryption Type** | Symmetric (shared key) | Asymmetric (public/private keys) |
| **Key Sharing** | Single key shared by all users | Each user has their own private key |
| **Adding Users** | Share the same key | Add their public key as recipient |
| **Removing Users** | Change key + re-encrypt all data | Remove from recipients, re-encrypt vault |
| **Performance** | Faster | Slightly slower |
| **File Size** | Smaller | Slightly larger |
| **Use Case** | Single user or trusted team | Multiple users, dynamic access |
| **Key Storage** | Keep one key very secure | Private keys stored separately |

## Configuration Options

### Common Options
```go
// Set provider type
vault.WithProvider(vault.ProviderTypeAES256) // or ProviderTypeAge

// Set storage path (works for both providers)
vault.WithLocalPath("/path/to/vault/storage")
```

### AES-Specific Options
```go
// Set AES-specific storage path
vault.WithAESPath("/path/to/storage")

// Key sources (tries in order until one works)
vault.WithAESKeyFromEnv("VAULT_KEY")
vault.WithAESKeyFromFile("~/.vault/key")
```

### Age-Specific Options
```go
// Set age-specific storage path
vault.WithAgePath("/path/to/storage")

// Identity sources (private keys for decryption)
vault.WithAgeIdentityFromEnv("AGE_PRIVATE_KEY")
vault.WithAgeIdentityFromFile("~/.age/key.txt")

// Recipients (public keys for encryption)
vault.WithRecipients("age1ql3blv6a5y...", "age1...")
```

## Vault Operations

```go
// Store a secret
secret := vault.NewSecretValue([]byte("secret-value"))
err := v.SetSecret("key-name", secret)

// Retrieve a secret
secret, err := v.GetSecret("key-name")
if err == vault.ErrSecretNotFound {
    // Handle missing secret
}

// List all secret keys
keys, err := v.ListSecrets()

// Check if secret exists
exists, err := v.HasSecret("key-name")

// Delete a secret
err := v.DeleteSecret("key-name")

// Clean up
err := v.Close()
```

## Repository Integration

Both vault types create a single encrypted file that can be safely committed to version control:

- **AES256**: `vault-{id}.enc` 
- **Age**: `vault-{id}.age`

The encrypted files contain no readable information and are safe to store in public repositories.

## Key Management Best Practices

### For AES256 Vaults
- Generate keys using `vault.GenerateEncryptionKey()`
- Store the key in a secure location (env var, key management service, etc.)
- Never commit the key to version control
- Rotate keys periodically by re-encrypting with a new key

### For Age Vaults
- Generate key pairs using `age-keygen`
- Store private keys securely (separate from the repository)
- Share public keys freely (they can be committed)
- Add/remove recipients by updating the vault configuration

## Error Handling

```go
import "errors"

secret, err := v.GetSecret("key")
if err != nil {
    if errors.Is(err, vault.ErrSecretNotFound) {
        // Handle missing secret
    } else {
        // Handle other errors
    }
}
```

## Thread Safety

All vault operations are thread-safe and can be used concurrently from multiple goroutines.