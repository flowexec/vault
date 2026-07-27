package vault

import (
	"errors"
	"fmt"
)

var (
	ErrSecretNotFound   = errors.New("secret not found")
	ErrInvalidKey       = errors.New("invalid secret key")
	ErrNoAccess         = errors.New("access denied")
	ErrInvalidConfig    = errors.New("invalid configuration")
	ErrVaultNotFound    = errors.New("vault not found")
	ErrDecryptionFailed = errors.New("decryption failed")
	ErrInvalidRecipient = errors.New("invalid recipient")
	ErrPathNotSecure    = errors.New("path is not secure")
	ErrVaultClosed      = errors.New("vault is closed")
	ErrVaultCorrupt     = errors.New("vault file is corrupt")
	// ErrReadOnly is returned by a vault that never writes secret material. An
	// external vault holds references to secrets kept in another system; the way
	// to add one is to link it, and the way to create one is to create it in that
	// system.
	ErrReadOnly = errors.New("vault is read-only")
	// ErrInvalidReference is returned when a reference is malformed or would be
	// unsafe to interpolate into a provider command.
	ErrInvalidReference = errors.New("invalid secret reference")
)

type VaultPathError struct {
	Path string
	Err  error
}

func (e *VaultPathError) Error() string {
	if e.Path != "" {
		return fmt.Sprintf("%s (%s): %v", ErrPathNotSecure, e.Path, e.Err)
	}
	return fmt.Sprintf("%v: %v", ErrPathNotSecure, e.Err)
}

func (e *VaultPathError) Unwrap() error {
	return e.Err
}

func NewVaultPathError(path string) *VaultPathError {
	return &VaultPathError{
		Path: path,
		Err:  ErrPathNotSecure,
	}
}
