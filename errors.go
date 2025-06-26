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
