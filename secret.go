package vault

import (
	"fmt"
	"regexp"
	"strings"
)

type Secret interface {
	// PlainTextString returns the decrypted value as a string
	PlainTextString() string

	// String returns a masked representation for display
	String() string

	// Bytes returns the raw byte representation of the secret
	Bytes() []byte

	// Zero securely clears the secret from memory
	Zero()
}

// SecureBytes is a wrapper around []byte that provides secure memory handling
type SecureBytes []byte

// Zero clears the byte slice.
//
// Note on what this can and cannot guarantee: it overwrites *this* buffer only.
// Any Go string derived from it (see PlainTextString) is immutable and cannot be
// zeroed, and the runtime may have copied the backing array during a heap move.
// Treat this as reducing exposure, not eliminating it.
func (s *SecureBytes) Zero() {
	if s == nil || len(*s) == 0 {
		return
	}
	// The previous implementation filled with random bytes first and then forced
	// a full runtime.GC() on every call. Neither helped: Go does not
	// dead-store-eliminate writes through a pointer-reachable slice, and a
	// forced GC per secret is a serious performance footgun in a library while
	// still not guaranteeing that stale copies are collected or overwritten.
	for i := range *s {
		(*s)[i] = 0
	}
	*s = (*s)[:0]
}

// Copy creates a secure copy of the bytes
func (s SecureBytes) Copy() SecureBytes {
	if len(s) == 0 {
		return SecureBytes{}
	}
	c := make(SecureBytes, len(s))
	copy(c, s)
	return c
}

type SecretValue struct {
	value SecureBytes
}

func NewSecretValue(value []byte) *SecretValue {
	secureValue := make(SecureBytes, len(value))
	copy(secureValue, value)
	return &SecretValue{value: secureValue}
}

// PlainTextString returns the secret as a string.
//
// The result is an immutable Go string and therefore cannot be zeroed; Zero()
// on this SecretValue will not reclaim it. Keep the returned value as
// short-lived as possible, and prefer Bytes() when the caller can clear it.
func (s *SecretValue) PlainTextString() string {
	return string(s.value)
}

// String masks the secret so it cannot be printed by accident.
//
// Deliberately a value receiver: with a pointer receiver, formatting a
// dereferenced copy (fmt.Sprintf("%v", *secret)) falls outside the method set
// and prints the raw bytes instead of the mask.
func (s SecretValue) String() string {
	return "********"
}

func (s *SecretValue) Bytes() []byte {
	// Return a copy to prevent external modification
	result := make([]byte, len(s.value))
	copy(result, s.value)
	return result
}

func (s *SecretValue) Zero() {
	s.value.Zero()
}

// secretKeyPattern is compiled once. ValidateSecretKey runs on every get, set,
// delete and existence check, so recompiling per call was pure waste.
var secretKeyPattern = regexp.MustCompile(`^[a-zA-Z0-9-_.]+$`)

// vaultIDPattern additionally forbids a leading dot, since a vault ID becomes
// part of a filename.
var vaultIDPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9-_.]*$`)

func ValidateSecretKey(reference string) error {
	if reference == "" {
		return ErrInvalidKey
	}
	if !secretKeyPattern.MatchString(reference) {
		return fmt.Errorf("%w: must only contain alphanumeric characters, dashes, underscores, and/or dots", ErrInvalidKey)
	}
	// A leading dash makes the key look like a flag to any backend CLI the
	// external provider shells out to -- a key of "-f" or "--vault" becomes an
	// option rather than an argument.
	if strings.HasPrefix(reference, "-") {
		return fmt.Errorf("%w: must not start with a dash", ErrInvalidKey)
	}
	// "." and ".." are path elements. The external provider passes keys through
	// to tools like pass, where they address entries within a store.
	if reference == "." || reference == ".." {
		return fmt.Errorf("%w: must not be %q", ErrInvalidKey, reference)
	}
	return nil
}

// ValidateVaultID checks an identifier that will be used to build filesystem
// paths and keyring entry names.
func ValidateVaultID(id string) error {
	if id == "" {
		return fmt.Errorf("%w: vault ID is required", ErrInvalidConfig)
	}
	if !vaultIDPattern.MatchString(id) {
		return fmt.Errorf(
			"%w: vault ID %q must start with a letter or digit and contain only "+
				"alphanumeric characters, dashes, underscores, and/or dots",
			ErrInvalidConfig, id,
		)
	}
	if strings.Contains(id, "..") {
		return fmt.Errorf("%w: vault ID %q must not contain %q", ErrInvalidConfig, id, "..")
	}
	return nil
}
