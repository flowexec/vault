package vault

import (
	"crypto/rand"
	"fmt"
	"regexp"
	"runtime"
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

// Zero securely clears the byte slice
func (s *SecureBytes) Zero() {
	if s != nil && len(*s) > 0 {
		// The series of steps below ensures that the memory is cleared securely. It prevents the compiler from
		// optimizing away the zeroing operation and is recommended to securely clear sensitive data in Go.
		_, _ = rand.Read(*s)
		for i := range *s {
			(*s)[i] = 0
		}
		*s = (*s)[:0]
		runtime.GC()
	}
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

func (s *SecretValue) PlainTextString() string {
	return string(s.value)
}

func (s *SecretValue) String() string {
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

func ValidateSecretKey(reference string) error {
	if reference == "" {
		return ErrInvalidKey
	}
	re := regexp.MustCompile(`^[a-zA-Z0-9-_.]+$`)
	if !re.MatchString(reference) {
		return fmt.Errorf("%w: must only contain alphanumeric characters, dashes, underscores, and/or dots", ErrInvalidKey)
	}
	return nil
}
