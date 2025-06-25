package vault

import (
	"errors"
	"fmt"
	"regexp"
)

type Secret interface {
	// PlainTextString returns the decrypted value as a string
	PlainTextString() string

	// String returns a masked representation for display
	String() string

	// Bytes returns the raw byte representation of the secret
	Bytes() []byte
}

type SecretValue struct {
	value []byte
}

func NewSecretValue(value []byte) *SecretValue {
	return &SecretValue{value: value}
}

func (s *SecretValue) PlainTextString() string {
	return string(s.value)
}

func (s *SecretValue) String() string {
	return "********"
}

func (s *SecretValue) Bytes() []byte {
	return s.value
}

func ValidateSecretKey(reference string) error {
	if reference == "" {
		return errors.New("reference cannot be empty")
	}
	re := regexp.MustCompile(`^[a-zA-Z0-9-_.]+$`)
	if !re.MatchString(reference) {
		return fmt.Errorf(
			"reference (%s) must only contain alphanumeric characters, dashes, underscores, and/or dots",
			reference,
		)
	}
	return nil
}
