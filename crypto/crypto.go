package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"

	"golang.org/x/crypto/scrypt"
)

// GenerateKey generates a random 32 byte key and returns it as a base64 encoded string.
func GenerateKey() (string, error) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	if err != nil {
		return "", fmt.Errorf("error reading random bytes: %w", err)
	}
	return EncodeValue(key), nil
}

// DeriveKey derives a 32 byte key from the provided password and salt and returns
// the key and salt as base64 encoded strings.
// If salt is nil, a random salt will be generated.
func DeriveKey(password, salt []byte) (string, string, error) {
	if salt == nil {
		salt = make([]byte, 32)
		if _, err := rand.Read(salt); err != nil {
			return "", "", err
		}
	}

	key, err := scrypt.Key(password, salt, 1048576, 8, 1, 32)
	if err != nil {
		return "", "", err
	}

	return EncodeValue(key), EncodeValue(salt), nil
}

// EncodeValue encodes a byte slice as a base64 encoded string.
func EncodeValue(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}

// DecodeValue decodes a base64 encoded string into a byte slice.
func DecodeValue(s string) ([]byte, error) {
	data, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	return data, nil
}

// EncryptValue encrypts a string using AES-256-GCM and returns the encrypted value as a base64 encoded string.
// The encryption key used for encryption must be a base64 encoded string.
func EncryptValue(encryptionKey string, text string) (string, error) {
	decodedMasterKey, err := DecodeValue(encryptionKey)
	if err != nil {
		return "", fmt.Errorf("error decoding master key: %w", err)
	}
	block, err := aes.NewCipher(decodedMasterKey)
	if err != nil {
		return "", fmt.Errorf("error creating new cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("error creating GCM: %w", err)
	}

	plaintext := []byte(text)
	// verify that the plaintext is not too long to fit in an int
	if len(plaintext) > 64*1024*1024 {
		return "", fmt.Errorf("plaintext too long to encrypt")
	}

	// Generate a random nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("error reading random bytes: %w", err)
	}

	// Encrypt and authenticate
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return EncodeValue(ciphertext), nil
}

// DecryptValue decrypts a string using AES-256-GCM and returns the decrypted value as a string.
// The master key used for decryption must be a base64 encoded string.
func DecryptValue(encryptionKey string, text string) (string, error) {
	decodedMasterKey, err := DecodeValue(encryptionKey)
	if err != nil {
		return "", fmt.Errorf("error decoding master key: %w", err)
	}
	block, err := aes.NewCipher(decodedMasterKey)
	if err != nil {
		return "", fmt.Errorf("error creating new cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("error creating GCM: %w", err)
	}

	ciphertext, err := DecodeValue(text)
	if err != nil {
		return "", fmt.Errorf("error decoding ciphertext: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return "", fmt.Errorf("ciphertext too short")
	}

	// Extract nonce and ciphertext
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]

	// Decrypt and authenticate
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("decryption failed: %w", err)
	}

	return string(plaintext), nil
}
