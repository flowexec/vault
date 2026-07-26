package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"strings"

	"golang.org/x/crypto/scrypt"
)

const (
	// KeyLen is the required key size. AES-256 means 32 bytes and nothing else:
	// aes.NewCipher also accepts 16 and 24, so without an explicit check a short
	// key silently downgrades an "AES256" vault to AES-128 or AES-192.
	KeyLen = 32

	// SaltLen is the size of a generated salt.
	SaltLen = 32
	// MinSaltLen is the smallest salt accepted for derivation.
	MinSaltLen = 16

	// scryptN is the CPU/memory cost. Memory used is roughly 128 * N * r, so
	// this is ~64 MiB per derivation. The previous value of 1<<20 required
	// ~1 GiB and several seconds, which thrashes or OOMs on a modest machine
	// and makes concurrent derivations a trivial local denial of service.
	scryptN = 1 << 16
	scryptR = 8
	scryptP = 1

	// legacyScryptN is the original cost. Salts issued before parameters were
	// recorded carry no parameter block, and must keep deriving the same key.
	legacyScryptN = 1 << 20

	saltPrefix = "scrypt"
	saltSep    = "$"

	// maxPlaintextLen bounds a single encryption.
	maxPlaintextLen = 64 * 1024 * 1024
)

// GenerateKey generates a random 32 byte key and returns it as a base64 encoded string.
func GenerateKey() (string, error) {
	key := make([]byte, KeyLen)
	_, err := rand.Read(key)
	if err != nil {
		return "", fmt.Errorf("error reading random bytes: %w", err)
	}
	return EncodeValue(key), nil
}

// DeriveKey derives a 32 byte key from the provided password and salt, returning
// the base64 encoded key and the salt that produced it.
//
// If salt is empty a fresh random one is generated. The returned salt carries
// the parameters used ("scrypt$N=...,r=...,p=...$<base64>") so that changing the
// defaults later cannot silently change the key derived from an existing salt.
// Pass the returned salt back verbatim to re-derive the same key.
func DeriveKey(password, salt []byte) (string, string, error) {
	// Deliberately len()==0 rather than salt==nil. []byte("") from a variable
	// string is non-nil, so a nil check let the natural "I have no salt, make
	// one" call fall through to an *unsalted*, fully deterministic derivation.
	if len(salt) == 0 {
		generated := make([]byte, SaltLen)
		if _, err := rand.Read(generated); err != nil {
			return "", "", fmt.Errorf("error generating salt: %w", err)
		}
		key, err := deriveScrypt(password, generated, scryptN)
		if err != nil {
			return "", "", err
		}
		return key, formatSalt(generated), nil
	}

	raw, n, err := parseSalt(salt)
	if err != nil {
		return "", "", err
	}
	key, err := deriveScrypt(password, raw, n)
	if err != nil {
		return "", "", err
	}
	return key, string(salt), nil
}

func formatSalt(raw []byte) string {
	return fmt.Sprintf("%s%sN=%d,r=%d,p=%d%s%s",
		saltPrefix, saltSep, scryptN, scryptR, scryptP, saltSep, EncodeValue(raw))
}

// parseSalt splits a salt into its raw bytes and cost parameter. A salt with no
// parameter block predates them and is used as-is with the original cost.
func parseSalt(salt []byte) ([]byte, int, error) {
	s := string(salt)
	if !strings.HasPrefix(s, saltPrefix+saltSep) {
		if len(salt) < MinSaltLen {
			return nil, 0, fmt.Errorf("salt must be at least %d bytes, got %d", MinSaltLen, len(salt))
		}
		return salt, legacyScryptN, nil
	}

	parts := strings.Split(s, saltSep)
	if len(parts) != 3 {
		return nil, 0, fmt.Errorf("malformed salt: expected %s$<params>$<base64>", saltPrefix)
	}

	var n, r, p int
	if _, err := fmt.Sscanf(parts[1], "N=%d,r=%d,p=%d", &n, &r, &p); err != nil {
		return nil, 0, fmt.Errorf("malformed salt parameters %q: %w", parts[1], err)
	}
	if r != scryptR || p != scryptP {
		return nil, 0, fmt.Errorf("unsupported salt parameters r=%d p=%d", r, p)
	}

	raw, err := DecodeValue(parts[2])
	if err != nil {
		return nil, 0, fmt.Errorf("malformed salt encoding: %w", err)
	}
	if len(raw) < MinSaltLen {
		return nil, 0, fmt.Errorf("salt must be at least %d bytes, got %d", MinSaltLen, len(raw))
	}
	return raw, n, nil
}

func deriveScrypt(password, salt []byte, n int) (string, error) {
	key, err := scrypt.Key(password, salt, n, scryptR, scryptP, KeyLen)
	if err != nil {
		return "", fmt.Errorf("error deriving key: %w", err)
	}
	return EncodeValue(key), nil
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

// decodeKey decodes and length-checks an encryption key.
func decodeKey(encryptionKey string) ([]byte, error) {
	key, err := DecodeValue(encryptionKey)
	if err != nil {
		return nil, fmt.Errorf("error decoding master key: %w", err)
	}
	if len(key) != KeyLen {
		return nil, fmt.Errorf(
			"encryption key must be %d bytes, got %d; expected a base64 encoded 256-bit key",
			KeyLen, len(key),
		)
	}
	return key, nil
}

// EncryptValue encrypts a string using AES-256-GCM and returns the encrypted value as a base64 encoded string.
// The encryption key used for encryption must be a base64 encoded string.
func EncryptValue(encryptionKey string, text string) (string, error) {
	decodedMasterKey, err := decodeKey(encryptionKey)
	if err != nil {
		return "", err
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
	if len(plaintext) > maxPlaintextLen {
		return "", fmt.Errorf("plaintext too long to encrypt")
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("error reading random bytes: %w", err)
	}
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return EncodeValue(ciphertext), nil
}

// DecryptValue decrypts a string using AES-256-GCM and returns the decrypted value as a string.
// The master key used for decryption must be a base64 encoded string.
func DecryptValue(encryptionKey string, text string) (string, error) {
	decodedMasterKey, err := decodeKey(encryptionKey)
	if err != nil {
		return "", err
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

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("decryption failed: %w", err)
	}

	return string(plaintext), nil
}
