package crypto_test

import (
	"strings"
	"testing"

	"github.com/flowexec/vault/crypto"
)

func TestGenerateKey(t *testing.T) {
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}
	if key == "" {
		t.Error("Generated key should not be empty")
	}

	decodedKey, err := crypto.DecodeValue(key)
	if err != nil {
		t.Fatalf("Failed to decode generated key: %v", err)
	}
	if len(decodedKey) == 0 {
		t.Error("Decoded key should not be empty")
	}

	// Test uniqueness
	key2, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("Failed to generate second key: %v", err)
	}
	if key == key2 {
		t.Error("Generated keys should be unique")
	}
}

// The returned salt is passed back verbatim; it carries the parameters it was
// produced with so a later change to the defaults cannot silently derive a
// different key from the same salt.
func TestDeriveKeyRoundTripsItsOwnSalt(t *testing.T) {
	password := []byte("password")

	derivedKey, outSalt, err := crypto.DeriveKey(password, nil)
	if err != nil {
		t.Fatalf("Failed to derive key without salt: %v", err)
	}
	if derivedKey == "" || outSalt == "" {
		t.Fatal("Derived key and salt should not be empty")
	}

	decodedDerivedKey, err := crypto.DecodeValue(derivedKey)
	if err != nil {
		t.Fatalf("Failed to decode derived key: %v", err)
	}
	if len(decodedDerivedKey) != crypto.KeyLen {
		t.Errorf("Derived key is %d bytes, want %d", len(decodedDerivedKey), crypto.KeyLen)
	}

	derivedKey2, outSalt2, err := crypto.DeriveKey(password, []byte(outSalt))
	if err != nil {
		t.Fatalf("Failed to derive key with the returned salt: %v", err)
	}
	if derivedKey != derivedKey2 {
		t.Error("Keys derived with the same password and salt should be identical")
	}
	if outSalt != outSalt2 {
		t.Errorf("Salt should round trip unchanged, got %s, want %s", outSalt2, outSalt)
	}
}

func TestDeriveKeyUsesDistinctSaltsPerCall(t *testing.T) {
	password := []byte("password")

	key1, salt1, err := crypto.DeriveKey(password, nil)
	if err != nil {
		t.Fatalf("Failed to derive first key: %v", err)
	}
	key2, salt2, err := crypto.DeriveKey(password, nil)
	if err != nil {
		t.Fatalf("Failed to derive second key: %v", err)
	}

	if salt1 == salt2 {
		t.Error("Each derivation should generate a fresh salt")
	}
	if key1 == key2 {
		t.Error("The same password with different salts must not produce the same key")
	}
}

// []byte("") from a variable string is non-nil, so the old salt==nil check
// never fired for the natural "I have no salt, generate one" call. That derived
// an unsalted, fully deterministic key -- identical for every user with the
// same passphrase, and precomputable.
func TestDeriveKeyTreatsEmptySaltAsAbsentNotUnsalted(t *testing.T) {
	password := []byte("password")
	empty := ""

	key1, salt1, err := crypto.DeriveKey(password, []byte(empty))
	if err != nil {
		t.Fatalf("Failed to derive key with empty salt: %v", err)
	}
	key2, salt2, err := crypto.DeriveKey(password, []byte(empty))
	if err != nil {
		t.Fatalf("Failed to derive second key with empty salt: %v", err)
	}

	if salt1 == "" || salt2 == "" {
		t.Fatal("An empty salt must produce a freshly generated one")
	}
	if salt1 == salt2 {
		t.Error("An empty salt produced the same salt twice; it is not being generated")
	}
	if key1 == key2 {
		t.Error("An empty salt derived a deterministic key; the salt is not being applied")
	}
}

func TestDeriveKeyRejectsShortSalts(t *testing.T) {
	if _, _, err := crypto.DeriveKey([]byte("password"), []byte("tiny")); err == nil {
		t.Error("Expected a short salt to be rejected")
	}
}

func TestEncryptDecryptValue(t *testing.T) {
	masterKey, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("Failed to generate master key: %v", err)
	}

	testCases := []string{
		"test value",
		"special chars: !@#$%^&*()",
		"unicode text: 🔐 secret 🚀",
		"",
		"very long text " + strings.Repeat("a", 1000),
		"multiline\ntext\nwith\nnewlines",
		"text\twith\ttabs",
	}

	for _, plaintext := range testCases {
		t.Run("encrypt_decrypt_"+plaintext[:minInt(10, len(plaintext))], func(t *testing.T) {
			encryptedValue, err := crypto.EncryptValue(masterKey, plaintext)
			if err != nil {
				t.Fatalf("Failed to encrypt: %v", err)
			}
			if encryptedValue == "" {
				t.Error("Encrypted value should not be empty")
			}
			if encryptedValue == plaintext && plaintext != "" {
				t.Error("Encrypted value should not equal plaintext")
			}

			decryptedValue, err := crypto.DecryptValue(masterKey, encryptedValue)
			if err != nil {
				t.Fatalf("Failed to decrypt: %v", err)
			}
			if decryptedValue != plaintext {
				t.Errorf("Decrypted value doesn't match. Expected %q, got %q", plaintext, decryptedValue)
			}
		})
	}
}

func TestEncryptionUniqueness(t *testing.T) {
	masterKey, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("Failed to generate master key: %v", err)
	}

	plaintext := "same data"

	encrypted1, err := crypto.EncryptValue(masterKey, plaintext)
	if err != nil {
		t.Fatalf("Failed to encrypt first time: %v", err)
	}

	encrypted2, err := crypto.EncryptValue(masterKey, plaintext)
	if err != nil {
		t.Fatalf("Failed to encrypt second time: %v", err)
	}

	if encrypted1 == encrypted2 {
		t.Error("Encrypting same data twice should produce different ciphertext")
	}

	// Both should decrypt to same value
	decrypted1, err := crypto.DecryptValue(masterKey, encrypted1)
	if err != nil {
		t.Fatalf("Failed to decrypt first ciphertext: %v", err)
	}
	if decrypted1 != plaintext {
		t.Errorf("First decryption should equal plaintext")
	}

	decrypted2, err := crypto.DecryptValue(masterKey, encrypted2)
	if err != nil {
		t.Fatalf("Failed to decrypt second ciphertext: %v", err)
	}
	if decrypted2 != plaintext {
		t.Errorf("Second decryption should equal plaintext")
	}
}

func TestEncryptDecryptWithWrongKey(t *testing.T) {
	key1, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("Failed to generate key1: %v", err)
	}
	key2, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("Failed to generate key2: %v", err)
	}

	plaintext := "secret data"

	encrypted, err := crypto.EncryptValue(key1, plaintext)
	if err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}

	// AES-GCM properly fails with wrong key
	_, err = crypto.DecryptValue(key2, encrypted)
	if err == nil {
		t.Error("DecryptValue should fail with wrong key in GCM mode")
	}

	// Should work with correct key
	decrypted, err := crypto.DecryptValue(key1, encrypted)
	if err != nil {
		t.Fatalf("Failed to decrypt with correct key: %v", err)
	}
	if decrypted != plaintext {
		t.Errorf("Expected %q, got %q", plaintext, decrypted)
	}
}

func TestInvalidKeys(t *testing.T) {
	plaintext := "test data"

	// Test encryption with invalid key
	_, err := crypto.EncryptValue("invalid-key", plaintext)
	if err == nil {
		t.Error("Expected error for invalid key in encryption")
	}

	// Test decryption with invalid key
	validKey, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("Failed to generate valid key: %v", err)
	}

	encrypted, err := crypto.EncryptValue(validKey, plaintext)
	if err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}

	_, err = crypto.DecryptValue("invalid-key", encrypted)
	if err == nil {
		t.Error("Expected error for invalid key in decryption")
	}
}

// aes.NewCipher accepts 16, 24 and 32 byte keys, so without an explicit length
// check a short key silently downgrades an "AES256" vault to AES-128 or -192.
func TestNonAES256KeysAreRejected(t *testing.T) {
	for _, size := range []int{8, 16, 24, 31, 33, 64} {
		key := crypto.EncodeValue(make([]byte, size))

		if _, err := crypto.EncryptValue(key, "data"); err == nil {
			t.Errorf("EncryptValue accepted a %d byte key, want rejection", size)
		}
		if _, err := crypto.DecryptValue(key, crypto.EncodeValue(make([]byte, 64))); err == nil {
			t.Errorf("DecryptValue accepted a %d byte key, want rejection", size)
		}
	}

	// The correct size still works.
	valid := crypto.EncodeValue(make([]byte, crypto.KeyLen))
	if _, err := crypto.EncryptValue(valid, "data"); err != nil {
		t.Errorf("EncryptValue rejected a %d byte key: %v", crypto.KeyLen, err)
	}
}

func TestInvalidCiphertext(t *testing.T) {
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Test ciphertext too short
	_, err = crypto.DecryptValue(key, "short")
	if err == nil {
		t.Error("Expected error for ciphertext too short")
	}

	// Test invalid base64 ciphertext
	_, err = crypto.DecryptValue(key, "invalid-base64!")
	if err == nil {
		t.Error("Expected error for invalid base64 ciphertext")
	}

	// Test valid base64 but invalid GCM ciphertext
	invalidCiphertext := crypto.EncodeValue([]byte("invalid-ciphertext-that-is-long-enough-to-have-nonce"))
	_, err = crypto.DecryptValue(key, invalidCiphertext)
	if err == nil {
		t.Error("Expected error for invalid GCM ciphertext")
	}
}

func TestEncodeDecodeValue(t *testing.T) {
	testData := []byte("test data for encoding")

	encoded := crypto.EncodeValue(testData)
	if encoded == "" {
		t.Error("Encoded value should not be empty")
	}

	decoded, err := crypto.DecodeValue(encoded)
	if err != nil {
		t.Fatalf("Failed to decode value: %v", err)
	}

	if string(decoded) != string(testData) {
		t.Errorf("Decoded data doesn't match original. Expected %s, got %s", string(testData), string(decoded))
	}

	// Test invalid base64
	_, err = crypto.DecodeValue("invalid-base64!")
	if err == nil {
		t.Error("Expected error for invalid base64")
	}
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
