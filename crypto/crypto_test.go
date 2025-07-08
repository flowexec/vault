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

func TestDeriveKeyWithProvidedSalt(t *testing.T) {
	salt, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("Failed to generate salt: %v", err)
	}
	decodedSalt, err := crypto.DecodeValue(salt)
	if err != nil {
		t.Fatalf("Failed to decode salt: %v", err)
	}
	if len(decodedSalt) == 0 {
		t.Error("Decoded salt should not be empty")
	}

	inputPassword := []byte("password")
	derivedKey, outSalt, err := crypto.DeriveKey(inputPassword, decodedSalt)
	if err != nil {
		t.Fatalf("Failed to derive key: %v", err)
	}
	if derivedKey == "" {
		t.Error("Derived key should not be empty")
	}
	if outSalt != salt {
		t.Errorf("Output salt should equal input salt, got %s, expected %s", outSalt, salt)
	}

	decodedDerivedKey, err := crypto.DecodeValue(derivedKey)
	if err != nil {
		t.Fatalf("Failed to decode derived key: %v", err)
	}
	if len(decodedDerivedKey) == 0 {
		t.Error("Decoded derived key should not be empty")
	}
}

func TestDeriveKeyWithoutSalt(t *testing.T) {
	inputPassword := []byte("password")
	derivedKey, outSalt, err := crypto.DeriveKey(inputPassword, nil)
	if err != nil {
		t.Fatalf("Failed to derive key without salt: %v", err)
	}
	if derivedKey == "" {
		t.Error("Derived key should not be empty")
	}
	if outSalt == "" {
		t.Error("Generated salt should not be empty")
	}

	decodedDerivedKey, err := crypto.DecodeValue(derivedKey)
	if err != nil {
		t.Fatalf("Failed to decode derived key: %v", err)
	}
	if len(decodedDerivedKey) == 0 {
		t.Error("Decoded derived key should not be empty")
	}

	// Test reproducibility with same salt
	decodedSalt, err := crypto.DecodeValue(outSalt)
	if err != nil {
		t.Fatalf("Failed to decode output salt: %v", err)
	}

	derivedKey2, outSalt2, err := crypto.DeriveKey(inputPassword, decodedSalt)
	if err != nil {
		t.Fatalf("Failed to derive key with same salt: %v", err)
	}
	if derivedKey != derivedKey2 {
		t.Error("Keys derived with same password and salt should be identical")
	}
	if outSalt != outSalt2 {
		t.Error("Output salt should be same when input salt is provided")
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
