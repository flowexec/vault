package main

import (
	"fmt"
	"log"
	"path/filepath"

	"github.com/jahvon/vault"
)

func main() {
	dir := "/Users/jahvon/workspaces/github.com/jahvon/vault/playground"
	fmt.Printf("Testing vault in: %s\n", dir)

	fmt.Println("\n=== Test 1: Create New Vault ===")
	vault1, err := vault.New(
		"test",
		vault.WithProvider(vault.ProviderTypeLocal),
		vault.WithRecipients("age1nmkk0tv7ntg5yld0uhxc9f05p0d6zwxcaftxcjvwy82djuuzg96skmuzlk"),
		vault.WithLocalPath(dir),
		vault.WithLocalIdentityFromFile("/Users/jahvon/workspaces/github.com/jahvon/vault/playground/key.txt"),
	)
	if err != nil {
		log.Fatal("Failed to create vault:", err)
	}
	defer vault1.Close()

	fmt.Printf("Created vault with ID: %s\n", vault1.ID())

	fmt.Println("\n=== Test 2: Set and Get Secrets ===")

	err = vault1.SetSecret("api-key", vault.NewSecretValue([]byte("my-secret-api-key")))
	if err != nil {
		log.Fatal("Failed to set secret:", err)
	}
	fmt.Println("✓ Set api-key")

	err = vault1.SetSecret("db-password", vault.NewSecretValue([]byte("super-secret-password")))
	if err != nil {
		log.Fatal("Failed to set db-password:", err)
	}
	fmt.Println("✓ Set db-password")

	secret, err := vault1.GetSecret("api-key")
	if err != nil {
		log.Fatal("Failed to get secret:", err)
	}
	fmt.Printf("✓ Retrieved api-key: %s (masked: %s)\n", secret.PlainTextString(), secret.String())

	fmt.Println("\n=== Test 3: List Secrets ===")
	secrets, err := vault1.ListSecrets()
	if err != nil {
		log.Fatal("Failed to list secrets:", err)
	}

	fmt.Printf("Found %d secrets:\n", len(secrets))
	for _, key := range secrets {
		fmt.Printf("  - %s\n", key)
	}

	fmt.Println("\n=== Test 4: Verify Encrypted File ===")
	vaultFiles, err := filepath.Glob(filepath.Join(dir, "*.age"))
	if err != nil {
		log.Fatal("Failed to find vault files:", err)
	}

	if len(vaultFiles) == 0 {
		log.Fatal("No .age vault files found!")
	}

	fmt.Printf("✓ Found encrypted vault file: %s\n", vaultFiles[0])
}
