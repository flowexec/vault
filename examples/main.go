package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/flowexec/vault"
)

func printMetadata(provider vault.Provider) {
	fmt.Println("Getting vault metadata...")
	metadata, err := provider.Metadata()
	if err != nil {
		fmt.Printf("Warning: could not read metadata: %v\n", err)
		return
	}
	fmt.Printf("Metadata: %s\n", metadata.RawData)
}

func main() {
	if len(os.Args) < 3 {
		fmt.Println("Usage: go run main.go <provider-config.json> <reference>")
		fmt.Println("Example: go run main.go providers/pass.json team/db/password")
		fmt.Println()
		fmt.Println("The reference is a path in the provider's own namespace, pointing at a")
		fmt.Println("secret that already exists. Nothing is created or modified.")
		fmt.Println()
		listProviders()
		os.Exit(1)
	}
	reference := os.Args[2]

	configPath := filepath.Clean(os.Args[1])
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		fmt.Printf("Error: Configuration file '%s' not found\n", configPath)
		os.Exit(1)
	}

	fmt.Printf("Testing vault provider configuration: %s\n", configPath)
	fmt.Println()

	config, err := vault.LoadConfigJSON(configPath)
	if err != nil {
		log.Fatalf("%v", err)
	}

	fmt.Printf("Provider ID: %s\n", config.ID)
	fmt.Println()

	if err := checkEnvironmentVariables(configPath); err != nil {
		fmt.Printf("Warning: Could not check environment variables: %v\n", err)
	}
	fmt.Println()

	// A distributed config does not know where the consuming tool keeps vault
	// state, so it carries no storage path. Here that is a throwaway directory:
	// the registry is the only thing this example writes anywhere.
	if config.External.StoragePath == "" {
		dir, err := os.MkdirTemp("", "vault-example-*")
		if err != nil {
			log.Fatalf("%v", err)
		}
		defer func() { _ = os.RemoveAll(dir) }()
		config.External.StoragePath = dir
	}

	provider, _, err := vault.New(config.ID,
		vault.WithProvider(vault.ProviderTypeExternal),
		vault.WithExternalConfig(config.External),
	)
	if err != nil {
		log.Fatalf("%v", err)
	}
	defer func() { _ = provider.Close() }()

	fmt.Printf("Using vault provider: %s\n", provider.ID())

	// Link management is a capability of read-through vaults specifically, so it
	// lives on its own interface rather than on Provider.
	links, ok := provider.(vault.ReferenceVault)
	if !ok {
		log.Fatalf("provider %s does not support links", provider.ID())
	}

	demonstrateLinks(provider, links, reference)

	fmt.Println("Testing completed successfully")
}

// demonstrateLinks walks the read-through lifecycle: link a reference, resolve
// it, list what the vault holds, then unlink.
func demonstrateLinks(provider vault.Provider, links vault.ReferenceVault, reference string) {
	fmt.Printf("Linking 'test-key' to %s...\n", reference)
	if err := links.Link("test-key", reference); err != nil {
		log.Fatalf("%v", err)
	}
	fmt.Println("Linked")

	fmt.Println("Checking if the key is linked...")
	exists, err := provider.HasSecret("test-key")
	if err != nil {
		log.Fatalf("%v", err)
	}
	fmt.Printf("Linked: %t\n", exists)

	fmt.Println("Reading through to the provider...")
	retrievedSecret, err := provider.GetSecret("test-key")
	if err != nil {
		log.Fatalf("%v", err)
	}
	fmt.Printf("Retrieved secret: %s\n", retrievedSecret.String())
	fmt.Printf("Secret length: %d characters\n", len(retrievedSecret.PlainTextString()))

	fmt.Println("Listing linked keys...")
	secrets, err := provider.ListSecrets()
	if err != nil {
		log.Fatalf("%v", err)
	}
	fmt.Printf("Found %d links:\n", len(secrets))
	for i, secret := range secrets {
		ref, refErr := links.Reference(secret)
		if refErr != nil {
			ref = fmt.Sprintf("<unresolvable: %v>", refErr)
		}
		fmt.Printf("  %d. %s -> %s\n", i+1, secret, ref)
	}

	printMetadata(provider)

	// Removes the link only. The secret in the provider is untouched -- that is
	// the point of the read-through design.
	fmt.Println("Unlinking test key...")
	if err := links.Unlink("test-key"); err != nil {
		log.Fatalf("%v", err)
	}
	fmt.Println("Unlinked (the secret itself was not modified)")
}

func listProviders() {
	fmt.Println("Available providers:")
	matches, err := filepath.Glob("providers/*.json")
	if err != nil {
		fmt.Printf("Error listing providers: %v\n", err)
		return
	}
	for _, match := range matches {
		fmt.Printf("  %s\n", strings.TrimPrefix(match, "providers/"))
	}
}

func checkEnvironmentVariables(configPath string) error {
	file, err := os.Open(filepath.Clean(configPath))
	if err != nil {
		return err
	}
	defer file.Close()

	var config map[string]interface{}
	if err := json.NewDecoder(file).Decode(&config); err != nil {
		return err
	}

	fmt.Println("Checking required environment variables:")

	external, ok := config["external"].(map[string]interface{})
	if !ok {
		fmt.Println("  No external configuration found")
		return nil
	}

	environment, ok := external["environment"].(map[string]interface{})
	if !ok {
		fmt.Println("  No environment variables required")
		return nil
	}

	for _, value := range environment {
		if valueStr, isStr := value.(string); isStr && strings.HasPrefix(valueStr, "$") {
			envVar := strings.TrimPrefix(valueStr, "$")
			if os.Getenv(envVar) != "" {
				fmt.Printf("  %s is set\n", envVar)
			} else {
				fmt.Printf("  Warning: %s is not set\n", envVar)
			}
		}
	}
	fmt.Println()
	return nil
}
