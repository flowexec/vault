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

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run main.go <provider-config.json>")
		fmt.Println("Example: go run main.go providers/bitwarden.json")
		fmt.Println()
		listProviders()
		os.Exit(1)
	}

	configPath := os.Args[1]
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

	provider, _, err := vault.New(config.ID,
		vault.WithProvider(vault.ProviderTypeExternal),
		vault.WithExternalConfig(config.External),
	)
	if err != nil {
		log.Fatalf("%v", err)
	}
	defer provider.Close()

	fmt.Printf("Using vault provider: %s\n", provider.ID())

	fmt.Println("Setting test secret...")
	testSecret := vault.NewSecretValue([]byte("test-secret-value-123"))
	err = provider.SetSecret("test-key", testSecret)
	if err != nil {
		log.Fatalf("%v", err)
	} else {
		fmt.Println("Secret set successfully")
	}

	fmt.Println("Checking if secret exists...")
	exists, err := provider.HasSecret("test-key")
	if err != nil {
		log.Fatalf("%v", err)
	} else {
		fmt.Printf("Secret exists: %t\n", exists)
	}

	fmt.Println("Retrieving secret...")
	retrievedSecret, err := provider.GetSecret("test-key")
	if err != nil {
		log.Fatalf("%v", err)
	} else {
		fmt.Printf("Retrieved secret: %s\n", retrievedSecret.String())
		fmt.Printf("Secret length: %d characters\n", len(retrievedSecret.PlainTextString()))
	}

	fmt.Println("Listing all secrets...")
	secrets, err := provider.ListSecrets()
	if err != nil {
		log.Fatalf("%v", err)
	} else {
		fmt.Printf("Found %d secrets:\n", len(secrets))
		for i, secret := range secrets {
			fmt.Printf("  %d. %s\n", i+1, secret)
		}
	}

	fmt.Println("Getting vault metadata...")
	metadata := provider.Metadata()
	fmt.Printf("Metadata: %s\n", metadata.RawData)

	fmt.Println("Cleaning up test secret...")
	err = provider.DeleteSecret("test-key")
	if err != nil {
		log.Fatalf("%v", err)
	} else {
		fmt.Println("Test secret deleted successfully")
	}

	fmt.Println("Testing completed successfully")
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
	file, err := os.Open(configPath)
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
