package vault

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	vaultFileBase = "vault"
	envSource     = "env"
	fileSource    = "file"
)

var (
	DefaultVaultKeyEnv = "VAULT_KEY"
)

type Metadata struct {
	Created      time.Time `json:"created"`
	LastModified time.Time `json:"lastModified"`
}

// validateSecurePath checks if a path is safe to use
func validateSecurePath(path string) error {
	if path == "" {
		return fmt.Errorf("path cannot be empty")
	}

	// Check for directory traversal attempts
	cleanPath := filepath.Clean(path)
	if strings.Contains(cleanPath, "..") {
		return NewVaultPathError(path)
	}

	// Check for null bytes
	if strings.Contains(path, "\x00") {
		return NewVaultPathError(path)
	}

	// Ensure the path is absolute after expansion
	absPath, err := filepath.Abs(cleanPath)
	if err != nil {
		return fmt.Errorf("failed to get absolute path: %w", err)
	}

	// Basic check that we're not accessing sensitive system directories
	systemDirs := []string{"/etc", "/sys", "/proc", "/dev"}
	for _, sysDir := range systemDirs {
		if strings.HasPrefix(absPath, sysDir) {
			return NewVaultPathError(path)
		}
	}

	return nil
}

func expandPath(path string) (string, error) {
	if path == "" {
		return "", nil
	}

	var expandedPath string

	switch path[0] {
	case '~':
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("failed to get user home directory: %w", err)
		}
		expandedPath = homeDir + path[1:]
	case '/':
		expandedPath = path
	case '.':
		wd, err := os.Getwd()
		if err != nil {
			return "", fmt.Errorf("failed to get working directory: %w", err)
		}
		expandedPath = wd + "/" + path[1:]
	case '$':
		envVar := path[1:]
		if value, exists := os.LookupEnv(envVar); exists {
			expandedPath = value
		} else {
			return "", fmt.Errorf("environment variable %s not found", envVar)
		}
	default:
		wd, err := os.Getwd()
		if err != nil {
			return "", fmt.Errorf("failed to get working directory: %w", err)
		}
		if wd[len(wd)-1] == '/' {
			expandedPath = wd + path
		} else {
			expandedPath = wd + "/" + path
		}
	}

	if err := validateSecurePath(expandedPath); err != nil {
		return "", err
	}

	return filepath.Clean(expandedPath), nil
}
