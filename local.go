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

// DefaultVaultKeyEnv is the environment variable consulted when no key source
// is configured. A const rather than a var: as a package-level var, any
// dependency could repoint every default key lookup in the process.
const DefaultVaultKeyEnv = "VAULT_KEY"

type Metadata struct {
	Created      time.Time `json:"created"`
	LastModified time.Time `json:"lastModified"`
	RawData      string    `json:"data,omitempty"`
}

// validateSecurePath checks if a path is safe to use
func validateSecurePath(path string) error {
	if path == "" {
		return fmt.Errorf("path cannot be empty")
	}

	// Check for null bytes
	if strings.Contains(path, "\x00") {
		return NewVaultPathError(path)
	}

	// Ensure the path is absolute after expansion
	absPath, err := filepath.Abs(filepath.Clean(path))
	if err != nil {
		return fmt.Errorf("failed to get absolute path: %w", err)
	}

	// Compare path elements rather than substrings. strings.Contains(clean, "..")
	// rejected legitimate names like "my..backup" while catching almost nothing
	// real, since Clean on an absolute path has already resolved any genuine ..
	// elements away.
	for _, elem := range strings.Split(absPath, string(filepath.Separator)) {
		if elem == ".." {
			return NewVaultPathError(path)
		}
	}

	// Basic check that we're not writing into sensitive system directories.
	// Compared as path prefixes, so "/etcetera" is no longer caught by "/etc".
	// This is a guard rail, not a security boundary -- it is Unix-only and a
	// symlink can still lead elsewhere.
	systemDirs := []string{"/etc", "/sys", "/proc", "/dev"}
	for _, sysDir := range systemDirs {
		if absPath == sysDir || strings.HasPrefix(absPath, sysDir+string(filepath.Separator)) {
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

	switch {
	// Only "~" itself or a "~/..." prefix. Slicing path[1:] unconditionally
	// turned "~user/x" into "<home>user/x", silently addressing the wrong file.
	case path == "~":
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("failed to get user home directory: %w", err)
		}
		expandedPath = homeDir
	case strings.HasPrefix(path, "~/"):
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("failed to get user home directory: %w", err)
		}
		expandedPath = filepath.Join(homeDir, path[2:])
	case strings.HasPrefix(path, "$"):
		// Split the leading variable from the rest so "$HOME/vault" works. The
		// previous code treated the whole remainder as the variable name and so
		// looked up an env var literally called "HOME/vault". Resolving via
		// os.ExpandEnv instead would be worse: an unset variable expands to ""
		// and "$NOPE/vault" would silently become "/vault".
		name, rest := path[1:], ""
		if i := strings.IndexAny(name, `/\`); i >= 0 {
			name, rest = name[:i], name[i+1:]
		}
		name = strings.TrimSuffix(strings.TrimPrefix(name, "{"), "}")

		value, exists := os.LookupEnv(name)
		if !exists || value == "" {
			return "", fmt.Errorf("environment variable %s not found", name)
		}
		expandedPath = filepath.Join(value, rest)
	case filepath.IsAbs(path):
		expandedPath = path
	default:
		// Everything relative -- including "./x", "../x" and ".config/x" --
		// joins against the working directory. The old code sliced path[1:] for
		// anything starting with a dot, which dropped the leading dot from
		// ".config/x" and silently swallowed the parent reference in "../x".
		wd, err := os.Getwd()
		if err != nil {
			return "", fmt.Errorf("failed to get working directory: %w", err)
		}
		expandedPath = filepath.Join(wd, path)
	}

	if err := validateSecurePath(expandedPath); err != nil {
		return "", err
	}

	return filepath.Clean(expandedPath), nil
}
