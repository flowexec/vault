package vault

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// ReferenceVault is implemented by vaults that hold references to secrets kept
// somewhere else rather than the secret material itself.
//
// Each entry pairs a key -- the alias the rest of the system uses -- with a
// reference the provider's CLI understands: an op:// URI, a pass entry path, an
// SSM parameter name. Reads resolve the alias and then read through. Because the
// alias is free, a caller never has to reorganise the store it is pointing at,
// and because a reference names a field as well as an item, one item's several
// credentials are individually addressable.
//
// Callers obtain this by type-asserting a Provider.
type ReferenceVault interface {
	// Link points key at reference, replacing any existing link for that key.
	Link(key, reference string) error
	// Unlink removes a key's link. The referenced secret is untouched.
	Unlink(key string) error
	// Reference returns the reference a key points at.
	Reference(key string) (string, error)
	// Links returns a copy of the whole registry.
	Links() (map[string]string, error)
}

const (
	// linkRegistryVersion is the on-disk format version of the registry.
	linkRegistryVersion = 1
	// linkRegistryExt is the extension resolveVaultPath appends. The registry
	// lives beside the other vault files rather than inside the provider config:
	// the config is authored once (command templates, environment) and the
	// registry is rewritten on every link, and rewriting a hand-authored file on
	// every mutation risks losing the templates the vault needs to function.
	linkRegistryExt = "links.json"
	// maxReferenceLength bounds a reference. AWS parameter names top out at 1011
	// characters, so this is comfortably above any real reference while still
	// refusing an unbounded string.
	maxReferenceLength = 2048
)

type linkRegistry struct {
	Version int               `json:"version"`
	Links   map[string]string `json:"links"`
}

// referenceUnsafe matches characters that must never appear in a reference.
//
// A reference is substituted into a command template that a shell then parses.
// Presets single-quote the substitution point, so a quote would close that
// quoting and everything after it would be interpreted; a backtick or $ would
// substitute a command even inside double quotes; a backslash escapes the next
// character. None of these appear in a legitimate reference for any supported
// provider.
var referenceUnsafe = regexp.MustCompile("['\"`$\\\\]")

// validateReference applies the safety floor, then the provider's own pattern.
//
// The two layers are separate on purpose. The pattern comes from a preset and
// lives in a config file a user can edit, so it can be loosened or removed; the
// floor cannot be, and it is what actually stands between a reference and a
// shell.
func validateReference(reference, pattern string) error {
	switch {
	case reference == "":
		return fmt.Errorf("%w: reference cannot be empty", ErrInvalidReference)
	case len(reference) > maxReferenceLength:
		return fmt.Errorf("%w: reference is longer than %d characters", ErrInvalidReference, maxReferenceLength)
	case referenceUnsafe.MatchString(reference):
		return fmt.Errorf(
			"%w: reference %q contains one of ' \" ` $ \\, which a shell would interpret",
			ErrInvalidReference, reference,
		)
	// A leading dash makes the reference look like an option to whichever CLI
	// receives it, turning a read into an unintended flag.
	case strings.HasPrefix(reference, "-"):
		return fmt.Errorf("%w: reference %q must not start with a dash", ErrInvalidReference, reference)
	}

	for _, r := range reference {
		// Covers newline and carriage return, which would let a reference add a
		// second command, as well as any other control character.
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("%w: reference %q contains a control character", ErrInvalidReference, reference)
		}
	}

	// References address entries within a store (a pass path, an SSM parameter
	// name), so a parent-directory element can walk out of it.
	for _, segment := range strings.Split(reference, "/") {
		if segment == ".." {
			return fmt.Errorf("%w: reference %q must not contain a %q path segment", ErrInvalidReference, reference, "..")
		}
	}

	if pattern != "" {
		re, err := regexp.Compile(pattern)
		if err != nil {
			return fmt.Errorf("%w: invalid reference pattern %q: %w", ErrInvalidConfig, pattern, err)
		}
		if !re.MatchString(reference) {
			return fmt.Errorf(
				"%w: reference %q does not match the expected form for this provider (%s)",
				ErrInvalidReference, reference, pattern,
			)
		}
	}

	return nil
}

// registryPath resolves this vault's registry file, proving it stays inside the
// configured storage directory.
func (v *ExternalVaultProvider) registryPath() (string, error) {
	if v.cfg.StoragePath == "" {
		return "", fmt.Errorf(
			"%w: external vault %q has no storage path, so it has nowhere to keep its links",
			ErrInvalidConfig, v.id,
		)
	}
	return resolveVaultPath(v.cfg.StoragePath, v.id, linkRegistryExt)
}

// loadRegistry reads the registry from disk.
//
// Deliberately read fresh on every operation rather than cached at construction.
// The file is small and every operation that uses it is about to spawn a
// provider CLI, so the read is free by comparison -- and a cache would go stale
// the moment a second process linked something, which is the ordinary case when
// a desktop app and a terminal are both open.
func (v *ExternalVaultProvider) loadRegistry() (*linkRegistry, error) {
	path, err := v.registryPath()
	if err != nil {
		return nil, err
	}

	data, exists, err := readVaultFile(path)
	if err != nil {
		return nil, err
	}
	if !exists {
		return &linkRegistry{Version: linkRegistryVersion, Links: map[string]string{}}, nil
	}

	var reg linkRegistry
	if err := json.Unmarshal(data, &reg); err != nil {
		return nil, fmt.Errorf("%w: unable to parse link registry %s: %w", ErrVaultCorrupt, path, err)
	}
	if err := checkVaultVersion(reg.Version, linkRegistryVersion, path); err != nil {
		return nil, err
	}
	if reg.Links == nil {
		reg.Links = map[string]string{}
	}
	return &reg, nil
}

// saveRegistry writes the registry atomically. Callers must hold the vault lock.
func (v *ExternalVaultProvider) saveRegistry(path string, reg *linkRegistry) error {
	reg.Version = linkRegistryVersion
	data, err := json.MarshalIndent(reg, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal link registry: %w", err)
	}
	return writeVaultFileAtomic(path, data)
}

// mutateRegistry runs fn against the registry under an exclusive cross-process
// lock, re-reading inside the lock so a concurrent link is not lost.
//
// The read-modify-write has to happen entirely inside the lock. Reading outside
// it and writing inside would take a snapshot that another process could
// invalidate before the write, and because the whole file is rewritten, that
// process's link would vanish.
func (v *ExternalVaultProvider) mutateRegistry(fn func(reg *linkRegistry) error) error {
	path, err := v.registryPath()
	if err != nil {
		return err
	}

	return withVaultLock(path, func() error {
		reg, err := v.loadRegistry()
		if err != nil {
			return err
		}
		if err := fn(reg); err != nil {
			return err
		}
		return v.saveRegistry(path, reg)
	})
}

func (v *ExternalVaultProvider) Link(key, reference string) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	if err := ValidateSecretKey(key); err != nil {
		return err
	}
	if v.closed {
		return ErrVaultClosed
	}
	if err := validateReference(reference, v.cfg.ReferencePattern); err != nil {
		return err
	}

	return v.mutateRegistry(func(reg *linkRegistry) error {
		reg.Links[key] = reference
		return nil
	})
}

func (v *ExternalVaultProvider) Unlink(key string) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	if err := ValidateSecretKey(key); err != nil {
		return err
	}
	if v.closed {
		return ErrVaultClosed
	}

	return v.mutateRegistry(func(reg *linkRegistry) error {
		if _, ok := reg.Links[key]; !ok {
			return fmt.Errorf("%w: %s is not linked in vault %s", ErrSecretNotFound, key, v.id)
		}
		delete(reg.Links, key)
		return nil
	})
}

func (v *ExternalVaultProvider) Reference(key string) (string, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()

	if v.closed {
		return "", ErrVaultClosed
	}
	return v.referenceLocked(key)
}

// referenceLocked resolves a key to its reference. The caller must hold at least
// a read lock; GetSecret and HasSecret both need this while already holding one.
func (v *ExternalVaultProvider) referenceLocked(key string) (string, error) {
	if err := ValidateSecretKey(key); err != nil {
		return "", err
	}

	reg, err := v.loadRegistry()
	if err != nil {
		return "", err
	}

	reference, ok := reg.Links[key]
	if !ok {
		return "", fmt.Errorf("%w: %s is not linked in vault %s", ErrSecretNotFound, key, v.id)
	}

	// Re-checked on the way out, not only on the way in. The registry is a file
	// on disk that can be hand-edited, and the reference is about to be
	// substituted into a shell command.
	if err := validateReference(reference, v.cfg.ReferencePattern); err != nil {
		return "", fmt.Errorf("link %s in vault %s is unusable: %w", key, v.id, err)
	}

	return reference, nil
}

func (v *ExternalVaultProvider) Links() (map[string]string, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()

	if v.closed {
		return nil, ErrVaultClosed
	}

	reg, err := v.loadRegistry()
	if err != nil {
		return nil, err
	}

	out := make(map[string]string, len(reg.Links))
	for k, ref := range reg.Links {
		out[k] = ref
	}
	return out, nil
}

// MigrateLegacyLinks seeds the registry from a pre-v0.4.0 config's list command,
// mapping every key the backend reports to itself.
//
// Before v0.4.0 an external vault addressed secrets by key directly, so the keys
// a legacy vault knows about are also valid references for it: linking each to
// its own name reproduces the old behaviour exactly, and the links can then be
// re-pointed at wherever those secrets actually live.
//
// This is deliberately explicit rather than something that happens on first
// open. It runs the provider's list command, which reaches the network and can
// raise a biometric prompt; doing that implicitly because a UI happened to
// render a vault list would be a surprise with no obvious cause.
//
// Existing links are never overwritten, so running it twice is safe.
func (v *ExternalVaultProvider) MigrateLegacyLinks() ([]string, error) {
	v.mu.Lock()
	defer v.mu.Unlock()

	if v.closed {
		return nil, ErrVaultClosed
	}
	if v.cfg.LegacyList.CommandTemplate == "" {
		return nil, fmt.Errorf("%w: vault %s has no legacy list command to migrate from", ErrInvalidConfig, v.id)
	}

	output, err := v.runLegacyList()
	if err != nil {
		return nil, err
	}

	sep := v.cfg.LegacyListSeparator
	if sep == "" {
		sep = "\n"
	}

	var migrated []string
	err = v.mutateRegistry(func(reg *linkRegistry) error {
		for _, key := range strings.Split(strings.TrimSpace(output), sep) {
			key = strings.TrimSpace(key)
			if key == "" {
				continue
			}
			if _, exists := reg.Links[key]; exists {
				continue
			}
			if !v.migratableKey(key) {
				continue
			}
			reg.Links[key] = key
			migrated = append(migrated, key)
		}
		sort.Strings(migrated)
		return nil
	})
	if err != nil {
		return nil, err
	}

	return migrated, nil
}

// runLegacyList executes the pre-v0.4.0 list command and returns its output.
func (v *ExternalVaultProvider) runLegacyList() (string, error) {
	cmd, err := v.renderCmdTemplate(v.cfg.LegacyList.CommandTemplate, "", "")
	if err != nil {
		return "", fmt.Errorf("failed to render legacy list cmd: %w", err)
	}

	output, err := v.executeCommand(cmd, "")
	if err != nil {
		return "", fmt.Errorf("failed to list secrets for migration: %w", err)
	}

	if tmpl := v.cfg.LegacyList.OutputTemplate; tmpl != "" {
		if output, err = v.renderOutputTemplate(tmpl, output); err != nil {
			return "", fmt.Errorf("failed to parse legacy list output: %w", err)
		}
	}
	return output, nil
}

// migratableKey reports whether a name a legacy backend returned can be used as
// both a key and a reference.
//
// A legacy backend can report names that were never valid keys -- nested paths,
// titles with spaces. Those are skipped rather than failing the whole migration;
// they can still be linked by hand under a chosen alias.
func (v *ExternalVaultProvider) migratableKey(key string) bool {
	return ValidateSecretKey(key) == nil && validateReference(key, v.cfg.ReferencePattern) == nil
}
