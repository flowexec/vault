package vault

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/jahvon/expression"
	"mvdan.cc/sh/v3/expand"
	"mvdan.cc/sh/v3/interp"
	"mvdan.cc/sh/v3/syntax"
)

type ExternalVaultProvider struct {
	mu      sync.RWMutex
	id      string
	execute func(ctx context.Context, cmd, input, dir string, envList []string) (string, error)

	ctx     context.Context
	timeout time.Duration
	closed  bool

	cfg *ExternalConfig
}

func NewExternalVaultProvider(cfg *Config) (*ExternalVaultProvider, error) {
	if cfg.External == nil {
		return nil, fmt.Errorf("%w: external configuration is required", ErrInvalidConfig)
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	// Timeout is validated by ExternalConfig.Validate, so this cannot fail here.
	timeout, _ := cfg.External.timeoutDuration()

	vault := &ExternalVaultProvider{
		ctx:     context.Background(),
		id:      cfg.ID,
		cfg:     cfg.External,
		timeout: timeout,
		execute: execute,
	}

	return vault, nil
}

func (v *ExternalVaultProvider) ID() string {
	return v.id
}

// SetContext replaces the context used for command execution, allowing callers to
// cancel in-flight operations. The Provider interface does not thread a context
// through its methods, so this is the supported way to make external commands
// cancellable.
func (v *ExternalVaultProvider) SetContext(ctx context.Context) {
	if ctx == nil {
		ctx = context.Background()
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	v.ctx = ctx
}

func (v *ExternalVaultProvider) GetSecret(key string) (Secret, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()

	return v.getSecretLocked(key)
}

// getSecretLocked implements GetSecret and assumes the caller already holds at
// least a read lock. HasSecret needs to delegate here rather than to GetSecret:
// sync.RWMutex does not support recursive read locking, so a writer arriving
// between the two RLock calls would deadlock both.
func (v *ExternalVaultProvider) getSecretLocked(key string) (Secret, error) {
	if err := ValidateSecretKey(key); err != nil {
		return nil, err
	}

	if v.closed {
		return nil, ErrVaultClosed
	}

	if v.cfg.Get.CommandTemplate == "" {
		return nil, fmt.Errorf("%w: get operation not configured", ErrInvalidConfig)
	}

	cmd, err := v.renderCmdTemplate(v.cfg.Get.CommandTemplate, key)
	if err != nil {
		return nil, fmt.Errorf("failed to render get cmd: %w", err)
	}

	var input string
	if v.cfg.Get.InputTemplate != "" {
		input, err = v.renderInputTemplate(v.cfg.Get.InputTemplate, key)
		if err != nil {
			return nil, fmt.Errorf("failed to render input template: %w", err)
		}
	}

	output, err := v.executeCommand(cmd, input)
	if err != nil {
		return nil, fmt.Errorf("failed to get secret: %w", err)
	}

	var secretValue string
	if v.cfg.Get.OutputTemplate != "" {
		secretValue, err = v.renderOutputTemplate(v.cfg.Get.OutputTemplate, output)
		if err != nil {
			return nil, fmt.Errorf("failed to parse output: %w", err)
		}
	} else {
		secretValue = trimCommandNewline(output)
	}

	return NewSecretValue([]byte(secretValue)), nil
}

func (v *ExternalVaultProvider) SetSecret(key string, value Secret) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	if err := ValidateSecretKey(key); err != nil {
		return err
	}

	if v.closed {
		return ErrVaultClosed
	}

	if v.cfg.Set.CommandTemplate == "" {
		return fmt.Errorf("%w: set operation not configured", ErrInvalidConfig)
	}

	// The secret value is deliberately not available to the command template. The
	// rendered command is parsed and run by a shell, and the template engine does
	// no quoting, so interpolating a secret there is a command-injection sink and
	// silently corrupts any value containing shell metacharacters. Values travel
	// over stdin via the set input template instead. ExternalConfig.Validate
	// rejects configs that still reference {{ value }} in the set command.
	cmd, err := v.renderCmdTemplate(v.cfg.Set.CommandTemplate, key)
	if err != nil {
		return fmt.Errorf("failed to render set cmd: %w", err)
	}

	var input string
	if v.cfg.Set.InputTemplate != "" {
		input, err = v.renderInputTemplateWithValue(v.cfg.Set.InputTemplate, key, value.PlainTextString())
		if err != nil {
			return fmt.Errorf("failed to render input template: %w", err)
		}
	}

	// The error from executeCommand already carries stderr. Do not add the command
	// output here: a backend that echoes the failing command back would put the
	// secret value into the returned error string.
	if _, err := v.executeCommand(cmd, input); err != nil {
		return fmt.Errorf("failed to set secret: %w", err)
	}

	return nil
}

func (v *ExternalVaultProvider) DeleteSecret(key string) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	if err := ValidateSecretKey(key); err != nil {
		return err
	}

	if v.closed {
		return ErrVaultClosed
	}

	if v.cfg.Delete.CommandTemplate == "" {
		return fmt.Errorf("%w: delete operation not configured", ErrInvalidConfig)
	}

	cmd, err := v.renderCmdTemplate(v.cfg.Delete.CommandTemplate, key)
	if err != nil {
		return fmt.Errorf("failed to render delete cmd: %w", err)
	}

	var input string
	if v.cfg.Delete.InputTemplate != "" {
		input, err = v.renderInputTemplate(v.cfg.Delete.InputTemplate, key)
		if err != nil {
			return fmt.Errorf("failed to render input template: %w", err)
		}
	}

	if _, err := v.executeCommand(cmd, input); err != nil {
		return fmt.Errorf("failed to delete secret: %w", err)
	}

	return nil
}

func (v *ExternalVaultProvider) ListSecrets() ([]string, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()

	if v.closed {
		return nil, ErrVaultClosed
	}

	if v.cfg.List.CommandTemplate == "" {
		return nil, fmt.Errorf("%w: list operation not configured", ErrInvalidConfig)
	}

	cmd, err := v.renderCmdTemplate(v.cfg.List.CommandTemplate, "")
	if err != nil {
		return nil, fmt.Errorf("failed to render list cmd: %w", err)
	}

	var input string
	if v.cfg.List.InputTemplate != "" {
		input, err = v.renderInputTemplate(v.cfg.List.InputTemplate, "")
		if err != nil {
			return nil, fmt.Errorf("failed to render input template: %w", err)
		}
	}

	output, err := v.executeCommand(cmd, input)
	if err != nil {
		return nil, fmt.Errorf("failed to list secrets: %w", err)
	}

	var secretsList string
	if v.cfg.List.OutputTemplate != "" {
		secretsList, err = v.renderOutputTemplate(v.cfg.List.OutputTemplate, output)
		if err != nil {
			return nil, fmt.Errorf("failed to parse list output: %w", err)
		}
	} else {
		secretsList = strings.TrimSpace(output)
	}

	if secretsList == "" {
		return []string{}, nil
	}

	sep := v.cfg.ListSeparator
	if sep == "" {
		sep = "\n"
	}
	secrets := strings.Split(secretsList, sep)
	result := make([]string, 0, len(secrets))
	for _, secret := range secrets {
		secret = strings.TrimSpace(secret)
		if secret != "" {
			result = append(result, secret)
		}
	}

	return result, nil
}

func (v *ExternalVaultProvider) HasSecret(key string) (bool, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()

	if err := ValidateSecretKey(key); err != nil {
		return false, err
	}

	if v.closed {
		return false, ErrVaultClosed
	}

	if v.cfg.Exists.CommandTemplate != "" {
		return v.hasSecretViaExistsCmd(key)
	}

	if _, err := v.getSecretLocked(key); err != nil {
		if v.isNotFoundErr(err) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func (v *ExternalVaultProvider) hasSecretViaExistsCmd(key string) (bool, error) {
	cmd, err := v.renderCmdTemplate(v.cfg.Exists.CommandTemplate, key)
	if err != nil {
		return false, fmt.Errorf("failed to render exists cmd: %w", err)
	}

	var input string
	if v.cfg.Exists.InputTemplate != "" {
		input, err = v.renderInputTemplate(v.cfg.Exists.InputTemplate, key)
		if err != nil {
			return false, fmt.Errorf("failed to render input template: %w", err)
		}
	}

	if _, err = v.executeCommand(cmd, input); err == nil {
		return true, nil
	}

	// A non-zero exit conventionally means "absent", but it is also how an expired
	// session, a network failure, or a permissions problem surfaces. NotFoundPattern
	// lets a config say which failures actually mean absence.
	//
	// It can only say so about failures that produce a message, though. An exists
	// command may answer purely by exit status -- `test -f`, `jq -e` -- and then
	// there is no text for the pattern to match. Treating that as "the pattern did
	// not match, so this is a real error" turns every ordinary miss into a failure,
	// so a silent non-zero exit is taken at its word: absent.
	var cmdErr *commandError
	if errors.As(err, &cmdErr) && cmdErr.diagnostics() == "" {
		return false, nil
	}

	if v.cfg.NotFoundPattern != "" && !strings.Contains(err.Error(), v.cfg.NotFoundPattern) {
		return false, err
	}
	return false, nil
}

func (v *ExternalVaultProvider) isNotFoundErr(err error) bool {
	if v.cfg.NotFoundPattern != "" {
		return strings.Contains(err.Error(), v.cfg.NotFoundPattern)
	}
	msg := err.Error()
	return strings.Contains(msg, "not found") ||
		strings.Contains(msg, "not exist") ||
		strings.Contains(msg, "not in")
}

func (v *ExternalVaultProvider) Close() error {
	v.mu.Lock()
	defer v.mu.Unlock()

	v.closed = true
	return nil
}

func (v *ExternalVaultProvider) SetExecutionFunc(
	fn func(ctx context.Context, cmd, input, dir string, envList []string) (string, error),
) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.execute = fn
}

func (v *ExternalVaultProvider) Metadata() (Metadata, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()

	if v.closed {
		return Metadata{}, ErrVaultClosed
	}

	if v.cfg.Metadata.CommandTemplate == "" {
		return Metadata{}, nil
	}

	cmd, err := v.renderCmdTemplate(v.cfg.Metadata.CommandTemplate, "")
	if err != nil {
		return Metadata{}, fmt.Errorf("failed to render metadata cmd: %w", err)
	}

	var input string
	if v.cfg.Metadata.InputTemplate != "" {
		input, err = v.renderInputTemplate(v.cfg.Metadata.InputTemplate, "")
		if err != nil {
			return Metadata{}, fmt.Errorf("failed to render input template: %w", err)
		}
	}

	output, err := v.executeCommand(cmd, input)
	if err != nil {
		return Metadata{}, fmt.Errorf("failed to read metadata: %w", err)
	}

	var metadataOutput string
	if v.cfg.Metadata.OutputTemplate != "" {
		metadataOutput, err = v.renderOutputTemplate(v.cfg.Metadata.OutputTemplate, output)
		if err != nil {
			return Metadata{}, fmt.Errorf("failed to parse metadata output: %w", err)
		}
	} else {
		metadataOutput = strings.TrimSpace(output)
	}

	return Metadata{RawData: metadataOutput}, nil
}

// commandError carries a failing command's diagnostic output alongside the
// error, so callers can tell "the command answered by exit status alone" from
// "the command complained about something" without parsing an error string.
type commandError struct {
	stderr string
	err    error
}

func (e *commandError) Error() string {
	if e.stderr == "" {
		return fmt.Sprintf("command failed: %v", e.err)
	}
	return fmt.Sprintf("command failed: %v, stderr: %s", e.err, e.stderr)
}

func (e *commandError) Unwrap() error { return e.err }

// diagnostics returns the command's output, trimmed. Empty means the command
// said nothing and reported only through its exit status.
func (e *commandError) diagnostics() string { return strings.TrimSpace(e.stderr) }

func (v *ExternalVaultProvider) executeCommand(cmd, input string) (string, error) {
	ctx := v.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	if v.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, v.timeout)
		defer cancel()
	}

	output, runErr := v.execute(ctx, cmd, input, v.cfg.WorkingDir, v.environmentToSlice())
	if runErr != nil {
		return "", &commandError{stderr: output, err: runErr}
	}

	return output, nil
}

func (v *ExternalVaultProvider) environmentToSlice() []string {
	expanded := expandEnv(v.cfg.Environment)
	envSlice := make([]string, 0, len(expanded))
	for key, value := range expanded {
		envSlice = append(envSlice, fmt.Sprintf("%s=%s", key, value))
	}
	return envSlice
}

// templateData is the variable set shared by the command and input templates.
// The secret value is intentionally absent; only renderInputTemplateWithValue
// adds it.
func (v *ExternalVaultProvider) templateData(key string) map[string]interface{} {
	return map[string]interface{}{
		"env":  expandEnv(v.cfg.Environment),
		"key":  key,
		"ref":  key,
		"id":   key,
		"name": key,
	}
}

func (v *ExternalVaultProvider) render(name, template string, data map[string]interface{}) (string, error) {
	// os.ExpandEnv is deliberately not applied here. It runs before the shell
	// parses the command, so it destroys $VAR, ${VAR}, $1, $? and $@, makes a
	// literal $ unwritable, and applies substitution before quoting -- the wrong
	// order for injection safety. execute() already appends the configured
	// environment to os.Environ(), so the interpreter resolves $VAR itself, with
	// correct quoting semantics and with cfg.Environment actually in scope.
	tmpl := expression.NewTemplate(fmt.Sprintf("%s-%s-template", v.id, name), data)
	if err := tmpl.Parse(template); err != nil {
		return "", fmt.Errorf("parsing %s template: %w", name, err)
	}

	result, err := tmpl.ExecuteToString()
	if err != nil {
		return "", fmt.Errorf("evaluating %s template: %w", name, err)
	}
	return result, nil
}

func (v *ExternalVaultProvider) renderCmdTemplate(template, key string) (string, error) {
	return v.render("args", template, v.templateData(key))
}

func (v *ExternalVaultProvider) renderInputTemplate(template, input string) (string, error) {
	return v.renderInputTemplateWithValue(template, input, "")
}

func (v *ExternalVaultProvider) renderInputTemplateWithValue(template, input, value string) (string, error) {
	data := v.templateData(input)
	data["input"] = input
	data["value"] = value
	data["password"] = value
	return v.render("input", template, data)
}

func (v *ExternalVaultProvider) renderOutputTemplate(template, output string) (string, error) {
	data := map[string]interface{}{
		"env":    expandEnv(v.cfg.Environment),
		"output": output,
	}

	// Unlike command templates, output templates are never handed to a shell, so
	// environment expansion here is safe and preserved for compatibility.
	return v.render("output", os.ExpandEnv(template), data)
}

func execute(ctx context.Context, cmd, input, dir string, envList []string) (string, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	parser := syntax.NewParser()
	reader := strings.NewReader(strings.TrimSpace(cmd))
	prog, err := parser.Parse(reader, "")
	if err != nil {
		return "", fmt.Errorf("unable to parse command - %w", err)
	}

	if envList == nil {
		envList = make([]string, 0)
	}
	envList = append(os.Environ(), envList...)

	stdInBuffer := strings.NewReader(input)
	stdOutBuffer := &strings.Builder{}
	stdErrBuffer := &strings.Builder{}

	runner, err := interp.New(
		interp.Dir(dir),
		interp.Env(expand.ListEnviron(envList...)),
		interp.StdIO(
			stdInBuffer,
			stdOutBuffer,
			stdErrBuffer,
		),
	)
	if err != nil {
		return "", fmt.Errorf("unable to create runner - %w", err)
	}

	err = runner.Run(ctx, prog)
	if err != nil {
		var exitStatus interp.ExitStatus
		if errors.As(err, &exitStatus) {
			return stdErrBuffer.String(), fmt.Errorf("command exited with non-zero status %w", exitStatus)
		}
		return stdErrBuffer.String(), fmt.Errorf("encountered an error executing command - %w", err)
	}

	// Only stdout is the result. Merging stderr in on success concatenates any
	// warning the backend emits (e.g. "gpg: WARNING: unsafe permissions") onto
	// the secret value itself. stderr is still returned on the error path above.
	//
	// Returned verbatim: trimming here would silently corrupt any secret with
	// deliberate leading or trailing whitespace. Callers that want a tidy string
	// (list, metadata) trim for themselves; GetSecret strips only the single
	// trailing newline a command adds.
	return stdOutBuffer.String(), nil
}

// trimCommandNewline removes the one trailing line ending a command conventionally
// adds to its output, and nothing else.
//
// TrimSpace would take real data with it: a passphrase may legitimately begin or
// end with a space, and a PEM block ends in a newline that some parsers require.
// A secret whose true value ends in a newline is still indistinguishable from one
// that does not -- that is inherent to reading a value off a command's stdout,
// and no amount of trimming policy can recover it.
func trimCommandNewline(s string) string {
	s = strings.TrimSuffix(s, "\n")
	return strings.TrimSuffix(s, "\r")
}

// expandEnv returns a new map with environment references expanded. It must not
// mutate the input: the caller's map is the shared provider config, and the read
// paths (GetSecret, ListSecrets, HasSecret, Metadata) hold only a read lock, so
// writing to it concurrently is an unrecoverable "concurrent map writes" fault.
func expandEnv(env map[string]string) map[string]string {
	out := make(map[string]string, len(env))
	for k, v := range env {
		if strings.Contains(v, "$") || strings.Contains(v, "{") {
			out[k] = os.ExpandEnv(v)
		} else {
			out[k] = v
		}
	}
	return out
}
