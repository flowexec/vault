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
	ctx     context.Context
	mu      sync.RWMutex
	id      string
	execute func(ctx context.Context, cmd, input, dir string, envList []string) (string, error)

	cfg *ExternalConfig
}

func NewExternalVaultProvider(cfg *Config) (*ExternalVaultProvider, error) {
	if cfg.External == nil {
		return nil, fmt.Errorf("external configuration is required")
	}

	vault := &ExternalVaultProvider{
		ctx:     context.Background(),
		id:      cfg.ID,
		cfg:     cfg.External,
		execute: execute,
	}

	return vault, nil
}

func (v *ExternalVaultProvider) ID() string {
	return v.id
}

func (v *ExternalVaultProvider) GetSecret(key string) (Secret, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()

	if err := ValidateSecretKey(key); err != nil {
		return nil, err
	}

	if v.cfg.Get.CommandTemplate == "" {
		return nil, fmt.Errorf("get operation not configured")
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
		secretValue = strings.TrimSpace(output)
	}

	return NewSecretValue([]byte(secretValue)), nil
}

func (v *ExternalVaultProvider) SetSecret(key string, value Secret) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	if err := ValidateSecretKey(key); err != nil {
		return err
	}

	if v.cfg.Set.CommandTemplate == "" {
		return fmt.Errorf("set operation not configured")
	}

	cmd, err := v.renderCmdTemplateWithValue(v.cfg.Set.CommandTemplate, key, value.PlainTextString())
	if err != nil {
		return fmt.Errorf("failed to render set cmd: %w", err)
	}

	var input string
	if v.cfg.Set.InputTemplate != "" {
		input, err = v.renderInputTemplate(v.cfg.Get.InputTemplate, key)
		if err != nil {
			return fmt.Errorf("failed to render input template: %w", err)
		}
	}

	out, err := v.executeCommand(cmd, input)
	if err != nil {
		return fmt.Errorf("failed to set secret: %w stdErr: %s", err, out)
	}

	return nil
}

func (v *ExternalVaultProvider) DeleteSecret(key string) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	if err := ValidateSecretKey(key); err != nil {
		return err
	}

	if v.cfg.Delete.CommandTemplate == "" {
		return fmt.Errorf("delete operation not configured")
	}

	cmd, err := v.renderCmdTemplate(v.cfg.Delete.CommandTemplate, key)
	if err != nil {
		return fmt.Errorf("failed to render delete cmd: %w", err)
	}

	var input string
	if v.cfg.Delete.InputTemplate != "" {
		input, err = v.renderInputTemplate(v.cfg.Get.InputTemplate, key)
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

	if v.cfg.List.CommandTemplate == "" {
		return nil, fmt.Errorf("list operation not configured")
	}

	cmd, err := v.renderCmdTemplate(v.cfg.List.CommandTemplate, "")
	if err != nil {
		return nil, fmt.Errorf("failed to render list cmd: %w", err)
	}

	var input string
	if v.cfg.List.InputTemplate != "" {
		input, err = v.renderInputTemplate(v.cfg.Get.InputTemplate, "")
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
	var result []string
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

	if v.cfg.Exists.CommandTemplate != "" {
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

		_, err = v.executeCommand(cmd, input)
		// typically, exists commands return non-zero exit code if secret doesn't exist
		return err == nil, nil
	}

	_, err := v.GetSecret(key)
	if err != nil {
		if strings.Contains(err.Error(), "not found") ||
			strings.Contains(err.Error(), "not exist") ||
			strings.Contains(err.Error(), "not in") {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func (v *ExternalVaultProvider) Close() error {
	return nil
}

func (v *ExternalVaultProvider) SetExecutionFunc(
	fn func(ctx context.Context, cmd, input, dir string, envList []string) (string, error),
) {
	v.execute = fn
}

func (v *ExternalVaultProvider) Metadata() Metadata {
	v.mu.RLock()
	defer v.mu.RUnlock()

	if v.cfg.Metadata.CommandTemplate == "" {
		return Metadata{}
	}

	cmd, err := v.renderCmdTemplate(v.cfg.Metadata.CommandTemplate, "")
	if err != nil {
		return Metadata{}
	}
	var input string
	if v.cfg.List.InputTemplate != "" {
		input, err = v.renderInputTemplate(v.cfg.Metadata.InputTemplate, "")
		if err != nil {
			return Metadata{}
		}
	}

	output, err := v.executeCommand(cmd, input)
	if err != nil {
		return Metadata{}
	}

	var metadataOutput string
	if v.cfg.Metadata.OutputTemplate != "" {
		metadataOutput, err = v.renderOutputTemplate(v.cfg.Metadata.OutputTemplate, output)
		if err != nil {
			return Metadata{}
		}
	} else {
		metadataOutput = strings.TrimSpace(output)
	}

	return Metadata{RawData: metadataOutput}
}

func (v *ExternalVaultProvider) executeCommand(cmd, input string) (string, error) {
	ctx := v.ctx
	if v.cfg.Timeout != "" {
		var cancel context.CancelFunc
		dur, parseErr := time.ParseDuration(v.cfg.Timeout)
		if parseErr != nil {
			return "", fmt.Errorf("invalid timeout duration: %w", parseErr)
		}
		ctx, cancel = context.WithTimeout(v.ctx, dur)
		defer cancel()
	}

	output, runErr := v.execute(ctx, cmd, input, v.cfg.WorkingDir, v.environmentToSlice())
	if runErr != nil {
		return "", fmt.Errorf("command failed: %w, stderr: %s", runErr, output)
	}

	return output, nil
}

func (v *ExternalVaultProvider) environmentToSlice() []string {
	var envSlice []string
	for key, value := range expandEnv(v.cfg.Environment) {
		envSlice = append(envSlice, fmt.Sprintf("%s=%s", key, value))
	}
	return envSlice
}

func (v *ExternalVaultProvider) renderCmdTemplate(template, key string) (string, error) {
	data := map[string]interface{}{
		"env":      expandEnv(v.cfg.Environment),
		"key":      key,
		"ref":      key,
		"id":       key,
		"name":     key,
		"template": template,
	}

	template = os.ExpandEnv(template)
	tmpl := expression.NewTemplate(fmt.Sprintf("%s-args-template", v.id), data)
	err := tmpl.Parse(template)
	if err != nil {
		return "", fmt.Errorf("parsing args template: %w", err)
	}

	result, err := tmpl.ExecuteToString()
	if err != nil {
		return "", fmt.Errorf("evaluating args template: %w", err)
	}
	return result, nil
}

func (v *ExternalVaultProvider) renderCmdTemplateWithValue(template, key, value string) (string, error) {
	data := map[string]interface{}{
		"env":      expandEnv(v.cfg.Environment),
		"key":      key,
		"ref":      key,
		"id":       key,
		"name":     key,
		"value":    value,
		"password": value,
		"template": template,
	}

	template = os.ExpandEnv(template)
	tmpl := expression.NewTemplate(fmt.Sprintf("%s-args-template", v.id), data)
	err := tmpl.Parse(template)
	if err != nil {
		return "", fmt.Errorf("parsing args template: %w", err)
	}

	result, err := tmpl.ExecuteToString()
	if err != nil {
		return "", fmt.Errorf("evaluating args template: %w", err)
	}
	return result, nil
}

func (v *ExternalVaultProvider) renderInputTemplate(template, input string) (string, error) {
	data := map[string]interface{}{
		"env":      expandEnv(v.cfg.Environment),
		"input":    input,
		"template": template,
	}

	template = os.ExpandEnv(template)
	tmpl := expression.NewTemplate(fmt.Sprintf("%s-input-template", v.id), data)
	err := tmpl.Parse(template)
	if err != nil {
		return "", fmt.Errorf("parsing input template: %w", err)
	}

	result, err := tmpl.ExecuteToString()
	if err != nil {
		return "", fmt.Errorf("evaluating input template: %w", err)
	}
	return result, nil
}

func (v *ExternalVaultProvider) renderOutputTemplate(template, output string) (string, error) {
	data := map[string]interface{}{
		"env":      expandEnv(v.cfg.Environment),
		"output":   output,
		"template": template,
	}

	template = os.ExpandEnv(template)
	tmpl := expression.NewTemplate(fmt.Sprintf("%s-output-template", v.id), data)
	err := tmpl.Parse(template)
	if err != nil {
		return "", fmt.Errorf("parsing output template: %w", err)
	}

	result, err := tmpl.ExecuteToString()
	if err != nil {
		return "", fmt.Errorf("evaluating output template: %w", err)
	}
	return result, nil
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
	output := stdOutBuffer.String()
	if stderr := stdErrBuffer.String(); stderr != "" {
		output += "\n" + stderr
	}
	return strings.TrimSpace(output), nil
}

func expandEnv(env map[string]string) map[string]string {
	for k, v := range env {
		if strings.Contains(v, "$") || strings.Contains(v, "{") {
			env[k] = os.ExpandEnv(v)
		}
	}
	return env
}
