# External Vault Provider Examples

This directory contains ready-to-use configurations for popular CLI tools.

## Available Configurations

- **[Bitwarden](./providers/bitwarden.json)**
- **[1Password](./providers/1password.json)**
- **[pass](./providers/pass.json)**
- **[AWS SSM Parameter Store](./providers/aws-ssm.json)**

## Quick Start

```bash
# Run the Go example against a configuration
go run main.go providers/pass.json
```

These configurations are covered by `TestShippedExampleProvidersAreUsable`, which
loads each one, renders every operation, and asserts that the secret value reaches
the backend over stdin and never appears in a command string.

## Setup Instructions

### Authentication Requirements

Each tool requires prior authentication:

- **Bitwarden**: `bw login && bw unlock`
- **1Password**: `op signin`
- **AWS SSM**: `aws configure`
- **pass**: Configure GPG keys

### Environment Variables

| Provider | Required Variables |
|----------|-------------------|
| Bitwarden | `BW_SESSION` |
| 1Password | `OP_SERVICE_ACCOUNT_TOKEN` |
| AWS SSM | `AWS_REGION` (+ credentials) |
| pass | `PASSWORD_STORE_DIR` (optional) |

## Configuration Structure

Each configuration follows this pattern:

```json
{
  "id": "provider-name",
  "type": "external", 
  "external": {
    "cmd": "cli-command",
    "get": {
      "cmd": "subcommand {{key}}",
      "output": "{{output}}"
    },
    "set": {
      "cmd": "subcommand {{key}}",
      "input": "{{value}}"
    },
    "list": {
      "cmd": "list-subcommand"
    },
    "delete": {
      "cmd": "delete-subcommand {{key}}"
    },
    "exists": {
      "cmd": "check-subcommand {{key}}"
    },
    "metadata": {
      "cmd": "status-subcommand"
    },
    "environment": {
      "ENV_VAR": "$ENV_VAR"
    },
    "timeout": "30s"
  }
}
```

## Template Variables

In `cmd` fields:

- `{{key}}` - The secret key/name (also available as `ref`, `id`, `name`)
- `{{env["VariableName"]}}`- Environment variable value

In `input` fields (piped to the command's stdin):

- `{{value}}` - The secret value, on `set` only
- `{{input}}` - The secret key
- `{{env["VariableName"]}}`

In `output` fields:

- `{{output}}` - Raw command output

### The secret value is never available to a `cmd` template

A rendered command is parsed and executed by a shell, and the template engine
performs no quoting. Interpolating a secret there is a command-injection sink and
silently corrupts any value containing shell metacharacters -- `p@$$w0rd` has `$$`
expanded to the process ID, and `correct horse battery` word-splits to `correct`.

Configurations that reference `{{value}}` or `{{password}}` in any `cmd` are
rejected at load. Pass the secret over stdin with an `input` template instead.

Shell syntax in a `cmd` works normally: `$VAR`, `${VAR:-default}` and `$(...)` are
resolved by the interpreter, with the configured `environment` in scope.
