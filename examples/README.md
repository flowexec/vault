# External Vault Provider Examples

This directory contains ready-to-use configurations for popular CLI tools.

## Available Configurations

- **[Bitwarden](./providers/bitwarden.json)**
- **[1Password](./providers/1password.json)**
- **[pass](./providers/pass.json)**
- **[AWS SSM Parameter Store](./providers/aws-ssm.json)**

## Quick Start

```bash
# Test a configuration
./test-provider.sh providers/bitwarden.json

# Run the Go example
go run main.go providers/pass.json
```

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
      "cmd": "subcommand {{key}} {{value}}"
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

Available in `cmd` and `output` fields:

- `{{key}}` - The secret key/name
- `{{value}}` - The secret value (for set operations)
- `{{env["VariableName"]}}`- Environment variable value
- `{{output}}` - Raw command output (for output templates)
