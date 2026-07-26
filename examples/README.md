# External Vault Provider Examples

This directory contains ready-to-use configurations for popular CLI tools.

An external vault **reads through** to the tool that owns your secrets. It holds
a set of links — a key you choose, paired with a reference that tool understands —
and resolves them on demand. It never writes to the provider, so pointing one at
a store you already use cannot damage it.

## Available Configurations

| Provider | Reference looks like |
|----------|----------------------|
| **[1Password](./providers/1password.json)** | `op://Team/AWS/access_key_id` |
| **[pass](./providers/pass.json)** | `team/db/password` |
| **[AWS SSM Parameter Store](./providers/aws-ssm.json)** | `/prod/db/password` |
| **[Bitwarden](./providers/bitwarden.json)** | an item ID |

Note the field on the end of the 1Password reference. One item's several
credentials are addressed individually, so an `AWS` item holding both an access
key and a secret key yields two links rather than one unreachable pair.

## Quick Start

```bash
# Run the Go example against a configuration
go run main.go providers/pass.json
```

These configurations are covered by `TestShippedExampleProvidersAreUsable`, which
loads each one, supplies a realistic reference, and asserts the rendered command
addresses that reference rather than the local key.

## Setup Instructions

### Authentication Requirements

Each tool requires prior authentication:

- **Bitwarden**: `bw login && bw unlock`
- **1Password**: enable "Integrate with 1Password CLI" in the app, or set
  `OP_SERVICE_ACCOUNT_TOKEN`. A session from `op signin` in a terminal is not
  visible to other applications.
- **AWS SSM**: `aws configure` or `aws sso login`
- **pass**: Configure GPG keys

### Environment Variables

| Provider | Required Variables |
|----------|-------------------|
| Bitwarden | `BW_SESSION` |
| 1Password | `OP_SERVICE_ACCOUNT_TOKEN` (only for service accounts) |
| AWS SSM | `AWS_REGION` (+ credentials) |
| pass | `PASSWORD_STORE_DIR` (optional) |

## Configuration Structure

Each configuration follows this pattern:

```json
{
  "id": "provider-name",
  "type": "external",
  "external": {
    "get": {
      "cmd": "read-subcommand '{{ref}}'",
      "output": "{{output}}"
    },
    "metadata": {
      "cmd": "status-subcommand"
    },
    "reference_pattern": "^expected/shape/.*$",
    "not_found_pattern": "NoSuchSecret",
    "environment": {
      "ENV_VAR": "$ENV_VAR"
    },
    "timeout": "30s"
  }
}
```

`storage_path` — where the link registry is kept — is deliberately absent from
these files. A configuration authored for distribution does not know where the
consuming tool keeps vault state, so the tool fills it in before opening the
vault.

`reference_pattern` describes what a reference for this provider looks like. It
is a usability gate: it catches a mistyped reference when you link it instead of
when you read it.

`not_found_pattern` separates "this link is broken" from "the provider is
unreachable". Without it, an expired session is indistinguishable from a deleted
secret.

## Template Variables

In `cmd` fields:

- `{{ref}}` — the reference this key is linked to. **This is what a provider
  command should use.**
- `{{key}}` — the local alias (also available as `id`, `name`)
- `{{env["VariableName"]}}` — environment variable value

In `output` fields:

- `{{output}}` — raw command output

Shell syntax in a `cmd` works normally: `$VAR`, `${VAR:-default}` and `$(...)`
are resolved by the interpreter, with the configured `environment` in scope.

### There is no `set`, `delete`, `list` or `exists`

Those commands existed when an external vault was a writable store, and they are
now inert — a configuration carrying them still loads, and they are never run.

Writing through to a provider meant either interpolating the secret into a shell
command (which silently corrupts any value with shell metacharacters — `p@$$w0rd`
has `$$` expanded to the process ID) or handing it to a CLI as an argv element,
where every process on the machine can see it. 1Password's own documentation
warns about exactly this. It also meant a `delete` that destroyed real data.

So: create secrets in the tool that owns them, then link them. Removing a link
removes only the link.

### References are validated before they reach a shell

Quotes, backticks, `$`, backslashes, control characters, a leading dash and `..`
path segments are all rejected — on the way in *and* again on the way out, since
the registry is a file that can be hand-edited. `reference_pattern` is applied on
top of that floor, never instead of it.
