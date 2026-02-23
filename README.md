# creddy-doppler

Doppler plugin for [Creddy](https://github.com/getcreddy/creddy) — scoped service tokens for secrets access.

## Overview

This plugin creates ephemeral Doppler service tokens, allowing AI agents to access secrets with short-lived, project-scoped credentials.

## Installation

```bash
creddy plugin install doppler
```

Or build from source:

```bash
make install
```

## Configuration

Add to your Creddy server config:

```yaml
integrations:
  doppler:
    plugin: creddy-doppler
    config:
      token: "dp.pt.xxxx"  # Personal or service account token
```

### Getting a Token

You need a Doppler token with permission to create service tokens:

1. **Personal Token:** Dashboard → Settings → Access Tokens → Generate
2. **Service Account:** Dashboard → Team → Service Accounts → Create

The token needs these permissions:
- `tokens:create` — to create service tokens for agents
- `tokens:delete` — to revoke tokens on expiry/unenroll
- Access to the projects/configs you want agents to use

## Scopes

| Scope | Description |
|-------|-------------|
| `doppler:project/config` | Access to specific project/config |
| `doppler:project/config:read` | Read-only access |
| `doppler:project/*` | Access to all configs in a project |

## Usage

### Agent Enrollment

```bash
# Request access to production secrets
creddy enroll --server https://creddy.example.com --name my-agent \
  --can doppler:myproject/production:read

# Multiple scopes
creddy enroll --server https://creddy.example.com --name my-agent \
  --can doppler:myproject/staging \
  --can doppler:myproject/production:read
```

### Getting Credentials

```bash
# Get a service token
creddy get doppler --scope myproject/production

# With specific TTL
creddy get doppler --scope myproject/production --ttl 30m
```

### Using the Credential

```bash
# Set as Doppler token
export DOPPLER_TOKEN=$(creddy get doppler --scope myproject/production)

# Use with Doppler CLI
doppler secrets

# Or fetch secrets directly
curl -s "https://api.doppler.com/v3/configs/config/secrets" \
  -H "Authorization: Bearer $DOPPLER_TOKEN" \
  -H "project: myproject" \
  -H "config: production"
```

## How It Works

1. Agent requests `creddy get doppler --scope project/config`
2. Creddy calls Doppler API to create a scoped service token
3. Token is returned with Creddy-managed TTL
4. On TTL expiry or unenroll → Creddy deletes the token via API

Service tokens are scoped to a specific project/config, so agents only get access to the secrets they need.

## Standalone Testing

Test the plugin without a Creddy server:

```bash
# Create config file
echo '{"token": "dp.pt.xxxx"}' > config.json

# Show plugin info
make info

# Validate configuration
make validate CONFIG=config.json

# Get a credential
make get CONFIG=config.json SCOPE="doppler:myproject/production"
```

## Development

```bash
# Build
make build

# Build for all platforms
make build-all

# Install locally
make install

# Watch for changes and rebuild
make dev
```

## License

Apache 2.0
