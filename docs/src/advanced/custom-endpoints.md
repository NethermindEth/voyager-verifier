# Custom Endpoints

The voyager-verifier supports using custom API endpoints instead of the predefined networks, allowing you to verify contracts against development environments, staging servers, or self-hosted Voyager instances.

## Overview

By default, the verifier connects to predefined networks:
- **Mainnet:** `https://api.voyager.online/beta`
- **Sepolia:** `https://sepolia-api.voyager.online/beta`
- **Dev:** `https://dev-api.voyager.online/beta`

However, you can specify a custom API endpoint using the `--url` flag to connect to:
- Development/staging environments
- Self-hosted Voyager instances
- Custom verification services
- Testing servers

## Basic Usage

### Command-Line Flag

Use the `--url` flag instead of `--network`:

```bash
voyager verify --url https://custom-api.example.com/beta \
  --class-hash 0x044dc2b3239382230d8b1e943df23b96f52eebcac93efe6e8bde92f9a2f1da18 \
  --contract-name MyContract
```

### Configuration File

Set a default custom endpoint in your `.voyager.toml`:

```toml
[voyager]
url = "https://custom-api.example.com/beta"
license = "MIT"
watch = true
```

Then run verification without specifying the URL:

```bash
voyager verify --class-hash 0x044dc2b3... --contract-name MyContract
```

## URL vs Network Flag

### Mutual Exclusivity

You cannot use both `--network` and `--url` simultaneously:

```bash
# ❌ This will fail
voyager verify --network mainnet --url https://custom.com/beta \
  --class-hash 0x044dc2b3... --contract-name MyContract

# ✅ Use one or the other
voyager verify --network mainnet --class-hash 0x044dc2b3... --contract-name MyContract
voyager verify --url https://custom.com/beta --class-hash 0x044dc2b3... --contract-name MyContract
```

### Priority System

When both are configured, the priority order is:

1. **CLI flag** (`--url` or `--network`) - Highest priority
2. **Config file** (`url` or `network` in `.voyager.toml`)
3. **Default value** (none - error if neither provided)

## Common Use Cases

### Development Environment

Test contract verification against a development instance:

```bash
voyager verify --url https://dev-api.internal.com/beta \
  --class-hash 0x044dc2b3239382230d8b1e943df23b96f52eebcac93efe6e8bde92f9a2f1da18 \
  --contract-name DevContract \
  --watch
```

**Configuration file approach:**

```toml
# .voyager.dev.toml
[voyager]
url = "https://dev-api.internal.com/beta"
license = "MIT"
watch = true
verbose = true
```

```bash
# Use custom config file
cp .voyager.dev.toml .voyager.toml
voyager verify --class-hash 0x044dc2b3... --contract-name DevContract
```

### Staging Environment

Verify contracts before production deployment:

```bash
voyager verify --url https://staging-api.example.com/beta \
  --class-hash 0x044dc2b3239382230d8b1e943df23b96f52eebcac93efe6e8bde92f9a2f1da18 \
  --contract-name StagingContract
```

### Self-Hosted Voyager Instance

Use your own Voyager deployment:

```bash
voyager verify --url https://voyager.mycompany.io/api/beta \
  --class-hash 0x044dc2b3239382230d8b1e943df23b96f52eebcac93efe6e8bde92f9a2f1da18 \
  --contract-name MyContract
```

### Local Testing

Connect to a local Voyager instance for testing:

```bash
voyager verify --url http://localhost:3000/api/beta \
  --class-hash 0x044dc2b3239382230d8b1e943df23b96f52eebcac93efe6e8bde92f9a2f1da18 \
  --contract-name TestContract
```

## URL Format Requirements

### Valid URL Structure

The URL must be a fully-qualified, valid URL:

```bash
# ✅ Valid URLs
https://api.example.com/beta
https://voyager.staging.internal:8443/api/v1
http://localhost:3000/api/beta
https://192.168.1.100:8080/beta

# ❌ Invalid URLs
example.com/api                    # Missing protocol
api.example.com                     # Missing protocol
https://                            # Incomplete
custom-endpoint                     # Not a URL
```

### Protocol Support

Both HTTP and HTTPS are supported:

- **HTTPS** - Recommended for production and public endpoints
- **HTTP** - Acceptable for local development and internal networks

```bash
# Production/staging - use HTTPS
voyager verify --url https://staging-api.example.com/beta \
  --class-hash 0x044dc2b3... --contract-name MyContract

# Local development - HTTP is acceptable
voyager verify --url http://localhost:3000/api/beta \
  --class-hash 0x044dc2b3... --contract-name MyContract
```

### Port Specification

Include port numbers when using non-standard ports:

```bash
voyager verify --url https://voyager.internal:8443/api/beta \
  --class-hash 0x044dc2b3239382230d8b1e943df23b96f52eebcac93efe6e8bde92f9a2f1da18 \
  --contract-name MyContract
```

## Multi-Environment Workflows

### Using Multiple Configuration Files

Maintain separate config files for each environment:

**`.voyager.dev.toml`:**
```toml
[voyager]
url = "https://dev-api.internal.com/beta"
license = "MIT"
watch = true
verbose = true
test-files = true
```

**`.voyager.staging.toml`:**
```toml
[voyager]
url = "https://staging-api.example.com/beta"
license = "MIT"
watch = true
lock-file = true
```

**`.voyager.prod.toml`:**
```toml
[voyager]
network = "mainnet"  # Use predefined network for production
license = "Apache-2.0"
watch = false
lock-file = true
```

**Workflow:**

```bash
# Development
cp .voyager.dev.toml .voyager.toml
voyager verify --class-hash $DEV_HASH --contract-name MyContract

# Staging
cp .voyager.staging.toml .voyager.toml
voyager verify --class-hash $STAGING_HASH --contract-name MyContract

# Production
cp .voyager.prod.toml .voyager.toml
voyager verify --class-hash $PROD_HASH --contract-name MyContract
```

### Environment-Based Selection

Use shell scripts to select endpoints based on environment:

```bash
#!/bin/bash

ENVIRONMENT=${1:-dev}

case $ENVIRONMENT in
  dev)
    API_URL="https://dev-api.internal.com/beta"
    ;;
  staging)
    API_URL="https://staging-api.example.com/beta"
    ;;
  prod)
    # Use predefined network for production
    voyager verify --network mainnet \
      --class-hash "$CLASS_HASH" \
      --contract-name "$CONTRACT_NAME"
    exit 0
    ;;
  *)
    echo "Unknown environment: $ENVIRONMENT"
    exit 1
    ;;
esac

voyager verify --url "$API_URL" \
  --class-hash "$CLASS_HASH" \
  --contract-name "$CONTRACT_NAME"
```

Usage:

```bash
# Verify on development
./verify.sh dev

# Verify on staging
./verify.sh staging

# Verify on production
./verify.sh prod
```

## Status Checking with Custom Endpoints

When checking verification status, use the same endpoint:

```bash
# Submit verification
voyager verify --url https://custom-api.example.com/beta \
  --class-hash 0x044dc2b3239382230d8b1e943df23b96f52eebcac93efe6e8bde92f9a2f1da18 \
  --contract-name MyContract

# Output: Job ID: abc-123-def

# Check status (must use same endpoint)
voyager status --url https://custom-api.example.com/beta \
  --job abc-123-def
```

**Important:** The job ID is specific to the API endpoint. You must use the same endpoint to check status that was used for submission.

## Configuration File Discovery

The verifier searches for `.voyager.toml` in:
1. Current working directory
2. Parent directories (walking up until found)

This allows you to place environment-specific configs at different levels:

```
project/
├── .voyager.toml              # Default (production)
├── environments/
│   ├── dev/
│   │   └── .voyager.toml      # Development config with custom URL
│   └── staging/
│       └── .voyager.toml      # Staging config with custom URL
└── contracts/
    └── my_contract/
        └── Scarb.toml
```

Run from the appropriate directory:

```bash
# Use development endpoint
cd environments/dev
voyager verify --class-hash $HASH --contract-name MyContract

# Use staging endpoint
cd environments/staging
voyager verify --class-hash $HASH --contract-name MyContract

# Use production (default)
cd project
voyager verify --class-hash $HASH --contract-name MyContract
```

## API Compatibility

### Endpoint Requirements

Custom endpoints must implement the Voyager API specification:

**Required endpoints:**
- `POST /verify` - Submit verification job
- `GET /verify/{job_id}` - Check verification status

**API contract:**
- Accept verification submissions with contract source files
- Return job ID on successful submission
- Provide status updates via job ID query
- Support the same status values (Submitted, Processing, Compiled, Success, Fail, CompileFailed)

### Version Compatibility

Ensure your custom endpoint supports:
- Cairo versions your contracts use
- Scarb versions in your development environment
- Dojo versions (if applicable)

The verifier sends version information with each request, so the custom endpoint must handle these appropriately.

## Troubleshooting

### Connection Errors

**Problem:** Cannot connect to custom endpoint

```
Error: Connection failed
```

**Solutions:**

1. **Check URL format:**
   ```bash
   # Ensure URL is valid
   curl -I https://custom-api.example.com/beta
   ```

2. **Verify network access:**
   ```bash
   # Can you reach the endpoint?
   ping custom-api.example.com
   ```

3. **Check firewall rules:**
   - Ensure outbound HTTPS (443) or HTTP (80) is allowed
   - Verify custom ports are accessible if using non-standard ports

4. **Validate SSL certificates:**
   ```bash
   # Test SSL connection
   openssl s_client -connect custom-api.example.com:443
   ```

### Authentication Errors

**Problem:** Endpoint requires authentication

```
Error: 401 Unauthorized
```

**Solutions:**

Custom authentication is not currently supported via command-line flags. If your endpoint requires authentication:

1. **Use a reverse proxy** - Set up nginx or similar to handle authentication
2. **VPN access** - Connect to VPN before running verifier
3. **API gateway** - Use an API gateway that handles authentication transparently

### API Incompatibility

**Problem:** Endpoint returns unexpected response format

```
Error: Failed to parse response
```

**Solutions:**

1. **Verify endpoint implements Voyager API** - Check that your custom endpoint follows the same API contract as official Voyager
2. **Check API version** - Ensure compatibility between verifier version and endpoint API version
3. **Enable verbose mode:**
   ```bash
   voyager verify --url https://custom-api.example.com/beta \
     --class-hash 0x044dc2b3... \
     --contract-name MyContract \
     --verbose
   ```

### URL Validation Errors

**Problem:** URL is rejected as invalid

```
Error: Invalid URL format
```

**Solutions:**

```bash
# ✅ Include protocol
voyager verify --url https://api.example.com/beta ...

# ❌ Don't omit protocol
voyager verify --url api.example.com/beta ...

# ✅ Use valid characters
voyager verify --url https://api.example.com/beta ...

# ❌ Avoid special characters in URL
voyager verify --url https://api example com/beta ...
```

## Security Considerations

### HTTPS in Production

Always use HTTPS for production and staging environments:

```toml
# ✅ Production config
[voyager]
url = "https://voyager.production.com/api/beta"

# ⚠️ Only use HTTP for local development
[voyager]
url = "http://localhost:3000/api/beta"
```

### URL Validation

The verifier validates URLs before use:
- Checks for valid URL format
- Ensures protocol is present (http:// or https://)
- Validates URL structure

However, it does **not** validate:
- SSL certificate authenticity (uses system default)
- Endpoint API compatibility
- Network reachability

### Internal Networks

When using custom endpoints on internal networks:
- Use VPN for remote access
- Implement network segmentation
- Use firewall rules to restrict access
- Consider using mutual TLS for enhanced security

## Best Practices

### 1. Environment-Specific Configs

Maintain separate configuration files for each environment:

```bash
.voyager.dev.toml
.voyager.staging.toml
.voyager.prod.toml (uses --network mainnet instead of custom URL)
```

### 2. Use HTTPS Where Possible

Prefer HTTPS for all non-local endpoints:

```toml
# ✅ Recommended
url = "https://staging-api.example.com/beta"

# ⚠️ Only for localhost
url = "http://localhost:3000/api/beta"
```

### 3. Document Your Endpoints

Maintain documentation of available endpoints:

```markdown
# Available Endpoints

- **Development:** https://dev-api.internal.com/beta
- **Staging:** https://staging-api.example.com/beta
- **Production:** Use `--network mainnet` (default)
```

### 4. Test Connectivity First

Before running verification, test endpoint connectivity:

```bash
# Quick connectivity check
curl -I https://custom-api.example.com/beta

# If successful, proceed with verification
voyager verify --url https://custom-api.example.com/beta \
  --class-hash 0x044dc2b3... --contract-name MyContract
```

### 5. Use Configuration Files

Prefer configuration files over CLI flags for custom endpoints:

```toml
# .voyager.toml
[voyager]
url = "https://custom-api.example.com/beta"
license = "MIT"
watch = true
```

```bash
# Cleaner command
voyager verify --class-hash 0x044dc2b3... --contract-name MyContract
```

## See Also

- [Configuration File Guide](../configuration/config-file.md) - Complete configuration system
- [CLI Options Reference](../configuration/cli-options.md) - All command-line flags
- [Command-Line Verification](../verification/command-line.md) - Direct CLI verification
- [CI/CD Integration](./ci-cd.md) - Using custom endpoints in CI/CD pipelines
