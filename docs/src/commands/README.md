# Command Reference

Voyager Verifier provides four main commands for contract verification and management.

## Available Commands

### Core Commands

- **[`verify`](./verify.md)** - Submit contracts for verification

  The primary command for submitting your Starknet contracts for verification on Voyager. Supports interactive wizard mode, direct CLI usage, and batch verification.

- **[`status`](./status.md)** - Check verification job status

  Query the status of a verification job using its job ID. Supports watch mode for continuous monitoring and multiple output formats.

- **[`check`](./check.md)** - Check if a class is already verified

  Query whether a contract class is already verified on Voyager before submitting a verification request. Useful for CI/CD pipelines.

- **[`history`](./history.md)** - Manage verification history

  View, filter, and manage your local verification history database. Track past verifications, recheck pending jobs, and view statistics.

## Quick Command Examples

### Verify a Contract

```bash
# Interactive wizard
voyager verify --wizard

# Direct command
voyager verify --network mainnet \
  --class-hash 0x044dc2b3... \
  --contract-name MyToken

# Batch verification
voyager verify  # Uses .voyager.toml configuration
```

### Check Status

```bash
# One-time status check
voyager status --network mainnet --job abc-123-def

# Watch until completion
voyager status --network mainnet --job abc-123-def --watch

# JSON output for scripts
voyager status --network mainnet --job abc-123-def --format json
```

### Check Verification

```bash
# Check if class is verified
voyager check --network mainnet --class-hash 0x044dc2b3...

# JSON output for scripts
voyager check --network mainnet --class-hash 0x044dc2b3... --json
```

### View History

```bash
# List all verifications
voyager history list

# Filter by status
voyager history list --status success

# View statistics
voyager history stats

# Recheck pending jobs
voyager history recheck --network mainnet
```

## Common Patterns

### First-Time Verification

For users new to the tool:

```bash
voyager verify --wizard
```

### Production Workflow

Typical production verification with all recommended flags:

```bash
voyager verify --network mainnet \
  --class-hash <HASH> \
  --contract-name <NAME> \
  --license MIT \
  --lock-file \
  --watch \
  --notify
```

### CI/CD Pipeline

Automated verification without watch mode:

```bash
voyager verify --network mainnet \
  --class-hash <HASH> \
  --contract-name <NAME> \
  --format json \
  --verbose
```

### Multi-Contract Deployment

For verifying multiple contracts:

```bash
# Define contracts in .voyager.toml
voyager verify --watch --batch-delay 5
```

## Global Options

These options are available across all commands:

### Help

Get help for any command:

```bash
voyager --help
voyager verify --help
voyager status --help
voyager history --help
```

### Version

Check the installed version:

```bash
voyager --version
```

## Network Selection

Most commands require network specification:

### Predefined Networks

```bash
--network mainnet    # Starknet mainnet
--network sepolia    # Sepolia testnet
--network dev        # Development network
```

### Custom Endpoint

```bash
--url https://api.custom.com/beta
```

### Configuration File

Set default network in `.voyager.toml`:

```toml
[voyager]
network = "mainnet"
```

## Output Formats

Commands that support multiple output formats:

```bash
--format text    # Human-readable (default)
--format json    # Machine-readable JSON
--format table   # Formatted table (for batch operations)
```

## Common Flags

### Verbosity

```bash
-v, --verbose    # Show detailed error messages
```

### Watch Mode

```bash
--watch          # Monitor job until completion
```

### Notifications

```bash
--notify         # Desktop notifications (requires --watch)
```

## Configuration Priority

Options can be specified in multiple ways. Priority order:

1. **CLI arguments** (highest priority)
2. **`.voyager.toml` configuration file**
3. **Default values** (lowest priority)

Example:

```bash
# .voyager.toml sets network = "sepolia"
# This command overrides to use mainnet
voyager verify --network mainnet --class-hash 0x044... --contract-name MyToken
```

## Exit Codes

Voyager Verifier uses standard exit codes:

- **0** - Success
- **1** - General error
- **2** - Invalid arguments
- **Other** - Specific error conditions

Use in scripts:

```bash
if voyager verify --network mainnet --class-hash 0x044... --contract-name MyToken; then
  echo "Verification submitted successfully"
else
  echo "Verification submission failed"
  exit 1
fi
```

## Environment Variables

### Proxy Configuration

```bash
export HTTP_PROXY=http://proxy.example.com:8080
export HTTPS_PROXY=http://proxy.example.com:8080
```

### Logging

```bash
export RUST_LOG=debug    # Enable debug logging
export RUST_LOG=info     # Info level logging (default)
```

## Shell Completion

Generate shell completion scripts:

```bash
# Bash
voyager completions bash > /etc/bash_completion.d/voyager

# Zsh
voyager completions zsh > /usr/local/share/zsh/site-functions/_voyager

# Fish
voyager completions fish > ~/.config/fish/completions/voyager.fish
```

Note: Completion support may vary by version. Check `voyager --help` for availability.

## Next Steps

Explore detailed documentation for each command:

- **[verify command](./verify.md)** - Complete verification reference
- **[status command](./status.md)** - Status checking reference
- **[check command](./check.md)** - Check verification status reference
- **[history command](./history.md)** - History management reference

For practical examples, see the [Examples section](../examples/README.md).
