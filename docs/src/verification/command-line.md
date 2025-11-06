# Command-Line Verification

Command-line verification provides direct control over the verification process through CLI flags and arguments, ideal for automation, CI/CD pipelines, and experienced users who prefer explicit control.

## Overview

Command-line mode offers:

- **Direct control** - Specify all parameters explicitly via flags
- **Automation-friendly** - Perfect for scripts and CI/CD pipelines
- **Config file support** - Use `.voyager.toml` to reduce verbosity
- **Flexible networking** - Choose predefined networks or custom endpoints
- **Workspace support** - Handle multi-package projects with `--package`
- **Batch operations** - Verify multiple contracts from config

## Basic Syntax

### With Predefined Network

```bash
voyager verify --network <NETWORK> \
  --class-hash <HASH> \
  --contract-name <NAME> \
  [OPTIONS]
```

### With Custom Endpoint

```bash
voyager verify --url <API_URL> \
  --class-hash <HASH> \
  --contract-name <NAME> \
  [OPTIONS]
```

## Required Arguments

### Network Selection

You must specify **either** `--network` or `--url` (but not both):

#### Predefined Networks

```bash
# Mainnet (production)
voyager verify --network mainnet \
  --class-hash 0x044dc2b3... \
  --contract-name MyContract

# Sepolia (testnet)
voyager verify --network sepolia \
  --class-hash 0x044dc2b3... \
  --contract-name MyContract

# Dev network
voyager verify --network dev \
  --class-hash 0x044dc2b3... \
  --contract-name MyContract
```

**Available networks:**
- `mainnet` - Main Starknet network (API: `https://api.voyager.online/beta`)
- `sepolia` - Starknet testnet (API: `https://sepolia-api.voyager.online/beta`)
- `dev` - Development network

#### Custom Endpoints

```bash
voyager verify --url https://api.custom.com/beta \
  --class-hash 0x044dc2b3... \
  --contract-name MyContract
```

Use custom endpoints for:
- Private networks
- Custom deployments
- Testing against staging environments

### Class Hash

```bash
--class-hash <HASH>
```

The class hash of your deployed contract.

**Requirements:**
- Must be a valid hexadecimal string
- Must start with `0x`
- Case-insensitive

**Examples:**
```bash
# Full hash
--class-hash 0x044dc2b3239382230d8b1e943df23b96f52eebcac93efe6e8bde92f9a2f1da18

# Different formats (all valid)
--class-hash 0x44dc2b3...  # Will be rejected if not complete
--class-hash 0x044DC2B3...  # Case doesn't matter
```

### Contract Name

```bash
--contract-name <NAME>
```

The name of the contract to verify (must match a contract in your project).

**Examples:**
```bash
--contract-name MyToken
--contract-name ERC20Contract
--contract-name my_nft_contract
```

## Optional Arguments

### Project Path

```bash
--path <PATH>
```

Path to your Scarb project directory. Defaults to the current working directory.

**Examples:**
```bash
# Verify project in a different directory
voyager verify --network mainnet \
  --class-hash 0x044dc2b3... \
  --contract-name MyContract \
  --path /home/user/projects/my-contract

# Verify from current directory (default)
voyager verify --network mainnet \
  --class-hash 0x044dc2b3... \
  --contract-name MyContract
```

### License

```bash
--license <SPDX_ID>
```

SPDX license identifier for your contract.

**Priority:**
1. `--license` CLI flag (highest priority)
2. `license` in `.voyager.toml` config
3. `license` in `Scarb.toml` package section
4. "All Rights Reserved" (default)

**Examples:**
```bash
--license MIT
--license Apache-2.0
--license GPL-3.0
--license BSD-3-Clause
```

See [SPDX License List](https://spdx.org/licenses/) for valid identifiers.

### Package Selection

```bash
--package <PACKAGE_ID>
```

**Required for workspace projects** with multiple packages. Specifies which package to verify.

**Examples:**
```bash
# Workspace project with multiple packages
voyager verify --network mainnet \
  --class-hash 0x044dc2b3... \
  --contract-name MyContract \
  --package token

# Single package project (--package not needed)
voyager verify --network mainnet \
  --class-hash 0x044dc2b3... \
  --contract-name MyContract
```

**Alternative:** Set `workspace.default-package` in `.voyager.toml` to avoid specifying `--package` every time:

```toml
[workspace]
default-package = "token"
```

### File Inclusion Options

#### Lock File

```bash
--lock-file
```

Include `Scarb.lock` file in the verification submission.

**Use cases:**
- Ensure reproducible builds by locking dependency versions
- Required for projects with specific dependency versions
- Useful for production deployments

**Example:**
```bash
voyager verify --network mainnet \
  --class-hash 0x044dc2b3... \
  --contract-name MyContract \
  --lock-file
```

#### Test Files

```bash
--test-files
```

Include test files from the `src/` directory in verification.

**Use cases:**
- Contracts that reference test utilities
- Test helper functions used by contract code
- Shared test fixtures

**Behavior:**
- Only includes test files from `src/` directory
- Files with "test" or "tests" in their path within `src/`
- Dedicated `tests/` directories are still excluded

**Example:**
```bash
voyager verify --network mainnet \
  --class-hash 0x044dc2b3... \
  --contract-name MyContract \
  --test-files
```

**Common scenario:**
```
src/
  ├── lib.cairo
  ├── contract.cairo
  └── test_helpers.cairo  # Included with --test-files
tests/
  └── integration.cairo   # Always excluded
```

### Watch Mode

```bash
--watch
```

Poll the verification status until completion instead of just submitting and exiting.

**Behavior:**
- Automatically polls the server for status updates
- Uses exponential backoff to avoid overwhelming the API
- Displays real-time progress
- Exits when verification completes (success or failure)

**Example:**
```bash
voyager verify --network mainnet \
  --class-hash 0x044dc2b3... \
  --contract-name MyContract \
  --watch
```

**Output:**
```
✓ Verification job submitted successfully
Job ID: abc-123-def-456

⏳ Watching verification job...

Status: Pending
⏱️  Estimated time: 2-5 minutes

Status: In Progress
⏱️  Progress: Compiling sources...

Status: Completed
✅ Verification successful!
🔗 View on Voyager: https://voyager.online/contract/0x044dc2b3...
```

See [Watch Mode](./watch-mode.md) for detailed documentation.

### Desktop Notifications

```bash
--notify
```

Send desktop notifications when verification completes. **Requires `--watch`** to be enabled.

**Example:**
```bash
voyager verify --network mainnet \
  --class-hash 0x044dc2b3... \
  --contract-name MyContract \
  --watch \
  --notify
```

**Notification content:**
- Success: "✅ Contract verified: MyContract"
- Failure: "❌ Verification failed: MyContract"

See [Desktop Notifications](../advanced/notifications.md) for platform setup and troubleshooting.

### Dry Run

```bash
--dry-run
```

Preview what files would be collected and sent without actually submitting for verification.

**Use cases:**
- Debug file collection issues
- Verify correct files are being included
- Preview verification payload before submission
- Check configuration without consuming API quota

**Example:**
```bash
voyager verify --network mainnet \
  --class-hash 0x044dc2b3... \
  --contract-name MyContract \
  --dry-run
```

See [Dry Run Mode](./dry-run.md) for detailed output examples.

### Verbose Output

```bash
--verbose
# or
-v
```

Display detailed error messages and debugging information.

**Use cases:**
- Troubleshooting verification failures
- Debugging file collection issues
- Understanding API errors
- Getting full compiler output from remote server

**Example:**
```bash
voyager verify --network mainnet \
  --class-hash 0x044dc2b3... \
  --contract-name MyContract \
  --verbose
```

## Complete Examples

### Basic Verification

Simplest form with required arguments only:

```bash
voyager verify --network mainnet \
  --class-hash 0x044dc2b3239382230d8b1e943df23b96f52eebcac93efe6e8bde92f9a2f1da18 \
  --contract-name MyToken
```

### Full-Featured Verification

With all common options:

```bash
voyager verify --network mainnet \
  --class-hash 0x044dc2b3239382230d8b1e943df23b96f52eebcac93efe6e8bde92f9a2f1da18 \
  --contract-name MyToken \
  --license MIT \
  --lock-file \
  --test-files \
  --watch \
  --notify \
  --verbose
```

### Workspace Project

Verifying a package in a workspace:

```bash
voyager verify --network mainnet \
  --class-hash 0x044dc2b3239382230d8b1e943df23b96f52eebcac93efe6e8bde92f9a2f1da18 \
  --contract-name TokenContract \
  --package token \
  --watch
```

### Custom Endpoint

Using a custom API endpoint:

```bash
voyager verify --url https://api.custom.network.com/beta \
  --class-hash 0x044dc2b3239382230d8b1e943df23b96f52eebcac93efe6e8bde92f9a2f1da18 \
  --contract-name MyContract \
  --license Apache-2.0 \
  --watch
```

### Development Workflow

Quick verification during development:

```bash
voyager verify --network sepolia \
  --class-hash 0x044dc2b3... \
  --contract-name TestContract \
  --test-files \
  --watch \
  --verbose
```

### Production Deployment

Production-ready with all safeguards:

```bash
voyager verify --network mainnet \
  --class-hash 0x044dc2b3239382230d8b1e943df23b96f52eebcac93efe6e8bde92f9a2f1da18 \
  --contract-name ProductionContract \
  --license MIT \
  --lock-file \
  --watch \
  --notify
```

### CI/CD Pipeline

Non-blocking verification for automation:

```bash
voyager verify --network mainnet \
  --class-hash 0x044dc2b3239382230d8b1e943df23b96f52eebcac93efe6e8bde92f9a2f1da18 \
  --contract-name MyContract \
  --license MIT \
  --lock-file \
  --verbose
# Don't use --watch in CI to avoid blocking
```

Then check status later:

```bash
voyager status --network mainnet --job <JOB_ID> --verbose
```

## Using Configuration Files

Reduce command-line verbosity with `.voyager.toml`:

### Basic Config

```toml
[voyager]
network = "mainnet"
license = "MIT"
watch = true
lock-file = true
```

Then your command becomes:

```bash
# Before (without config)
voyager verify --network mainnet --license MIT --watch --lock-file \
  --class-hash 0x044dc2b3... --contract-name MyContract

# After (with config)
voyager verify --class-hash 0x044dc2b3... --contract-name MyContract
```

### Workspace Config

```toml
[voyager]
network = "mainnet"
license = "MIT"
watch = true

[workspace]
default-package = "token"
```

Then verify without specifying package:

```bash
voyager verify --class-hash 0x044dc2b3... --contract-name MyContract
# Uses default-package from config
```

### Override Config Values

CLI arguments always take precedence:

```toml
# .voyager.toml
[voyager]
network = "mainnet"
```

```bash
# Override network for this verification
voyager verify --network sepolia \
  --class-hash 0x044dc2b3... \
  --contract-name MyContract
```

See [Configuration File Guide](../configuration/config-file.md) for comprehensive documentation.

## Comparison with Wizard Mode

| Aspect | Command Line | Wizard (`--wizard`) |
|--------|-------------|---------------------|
| **Best for** | Experienced users, automation | First-time users, occasional use |
| **Speed** | Fast (one command) | Slower (interactive prompts) |
| **Automation** | Excellent | Not suitable |
| **Learning curve** | Requires knowing all flags | Guided, self-explanatory |
| **Config support** | Full config file integration | Limited |
| **Batch verification** | Supported | Not supported |
| **CI/CD** | Perfect | Not recommended |
| **Error prevention** | Manual validation | Built-in validation |

**When to use command-line:**
- You know exactly what you're doing
- Automating verification in scripts
- Using in CI/CD pipelines
- Verifying multiple contracts (batch mode)
- Using config files for team consistency

**When to use wizard:**
- First time using the tool
- Occasional verification (not memorized flags)
- Want guided experience with validation
- Exploring options without reading docs
- Prefer interactive prompts over flags

## Common Patterns

### Quick Verify with Defaults

Minimal command with sensible defaults:

```bash
voyager verify --network mainnet \
  --class-hash 0x044dc2b3... \
  --contract-name MyContract
```

### Verify and Wait

Submit and monitor until completion:

```bash
voyager verify --network mainnet \
  --class-hash 0x044dc2b3... \
  --contract-name MyContract \
  --watch
```

### Verify with Notifications

Get notified when done (great for long builds):

```bash
voyager verify --network mainnet \
  --class-hash 0x044dc2b3... \
  --contract-name MyContract \
  --watch \
  --notify
```

### Debug Verification

Preview files and see detailed output:

```bash
# First, dry run to check files
voyager verify --network mainnet \
  --class-hash 0x044dc2b3... \
  --contract-name MyContract \
  --dry-run

# Then verify with verbose output
voyager verify --network mainnet \
  --class-hash 0x044dc2b3... \
  --contract-name MyContract \
  --verbose \
  --watch
```

### Team Consistency

Use shared config for consistent verification:

```toml
# .voyager.toml (committed to repo)
[voyager]
network = "mainnet"
license = "MIT"
lock-file = true
watch = true
verbose = false
```

All team members use the same command:

```bash
voyager verify --class-hash 0x044dc2b3... --contract-name MyContract
```

## Error Handling

### Common Errors

#### Missing Required Arguments

```
Error: Missing required argument: --class-hash
```

**Solution:** Provide the missing argument:
```bash
voyager verify --network mainnet --class-hash 0x044dc2b3... --contract-name MyContract
```

#### Invalid Network/URL Combination

```
Error: Cannot specify both --network and --url
```

**Solution:** Use only one:
```bash
# Either network
voyager verify --network mainnet ...

# Or custom URL
voyager verify --url https://api.custom.com/beta ...
```

#### Package Required for Workspace

```
Error: Multiple packages found. Use --package to specify which one to verify.
```

**Solution:** Specify the package:
```bash
voyager verify --network mainnet \
  --class-hash 0x044dc2b3... \
  --contract-name MyContract \
  --package token
```

Or set default in config:
```toml
[workspace]
default-package = "token"
```

#### Invalid Class Hash

```
Error: Invalid class hash format. Must be hexadecimal starting with 0x
```

**Solution:** Ensure proper format:
```bash
# Correct
--class-hash 0x044dc2b3239382230d8b1e943df23b96f52eebcac93efe6e8bde92f9a2f1da18

# Incorrect
--class-hash 044dc2b3...  # Missing 0x prefix
--class-hash 0xZZZ...     # Invalid hex characters
```

### Troubleshooting Tips

1. **Use `--dry-run` first** to preview file collection
2. **Add `--verbose`** to see detailed error messages
3. **Check local build** with `scarb --release build`
4. **Verify network connectivity** to API endpoints
5. **Review history** with `voyager history list` to check past attempts

See [Troubleshooting Guide](../troubleshooting/README.md) for comprehensive debugging help.

## Next Steps

- **[Watch Mode](./watch-mode.md)** - Learn about real-time verification monitoring
- **[Dry Run Mode](./dry-run.md)** - Preview verification before submission
- **[Batch Verification](./batch-verification.md)** - Verify multiple contracts at once
- **[Configuration File](../configuration/config-file.md)** - Reduce command verbosity
- **[CLI Options Reference](../configuration/cli-options.md)** - Complete flag documentation
