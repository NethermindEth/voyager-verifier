# CLI Options Reference

Complete reference documentation for all command-line flags and options supported by Voyager Verifier.

## Overview

This reference covers all CLI options for the `verify` command. For other commands (`status`, `history`), see [Command Reference](../commands/README.md).

## Command Structure

```bash
voyager verify [NETWORK_OPTION] [REQUIRED_OPTIONS] [OPTIONAL_FLAGS]
```

## Network Options

### `--network <NETWORK>`

**Type:** String
**Values:** `mainnet`, `sepolia`, `dev`
**Required:** Yes (unless `--url` is used)
**Conflicts with:** `--url`
**Config equivalent:** `voyager.network`

Specify which Starknet network to verify on.

**Values:**
- `mainnet` - Main Starknet network (API: `https://api.voyager.online/beta`)
- `sepolia` - Starknet testnet (API: `https://sepolia-api.voyager.online/beta`)
- `dev` - Development network

**Examples:**
```bash
# Mainnet
voyager verify --network mainnet --class-hash 0x123... --contract-name MyContract

# Sepolia testnet
voyager verify --network sepolia --class-hash 0x123... --contract-name TestContract

# Dev network
voyager verify --network dev --class-hash 0x123... --contract-name DevContract
```

### `--url <URL>`

**Type:** String (URL)
**Required:** Yes (unless `--network` is used)
**Conflicts with:** `--network`
**Config equivalent:** `voyager.url`

Specify a custom API endpoint URL.

**Format:** Must be a valid HTTP/HTTPS URL

**Use cases:**
- Private Starknet networks
- Custom deployments
- Staging environments
- Testing against development servers

**Examples:**
```bash
# Custom endpoint
voyager verify --url https://api.custom.com/beta \
  --class-hash 0x123... \
  --contract-name MyContract

# Local development server
voyager verify --url http://localhost:8080 \
  --class-hash 0x123... \
  --contract-name LocalContract
```

**Note:** Cannot use both `--network` and `--url`. Choose one.

## Required Options

### `--class-hash <HASH>`

**Type:** Hexadecimal string
**Required:** Yes (unless using batch mode)
**Config equivalent:** N/A (specified per contract)

The class hash of your deployed Starknet contract.

**Format:**
- Must start with `0x`
- Must be valid hexadecimal (0-9, a-f, A-F)
- Case-insensitive
- Full 64-character hash recommended

**Examples:**
```bash
# Full hash
--class-hash 0x044dc2b3239382230d8b1e943df23b96f52eebcac93efe6e8bde92f9a2f1da18

# Case doesn't matter
--class-hash 0x044DC2B3239382230D8B1E943DF23B96F52EEBCAC93EFE6E8BDE92F9A2F1DA18
```

**Common errors:**
```bash
# Missing 0x prefix - INVALID
--class-hash 044dc2b3...

# Invalid characters - INVALID
--class-hash 0xZZZ123...

# Truncated hash - may be rejected
--class-hash 0x044dc2b3...
```

### `--contract-name <NAME>`

**Type:** String
**Required:** Yes (unless using batch mode)
**Config equivalent:** N/A (specified per contract)

The name of the contract to verify. Must match a contract defined in your Scarb project.

**Format:**
- Alphanumeric and underscores allowed
- No spaces
- Case-sensitive

**Examples:**
```bash
--contract-name MyToken
--contract-name ERC20Contract
--contract-name my_nft_contract
--contract-name GameEngine
```

## Project Options

### `--path <PATH>`

**Type:** File system path
**Required:** No
**Default:** Current working directory
**Config equivalent:** N/A

Path to your Scarb project directory.

**Format:** Absolute or relative path to directory containing `Scarb.toml`

**Examples:**
```bash
# Absolute path
voyager verify --network mainnet \
  --class-hash 0x123... \
  --contract-name MyContract \
  --path /home/user/projects/my-contract

# Relative path
voyager verify --network mainnet \
  --class-hash 0x123... \
  --contract-name MyContract \
  --path ../my-contract

# Current directory (default)
voyager verify --network mainnet \
  --class-hash 0x123... \
  --contract-name MyContract
```

### `--package <PACKAGE>`

**Type:** String
**Required:** Yes for multi-package workspaces
**Default:** None (or `workspace.default-package` from config)
**Config equivalent:** `workspace.default-package`

Specify which package to verify in workspace projects.

**Use cases:**
- Required when workspace has multiple packages
- Optional when workspace has only one package
- Not needed for single-package projects

**Examples:**
```bash
# Workspace with multiple packages
voyager verify --network mainnet \
  --class-hash 0x123... \
  --contract-name TokenContract \
  --package token

# Override default-package from config
voyager verify --network mainnet \
  --class-hash 0x123... \
  --contract-name NFTContract \
  --package nft
```

**Error if missing:**
```
Error: Multiple packages found. Use --package to specify which one to verify.
Available packages: token, nft, marketplace
```

### `--project-type <TYPE>`

**Type:** String
**Values:** `scarb`, `dojo`, `auto`
**Required:** No
**Default:** `auto`
**Config equivalent:** `voyager.project-type`

Specify the project build tool type.

**Values:**
- `auto` - Auto-detect from project structure (default)
- `scarb` - Force Scarb project detection
- `dojo` - Force Dojo project detection

**Examples:**
```bash
# Auto-detect (default)
voyager verify --network mainnet --class-hash 0x123... --contract-name MyContract

# Force Scarb
voyager verify --network mainnet \
  --class-hash 0x123... \
  --contract-name MyContract \
  --project-type scarb

# Force Dojo
voyager verify --network mainnet \
  --class-hash 0x123... \
  --contract-name GameWorld \
  --project-type dojo
```

## License Options

### `--license <SPDX_ID>`

**Type:** String (SPDX identifier)
**Required:** No
**Default:** From `.voyager.toml`, then `Scarb.toml`, then "All Rights Reserved"
**Config equivalent:** `voyager.license`

SPDX license identifier for your contract.

**Priority order:**
1. `--license` CLI flag
2. `license` in `.voyager.toml`
3. `license` in `Scarb.toml`
4. "All Rights Reserved" (default)

**Common licenses:**
- `MIT`
- `Apache-2.0`
- `GPL-3.0`
- `BSD-3-Clause`
- `AGPL-3.0`
- `ISC`
- `MPL-2.0`

**Examples:**
```bash
--license MIT
--license Apache-2.0
--license GPL-3.0
--license "BSD-3-Clause"
```

See [SPDX License List](https://spdx.org/licenses/) for all valid identifiers.

## File Inclusion Options

### `--lock-file`

**Type:** Boolean flag
**Required:** No
**Default:** `false`
**Config equivalent:** `voyager.lock-file`

Include `Scarb.lock` file in verification submission.

**Use cases:**
- Ensure reproducible builds
- Lock dependency versions
- Production deployments
- Strict version requirements

**Examples:**
```bash
# Include lock file
voyager verify --network mainnet \
  --class-hash 0x123... \
  --contract-name MyContract \
  --lock-file
```

**What it does:**
- Includes `Scarb.lock` in submitted files
- Ensures remote build uses exact same dependency versions
- Prevents compilation differences from dependency updates

### `--test-files`

**Type:** Boolean flag
**Required:** No
**Default:** `false`
**Config equivalent:** `voyager.test-files`

Include test files from `src/` directory in verification.

**Behavior:**
- Includes files with "test" or "tests" in their path within `src/`
- Dedicated `tests/` directories still excluded
- Useful when contract imports test utilities

**Examples:**
```bash
# Include test files
voyager verify --network mainnet \
  --class-hash 0x123... \
  --contract-name MyContract \
  --test-files
```

**File inclusion:**
```
src/
  ├── contract.cairo      # ✓ Always included
  ├── utils.cairo         # ✓ Always included
  ├── test_helpers.cairo  # ✓ Included with --test-files
  └── tests.cairo         # ✓ Included with --test-files
tests/
  └── integration.cairo   # ✗ Always excluded
```

**Common error without this flag:**
```
error[E0005]: Module file not found. Expected path: /tmp/.../src/test_helpers.cairo
```

**Solution:** Add `--test-files` flag

## Behavioral Options

### `--watch`

**Type:** Boolean flag
**Required:** No
**Default:** `false`
**Config equivalent:** `voyager.watch`

Poll verification status until completion instead of just submitting.

**Behavior:**
- Submits verification
- Polls status with exponential backoff
- Shows real-time progress updates
- Exits when complete (success or failure)

**Examples:**
```bash
# Watch verification progress
voyager verify --network mainnet \
  --class-hash 0x123... \
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
```

**Without `--watch`:**
```
✓ Verification job submitted successfully
Job ID: abc-123-def-456

Use 'voyager status --network mainnet --job abc-123-def-456' to check status
```

See [Watch Mode](../verification/watch-mode.md) for detailed documentation.

### `--notify`

**Type:** Boolean flag
**Required:** No
**Default:** `false`
**Requires:** `--watch`
**Config equivalent:** `voyager.notify`

Send desktop notifications when verification completes.

**Requirements:**
- Must use with `--watch`
- Platform-specific notification system must be available

**Examples:**
```bash
# Enable notifications
voyager verify --network mainnet \
  --class-hash 0x123... \
  --contract-name MyContract \
  --watch \
  --notify
```

**Notification messages:**
- Success: "✅ Contract verified: MyContract"
- Failure: "❌ Verification failed: MyContract"

**Platform support:**
- Linux: libnotify (notify-send)
- macOS: native notification center
- Windows: native notification system

See [Desktop Notifications](../advanced/notifications.md) for platform setup.

### `--verbose` / `-v`

**Type:** Boolean flag
**Required:** No
**Default:** `false`
**Config equivalent:** `voyager.verbose`

Show detailed error messages and debugging information.

**Displays:**
- Full compiler output from remote server
- Detailed API errors
- Debug information
- Stack traces (when applicable)

**Examples:**
```bash
# Long form
voyager verify --network mainnet \
  --class-hash 0x123... \
  --contract-name MyContract \
  --verbose

# Short form
voyager verify --network mainnet \
  --class-hash 0x123... \
  --contract-name MyContract \
  -v
```

**Use cases:**
- Debugging verification failures
- Understanding compilation errors
- Troubleshooting file collection issues
- CI/CD logging

**Example output:**
```
Error: [E004] Compilation failed

Without --verbose:
  Compilation failed: `scarb` command exited with error

With --verbose:
  Compilation failed: `scarb` command exited with error

  Full compiler output:
  error[E0005]: Module file not found. Expected path: /tmp/targets/.../src/tests.cairo
   --> lib.cairo:3:1
    |
  3 | pub mod tests;
    | ^^^^^^^^^^^^^^

  Solution: Use --test-files flag to include test files in verification
```

### `--dry-run`

**Type:** Boolean flag
**Required:** No
**Default:** `false`
**Config equivalent:** N/A

Preview what files would be collected without actually submitting.

**Behavior:**
- Collects files as normal
- Displays configuration and file list
- Does NOT submit to API
- Does NOT consume API quota

**Examples:**
```bash
# Basic dry run
voyager verify --network mainnet \
  --class-hash 0x123... \
  --contract-name MyContract \
  --dry-run

# Dry run with verbose output
voyager verify --network mainnet \
  --class-hash 0x123... \
  --contract-name MyContract \
  --dry-run \
  --verbose
```

**Output:**
```
════════════════════════════════════════════════════════
Dry Run: Verification Preview
════════════════════════════════════════════════════════

Configuration:
  Network:      mainnet
  Class Hash:   0x044dc2b3...
  Contract:     MyContract
  License:      MIT

Files to be submitted (5 files):
  ├── Scarb.toml (245 bytes)
  ├── src/lib.cairo (1,234 bytes)
  ├── src/contract.cairo (5,678 bytes)
  ├── src/utils.cairo (890 bytes)
  └── src/events.cairo (456 bytes)

Total size: 8,503 bytes (8.3 KB)
```

See [Dry Run Mode](../verification/dry-run.md) for detailed documentation.

### `--wizard`

**Type:** Boolean flag
**Required:** No
**Default:** `false`
**Conflicts with:** Most other options

Launch interactive wizard mode for guided verification.

**Behavior:**
- Prompts step-by-step for all required information
- Validates input before proceeding
- Auto-detects licenses from `Scarb.toml`
- Shows confirmation before submission

**Examples:**
```bash
# Start wizard
voyager verify --wizard
```

**Cannot combine with:**
- `--class-hash`
- `--contract-name`
- `--package`
- Most other flags (wizard asks for these)

**Can combine with:**
- `--path` (to specify project directory)
- `--network` (pre-select network)

See [Interactive Wizard](../verification/interactive-wizard.md) for detailed documentation.

## Batch Verification Options

### `--fail-fast`

**Type:** Boolean flag
**Required:** No
**Default:** `false` (continue all)
**Config equivalent:** N/A
**Only for:** Batch verification mode

Stop batch verification on first failure.

**Behavior:**
- **Without flag:** Continues verifying remaining contracts after failure
- **With flag:** Stops immediately when any contract fails

**Examples:**
```bash
# Stop on first failure
voyager verify --fail-fast

# Continue all (default)
voyager verify
```

**Use cases:**
- Development: Stop on first error to fix issues quickly
- Production: Continue all to see complete status

### `--batch-delay <SECONDS>`

**Type:** Integer (seconds)
**Required:** No
**Default:** `0` (no delay)
**Config equivalent:** N/A
**Only for:** Batch verification mode

Add delay between contract submissions for rate limiting.

**Format:** Number of seconds to wait

**Examples:**
```bash
# 5-second delay between submissions
voyager verify --batch-delay 5

# 10-second delay
voyager verify --batch-delay 10
```

**Use cases:**
- Rate limit compliance
- Avoiding API throttling
- Spreading load over time

**Output:**
```
[1/3] Verifying: MyToken
  ✓ Submitted - Job ID: abc-123-def

  ⏳ Waiting 5 seconds before next submission...

[2/3] Verifying: MyNFT
  ✓ Submitted - Job ID: ghi-456-jkl
```

## Flag Combinations

### Common Combinations

#### 1. Quick Submit (No Watching)
```bash
voyager verify --network mainnet \
  --class-hash 0x123... \
  --contract-name MyContract
```

#### 2. Watch with Notifications
```bash
voyager verify --network mainnet \
  --class-hash 0x123... \
  --contract-name MyContract \
  --watch \
  --notify
```

#### 3. Full Production Build
```bash
voyager verify --network mainnet \
  --class-hash 0x123... \
  --contract-name MyContract \
  --license MIT \
  --lock-file \
  --watch \
  --notify
```

#### 4. Debug Mode
```bash
voyager verify --network sepolia \
  --class-hash 0x123... \
  --contract-name MyContract \
  --test-files \
  --verbose \
  --watch
```

#### 5. CI/CD Mode
```bash
voyager verify --network mainnet \
  --class-hash 0x123... \
  --contract-name MyContract \
  --lock-file \
  --verbose
# No --watch to avoid blocking
```

#### 6. Dry Run Testing
```bash
voyager verify --network mainnet \
  --class-hash 0x123... \
  --contract-name MyContract \
  --test-files \
  --lock-file \
  --dry-run \
  --verbose
```

### Invalid Combinations

#### Cannot Use Both Network Options
```bash
# INVALID - cannot use both
voyager verify --network mainnet --url https://custom.com \
  --class-hash 0x123... \
  --contract-name MyContract

Error: Cannot specify both --network and --url
```

#### Notify Requires Watch
```bash
# INVALID - notify requires watch
voyager verify --network mainnet \
  --class-hash 0x123... \
  --contract-name MyContract \
  --notify

Error: --notify requires --watch to be enabled
```

#### Wizard Conflicts with Manual Options
```bash
# INVALID - wizard doesn't accept these
voyager verify --wizard --class-hash 0x123...

Error: Cannot use --class-hash with --wizard mode
```

#### Batch Options Outside Batch Mode
```bash
# INVALID - batch options require [[contracts]] in config
voyager verify --network mainnet \
  --class-hash 0x123... \
  --contract-name MyContract \
  --fail-fast

Error: --fail-fast only available in batch mode
```

## Config File vs CLI Options

### Priority Order

1. **CLI flags** (highest)
2. **Config file** (`.voyager.toml`)
3. **Scarb.toml** (license only)
4. **Defaults** (lowest)

### Example

**Config file (`.voyager.toml`):**
```toml
[voyager]
network = "mainnet"
license = "MIT"
watch = true
lock-file = true
```

**Command:**
```bash
voyager verify --network sepolia \
  --class-hash 0x123... \
  --contract-name MyContract \
  --verbose
```

**Effective settings:**
- `network = sepolia` (from CLI)
- `license = MIT` (from config)
- `watch = true` (from config)
- `lock-file = true` (from config)
- `verbose = true` (from CLI)

## Getting Help

### Show All Options

```bash
voyager verify --help
```

### Show Version

```bash
voyager --version
```

### Command-Specific Help

```bash
voyager status --help
voyager history --help
```

## Quick Reference Table

| Flag | Type | Required | Default | Config Equivalent |
|------|------|----------|---------|-------------------|
| `--network` | String | Yes* | None | `voyager.network` |
| `--url` | String | Yes* | None | `voyager.url` |
| `--class-hash` | String | Yes** | None | N/A |
| `--contract-name` | String | Yes** | None | N/A |
| `--path` | String | No | `.` | N/A |
| `--package` | String | Sometimes | None | `workspace.default-package` |
| `--project-type` | String | No | `auto` | `voyager.project-type` |
| `--license` | String | No | See docs | `voyager.license` |
| `--lock-file` | Flag | No | `false` | `voyager.lock-file` |
| `--test-files` | Flag | No | `false` | `voyager.test-files` |
| `--watch` | Flag | No | `false` | `voyager.watch` |
| `--notify` | Flag | No | `false` | `voyager.notify` |
| `--verbose`, `-v` | Flag | No | `false` | `voyager.verbose` |
| `--dry-run` | Flag | No | `false` | N/A |
| `--wizard` | Flag | No | `false` | N/A |
| `--fail-fast` | Flag | No | `false` | N/A |
| `--batch-delay` | Integer | No | `0` | N/A |

\* Either `--network` or `--url` required
\** Not required in batch mode or wizard mode

## Next Steps

- **[Configuration File Guide](./config-file.md)** - Reduce CLI verbosity with config
- **[Command-Line Verification](../verification/command-line.md)** - Practical usage examples
- **[Interactive Wizard](../verification/interactive-wizard.md)** - Guided verification mode
- **[Batch Verification](../verification/batch-verification.md)** - Verify multiple contracts
