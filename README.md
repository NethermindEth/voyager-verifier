# voyager-verifier

Client for the [Voyager Starknet block explorer](https://voyager.online), that allows you to verify your starknet classes.

## Installation

### With asdf (Recommended)

First, install [asdf](https://asdf-vm.com/guide/getting-started.html) if you haven't already.

```bash
asdf plugin add voyager https://github.com/NethermindEth/asdf-voyager-verifier.git

asdf install voyager latest
```

### With Cargo

Alternatively, you can install directly from source:

```bash
cargo install voyager-verifier
```

## Quickstart guide

### Scarb

Contract verifier works with [Scarb](https://docs.swmansion.com/scarb) based projects. The tool assumes that `scarb` command is available in the environment and project is building properly by executing `scarb build`.

#### Supported versions

Client is version agnostic, the Scarb/Cairo versions support is determined by the server availability. As of writing this (2025) Cairo up to 2.11.4 is supported with newer versions being added with a slight lag after release.

### Project configuration

**⚠️ Important**: Every compiler configuration used for deployment must be placed under `[profile.release]` since the remote compiler will run `scarb --release build`. This includes any custom compiler settings, optimizations, or dependencies that are required for your contract to build correctly in the verification environment.

**Note**: At the moment, Sepolia-only verification is not available. However, classes verified on mainnet will appear verified on Sepolia as well.

For license information, you can specify it in your Scarb.toml:

```toml
[package]
name = "my_project"
version = "0.1.0"
license = "MIT"  # Optional: Define license here using a valid SPDX identifier

[dependencies]
starknet = ">=2.11.2"

[[target.starknet-contract]]
sierra = true

[profile.release.cairo]
# Add any compiler configurations needed for deployment here
# For example:
# sierra-replace-ids = false
# inlining-strategy = "avoid"
```

Alternatively, you can provide the license via the `--license` CLI argument when verifying your contract.

**Important**: For workspace projects with multiple packages, you must use the `--package` argument to specify which package to verify.

### Verify your contract

#### Interactive Wizard Mode (Recommended for First-Time Users)

For a guided, step-by-step verification experience, use the interactive wizard:

```bash
voyager verify --wizard
```

The wizard will prompt you for all required information:
- Network selection (Mainnet/Sepolia/Dev/Custom)
- Class hash
- Package selection (for workspace projects)
- Contract name
- License (with auto-detection from Scarb.toml)
- Optional features (lock file, test files, watch mode, verbose output)

This is the easiest way to verify your contract if you're new to the tool or don't use it frequently.

#### Batch Verification Mode

For verifying multiple contracts at once, define them in `.voyager.toml`:

```toml
[voyager]
network = "mainnet"
license = "MIT"

[[contracts]]
class-hash = "0x044dc2b3..."
contract-name = "MyToken"

[[contracts]]
class-hash = "0x055dc2b3..."
contract-name = "MyNFT"
```

Then simply run:

```bash
voyager verify
```

See the [Batch Verification](#batch-verification) section for detailed documentation.

#### Command-Line Mode

Once you have the verifier installed, execute:

**Using predefined networks:**

```bash
voyager verify --network mainnet \
    --class-hash <YOUR_CONTRACT_CLASS_HASH> \
    --contract-name <YOUR_CONTRACT_NAME> \
    --path <PATH_TO_YOUR_SCARB_PROJECT> \ # if you are running outside project root
    --license <SPDX_LICENSE_ID> # if not provided in Scarb.toml
    --lock-file \ # optional: include Scarb.lock file in verification
    --test-files # optional: include test files from src/ directory in verification
```

**Using custom API endpoint:**

```bash
voyager verify --url https://api.custom.com/beta \
    --class-hash <YOUR_CONTRACT_CLASS_HASH> \
    --contract-name <YOUR_CONTRACT_NAME> \
    --path <PATH_TO_YOUR_SCARB_PROJECT> \ # if you are running outside project root
    --license <SPDX_LICENSE_ID> # if not provided in Scarb.toml
    --lock-file \ # optional: include Scarb.lock file in verification
    --test-files # optional: include test files from src/ directory in verification
```

For workspace projects (multiple packages), you'll need to specify the package:

```bash
# With predefined network
voyager verify --network mainnet \
  --class-hash <YOUR_CONTRACT_CLASS_HASH> \
  --contract-name <YOUR_CONTRACT_NAME> \
  --package <PACKAGE_ID>

# With custom API endpoint
voyager verify --url https://api.custom.com/beta \
  --class-hash <YOUR_CONTRACT_CLASS_HASH> \
  --contract-name <YOUR_CONTRACT_NAME> \
  --package <PACKAGE_ID>
```

When successful you'll be given verification job id, which you can pass to:

```bash
# With predefined network
voyager status --network mainnet --job <JOB_ID>

# With custom API endpoint
voyager status --url https://api.custom.com/beta --job <JOB_ID>
```

to check the verification status. Afterwards visit [Voyager website](https://sepolia.voyager.online/) and search for your class hash to see the *verified* badge.

## Configuration File

### Overview

To reduce command-line verbosity and enable shareable team configurations, you can create a `.voyager.toml` configuration file in your project root. This allows you to set default values for common verification options.

**Priority:** CLI arguments > Config file > Default values

### Creating a Configuration File

Create a `.voyager.toml` file in your project directory:

```toml
[voyager]
network = "mainnet"
license = "MIT"
watch = true
test-files = false
lock-file = true
verbose = false

[workspace]
default-package = "my_contract"
```

An example configuration file is provided at `.voyager.toml.example` in this repository.

### Configuration File Location

The verifier searches for `.voyager.toml` in:
1. Current working directory
2. Parent directories (walking up until a config file is found)

### Available Configuration Options

#### `[voyager]` Section

- **`network`** - Network to verify on (`mainnet`, `sepolia`, `dev`)
  - Overridden by: `--network`

- **`license`** - SPDX license identifier (e.g., `MIT`, `Apache-2.0`)
  - Overridden by: `--license`
  - Falls back to license in `Scarb.toml` if not specified

- **`watch`** - Wait indefinitely for verification result (boolean)
  - Overridden by: `--watch`
  - Default: `false`

- **`test-files`** - Include test files from src/ directory (boolean)
  - Overridden by: `--test-files`
  - Default: `false`

- **`lock-file`** - Include Scarb.lock file (boolean)
  - Overridden by: `--lock-file`
  - Default: `false`

- **`verbose`** - Show detailed error messages (boolean)
  - Overridden by: `--verbose` or `-v`
  - Default: `false`

- **`notify`** - Send desktop notifications when verification completes (boolean)
  - Overridden by: `--notify`
  - Default: `false`
  - Requires: `watch = true`
  - Note: Only works when watch mode is enabled

- **`url`** - Custom API endpoint URL (string)
  - Overridden by: `--url`
  - Alternative to using `--network`

- **`project-type`** - Project type (`scarb`, `dojo`, `auto`)
  - Overridden by: `--project-type`
  - Default: `auto`

#### `[workspace]` Section

- **`default-package`** - Default package for verification in workspace projects
  - Overridden by: `--package`

### Example Configurations

#### Production Deployment

```toml
[voyager]
network = "mainnet"
license = "Apache-2.0"
watch = true
test-files = false
lock-file = true
verbose = false
```

#### Development/Testing

```toml
[voyager]
network = "sepolia"
license = "MIT"
watch = true
test-files = true
lock-file = true
verbose = true
```

#### CI/CD

```toml
[voyager]
network = "mainnet"
watch = false  # Don't block CI pipeline
test-files = false
lock-file = true
verbose = true  # Get detailed logs
```

#### Workspace Project

```toml
[voyager]
network = "mainnet"
license = "MIT"
watch = true

[workspace]
default-package = "my_contract"  # No need to specify --package every time
```

### Benefits

- **Reduce command-line verbosity** - No need to repeatedly specify the same options
- **Shareable configurations** - Commit `.voyager.toml` to share settings with your team
- **Per-project settings** - Different projects can have different verification defaults
- **Environment-specific configs** - Use different configs for dev/staging/production

### Usage with Config File

With a config file in place:

```toml
# .voyager.toml
[voyager]
network = "mainnet"
license = "MIT"
watch = true
lock-file = true
```

Your verification commands become much simpler:

```bash
# Before (without config file)
voyager verify --network mainnet --license MIT --watch --lock-file \
  --class-hash 0x044dc2b3... --contract-name MyContract

# After (with config file)
voyager verify --class-hash 0x044dc2b3... --contract-name MyContract
```

CLI arguments still override config values when needed:

```bash
# Use sepolia network instead of mainnet (from config)
voyager verify --network sepolia --class-hash 0x044dc2b3... --contract-name MyContract
```

## Batch Verification

### Overview

Batch verification allows you to verify multiple contracts in a single command by defining them in your `.voyager.toml` configuration file. This is particularly useful for:
- Workspace projects with multiple contracts
- Multi-contract deployments
- Verifying entire protocol suites at once

### Setting Up Batch Verification

Add a `[[contracts]]` array to your `.voyager.toml` file:

```toml
[voyager]
network = "mainnet"
license = "MIT"
watch = true

# Define multiple contracts to verify
[[contracts]]
class-hash = "0x044dc2b3239382230d8b1e943df23b96f52eebcac93efe6e8bde92f9a2f1da18"
contract-name = "MyToken"
package = "token"  # Optional - uses workspace.default-package if not specified

[[contracts]]
class-hash = "0x055dc2b3239382230d8b1e943df23b96f52eebcac93efe6e8bde92f9a2f1da19"
contract-name = "MyNFT"
package = "nft"

[[contracts]]
class-hash = "0x066dc2b3239382230d8b1e943df23b96f52eebcac93efe6e8bde92f9a2f1da20"
contract-name = "MyMarketplace"
# package omitted - will use workspace.default-package or auto-detect
```

### Running Batch Verification

Once contracts are defined in your config file, simply run:

```bash
voyager verify
```

The tool automatically detects batch mode when the `[[contracts]]` array is present and verifies all contracts sequentially.

### Batch Verification Options

Control batch behavior with additional flags:

```bash
# Wait for all verifications to complete
voyager verify --watch

# Stop on first failure (default: continue all)
voyager verify --fail-fast

# Add delay between submissions (rate limiting)
voyager verify --batch-delay 10

# Combine options
voyager verify --watch --batch-delay 5 --verbose
```

### Available Flags

- `--watch` - Monitor all verification jobs until completion
- `--fail-fast` - Stop batch on first failure (default: continue with remaining contracts)
- `--batch-delay <SECONDS>` - Add delay between submissions for rate limiting
- `--verbose` - Show detailed error messages for failed verifications

### Example Output

```
[1/3] Verifying: MyToken
  ✓ Submitted - Job ID: abc-123-def

[2/3] Verifying: MyNFT
  ⏳ Waiting 5 seconds before next submission...
  ✓ Submitted - Job ID: ghi-456-jkl

[3/3] Verifying: MyMarketplace
  ✓ Submitted - Job ID: mno-789-pqr

════════════════════════════════════════════════════════
Batch Verification Summary
════════════════════════════════════════════════════════
Total contracts:  3
Submitted:        3
Succeeded:        0
Failed:           0
Pending:          3
════════════════════════════════════════════════════════

Contract Details:
  ⏳ Submitted MyToken (Job: abc-123-def)
  ⏳ Submitted MyNFT (Job: ghi-456-jkl)
  ⏳ Submitted MyMarketplace (Job: mno-789-pqr)
```

With `--watch` enabled, the tool monitors all jobs and displays live updates:

```
⏳ Watching 3 verification job(s)...

  ✓ 2 Succeeded | ⏳ 1 Pending | ✗ 0 Failed

=== Final Summary ===
════════════════════════════════════════════════════════
Batch Verification Summary
════════════════════════════════════════════════════════
Total contracts:  3
Submitted:        3
Succeeded:        3
Failed:           0
Pending:          0
════════════════════════════════════════════════════════

Contract Details:
  ✓ Success MyToken (Job: abc-123-def)
  ✓ Success MyNFT (Job: ghi-456-jkl)
  ✓ Success MyMarketplace (Job: mno-789-pqr)
```

### Important Notes

- **Auto-detection**: Batch mode is automatically enabled when `[[contracts]]` array exists in config
- **Incompatible flags**: Cannot use `--class-hash`, `--contract-name`, or `--wizard` with batch mode
- **Shared settings**: All contracts in a batch use the same `[voyager]` settings (network, license, etc.)
- **Package resolution**: If `package` is omitted, the tool uses `workspace.default-package` or auto-detects
- **Error handling**: By default, continues with remaining contracts if one fails (use `--fail-fast` to stop)
- **History tracking**: All batch verifications are tracked in the history database

### Use Cases

#### Multi-Contract Workspace

```toml
[voyager]
network = "mainnet"
license = "MIT"
watch = true

[workspace]
default-package = "contracts"

[[contracts]]
class-hash = "0x123..."
contract-name = "Token"

[[contracts]]
class-hash = "0x456..."
contract-name = "NFT"

[[contracts]]
class-hash = "0x789..."
contract-name = "Marketplace"
```

#### Protocol Suite Deployment

```toml
[voyager]
network = "mainnet"
license = "Apache-2.0"
watch = true
lock-file = true

[[contracts]]
class-hash = "0xabc..."
contract-name = "CoreProtocol"
package = "core"

[[contracts]]
class-hash = "0xdef..."
contract-name = "GovernanceModule"
package = "governance"

[[contracts]]
class-hash = "0x012..."
contract-name = "TreasuryModule"
package = "treasury"
```

#### Rate-Limited Batch

For deployments requiring rate limiting:

```bash
# Submit with 10-second delay between contracts
voyager verify --batch-delay 10 --watch
```

## Verification History

### Overview

The verifier automatically tracks all verification jobs in a local database (`~/.voyager/history.db`), allowing you to:
- View past verifications across sessions
- Re-check pending jobs
- Filter by status, network, or date
- Generate verification statistics
- Clean old records

No additional setup is required - the history database is created automatically on first use.

### Viewing Verification History

List all recent verifications:

```bash
voyager history list
```

Filter by status:

```bash
voyager history list --status success
voyager history list --status pending
```

Filter by network:

```bash
voyager history list --network mainnet
voyager history list --network sepolia
```

Limit results:

```bash
voyager history list --limit 10
```

### Checking Job Status from History

View detailed information about a specific job:

```bash
voyager history status --job <JOB_ID>
```

Refresh status from the API and update the database:

```bash
voyager history status --job <JOB_ID> --network mainnet --refresh
```

### Re-checking Pending Jobs

Automatically re-check all pending verifications and update their status:

```bash
voyager history recheck --network mainnet
```

This is useful for checking on multiple in-progress verifications at once.

### Cleaning Old Records

Delete records older than a specified number of days:

```bash
voyager history clean --older-than 30
```

Delete all history (with confirmation):

```bash
voyager history clean --all
```

### Viewing Statistics

Get an overview of your verification success rates:

```bash
voyager history stats
```

Example output:
```
Verification History Statistics
================================

Total verifications: 47
Successful: 41 (87%)
Failed: 4 (9%)
Pending: 2 (4%)
```

## Desktop Notifications

### Overview

When using the `--watch` flag to wait for verification completion, you can optionally enable desktop notifications to be alerted when verification finishes. This is useful when running long verifications in the background.

### Enabling Notifications

Add the `--notify` flag along with `--watch`:

```bash
voyager verify --network mainnet \
  --class-hash 0x044dc2b3... \
  --contract-name MyContract \
  --watch \
  --notify
```

### Features

- **Cross-platform support**: Works on Linux, macOS, and Windows
- **Automatic status detection**: Shows success (✅) or failure (❌) in notification
- **Non-intrusive**: Notifications only appear on completion
- **Optional**: Works without notifications if the feature is disabled

### Disabling Notifications

Notifications are an optional feature. To build without notification support:

```bash
cargo build --release --no-default-features
```

### Example Workflow

```bash
# Start a verification with notifications
voyager verify --network mainnet \
  --class-hash 0x123... \
  --contract-name MyContract \
  --watch \
  --notify

# Continue working on other tasks
# You'll receive a desktop notification when verification completes

# Later, check your verification history
voyager history list --limit 5
```

## Detailed information

### Verification

`voyager` provides three main subcommands: `verify`, `status`, and `history`. For `verify` and `status` commands the user needs to specify either:

1. **Predefined network** via the `--network` argument:
   - `mainnet` - main starknet network (default API endpoint: <https://api.voyager.online/beta>)
   - `sepolia` - test network (default API endpoint: <https://sepolia-api.voyager.online/beta>)

2. **Custom API endpoint** via the `--url` argument:
   - `--url <URL>` - specify custom API endpoint URL (e.g., `https://api.custom.com/beta`)

Either `--network` or `--url` must be provided, but not both.

#### Verification process

In order to verify a contract, you can either use the interactive wizard (`--wizard`) or provide arguments directly via the command line:

- `--wizard`, run interactive verification wizard (recommended for first-time users)
  - Prompts you step-by-step for all required information
  - Auto-detects licenses from Scarb.toml
  - Provides helpful explanations for each option
- `--class-hash`, class hash of the declared contract
- `--contract-name`, name of the contract to verify
- `--path`, path to directory containing scarb project (If omitted it will use current working directory)
- `--dry-run`, perform dry run to preview what files would be collected and submitted without actually sending them for verification
- `--license`, SPDX license identifier (optional, will use license from Scarb.toml if defined there, otherwise defaults to "All Rights Reserved")
  - The license should be a valid [SPDX license identifier](https://spdx.org/licenses/) such as MIT, Apache-2.0, etc.
- `--lock-file`, include Scarb.lock file in verification submission (optional, defaults to false)
  - When enabled, the tool will include the Scarb.lock file (if it exists) in the files sent to the remote API for verification
  - This can be useful for ensuring reproducible builds by locking dependency versions
- `--test-files`, include test files from src/ directory in verification submission (optional, defaults to false)
  - When enabled, the tool will include test files (files with "test" or "tests" in their path) that are located within the src/ directory
  - This can be useful when your contract depends on test utilities or helper functions for verification
  - Only affects files within the src/ directory; test files in dedicated test directories are still excluded
- `--watch`, wait indefinitely for verification result (optional)
  - Polls the verification status until completion
  - Can be combined with `--notify` to receive desktop notifications when verification completes
- `--notify`, send desktop notifications when verification completes (requires `--watch`)
- `--package`, specify which package to verify (required for workspace projects with multiple packages)

There are more options, each of them is documented in the `--help` output.

If the verification submission is successful, client will output the verification job id.

#### Checking job status

User can query the verification job status using `status` command and providing job id as the `--job` argument value. The status check will poll the server with exponential backoff until the verification is complete or fails.

Alternatively, you can use the `history` command to check jobs that have been tracked locally:

```bash
# Check from history (faster, uses local database)
voyager history status --job <JOB_ID>

# Re-check and update from API
voyager history status --job <JOB_ID> --network mainnet --refresh
```

All verification jobs are automatically tracked in the local history database (`~/.voyager/history.db`), allowing you to check their status even across different CLI sessions.

## Troubleshooting

When verification fails, you may see a generic error message like:

```
Error: [E004] Compilation failed: Compilation failed: `scarb` command exited with error
```

To get more detailed information about what went wrong, use the `--verbose` (or `-v`) flag:

```bash
voyager status --network mainnet --job <JOB_ID> --verbose
```

### Common Errors and Solutions

#### Error: Module file not found (error[E0005])

**Example:**
```
error[E0005]: Module file not found. Expected path: /tmp/targets/.../src/tests.cairo
```

**Cause:** A module is declared in your `lib.cairo` but the file doesn't exist or wasn't included in the verification submission.

**Solutions:**
- If the missing file is a test file (like `tests.cairo`, `test.cairo`, or files with `test` in the name), use the `--test-files` flag to include them:
  ```bash
  voyager verify --network mainnet \
    --class-hash <HASH> \
    --contract-name <NAME> \
    --test-files
  ```
- Alternatively, remove the module declaration from `lib.cairo` if tests aren't needed for verification:
  ```cairo
  // Remove or comment out:
  // pub mod tests;
  ```
- Verify the module file exists in your local project at the expected path

#### Error: Syntax errors or import failures

**Cause:** Your code has syntax errors or missing imports that prevent compilation.

**Solutions:**
- Run `scarb build` locally first to verify your project compiles correctly
- Check that all dependencies are properly declared in `[dependencies]` section of `Scarb.toml`
- Verify all import paths are correct and modules are properly defined in `lib.cairo`
- Ensure you're compiling with `[profile.release]` settings (the remote compiler uses `scarb --release build`)

### Debugging Tips

1. **Use `--dry-run` to preview submission:**
   ```bash
   voyager verify --network mainnet \
     --class-hash <HASH> \
     --contract-name <NAME> \
     --dry-run
   ```
   This shows which files will be sent without actually submitting.

2. **Check your local build:**
   ```bash
   scarb --release build
   ```
   The remote compiler uses the same command, so if it fails locally it will fail remotely.

3. **Use `--verbose` to see full error output:**
   ```bash
   voyager status --network mainnet --job <JOB_ID> --verbose
   ```
   This displays the complete compiler output from the remote server.

4. **Review `[profile.release]` configuration:**
   Remember that the remote compiler uses `scarb --release build`, so any special compiler settings must be under `[profile.release]`:
   ```toml
   [profile.release.cairo]
   sierra-replace-ids = true
   ```

5. **Check file inclusion:**
   - Test files in `src/` are excluded by default (use `--test-files` to include)
   - `Scarb.lock` is excluded by default (use `--lock-file` to include)
   - All `.cairo` files in `src/` are included
   - Files listed as dependencies in `Scarb.toml` are resolved and included

### Getting Help

If you're still experiencing issues:
1. Run verification with `--verbose` flag and save the full error output
2. Check that your project builds locally with `scarb --release build`
3. Review the error message for specific file paths or error codes
4. For persistent issues, reach out to @StarknetVoyager on Telegram
