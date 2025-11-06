# Configuration File Guide

The configuration file (`.voyager.toml`) provides a convenient way to set default values for verification options, reducing command-line verbosity and enabling shareable team configurations.

## Overview

Configuration files offer:

- **Reduced verbosity** - No need to repeatedly specify the same options
- **Team consistency** - Commit `.voyager.toml` to share settings across team
- **Per-project defaults** - Different projects can have different verification settings
- **Environment-specific configs** - Use different configs for dev/staging/production
- **Priority system** - CLI arguments always override config values
- **Automatic discovery** - Searches current and parent directories

## File Location

### Discovery Mechanism

The verifier searches for `.voyager.toml` in the following order:

1. **Current working directory** - `./voyager.toml`
2. **Parent directories** - Walks up the directory tree until found
3. **No config** - Uses default values if no config file is found

**Example directory search:**
```
/home/user/projects/my-contract/
  └── packages/
      └── token/  ← Current directory
```

Search order:
1. `/home/user/projects/my-contract/packages/token/.voyager.toml`
2. `/home/user/projects/my-contract/packages/.voyager.toml`
3. `/home/user/projects/my-contract/.voyager.toml`
4. `/home/user/projects/.voyager.toml`
5. `/home/user/.voyager.toml`

The first file found is used.

### Recommended Locations

**Single package project:**
```
my-contract/
├── .voyager.toml  ← Place here
├── Scarb.toml
└── src/
```

**Workspace project:**
```
my-workspace/
├── .voyager.toml  ← Place here (root level)
├── Scarb.toml
└── packages/
    ├── token/
    └── nft/
```

**Monorepo:**
```
monorepo/
├── .voyager.toml  ← Global defaults (optional)
└── contracts/
    ├── .voyager.toml  ← Contract-specific settings
    ├── token/
    └── nft/
```

## Basic Structure

```toml
[voyager]
# Main configuration section
network = "mainnet"
license = "MIT"

[workspace]
# Workspace-specific settings (optional)
default-package = "my_contract"

[[contracts]]
# Batch verification array (optional)
class-hash = "0x123..."
contract-name = "MyContract"
```

## Configuration Sections

### `[voyager]` Section

Main configuration section for verification options.

#### Network Options

##### `network`

**Type:** String
**Values:** `"mainnet"`, `"sepolia"`, `"dev"`
**Default:** None (must be specified)
**Overridden by:** `--network`

Specifies which network to verify on.

```toml
[voyager]
network = "mainnet"  # Main Starknet network
# OR
network = "sepolia"  # Test network
# OR
network = "dev"      # Development network
```

**API Endpoints:**
- `mainnet` → `https://api.voyager.online/beta`
- `sepolia` → `https://sepolia-api.voyager.online/beta`

**Example usage:**
```bash
# Uses network from config
voyager verify --class-hash 0x123... --contract-name MyContract

# Override config network
voyager verify --network sepolia --class-hash 0x123... --contract-name MyContract
```

##### `url`

**Type:** String
**Default:** None
**Overridden by:** `--url`

Custom API endpoint URL. Alternative to using `network`.

```toml
[voyager]
url = "https://api.custom.com/beta"
```

**Note:** Cannot use both `network` and `url`. Choose one.

#### License Options

##### `license`

**Type:** String
**Default:** "All Rights Reserved"
**Overridden by:** `--license`

SPDX license identifier for your contract.

```toml
[voyager]
license = "MIT"
```

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

See [SPDX License List](https://spdx.org/licenses/) for all valid identifiers.

#### Behavioral Options

##### `watch`

**Type:** Boolean
**Default:** `false`
**Overridden by:** `--watch`

Wait for verification to complete instead of just submitting.

```toml
[voyager]
watch = true
```

**When enabled:**
- Polls verification status until completion
- Shows real-time progress updates
- Exits when verification succeeds or fails
- Can be combined with `notify`

**When disabled:**
- Submits verification and exits immediately
- Returns job ID for later checking
- Useful for CI/CD pipelines

##### `notify`

**Type:** Boolean
**Default:** `false`
**Overridden by:** `--notify`
**Requires:** `watch = true`

Send desktop notifications when verification completes.

```toml
[voyager]
watch = true
notify = true  # Only works with watch = true
```

**Notification types:**
- ✅ Success: "Contract verified: MyContract"
- ❌ Failure: "Verification failed: MyContract"

See [Desktop Notifications](../advanced/notifications.md) for platform-specific setup.

##### `verbose`

**Type:** Boolean
**Default:** `false`
**Overridden by:** `--verbose` or `-v`

Show detailed error messages and debugging information.

```toml
[voyager]
verbose = true
```

**When enabled:**
- Shows full compiler output
- Displays detailed API errors
- Useful for debugging failures
- Recommended for CI/CD logs

#### File Inclusion Options

##### `lock-file`

**Type:** Boolean
**Default:** `false`
**Overridden by:** `--lock-file`

Include `Scarb.lock` file in verification submission.

```toml
[voyager]
lock-file = true
```

**Use cases:**
- Ensure reproducible builds
- Lock dependency versions
- Production deployments

##### `test-files`

**Type:** Boolean
**Default:** `false`
**Overridden by:** `--test-files`

Include test files from `src/` directory in verification.

```toml
[voyager]
test-files = true
```

**Behavior:**
- Includes files with "test" or "tests" in path within `src/`
- Dedicated `tests/` directories still excluded
- Use when contract references test utilities

**Example:**
```
src/
  ├── contract.cairo      # Always included
  ├── test_helpers.cairo  # Included with test-files = true
  └── tests.cairo         # Included with test-files = true
tests/
  └── integration.cairo   # Always excluded
```

#### Project Type Options

##### `project-type`

**Type:** String
**Values:** `"scarb"`, `"dojo"`, `"auto"`
**Default:** `"auto"`
**Overridden by:** `--project-type`

Specify the project build tool type.

```toml
[voyager]
project-type = "auto"  # Auto-detect (default)
# OR
project-type = "scarb"  # Force Scarb
# OR
project-type = "dojo"   # Force Dojo
```

**Auto-detection logic:**
1. Checks for `Scarb.toml` with `[tool.dojo]` section → Dojo
2. Checks for `Scarb.toml` → Scarb
3. Falls back to Scarb if uncertain

### `[workspace]` Section

Configuration for workspace projects with multiple packages.

##### `default-package`

**Type:** String
**Default:** None
**Overridden by:** `--package`

Default package to verify in workspace projects.

```toml
[workspace]
default-package = "my_contract"
```

**Use case:**
Eliminates need to specify `--package` every time:

```bash
# Without default-package
voyager verify --class-hash 0x123... --contract-name MyContract --package token

# With default-package = "token"
voyager verify --class-hash 0x123... --contract-name MyContract
```

**Override when needed:**
```bash
voyager verify --class-hash 0x123... --contract-name MyContract --package nft
```

### `[[contracts]]` Array

Configuration for batch verification of multiple contracts.

**Structure:**
```toml
[[contracts]]
class-hash = "0x123..."
contract-name = "MyContract"
package = "token"  # Optional
```

**Fields:**

##### `class-hash`

**Type:** String
**Required:** Yes

The class hash of the deployed contract.

```toml
[[contracts]]
class-hash = "0x044dc2b3239382230d8b1e943df23b96f52eebcac93efe6e8bde92f9a2f1da18"
```

##### `contract-name`

**Type:** String
**Required:** Yes

The name of the contract to verify.

```toml
[[contracts]]
contract-name = "MyToken"
```

##### `package`

**Type:** String
**Required:** No
**Default:** Uses `workspace.default-package` or auto-detects

Package name for workspace projects.

```toml
[[contracts]]
package = "token"
```

**Batch verification example:**
```toml
[voyager]
network = "mainnet"
license = "MIT"
watch = true

[[contracts]]
class-hash = "0x123..."
contract-name = "Token"
package = "token"

[[contracts]]
class-hash = "0x456..."
contract-name = "NFT"
package = "nft"

[[contracts]]
class-hash = "0x789..."
contract-name = "Marketplace"
# package omitted - uses workspace.default-package
```

**Usage:**
```bash
voyager verify  # Verifies all contracts in [[contracts]] array
```

See [Batch Verification](../verification/batch-verification.md) for detailed documentation.

## Priority System

Settings are applied in order of priority:

### 1. CLI Arguments (Highest Priority)

Command-line flags always override config file and defaults.

```bash
voyager verify --network sepolia --license Apache-2.0 ...
```

### 2. Configuration File

Settings from `.voyager.toml` in discovered location.

```toml
[voyager]
network = "mainnet"
license = "MIT"
```

### 3. Scarb.toml (License Only)

License fallback from package metadata.

```toml
[package]
license = "MIT"
```

### 4. Default Values (Lowest Priority)

Built-in defaults when nothing else is specified.

**Example priority in action:**
```toml
# .voyager.toml
[voyager]
network = "mainnet"
license = "MIT"
watch = true
```

```bash
# CLI overrides network and license
voyager verify --network sepolia --license Apache-2.0 \
  --class-hash 0x123... --contract-name MyContract

# Effective values:
# network = "sepolia" (from CLI)
# license = "Apache-2.0" (from CLI)
# watch = true (from config)
```

## Complete Examples

### Example 1: Production Deployment

```toml
[voyager]
network = "mainnet"
license = "Apache-2.0"
watch = true
notify = true
test-files = false
lock-file = true
verbose = false
```

**Use case:** Production mainnet deployments with notifications

**Usage:**
```bash
voyager verify --class-hash 0x123... --contract-name ProductionContract
```

### Example 2: Development/Testing

```toml
[voyager]
network = "sepolia"
license = "MIT"
watch = true
notify = true
test-files = true
lock-file = true
verbose = true
```

**Use case:** Development on testnet with detailed output

**Usage:**
```bash
voyager verify --class-hash 0x123... --contract-name TestContract
```

### Example 3: CI/CD Pipeline

```toml
[voyager]
network = "mainnet"
watch = false  # Don't block pipeline
notify = false  # No notifications in CI
test-files = false
lock-file = true
verbose = true  # Detailed logs
```

**Use case:** Automated verification in CI/CD

**Usage:**
```bash
voyager verify --class-hash $CLASS_HASH --contract-name MyContract
```

### Example 4: Workspace Project

```toml
[voyager]
network = "mainnet"
license = "MIT"
watch = true
notify = true

[workspace]
default-package = "my_contract"
```

**Use case:** Workspace with default package selection

**Usage:**
```bash
# Uses default-package
voyager verify --class-hash 0x123... --contract-name MyContract

# Override package when needed
voyager verify --class-hash 0x456... --contract-name OtherContract --package other
```

### Example 5: Batch Verification

```toml
[voyager]
network = "mainnet"
license = "MIT"
watch = true

[workspace]
default-package = "contracts"

[[contracts]]
class-hash = "0x044dc2b3239382230d8b1e943df23b96f52eebcac93efe6e8bde92f9a2f1da18"
contract-name = "MyToken"
package = "token"

[[contracts]]
class-hash = "0x055dc2b3239382230d8b1e943df23b96f52eebcac93efe6e8bde92f9a2f1da19"
contract-name = "MyNFT"
package = "nft"

[[contracts]]
class-hash = "0x066dc2b3239382230d8b1e943df23b96f52eebcac93efe6e8bde92f9a2f1da20"
contract-name = "MyMarketplace"
```

**Use case:** Verify multiple contracts at once

**Usage:**
```bash
voyager verify  # Verifies all three contracts
```

### Example 6: Dojo Project

```toml
[voyager]
network = "mainnet"
license = "MIT"
project-type = "dojo"
watch = true
notify = true
lock-file = true
```

**Use case:** Dojo game contracts

**Usage:**
```bash
voyager verify --class-hash 0x123... --contract-name GameContract
```

### Example 7: Custom Endpoint

```toml
[voyager]
url = "https://api.custom.network.com/beta"
license = "MIT"
watch = true
verbose = true
```

**Use case:** Private or custom Starknet network

**Usage:**
```bash
voyager verify --class-hash 0x123... --contract-name MyContract
```

### Example 8: Minimal Configuration

```toml
[voyager]
network = "mainnet"
license = "MIT"
```

**Use case:** Simple projects with minimal configuration

**Usage:**
```bash
voyager verify --class-hash 0x123... --contract-name MyContract --watch
```

## Creating Your Configuration File

### Step 1: Copy Example File

```bash
cp .voyager.toml.example .voyager.toml
```

Or download from repository:
```bash
curl -O https://raw.githubusercontent.com/NethermindEth/voyager-verifier/main/.voyager.toml.example
mv .voyager.toml.example .voyager.toml
```

### Step 2: Edit for Your Needs

```toml
[voyager]
# Choose your network
network = "mainnet"  # or "sepolia" for testnet

# Set your license
license = "MIT"  # or your preferred SPDX identifier

# Enable watch mode for live updates
watch = true

# Enable notifications (optional)
notify = true

# Include lock file for reproducible builds
lock-file = true

# Other options as needed
test-files = false
verbose = false
```

### Step 3: Test Configuration

Use dry run to verify configuration is loaded correctly:

```bash
voyager verify --class-hash 0x123... --contract-name MyContract --dry-run
```

Check that the configuration summary shows your settings.

### Step 4: Commit to Repository (Optional)

```bash
git add .voyager.toml
git commit -m "Add Voyager verification config"
```

Share configuration with your team.

## Best Practices

### 1. Use Config Files for Shared Settings

**Good:**
```toml
# .voyager.toml - committed to repo
[voyager]
network = "mainnet"
license = "MIT"
lock-file = true
```

**Why:** Team consistency, less verbosity

### 2. Keep Sensitive Data Out of Config

**Bad:**
```toml
[voyager]
api-key = "secret123"  # Never do this!
```

**Good:**
Use environment variables or CLI arguments for sensitive data.

### 3. Document Project-Specific Settings

```toml
[voyager]
network = "mainnet"
license = "MIT"

# We include test files because our contract uses shared test utilities
test-files = true

# Lock file ensures reproducible builds across team
lock-file = true
```

### 4. Use Different Configs for Different Environments

```bash
# Development
.voyager.dev.toml

# Production
.voyager.prod.toml
```

Then specify which config:
```bash
cp .voyager.dev.toml .voyager.toml  # For development
cp .voyager.prod.toml .voyager.toml  # For production
```

### 5. Override Config Values When Needed

Don't be afraid to override config for one-off cases:

```bash
# Usually use mainnet from config, but test on sepolia
voyager verify --network sepolia --class-hash 0x123... --contract-name MyContract
```

### 6. Enable Verbose in CI/CD

```toml
[voyager]
network = "mainnet"
watch = false
verbose = true  # Always enable for CI logs
```

### 7. Use Batch Mode for Multi-Contract Deployments

```toml
[[contracts]]
class-hash = "0x123..."
contract-name = "Token"

[[contracts]]
class-hash = "0x456..."
contract-name = "NFT"
```

Single command verifies all contracts.

## Troubleshooting

### Config File Not Found

**Problem:** Settings from `.voyager.toml` not being applied.

**Solution:**
1. Verify file exists: `ls -la .voyager.toml`
2. Check file location (current or parent directory)
3. Use `--dry-run` to see which config is loaded

```bash
voyager verify --class-hash 0x123... --contract-name MyContract --dry-run
```

### Invalid TOML Syntax

**Problem:** Error parsing configuration file.

**Example error:**
```
Error: Failed to parse configuration file: expected an equals, found an identifier at line 5
```

**Solution:** Check TOML syntax:
- Strings must be quoted: `network = "mainnet"`
- Booleans are lowercase: `watch = true`
- Arrays use double brackets: `[[contracts]]`

**Validate TOML:**
```bash
# Use online validator or CLI tool
cat .voyager.toml | toml-lint
```

### Network and URL Both Specified

**Problem:**
```
Error: Cannot specify both 'network' and 'url' in config
```

**Solution:** Choose one:
```toml
[voyager]
network = "mainnet"  # Use this
# url = "..."        # OR this, not both
```

### Notify Without Watch

**Problem:** Notifications not working.

**Solution:** Enable watch mode:
```toml
[voyager]
watch = true  # Required for notify
notify = true
```

### Wrong Package Selected

**Problem:** Workspace selecting wrong package.

**Solution:** Set default package:
```toml
[workspace]
default-package = "correct_package"
```

Or override via CLI:
```bash
voyager verify --package correct_package ...
```

## Advanced Configuration

### Environment-Specific Configs

Use shell scripts to switch configs:

```bash
#!/bin/bash
# switch-env.sh

if [ "$1" == "dev" ]; then
    cp .voyager.dev.toml .voyager.toml
elif [ "$1" == "prod" ]; then
    cp .voyager.prod.toml .voyager.toml
else
    echo "Usage: ./switch-env.sh [dev|prod]"
fi
```

### Config File Per Package

For monorepos with multiple contracts:

```
monorepo/
├── contracts/
│   ├── token/
│   │   └── .voyager.toml  ← Token-specific
│   └── nft/
│       └── .voyager.toml  ← NFT-specific
└── .voyager.toml          ← Global defaults
```

### Template Configs

Create reusable templates:

```bash
# templates/
#   ├── .voyager.mainnet.toml
#   ├── .voyager.sepolia.toml
#   └── .voyager.ci.toml

# Copy template to use
cp templates/.voyager.mainnet.toml .voyager.toml
```

## Next Steps

- **[CLI Options Reference](./cli-options.md)** - Complete flag documentation
- **[Workspace Settings](./workspace.md)** - Multi-package configuration
- **[Configuration Examples](./examples.md)** - More real-world examples
- **[Batch Verification](../verification/batch-verification.md)** - Using [[contracts]] array
