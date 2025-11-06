# Workspace Settings

Configuration guide for verifying contracts in Scarb workspace projects with multiple packages.

## Overview

Workspace settings allow you to:

- **Manage multi-package projects** - Single Scarb.toml with multiple contract packages
- **Set default package** - Avoid specifying `--package` every time
- **Batch verification** - Verify multiple packages at once
- **Package-specific settings** - Different configurations per package
- **Simplified commands** - Less typing for common workflows

## What is a Workspace?

A Scarb workspace is a project structure with multiple packages (crates) defined in a single root `Scarb.toml` file.

**Example workspace structure:**
```
my-workspace/
├── Scarb.toml          ← Workspace root
└── packages/
    ├── token/
    │   ├── Scarb.toml
    │   └── src/
    ├── nft/
    │   ├── Scarb.toml
    │   └── src/
    └── marketplace/
        ├── Scarb.toml
        └── src/
```

**Root Scarb.toml:**
```toml
[workspace]
members = [
    "packages/token",
    "packages/nft",
    "packages/marketplace",
]
```

## Configuration

### `[workspace]` Section

Add workspace configuration to `.voyager.toml`:

```toml
[workspace]
default-package = "package_name"
```

### `default-package` Option

**Type:** String
**Required:** No
**Overridden by:** `--package` CLI flag

Sets the default package to verify when `--package` is not specified.

**Benefits:**
- Eliminates need to type `--package` every time
- Useful when primarily working with one package
- Can still override when needed

**Example:**
```toml
[voyager]
network = "mainnet"
license = "MIT"

[workspace]
default-package = "token"
```

**Usage:**
```bash
# Uses default-package = "token"
voyager verify --class-hash 0x123... --contract-name TokenContract

# Override to use different package
voyager verify --class-hash 0x456... --contract-name NFTContract --package nft
```

## Package Selection

### Automatic Detection

For single-package workspaces, the package is auto-detected:

```bash
# No --package needed if only one package exists
voyager verify --network mainnet \
  --class-hash 0x123... \
  --contract-name MyContract
```

### Explicit Selection

For multi-package workspaces, you must specify the package:

**Via CLI:**
```bash
voyager verify --network mainnet \
  --class-hash 0x123... \
  --contract-name TokenContract \
  --package token
```

**Via Config:**
```toml
[workspace]
default-package = "token"
```

Then:
```bash
voyager verify --network mainnet \
  --class-hash 0x123... \
  --contract-name TokenContract
# Uses default-package
```

### Error if Missing

Without `--package` or `default-package` in multi-package workspace:

```
Error: Multiple packages found. Use --package to specify which one to verify.

Available packages:
  - token
  - nft
  - marketplace

Use --package <name> or set workspace.default-package in .voyager.toml
```

## Complete Examples

### Example 1: Basic Workspace Config

**Project structure:**
```
my-defi-protocol/
├── .voyager.toml
├── Scarb.toml
└── packages/
    ├── token/
    ├── staking/
    └── governance/
```

**.voyager.toml:**
```toml
[voyager]
network = "mainnet"
license = "MIT"
watch = true

[workspace]
default-package = "token"  # Work primarily with token package
```

**Usage:**
```bash
# Verify token (uses default)
voyager verify --class-hash 0x123... --contract-name Token

# Verify staking (override)
voyager verify --class-hash 0x456... --contract-name Staking --package staking

# Verify governance (override)
voyager verify --class-hash 0x789... --contract-name Governor --package governance
```

### Example 2: No Default Package

**.voyager.toml:**
```toml
[voyager]
network = "mainnet"
license = "Apache-2.0"
watch = true

# No default-package set
```

**Usage:**
```bash
# Must specify --package every time
voyager verify --class-hash 0x123... --contract-name Token --package token
voyager verify --class-hash 0x456... --contract-name NFT --package nft
```

### Example 3: Batch Verification in Workspace

Verify multiple contracts from different packages:

**.voyager.toml:**
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
package = "token"

[[contracts]]
class-hash = "0x456..."
contract-name = "NFT"
package = "nft"

[[contracts]]
class-hash = "0x789..."
contract-name = "Marketplace"
package = "marketplace"
```

**Usage:**
```bash
voyager verify  # Verifies all three contracts from different packages
```

### Example 4: Development vs Production Packages

Different configs for different packages:

**.voyager.token.toml:**
```toml
[voyager]
network = "mainnet"
license = "MIT"
watch = true
lock-file = true

[workspace]
default-package = "token"
```

**.voyager.test.toml:**
```toml
[voyager]
network = "sepolia"
license = "MIT"
watch = true
test-files = true
verbose = true

[workspace]
default-package = "test_contracts"
```

**Usage:**
```bash
# Production token verification
cp .voyager.token.toml .voyager.toml
voyager verify --class-hash 0x123... --contract-name Token

# Test contract verification
cp .voyager.test.toml .voyager.toml
voyager verify --class-hash 0x456... --contract-name TestToken
```

## Common Workflows

### Workflow 1: Primary Package Development

When working primarily on one package in a workspace:

**Setup:**
```toml
[workspace]
default-package = "my_main_package"
```

**Daily usage:**
```bash
# All commands use my_main_package by default
voyager verify --class-hash 0x123... --contract-name Contract1
voyager verify --class-hash 0x456... --contract-name Contract2
voyager verify --class-hash 0x789... --contract-name Contract3
```

### Workflow 2: Multi-Package Development

When regularly working across multiple packages:

**Setup:**
```toml
# No default-package
```

**Usage with aliases:**
```bash
# Create shell aliases
alias verify-token='voyager verify --package token'
alias verify-nft='voyager verify --package nft'
alias verify-market='voyager verify --package marketplace'

# Use aliases
verify-token --class-hash 0x123... --contract-name Token
verify-nft --class-hash 0x456... --contract-name NFT
```

### Workflow 3: Batch Verification

Verify entire workspace at once:

**Setup:**
```toml
[voyager]
network = "mainnet"
license = "MIT"
watch = true

[workspace]
default-package = "core"

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
package = "marketplace"
```

**Single command:**
```bash
voyager verify
```

### Workflow 4: Package-Specific Configs

Different verification settings per package:

**Directory structure:**
```
workspace/
├── .voyager.toml           ← Global defaults
└── packages/
    ├── token/
    │   └── .voyager.toml   ← Token-specific
    └── nft/
        └── .voyager.toml   ← NFT-specific
```

**packages/token/.voyager.toml:**
```toml
[voyager]
network = "mainnet"
license = "MIT"
lock-file = true

[workspace]
default-package = "token"
```

**packages/nft/.voyager.toml:**
```toml
[voyager]
network = "mainnet"
license = "Apache-2.0"
test-files = true

[workspace]
default-package = "nft"
```

**Usage:**
```bash
# From token directory
cd packages/token
voyager verify --class-hash 0x123... --contract-name Token
# Uses token/.voyager.toml config

# From nft directory
cd ../nft
voyager verify --class-hash 0x456... --contract-name NFT
# Uses nft/.voyager.toml config
```

## Package Discovery

### How Voyager Finds Packages

1. **Reads root Scarb.toml** - Looks for `[workspace]` section
2. **Parses workspace members** - Gets list of package paths
3. **Validates packages** - Ensures each package has valid Scarb.toml
4. **Lists available packages** - Shows all packages if selection required

**Example:**
```toml
# Root Scarb.toml
[workspace]
members = [
    "packages/token",
    "packages/nft",
    "packages/*",  # Glob patterns supported
]
```

### Package Naming

Package names come from individual package `Scarb.toml` files:

**packages/token/Scarb.toml:**
```toml
[package]
name = "my_token"  # This is the package name to use
version = "0.1.0"
```

**Usage:**
```bash
voyager verify --class-hash 0x123... --contract-name Token --package my_token
```

## Troubleshooting

### Issue 1: Package Not Found

**Error:**
```
Error: Package 'token' not found in workspace

Available packages:
  - my_token
  - my_nft
  - my_marketplace
```

**Cause:** Using directory name instead of package name

**Solution:** Check package name in `Scarb.toml`:
```toml
[package]
name = "my_token"  # Use this name
```

```bash
voyager verify --class-hash 0x123... --contract-name Token --package my_token
```

### Issue 2: Multiple Packages Error

**Error:**
```
Error: Multiple packages found. Use --package to specify which one to verify.
```

**Solutions:**

**Option A - Use CLI flag:**
```bash
voyager verify --class-hash 0x123... --contract-name Token --package token
```

**Option B - Set default in config:**
```toml
[workspace]
default-package = "token"
```

### Issue 3: Wrong Package Selected

**Problem:** Verification fails because wrong package is being used

**Debug:**
```bash
# Use dry run to see which package is selected
voyager verify --class-hash 0x123... --contract-name Token --dry-run
```

**Output shows:**
```
Package: wrong_package  # ← This shows selected package
```

**Solution:**
```bash
# Explicitly specify correct package
voyager verify --class-hash 0x123... --contract-name Token --package correct_package
```

Or update config:
```toml
[workspace]
default-package = "correct_package"
```

### Issue 4: Config Not Being Applied

**Problem:** default-package setting not working

**Check:**
```bash
# Verify config file location
ls -la .voyager.toml

# Check if in workspace root
pwd
```

**Solution:** Ensure `.voyager.toml` is in workspace root or current directory:
```
workspace-root/
├── .voyager.toml  ← Should be here
├── Scarb.toml
└── packages/
```

### Issue 5: Batch Mode Package Issues

**Problem:** Batch verification using wrong packages

**Check config:**
```toml
[[contracts]]
class-hash = "0x123..."
contract-name = "Token"
package = "token"  # ← Ensure correct package specified
```

**Debug:**
```bash
# Dry run batch mode
voyager verify --dry-run
```

## Best Practices

### 1. Always Set default-package

For workspaces where you primarily work on one package:

```toml
[workspace]
default-package = "your_main_package"
```

**Benefits:**
- Less typing
- Fewer errors from forgetting `--package`
- Cleaner command history

### 2. Use Descriptive Package Names

**Good:**
```toml
[package]
name = "erc20_token"
name = "erc721_nft"
name = "marketplace_v2"
```

**Bad:**
```toml
[package]
name = "contract1"
name = "pkg"
name = "test"
```

### 3. Document Package Structure

Add comments to `.voyager.toml`:

```toml
[voyager]
network = "mainnet"
license = "MIT"

[workspace]
# Primary contract package - use this for most verifications
default-package = "token"

# Other packages available:
# - nft: ERC721 implementation
# - marketplace: Trading platform
# - governance: DAO governance
```

### 4. Create Package-Specific Configs

For packages with different requirements:

```
workspace/
├── .voyager.toml              ← Global defaults
└── packages/
    ├── production_contract/
    │   └── .voyager.toml      ← Production settings
    └── test_contract/
        └── .voyager.toml      ← Test settings
```

### 5. Use Batch Mode for Full Workspace

Verify all packages at once after deployment:

```toml
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
package = "marketplace"
```

```bash
voyager verify --watch
```

### 6. Test Package Selection

Always dry run first to verify correct package:

```bash
voyager verify --class-hash 0x123... --contract-name Token --dry-run
```

Check output shows correct package before actual verification.

## Integration with CI/CD

### GitHub Actions Example

```yaml
name: Verify Workspace Contracts

on:
  push:
    branches: [main]

jobs:
  verify:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        package: [token, nft, marketplace]
    steps:
      - uses: actions/checkout@v3

      - name: Install Voyager
        run: cargo install voyager-verifier

      - name: Verify ${{ matrix.package }}
        run: |
          voyager verify \
            --network mainnet \
            --class-hash ${{ secrets[format('{0}_CLASS_HASH', matrix.package)] }} \
            --contract-name ${{ matrix.package }} \
            --package ${{ matrix.package }} \
            --verbose
```

### Batch Verification in CI

```yaml
- name: Verify All Contracts
  run: |
    # Use batch mode from .voyager.toml
    voyager verify --verbose
```

## Next Steps

- **[Configuration File Guide](./config-file.md)** - Complete config documentation
- **[Batch Verification](../verification/batch-verification.md)** - Verify multiple contracts
- **[Configuration Examples](./examples.md)** - More workspace examples
- **[CLI Options Reference](./cli-options.md)** - All --package flag details
