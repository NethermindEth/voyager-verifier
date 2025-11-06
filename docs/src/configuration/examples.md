# Configuration Examples

Real-world configuration examples for common use cases and scenarios.

## Overview

This guide provides ready-to-use `.voyager.toml` configurations for:

- Production deployments
- Development and testing
- CI/CD pipelines
- Workspace projects
- Dojo projects
- Custom networks
- Team environments

Copy and adapt these examples to your specific needs.

## Production Deployments

### Mainnet Production (Conservative)

**Use case:** Production mainnet deployment with maximum reliability

**.voyager.toml:**
```toml
[voyager]
# Main Starknet network
network = "mainnet"

# Production license
license = "Apache-2.0"

# Wait for verification to complete
watch = true

# Get notified when done
notify = true

# Lock dependencies for reproducibility
lock-file = true

# Don't include test files
test-files = false

# Keep logs clean for production
verbose = false
```

**Usage:**
```bash
voyager verify --class-hash 0x123... --contract-name ProductionContract
```

### Mainnet Production (Aggressive)

**Use case:** Fast deployment with monitoring

**.voyager.toml:**
```toml
[voyager]
network = "mainnet"
license = "MIT"

# Don't wait - submit and continue
watch = false

# Production build settings
lock-file = true
test-files = false
verbose = false
```

**Usage:**
```bash
# Submit and get job ID immediately
voyager verify --class-hash 0x123... --contract-name FastDeploy

# Check status later
voyager status --network mainnet --job <JOB_ID>
```

## Development & Testing

### Sepolia Development

**Use case:** Active development on Sepolia testnet

**.voyager.toml:**
```toml
[voyager]
# Test network
network = "sepolia"

# Development license
license = "MIT"

# Watch for immediate feedback
watch = true

# Get notified
notify = true

# Include test files (often needed in dev)
test-files = true

# Lock file for consistency
lock-file = true

# Verbose output for debugging
verbose = true
```

**Usage:**
```bash
voyager verify --class-hash 0x123... --contract-name DevContract
```

### Local Testing

**Use case:** Testing with local Starknet node

**.voyager.toml:**
```toml
[voyager]
# Custom local endpoint
url = "http://localhost:5050"

license = "MIT"
watch = true
test-files = true
verbose = true
```

**Usage:**
```bash
voyager verify --class-hash 0x123... --contract-name LocalTest
```

## CI/CD Pipelines

### GitHub Actions / GitLab CI

**Use case:** Automated verification in CI/CD

**.voyager.toml:**
```toml
[voyager]
network = "mainnet"
license = "MIT"

# DON'T wait - CI should be fast
watch = false

# NO notifications in CI
notify = false

# Lock file for reproducibility
lock-file = true

# NO test files in production
test-files = false

# Verbose for CI logs
verbose = true
```

**GitHub Actions:**
```yaml
- name: Verify Contract
  run: |
    voyager verify \
      --class-hash ${{ secrets.CLASS_HASH }} \
      --contract-name MyContract

    # Store job ID for later checks
    JOB_ID=$(voyager verify ... | grep "Job ID" | awk '{print $3}')
    echo "JOB_ID=$JOB_ID" >> $GITHUB_ENV
```

### CI with Verification Wait

**Use case:** CI that waits for verification

**.voyager.toml:**
```toml
[voyager]
network = "mainnet"
license = "Apache-2.0"

# Wait for result in CI
watch = true

# No notifications
notify = false

lock-file = true
test-files = false
verbose = true
```

**Usage:**
```yaml
- name: Verify and Wait
  run: |
    voyager verify \
      --class-hash ${{ secrets.CLASS_HASH }} \
      --contract-name MyContract
    # CI will wait for completion
```

## Workspace Projects

### Multi-Package Workspace

**Use case:** Workspace with multiple contract packages

**Project structure:**
```
my-protocol/
├── .voyager.toml
├── Scarb.toml
└── packages/
    ├── token/
    ├── nft/
    └── marketplace/
```

**.voyager.toml:**
```toml
[voyager]
network = "mainnet"
license = "MIT"
watch = true
notify = true
lock-file = true

[workspace]
# Primary package
default-package = "token"
```

**Usage:**
```bash
# Verify token (uses default)
voyager verify --class-hash 0x123... --contract-name Token

# Verify nft (override default)
voyager verify --class-hash 0x456... --contract-name NFT --package nft
```

### Batch Workspace Verification

**Use case:** Verify all contracts in workspace at once

**.voyager.toml:**
```toml
[voyager]
network = "mainnet"
license = "MIT"
watch = true
notify = true

[workspace]
default-package = "core"

# Define all contracts
[[contracts]]
class-hash = "0x044dc2b3239382230d8b1e943df23b96f52eebcac93efe6e8bde92f9a2f1da18"
contract-name = "Token"
package = "token"

[[contracts]]
class-hash = "0x055dc2b3239382230d8b1e943df23b96f52eebcac93efe6e8bde92f9a2f1da19"
contract-name = "NFT"
package = "nft"

[[contracts]]
class-hash = "0x066dc2b3239382230d8b1e943df23b96f52eebcac93efe6e8bde92f9a2f1da20"
contract-name = "Marketplace"
package = "marketplace"
```

**Usage:**
```bash
# Verify all contracts
voyager verify

# With rate limiting
voyager verify --batch-delay 5
```

## Dojo Projects

### Basic Dojo Game

**Use case:** Dojo game project on mainnet

**.voyager.toml:**
```toml
[voyager]
network = "mainnet"
license = "MIT"

# Specify Dojo project type
project-type = "dojo"

watch = true
notify = true
lock-file = true
test-files = false
verbose = false
```

**Usage:**
```bash
voyager verify --class-hash 0x123... --contract-name GameWorld
```

### Dojo Development

**Use case:** Active Dojo game development

**.voyager.toml:**
```toml
[voyager]
network = "sepolia"
license = "MIT"
project-type = "dojo"

watch = true
notify = true
test-files = true
lock-file = true
verbose = true
```

**Usage:**
```bash
voyager verify --class-hash 0x123... --contract-name TestWorld
```

## Custom Networks

### Private Network

**Use case:** Custom Starknet deployment

**.voyager.toml:**
```toml
[voyager]
# Custom API endpoint
url = "https://api.private-network.com/beta"

license = "Proprietary"
watch = true
notify = true
lock-file = true
verbose = true
```

**Usage:**
```bash
voyager verify --class-hash 0x123... --contract-name PrivateContract
```

### Staging Environment

**Use case:** Staging network for pre-production testing

**.voyager.toml:**
```toml
[voyager]
url = "https://staging-api.company.com/beta"
license = "MIT"

# Watch for staging tests
watch = true
notify = true

# Include test files in staging
test-files = true
lock-file = true
verbose = true
```

**Usage:**
```bash
voyager verify --class-hash 0x123... --contract-name StagingContract
```

## Team Environments

### Shared Team Config

**Use case:** Consistent verification across team

**.voyager.toml (committed to repo):**
```toml
[voyager]
network = "mainnet"
license = "Apache-2.0"

# Team standards
watch = true
notify = false  # Let individuals enable
lock-file = true
test-files = false
verbose = false

[workspace]
default-package = "core"
```

**Individual override (.gitignored):**
```.voyager.local.toml
[voyager]
# Personal preferences
notify = true  # Enable notifications for me
verbose = true  # I like verbose output
```

**Usage:**
```bash
# Copy local config before running
cp .voyager.local.toml .voyager.toml
voyager verify --class-hash 0x123... --contract-name MyContract
```

### Multi-Environment Team Setup

**Use case:** Different configs for dev/staging/prod

**Templates:**
```
.voyager.dev.toml     # Development
.voyager.staging.toml # Staging
.voyager.prod.toml    # Production
```

**.voyager.dev.toml:**
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

**.voyager.staging.toml:**
```toml
[voyager]
url = "https://staging-api.company.com"
license = "MIT"
watch = true
notify = true
test-files = true
lock-file = true
verbose = true
```

**.voyager.prod.toml:**
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

**Switching environments:**
```bash
# Use development
cp .voyager.dev.toml .voyager.toml

# Use staging
cp .voyager.staging.toml .voyager.toml

# Use production
cp .voyager.prod.toml .voyager.toml
```

## Specialized Scenarios

### Minimal Configuration

**Use case:** Quick setup with defaults

**.voyager.toml:**
```toml
[voyager]
network = "mainnet"
license = "MIT"
```

**Usage:**
```bash
# Manually specify other options
voyager verify --class-hash 0x123... --contract-name Simple --watch
```

### Maximum Verbosity (Debug)

**Use case:** Troubleshooting verification issues

**.voyager.toml:**
```toml
[voyager]
network = "sepolia"  # Use testnet for debugging
license = "MIT"

# All debug options enabled
watch = true
notify = true
test-files = true
lock-file = true
verbose = true
```

**Usage:**
```bash
# Also use dry-run for maximum information
voyager verify --class-hash 0x123... --contract-name Debug --dry-run
```

### Fast Iteration

**Use case:** Rapid development cycle

**.voyager.toml:**
```toml
[voyager]
network = "sepolia"
license = "MIT"

# No waiting - fast feedback
watch = false
notify = false
test-files = true
verbose = false
```

**Usage:**
```bash
# Submit quickly
voyager verify --class-hash 0x123... --contract-name QuickTest

# Check later
voyager status --network sepolia --job <JOB_ID>
```

### Notification-Heavy

**Use case:** Long-running verifications with notifications

**.voyager.toml:**
```toml
[voyager]
network = "mainnet"
license = "MIT"

# Always watch and notify
watch = true
notify = true

lock-file = true
test-files = false
verbose = false
```

**Usage:**
```bash
# Start verification and continue other work
voyager verify --class-hash 0x123... --contract-name LongBuild
# You'll get notified when done
```

## Protocol-Specific Examples

### DeFi Protocol

**Use case:** Multi-contract DeFi protocol

**.voyager.toml:**
```toml
[voyager]
network = "mainnet"
license = "MIT"
watch = true
notify = true
lock-file = true

[workspace]
default-package = "core"

# All protocol contracts
[[contracts]]
class-hash = "0x123..."
contract-name = "AMM"
package = "amm"

[[contracts]]
class-hash = "0x456..."
contract-name = "LendingPool"
package = "lending"

[[contracts]]
class-hash = "0x789..."
contract-name = "GovernanceToken"
package = "governance"

[[contracts]]
class-hash = "0xabc..."
contract-name = "Treasury"
package = "treasury"
```

**Usage:**
```bash
# Verify entire protocol
voyager verify --batch-delay 10
```

### NFT Marketplace

**Use case:** NFT marketplace with multiple contracts

**.voyager.toml:**
```toml
[voyager]
network = "mainnet"
license = "Apache-2.0"
watch = true
notify = true
lock-file = true

[workspace]
default-package = "nft"

[[contracts]]
class-hash = "0x123..."
contract-name = "NFTCollection"
package = "nft"

[[contracts]]
class-hash = "0x456..."
contract-name = "Marketplace"
package = "marketplace"

[[contracts]]
class-hash = "0x789..."
contract-name = "Auction"
package = "auction"
```

**Usage:**
```bash
voyager verify
```

### GameFi Project

**Use case:** Dojo-based game with multiple systems

**.voyager.toml:**
```toml
[voyager]
network = "mainnet"
license = "MIT"
project-type = "dojo"
watch = true
notify = true
lock-file = true

[[contracts]]
class-hash = "0x123..."
contract-name = "GameWorld"

[[contracts]]
class-hash = "0x456..."
contract-name = "PlayerSystem"

[[contracts]]
class-hash = "0x789..."
contract-name = "ItemSystem"

[[contracts]]
class-hash = "0xabc..."
contract-name = "BattleSystem"
```

**Usage:**
```bash
voyager verify --batch-delay 5
```

## Migration Scenarios

### Gradual Migration from CLI

**Phase 1 - Start with minimal config:**
```toml
[voyager]
network = "mainnet"
license = "MIT"
```

**Phase 2 - Add commonly used options:**
```toml
[voyager]
network = "mainnet"
license = "MIT"
watch = true
lock-file = true
```

**Phase 3 - Full configuration:**
```toml
[voyager]
network = "mainnet"
license = "MIT"
watch = true
notify = true
lock-file = true
test-files = false
verbose = false

[workspace]
default-package = "main"
```

### Moving to Batch Mode

**Before (individual commands):**
```bash
voyager verify --network mainnet --class-hash 0x123... --contract-name Token
voyager verify --network mainnet --class-hash 0x456... --contract-name NFT
voyager verify --network mainnet --class-hash 0x789... --contract-name Market
```

**After (batch config):**
```toml
[voyager]
network = "mainnet"
license = "MIT"
watch = true

[[contracts]]
class-hash = "0x123..."
contract-name = "Token"

[[contracts]]
class-hash = "0x456..."
contract-name = "NFT"

[[contracts]]
class-hash = "0x789..."
contract-name = "Market"
```

```bash
# Single command
voyager verify
```

## Best Practices Summary

### 1. Start Simple

```toml
[voyager]
network = "mainnet"
license = "MIT"
```

Add options as needed.

### 2. Use Comments

```toml
[voyager]
network = "mainnet"
license = "MIT"

# Enable for local development
# watch = true
# verbose = true

# Enable for CI
# watch = false
# verbose = true
```

### 3. Version Control

**Commit:**
- `.voyager.toml` - Team defaults
- `.voyager.example.toml` - Template

**Ignore:**
- `.voyager.local.toml` - Personal preferences

### 4. Environment-Specific

Create separate configs:
- `.voyager.dev.toml`
- `.voyager.staging.toml`
- `.voyager.prod.toml`

### 5. Document Decisions

```toml
[voyager]
network = "mainnet"
license = "Apache-2.0"

# We use watch=true because verification takes 5-10 minutes
# and immediate feedback is valuable
watch = true

# Lock file ensures reproducible builds across team
lock-file = true

# Test files excluded in production builds
test-files = false
```

## Troubleshooting Templates

### Debug Configuration

When things aren't working:

```toml
[voyager]
network = "sepolia"  # Use testnet
license = "MIT"

# Maximum visibility
watch = true
notify = false  # Disable to reduce noise
test-files = true  # Include everything
lock-file = true
verbose = true  # See all errors
```

Use with:
```bash
voyager verify --class-hash 0x123... --contract-name Debug --dry-run
```

### Minimal Test Configuration

For isolating issues:

```toml
[voyager]
network = "sepolia"
license = "MIT"
# Nothing else - pure defaults
```

## Next Steps

- **[Configuration File Guide](./config-file.md)** - Complete config reference
- **[Workspace Settings](./workspace.md)** - Multi-package projects
- **[CLI Options Reference](./cli-options.md)** - All available flags
- **[Batch Verification](../verification/batch-verification.md)** - Multiple contracts
