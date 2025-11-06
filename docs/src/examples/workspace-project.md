# Workspace Project Example

This example demonstrates how to verify contracts in a Scarb workspace containing multiple packages. Workspaces are common in larger projects where you organize related contracts, libraries, and shared code into separate Cairo packages.

## Overview

You'll learn how to:
- Set up a Scarb workspace with multiple packages
- Configure workspace settings for verification
- Specify which package to verify
- Use default package configuration
- Verify different contracts from the same workspace

**Time Required:** 15-20 minutes

**Difficulty:** Intermediate

## What is a Scarb Workspace?

A Scarb workspace is a collection of one or more Cairo packages that share:
- Common dependencies
- Single `Scarb.lock` file
- Unified build configuration
- Shared workspace root

Workspaces are ideal for:
- **Protocol suites** - Multiple interconnected contracts
- **Shared libraries** - Common utilities used across contracts
- **Modular architecture** - Separating concerns into packages
- **Monorepo organization** - Managing related projects together

## Project Structure

We'll create a DeFi protocol workspace with this structure:

```
defi-protocol/
├── Scarb.toml                    # Workspace root configuration
├── Scarb.lock                    # Shared dependency lock file
├── .voyager.toml                 # Verification configuration
├── packages/
│   ├── token/                    # ERC20 token package
│   │   ├── Scarb.toml
│   │   └── src/
│   │       └── lib.cairo
│   ├── staking/                  # Staking contract package
│   │   ├── Scarb.toml
│   │   └── src/
│   │       └── lib.cairo
│   └── common/                   # Shared utilities package
│       ├── Scarb.toml
│       └── src/
│           └── lib.cairo
└── README.md
```

## Step 1: Create Workspace Root

Create the workspace directory and root `Scarb.toml`:

```bash
mkdir defi-protocol
cd defi-protocol
```

Create `Scarb.toml` in the root directory:

```toml
[workspace]
members = [
    "packages/common",
    "packages/token",
    "packages/staking"
]

[workspace.package]
version = "1.0.0"
authors = ["Your Name <your.email@example.com>"]
license = "MIT"
edition = "2024_07"

[workspace.dependencies]
starknet = "2.13.1"
```

**Key Points:**
- `[workspace]` defines the workspace structure
- `members` lists all packages in the workspace
- `[workspace.package]` sets default metadata for all packages
- `[workspace.dependencies]` defines shared dependencies

## Step 2: Create Common Utilities Package

Create the shared utilities package:

```bash
mkdir -p packages/common/src
```

Create `packages/common/Scarb.toml`:

```toml
[package]
name = "common"
version.workspace = true
edition.workspace = true
license.workspace = true

[dependencies]
starknet.workspace = true

[[target.starknet-contract]]
sierra = true
```

Create `packages/common/src/lib.cairo`:

```cairo
/// Common utilities and constants used across the protocol
use starknet::ContractAddress;

/// Protocol-wide constants
pub mod constants {
    pub const SCALE_FACTOR: u256 = 1000000;  // 6 decimals
    pub const MAX_FEE_BPS: u16 = 1000;       // 10% max fee
}

/// Utility functions
pub trait Math<T> {
    fn mul_div(a: T, b: T, c: T) -> T;
}

/// Address validation utilities
pub fn is_valid_address(addr: ContractAddress) -> bool {
    addr.into() != 0
}
```

## Step 3: Create Token Package

Create the ERC20 token package:

```bash
mkdir -p packages/token/src
```

Create `packages/token/Scarb.toml`:

```toml
[package]
name = "token"
version.workspace = true
edition.workspace = true
license.workspace = true

[dependencies]
starknet.workspace = true
common = { path = "../common" }

[[target.starknet-contract]]
sierra = true

[profile.release.cairo]
sierra-replace-ids = true
```

Create `packages/token/src/lib.cairo`:

```cairo
use starknet::ContractAddress;
use common::constants::SCALE_FACTOR;

#[starknet::interface]
pub trait IERC20<TContractState> {
    fn name(self: @TContractState) -> ByteArray;
    fn symbol(self: @TContractState) -> ByteArray;
    fn decimals(self: @TContractState) -> u8;
    fn total_supply(self: @TContractState) -> u256;
    fn balance_of(self: @TContractState, account: ContractAddress) -> u256;
    fn transfer(ref self: TContractState, recipient: ContractAddress, amount: u256) -> bool;
}

#[starknet::contract]
pub mod Token {
    use starknet::{ContractAddress, get_caller_address};
    use starknet::storage::{
        Map, StorageMapReadAccess, StorageMapWriteAccess,
        StoragePointerReadAccess, StoragePointerWriteAccess
    };

    #[storage]
    struct Storage {
        name: ByteArray,
        symbol: ByteArray,
        decimals: u8,
        total_supply: u256,
        balances: Map<ContractAddress, u256>,
    }

    #[constructor]
    fn constructor(
        ref self: ContractState,
        name: ByteArray,
        symbol: ByteArray,
        initial_supply: u256,
        recipient: ContractAddress
    ) {
        self.name.write(name);
        self.symbol.write(symbol);
        self.decimals.write(18);
        self.total_supply.write(initial_supply);
        self.balances.write(recipient, initial_supply);
    }

    #[abi(embed_v0)]
    impl ERC20Impl of super::IERC20<ContractState> {
        fn name(self: @ContractState) -> ByteArray {
            self.name.read()
        }

        fn symbol(self: @ContractState) -> ByteArray {
            self.symbol.read()
        }

        fn decimals(self: @ContractState) -> u8 {
            self.decimals.read()
        }

        fn total_supply(self: @ContractState) -> u256 {
            self.total_supply.read()
        }

        fn balance_of(self: @ContractState, account: ContractAddress) -> u256 {
            self.balances.read(account)
        }

        fn transfer(ref self: ContractState, recipient: ContractAddress, amount: u256) -> bool {
            let sender = get_caller_address();
            let sender_balance = self.balances.read(sender);
            assert(sender_balance >= amount, 'Insufficient balance');

            self.balances.write(sender, sender_balance - amount);
            self.balances.write(recipient, self.balances.read(recipient) + amount);
            true
        }
    }
}
```

## Step 4: Create Staking Package

Create the staking contract package:

```bash
mkdir -p packages/staking/src
```

Create `packages/staking/Scarb.toml`:

```toml
[package]
name = "staking"
version.workspace = true
edition.workspace = true
license.workspace = true

[dependencies]
starknet.workspace = true
common = { path = "../common" }
token = { path = "../token" }

[[target.starknet-contract]]
sierra = true

[profile.release.cairo]
sierra-replace-ids = true
```

Create `packages/staking/src/lib.cairo`:

```cairo
use starknet::ContractAddress;

#[starknet::interface]
pub trait IStaking<TContractState> {
    fn stake(ref self: TContractState, amount: u256);
    fn unstake(ref self: TContractState, amount: u256);
    fn get_staked_balance(self: @TContractState, account: ContractAddress) -> u256;
}

#[starknet::contract]
pub mod Staking {
    use starknet::{ContractAddress, get_caller_address};
    use starknet::storage::{
        Map, StorageMapReadAccess, StorageMapWriteAccess,
        StoragePointerReadAccess, StoragePointerWriteAccess
    };
    use common::is_valid_address;

    #[storage]
    struct Storage {
        token_address: ContractAddress,
        staked_balances: Map<ContractAddress, u256>,
        total_staked: u256,
    }

    #[constructor]
    fn constructor(ref self: ContractState, token_address: ContractAddress) {
        assert(is_valid_address(token_address), 'Invalid token address');
        self.token_address.write(token_address);
    }

    #[abi(embed_v0)]
    impl StakingImpl of super::IStaking<ContractState> {
        fn stake(ref self: ContractState, amount: u256) {
            let caller = get_caller_address();
            assert(amount > 0, 'Amount must be positive');

            let current_stake = self.staked_balances.read(caller);
            self.staked_balances.write(caller, current_stake + amount);
            self.total_staked.write(self.total_staked.read() + amount);
        }

        fn unstake(ref self: ContractState, amount: u256) {
            let caller = get_caller_address();
            let current_stake = self.staked_balances.read(caller);
            assert(current_stake >= amount, 'Insufficient staked balance');

            self.staked_balances.write(caller, current_stake - amount);
            self.total_staked.write(self.total_staked.read() - amount);
        }

        fn get_staked_balance(self: @ContractState, account: ContractAddress) -> u256 {
            self.staked_balances.read(account)
        }
    }
}
```

## Step 5: Build the Workspace

Build all packages in the workspace:

```bash
scarb build
```

**Expected Output:**
```
   Compiling common v1.0.0 (~/defi-protocol/packages/common/Scarb.toml)
   Compiling token v1.0.0 (~/defi-protocol/packages/token/Scarb.toml)
   Compiling staking v1.0.0 (~/defi-protocol/packages/staking/Scarb.toml)
    Finished release target(s) in 3 seconds
```

All three packages are built together, with dependencies resolved correctly.

## Step 6: Deploy Contracts

Deploy the contracts you want to verify. For this example, let's assume you've deployed:

**Token Contract:**
```
Class Hash: 0x044dc2b3239382230d8b1e943df23b96f52eebcac93efe6e8bde92f9a2f1da18
```

**Staking Contract:**
```
Class Hash: 0x055dc2b3239382230d8b1e943df23b96f52eebcac93efe6e8bde92f9a2f1da19
```

## Step 7: Verify Workspace Contracts

### Method 1: Verify with Explicit Package Selection

When verifying workspace contracts, you **must** specify which package to verify using `--package`:

```bash
# Verify the token contract
voyager verify \
    --network mainnet \
    --class-hash 0x044dc2b3239382230d8b1e943df23b96f52eebcac93efe6e8bde92f9a2f1da18 \
    --contract-name Token \
    --package token \
    --watch

# Verify the staking contract
voyager verify \
    --network mainnet \
    --class-hash 0x055dc2b3239382230d8b1e943df23b96f52eebcac93efe6e8bde92f9a2f1da19 \
    --contract-name Staking \
    --package staking \
    --watch
```

**Important:** Without `--package`, voyager-verifier won't know which package to verify in a workspace.

### Method 2: Using Configuration File with Default Package

Create `.voyager.toml` in the workspace root to set a default package:

```toml
[voyager]
network = "mainnet"
license = "MIT"
watch = true
verbose = false

[workspace]
default-package = "token"  # Set default package for verification
```

Now you can omit `--package` for the default:

```bash
# Verifies the default package (token)
voyager verify \
    --class-hash 0x044dc2b3239382230d8b1e943df23b96f52eebcac93efe6e8bde92f9a2f1da18 \
    --contract-name Token

# Still need to specify non-default packages
voyager verify \
    --class-hash 0x055dc2b3239382230d8b1e943df23b96f52eebcac93efe6e8bde92f9a2f1da19 \
    --contract-name Staking \
    --package staking
```

### Method 3: Batch Verification for Workspace

For multiple contracts in a workspace, use batch verification:

Create `.voyager.toml`:

```toml
[voyager]
network = "mainnet"
license = "MIT"
watch = true

[workspace]
default-package = "token"

# Define all contracts to verify
[[contracts]]
class-hash = "0x044dc2b3239382230d8b1e943df23b96f52eebcac93efe6e8bde92f9a2f1da18"
contract-name = "Token"
package = "token"

[[contracts]]
class-hash = "0x055dc2b3239382230d8b1e943df23b96f52eebcac93efe6e8bde92f9a2f1da19"
contract-name = "Staking"
package = "staking"
```

Then run batch verification:

```bash
voyager verify
```

This verifies both contracts automatically.

## Expected Output

### Single Package Verification

```
✓ Workspace detected: 3 packages found
✓ Selected package: token
✓ Building package: token (includes dependency: common)
✓ Files collected: 2 files
  - packages/token/src/lib.cairo
  - packages/common/src/lib.cairo
✓ Verification job submitted: abc-123-def-456

⏳ Waiting for verification...

✓ Verification successful!

View on Voyager: https://voyager.online/class/0x044dc2b3...
```

### Batch Workspace Verification

```
[1/2] Verifying: Token (package: token)
  ✓ Submitted - Job ID: abc-123-def

[2/2] Verifying: Staking (package: staking)
  ✓ Submitted - Job ID: ghi-456-jkl

════════════════════════════════════════
Batch Verification Summary
════════════════════════════════════════
Total contracts:  2
Submitted:        2
Succeeded:        0
Failed:           0
Pending:          2
════════════════════════════════════════

⏳ Watching verification jobs...

✓ All verifications completed successfully!
```

## Troubleshooting

### Error: "Package must be specified for workspace projects"

**Problem:** Didn't specify `--package` flag

**Solution:**
```bash
# Add --package flag
voyager verify \
    --network mainnet \
    --class-hash <HASH> \
    --contract-name Token \
    --package token  # Required for workspaces!
```

Or set `default-package` in `.voyager.toml`:
```toml
[workspace]
default-package = "token"
```

### Error: "Package 'xyz' not found in workspace"

**Problem:** Specified package doesn't exist or typo in package name

**Solutions:**
1. Check package name matches `[package]` name in `packages/xyz/Scarb.toml`
2. Verify package is listed in workspace `members` in root `Scarb.toml`
3. Ensure package directory structure is correct

### Error: "Dependency resolution failed"

**Problem:** Package dependencies not found or misconfigured

**Solutions:**
1. Verify `[dependencies]` in package Scarb.toml:
   ```toml
   common = { path = "../common" }  # Correct relative path
   ```
2. Check all workspace members are listed in root Scarb.toml
3. Run `scarb build` to test dependency resolution

### Files from Wrong Package Included

**Problem:** Incorrect package selected

**Solution:** Use `--dry-run` to verify correct files:
```bash
voyager verify \
    --network mainnet \
    --class-hash <HASH> \
    --contract-name Token \
    --package token \
    --dry-run  # Preview which files will be sent
```

## Best Practices

### 1. Use Workspace-Level Configuration

Create `.voyager.toml` at workspace root:

```toml
[voyager]
network = "mainnet"
license = "MIT"
watch = true
lock-file = true  # Include Scarb.lock for reproducible builds

[workspace]
default-package = "token"  # Most frequently verified package

[[contracts]]
class-hash = "0x044dc2..."
contract-name = "Token"
package = "token"

[[contracts]]
class-hash = "0x055dc2..."
contract-name = "Staking"
package = "staking"
```

### 2. Use Workspace Dependencies

Define shared dependencies at workspace level:

```toml
# Root Scarb.toml
[workspace.dependencies]
starknet = "2.13.1"
openzeppelin = "0.15.0"

# Package Scarb.toml
[dependencies]
starknet.workspace = true
openzeppelin.workspace = true
```

This ensures consistent versions across packages.

### 3. Set Default Package for Primary Contract

If you have a main contract that's verified often:

```toml
[workspace]
default-package = "token"  # Your primary contract package
```

### 4. Verify All Packages After Changes

When updating shared code (like `common`), re-verify all dependent contracts:

```bash
# Use batch verification
voyager verify  # Verifies all contracts in .voyager.toml
```

### 5. Use Consistent Naming

Match package names to contract purposes:

```
packages/
├── token/          # Contains Token contract
├── staking/        # Contains Staking contract
└── governance/     # Contains Governance contract
```

### 6. Include Lock File for Workspaces

For workspace projects, always include `Scarb.lock`:

```bash
voyager verify \
    --network mainnet \
    --class-hash <HASH> \
    --contract-name Token \
    --package token \
    --lock-file  # Ensures exact dependency versions
```

### 7. Test Individual Package Builds

Before verification, test each package builds correctly:

```bash
# Build specific package
scarb build --package token

# Build all packages
scarb build
```

## Common Workspace Patterns

### Pattern 1: Shared Library Package

```
workspace/
├── Scarb.toml
├── packages/
│   ├── lib/           # Shared utilities (not a contract)
│   │   └── src/
│   │       └── lib.cairo
│   ├── token/         # Uses lib
│   └── staking/       # Uses lib
```

Only verify `token` and `staking` (not `lib`).

### Pattern 2: Multiple Contract Implementations

```
workspace/
├── Scarb.toml
├── packages/
│   ├── erc20/         # ERC20 implementation
│   ├── erc721/        # ERC721 implementation
│   └── erc1155/       # ERC1155 implementation
```

Verify each contract independently:
```toml
[[contracts]]
package = "erc20"
# ...

[[contracts]]
package = "erc721"
# ...
```

### Pattern 3: Protocol Suite

```
workspace/
├── Scarb.toml
├── packages/
│   ├── core/          # Core protocol logic
│   ├── periphery/     # Helper contracts
│   ├── governance/    # Governance contracts
│   └── utils/         # Shared utilities
```

Use batch verification for the entire suite.

## Next Steps

Now that you understand workspace verification:

1. **[Dojo Projects](./dojo-project.md)** - Learn Dojo-specific verification
2. **[Batch Verification](./multi-contract.md)** - Master batch verification for multiple contracts
3. **[CI/CD Integration](./ci-pipeline.md)** - Automate workspace verification
4. **[Configuration Guide](../configuration/workspace.md)** - Deep dive into workspace configuration

## Additional Resources

- **[Workspace Configuration](../configuration/workspace.md)** - Complete workspace settings reference
- **[Batch Verification](./multi-contract.md)** - Multiple contract verification
- **[Scarb Workspaces](https://docs.swmansion.com/scarb/docs/reference/workspaces)** - Official Scarb workspace documentation
- **[Project Types](../core-concepts/project-types.md)** - Understanding different project structures

---

**Ready for more advanced examples?** Continue to [Dojo Project Verification](./dojo-project.md) →
