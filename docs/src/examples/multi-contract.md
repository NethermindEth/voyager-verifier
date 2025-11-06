# Multi-Contract Deployment

This example demonstrates batch verification of multiple contracts in a single command. Batch verification is ideal for protocol suites, multi-contract dApps, and team workflows where you need to verify many contracts efficiently.

## Overview

You'll learn how to:
- Configure batch verification with multiple contracts
- Submit and monitor multiple verifications simultaneously
- Use fail-fast mode for critical deployments
- Apply rate limiting with batch delays
- Handle partial failures gracefully
- Combine batch mode with workspace projects

**Time Required:** 15-20 minutes

**Difficulty:** Intermediate

## What is Batch Verification?

Batch verification allows you to verify multiple contracts in a single command by defining them in your `.voyager.toml` configuration file. Instead of running separate `verify` commands for each contract, batch mode:

- **Submits multiple contracts sequentially** - Processes contracts one by one
- **Tracks all jobs individually** - Each contract gets its own job ID
- **Continues on error by default** - Optional fail-fast mode available
- **Supports rate limiting** - Configurable delays between submissions
- **Provides comprehensive summaries** - Complete batch status at end
- **Integrates with watch mode** - Real-time monitoring of all jobs

## Use Cases

### Protocol Suite Deployment

Deploy an entire DeFi protocol with interconnected contracts:
- Core protocol contract
- Token contracts (ERC20, governance tokens)
- Staking and rewards contracts
- Treasury and timelock contracts
- Governance modules

### Multi-Contract dApp

Verify all contracts for a complex application:
- NFT collection contracts
- Marketplace contracts
- Royalty distributor
- Metadata registry
- Access control contracts

### Mass Verification After Network Migration

Re-verify all contracts after:
- Network upgrades
- API changes
- Source code updates
- License changes

### Team Workflows

Streamline team verification processes:
- Shared configuration in version control
- Consistent verification settings across team
- Automated batch verification in CI/CD
- Simplified deployment workflows

## Project Structure

We'll create a comprehensive DeFi protocol with multiple interconnected contracts:

```
defi-protocol/
├── Scarb.toml                    # Project configuration
├── Scarb.lock                    # Dependency lock file
├── .voyager.toml                 # Batch verification config
└── src/
    ├── lib.cairo                 # Module declarations
    ├── token.cairo               # ERC20 token contract
    ├── staking.cairo             # Staking contract
    ├── rewards.cairo             # Rewards distribution
    ├── governance.cairo          # Governance contract
    └── treasury.cairo            # Treasury management
```

## Step 1: Create the Project

Initialize a new Scarb project for our protocol:

```bash
scarb new defi-protocol
cd defi-protocol
```

## Step 2: Configure Scarb.toml

Update your `Scarb.toml`:

```toml
[package]
name = "defi_protocol"
version = "1.0.0"
edition = "2024_07"
license = "MIT"

[dependencies]
starknet = ">=2.8.0"

[[target.starknet-contract]]
sierra = true

[profile.release.cairo]
sierra-replace-ids = true
```

## Step 3: Create Multiple Contracts

For brevity, we'll show simplified contract examples. In practice, these would be full implementations.

### Token Contract (`src/token.cairo`)

```cairo
use starknet::ContractAddress;

#[starknet::interface]
pub trait IToken<TContractState> {
    fn name(self: @TContractState) -> ByteArray;
    fn symbol(self: @TContractState) -> ByteArray;
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
        self.total_supply.write(initial_supply);
        self.balances.write(recipient, initial_supply);
    }

    #[abi(embed_v0)]
    impl TokenImpl of super::IToken<ContractState> {
        fn name(self: @ContractState) -> ByteArray {
            self.name.read()
        }

        fn symbol(self: @ContractState) -> ByteArray {
            self.symbol.read()
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

### Staking Contract (`src/staking.cairo`)

```cairo
use starknet::ContractAddress;

#[starknet::interface]
pub trait IStaking<TContractState> {
    fn stake(ref self: TContractState, amount: u256);
    fn unstake(ref self: TContractState, amount: u256);
    fn get_staked_balance(self: @TContractState, account: ContractAddress) -> u256;
    fn total_staked(self: @TContractState) -> u256;
}

#[starknet::contract]
pub mod Staking {
    use starknet::{ContractAddress, get_caller_address};
    use starknet::storage::{
        Map, StorageMapReadAccess, StorageMapWriteAccess,
        StoragePointerReadAccess, StoragePointerWriteAccess
    };

    #[storage]
    struct Storage {
        token_address: ContractAddress,
        staked_balances: Map<ContractAddress, u256>,
        total_staked: u256,
    }

    #[constructor]
    fn constructor(ref self: ContractState, token_address: ContractAddress) {
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

        fn total_staked(self: @ContractState) -> u256 {
            self.total_staked.read()
        }
    }
}
```

### Rewards Contract (`src/rewards.cairo`)

```cairo
use starknet::ContractAddress;

#[starknet::interface]
pub trait IRewards<TContractState> {
    fn distribute_rewards(ref self: TContractState, amount: u256);
    fn claim_rewards(ref self: TContractState);
    fn get_pending_rewards(self: @TContractState, account: ContractAddress) -> u256;
}

#[starknet::contract]
pub mod Rewards {
    use starknet::{ContractAddress, get_caller_address};
    use starknet::storage::{
        Map, StorageMapReadAccess, StorageMapWriteAccess,
        StoragePointerReadAccess, StoragePointerWriteAccess
    };

    #[storage]
    struct Storage {
        staking_contract: ContractAddress,
        pending_rewards: Map<ContractAddress, u256>,
        total_distributed: u256,
    }

    #[constructor]
    fn constructor(ref self: ContractState, staking_contract: ContractAddress) {
        self.staking_contract.write(staking_contract);
    }

    #[abi(embed_v0)]
    impl RewardsImpl of super::IRewards<ContractState> {
        fn distribute_rewards(ref self: ContractState, amount: u256) {
            assert(amount > 0, 'Amount must be positive');
            self.total_distributed.write(self.total_distributed.read() + amount);
        }

        fn claim_rewards(ref self: ContractState) {
            let caller = get_caller_address();
            let rewards = self.pending_rewards.read(caller);
            assert(rewards > 0, 'No rewards to claim');

            self.pending_rewards.write(caller, 0);
        }

        fn get_pending_rewards(self: @ContractState, account: ContractAddress) -> u256 {
            self.pending_rewards.read(account)
        }
    }
}
```

### Governance Contract (`src/governance.cairo`)

```cairo
use starknet::ContractAddress;

#[starknet::interface]
pub trait IGovernance<TContractState> {
    fn propose(ref self: TContractState, description: ByteArray);
    fn vote(ref self: TContractState, proposal_id: u256, support: bool);
    fn execute(ref self: TContractState, proposal_id: u256);
}

#[starknet::contract]
pub mod Governance {
    use starknet::{ContractAddress, get_caller_address};
    use starknet::storage::{
        Map, StorageMapReadAccess, StorageMapWriteAccess,
        StoragePointerReadAccess, StoragePointerWriteAccess
    };

    #[storage]
    struct Storage {
        token_address: ContractAddress,
        proposal_count: u256,
        proposals: Map<u256, ByteArray>,
    }

    #[constructor]
    fn constructor(ref self: ContractState, token_address: ContractAddress) {
        self.token_address.write(token_address);
    }

    #[abi(embed_v0)]
    impl GovernanceImpl of super::IGovernance<ContractState> {
        fn propose(ref self: ContractState, description: ByteArray) {
            let proposal_id = self.proposal_count.read() + 1;
            self.proposals.write(proposal_id, description);
            self.proposal_count.write(proposal_id);
        }

        fn vote(ref self: ContractState, proposal_id: u256, support: bool) {
            assert(proposal_id <= self.proposal_count.read(), 'Invalid proposal ID');
            // Vote logic here
        }

        fn execute(ref self: ContractState, proposal_id: u256) {
            assert(proposal_id <= self.proposal_count.read(), 'Invalid proposal ID');
            // Execution logic here
        }
    }
}
```

### Treasury Contract (`src/treasury.cairo`)

```cairo
use starknet::ContractAddress;

#[starknet::interface]
pub trait ITreasury<TContractState> {
    fn deposit(ref self: TContractState, amount: u256);
    fn withdraw(ref self: TContractState, amount: u256, recipient: ContractAddress);
    fn get_balance(self: @TContractState) -> u256;
}

#[starknet::contract]
pub mod Treasury {
    use starknet::{ContractAddress, get_caller_address};
    use starknet::storage::{StoragePointerReadAccess, StoragePointerWriteAccess};

    #[storage]
    struct Storage {
        governance_address: ContractAddress,
        balance: u256,
    }

    #[constructor]
    fn constructor(ref self: ContractState, governance_address: ContractAddress) {
        self.governance_address.write(governance_address);
    }

    #[abi(embed_v0)]
    impl TreasuryImpl of super::ITreasury<ContractState> {
        fn deposit(ref self: ContractState, amount: u256) {
            assert(amount > 0, 'Amount must be positive');
            self.balance.write(self.balance.read() + amount);
        }

        fn withdraw(ref self: ContractState, amount: u256, recipient: ContractAddress) {
            let caller = get_caller_address();
            assert(caller == self.governance_address.read(), 'Only governance can withdraw');
            assert(amount <= self.balance.read(), 'Insufficient balance');

            self.balance.write(self.balance.read() - amount);
        }

        fn get_balance(self: @ContractState) -> u256 {
            self.balance.read()
        }
    }
}
```

### Module Declaration (`src/lib.cairo`)

```cairo
pub mod token;
pub mod staking;
pub mod rewards;
pub mod governance;
pub mod treasury;
```

## Step 4: Build the Project

Verify all contracts compile correctly:

```bash
scarb build
```

**Expected Output:**
```
   Compiling defi_protocol v1.0.0 (~/defi-protocol/Scarb.toml)
    Finished release target(s) in 4 seconds
```

## Step 5: Deploy All Contracts

Deploy each contract and save the class hashes. For this example, assume you've deployed:

**Token Contract:**
```
Class Hash: 0x044dc2b3239382230d8b1e943df23b96f52eebcac93efe6e8bde92f9a2f1da18
```

**Staking Contract:**
```
Class Hash: 0x055dc2b3239382230d8b1e943df23b96f52eebcac93efe6e8bde92f9a2f1da19
```

**Rewards Contract:**
```
Class Hash: 0x066dc2b3239382230d8b1e943df23b96f52eebcac93efe6e8bde92f9a2f1da20
```

**Governance Contract:**
```
Class Hash: 0x077dc2b3239382230d8b1e943df23b96f52eebcac93efe6e8bde92f9a2f1da21
```

**Treasury Contract:**
```
Class Hash: 0x088dc2b3239382230d8b1e943df23b96f52eebcac93efe6e8bde92f9a2f1da22
```

## Setting Up Batch Verification

### Method 1: Configuration File Approach (Recommended)

Create `.voyager.toml` in your project root with all contracts defined:

```toml
[voyager]
network = "mainnet"
license = "MIT"
watch = true
lock-file = true
verbose = false

# Define all contracts to verify
[[contracts]]
class-hash = "0x044dc2b3239382230d8b1e943df23b96f52eebcac93efe6e8bde92f9a2f1da18"
contract-name = "Token"

[[contracts]]
class-hash = "0x055dc2b3239382230d8b1e943df23b96f52eebcac93efe6e8bde92f9a2f1da19"
contract-name = "Staking"

[[contracts]]
class-hash = "0x066dc2b3239382230d8b1e943df23b96f52eebcac93efe6e8bde92f9a2f1da20"
contract-name = "Rewards"

[[contracts]]
class-hash = "0x077dc2b3239382230d8b1e943df23b96f52eebcac93efe6e8bde92f9a2f1da21"
contract-name = "Governance"

[[contracts]]
class-hash = "0x088dc2b3239382230d8b1e943df23b96f52eebcac93efe6e8bde92f9a2f1da22"
contract-name = "Treasury"
```

**Key Configuration Options:**

- `[voyager]` - Global settings applied to all contracts
- `[[contracts]]` - Array of contracts to verify (double brackets create array elements)
- `class-hash` - Required for each contract
- `contract-name` - Required for each contract
- `package` - Optional, for workspace projects (see Method 3)

### Method 2: Programmatic Approach

For dynamic batch verification, use a script to generate the config:

```bash
#!/bin/bash
# generate-batch-config.sh

# Read class hashes from deployment manifest
TOKEN_HASH=$(jq -r '.contracts.token' deployment.json)
STAKING_HASH=$(jq -r '.contracts.staking' deployment.json)
REWARDS_HASH=$(jq -r '.contracts.rewards' deployment.json)
GOVERNANCE_HASH=$(jq -r '.contracts.governance' deployment.json)
TREASURY_HASH=$(jq -r '.contracts.treasury' deployment.json)

# Generate .voyager.toml
cat > .voyager.toml <<EOF
[voyager]
network = "mainnet"
license = "MIT"
watch = true

[[contracts]]
class-hash = "$TOKEN_HASH"
contract-name = "Token"

[[contracts]]
class-hash = "$STAKING_HASH"
contract-name = "Staking"

[[contracts]]
class-hash = "$REWARDS_HASH"
contract-name = "Rewards"

[[contracts]]
class-hash = "$GOVERNANCE_HASH"
contract-name = "Governance"

[[contracts]]
class-hash = "$TREASURY_HASH"
contract-name = "Treasury"
EOF

echo "Generated .voyager.toml for batch verification"
```

**Usage:**
```bash
chmod +x generate-batch-config.sh
./generate-batch-config.sh
voyager verify
```

### Method 3: Workspace Batch Verification

For workspace projects with multiple packages:

```toml
[voyager]
network = "mainnet"
license = "MIT"
watch = true

[workspace]
default-package = "core"

# Contracts from different packages
[[contracts]]
class-hash = "0x044dc2..."
contract-name = "Token"
package = "token"  # Specify package explicitly

[[contracts]]
class-hash = "0x055dc2..."
contract-name = "Staking"
package = "staking"

[[contracts]]
class-hash = "0x066dc2..."
contract-name = "CoreLogic"
# Uses default-package = "core"
```

## Configuration Options

### Batch-Specific Flags

#### `--fail-fast`

Stop batch verification on first failure:

```bash
voyager verify --fail-fast
```

**Default behavior (without `--fail-fast`):**
- Continues with remaining contracts if one fails
- All results shown in final summary
- Maximum verification coverage

**With `--fail-fast`:**
- Stops immediately when a contract fails
- Remaining contracts are not submitted
- Useful for critical deployment pipelines where order matters

**Example:**
```bash
# Development: continue on error to see all issues
voyager verify --watch

# Production: stop on first failure
voyager verify --fail-fast --watch
```

#### `--batch-delay <SECONDS>`

Add delay between contract submissions for rate limiting:

```bash
voyager verify --batch-delay 5
```

**Use cases:**
- API rate limiting (avoid overwhelming the verification service)
- Server load management
- Staggered deployments for monitoring
- Large batches (10+ contracts)

**Recommended delays:**
- Small batches (2-5 contracts): 0-3 seconds
- Medium batches (6-15 contracts): 3-5 seconds
- Large batches (16+ contracts): 5-10 seconds

**Example:**
```bash
# Verify 10 contracts with 5 second delay
voyager verify --batch-delay 5 --watch
```

#### `--watch`

Monitor all verification jobs until completion:

```bash
voyager verify --watch
```

**Behavior:**
- Submits all contracts first
- Then monitors all jobs concurrently
- Shows real-time progress updates
- Displays final summary when all complete

**Output shows:**
- Number of succeeded verifications
- Number of pending verifications
- Number of failed verifications
- Updates every 2 seconds

#### `--notify`

Get desktop notifications when batch completes:

```bash
voyager verify --watch --notify
```

**Requires:** `--watch` flag must be enabled

**Notifications:**
- Success: "Batch verification completed: 5/5 succeeded"
- Partial: "Batch verification completed: 3/5 succeeded, 2 failed"
- Failure: "Batch verification failed: 0/5 succeeded"

### Per-Contract Configuration

Each contract in the `[[contracts]]` array can have individual settings:

```toml
[[contracts]]
class-hash = "0x123..."
contract-name = "Token"
package = "token"  # For workspace projects

[[contracts]]
class-hash = "0x456..."
contract-name = "NFT"
package = "nft"  # Different package

[[contracts]]
class-hash = "0x789..."
contract-name = "Marketplace"
# package omitted - uses workspace.default-package or auto-detect
```

### Overriding Global Settings

CLI arguments override config file settings:

```bash
# Config has network = "mainnet", but verify on sepolia
voyager verify --network sepolia

# Config has watch = false, but enable watch mode
voyager verify --watch

# Override license for this batch
voyager verify --license Apache-2.0
```

## Step-by-Step Batch Verification

### Step 1: Create the Configuration File

Create `.voyager.toml` in your project root:

```bash
touch .voyager.toml
```

### Step 2: Define All Contracts to Verify

Edit `.voyager.toml`:

```toml
[voyager]
network = "mainnet"
license = "MIT"
watch = true
lock-file = true

[[contracts]]
class-hash = "0x044dc2b3239382230d8b1e943df23b96f52eebcac93efe6e8bde92f9a2f1da18"
contract-name = "Token"

[[contracts]]
class-hash = "0x055dc2b3239382230d8b1e943df23b96f52eebcac93efe6e8bde92f9a2f1da19"
contract-name = "Staking"

[[contracts]]
class-hash = "0x066dc2b3239382230d8b1e943df23b96f52eebcac93efe6e8bde92f9a2f1da20"
contract-name = "Rewards"

[[contracts]]
class-hash = "0x077dc2b3239382230d8b1e943df23b96f52eebcac93efe6e8bde92f9a2f1da21"
contract-name = "Governance"

[[contracts]]
class-hash = "0x088dc2b3239382230d8b1e943df23b96f52eebcac93efe6e8bde92f9a2f1da22"
contract-name = "Treasury"
```

### Step 3: Run Batch Verification

Execute the batch:

```bash
voyager verify
```

That's it! No additional arguments needed. The tool automatically detects batch mode from the `[[contracts]]` array.

### Step 4: Monitor Progress

With `watch = true` in config (or `--watch` flag), you'll see real-time progress:

```
[1/5] Verifying: Token
  ✓ Submitted - Job ID: abc-123-def

[2/5] Verifying: Staking
  ✓ Submitted - Job ID: ghi-456-jkl

[3/5] Verifying: Rewards
  ✓ Submitted - Job ID: mno-789-pqr

[4/5] Verifying: Governance
  ✓ Submitted - Job ID: stu-012-vwx

[5/5] Verifying: Treasury
  ✓ Submitted - Job ID: yza-345-bcd

════════════════════════════════════════
Batch Verification Summary
════════════════════════════════════════
Total contracts:  5
Submitted:        5
Succeeded:        0
Failed:           0
Pending:          5
════════════════════════════════════════

⏳ Watching 5 verification job(s)...

  ✓ 2 Succeeded | ⏳ 3 Pending | ✗ 0 Failed

[Updates every 2 seconds...]
```

### Step 5: Handle Failures

If a contract fails, you'll see it in the summary:

```
[1/5] Verifying: Token
  ✗ Failed - Error: Invalid class hash format

[2/5] Verifying: Staking
  ✓ Submitted - Job ID: ghi-456-jkl

[Continues with remaining contracts...]
```

**To retry failed verifications:**

1. Fix the issue (e.g., correct class hash)
2. Update `.voyager.toml`
3. Run `voyager verify` again

**To verify only specific contracts:**

```bash
# Remove failed contracts from [[contracts]] array temporarily
# Or comment them out:
# [[contracts]]
# class-hash = "0x044dc2..."  # Failed, will fix later
# contract-name = "Token"
```

### Step 6: Verify Results

Once complete, check the final summary:

```
✓ 5 Succeeded | ⏳ 0 Pending | ✗ 0 Failed

════════════════════════════════════════
Batch Verification Summary
════════════════════════════════════════
Total contracts:  5
Submitted:        5
Succeeded:        5
Failed:           0
Pending:          0
════════════════════════════════════════

Contract Details:
  ✓ Success Token (Job: abc-123-def)
  ✓ Success Staking (Job: ghi-456-jkl)
  ✓ Success Rewards (Job: mno-789-pqr)
  ✓ Success Governance (Job: stu-012-vwx)
  ✓ Success Treasury (Job: yza-345-bcd)
```

Visit Voyager to confirm all contracts show verified badges.

## Running Batch Verification

### Basic Batch

Simple batch verification with default settings:

```bash
voyager verify
```

**Requirements:**
- `.voyager.toml` exists with `[[contracts]]` array
- `network` specified in config or via `--network` flag
- No `--class-hash` or `--contract-name` flags (these conflict with batch mode)

### With Watch Mode

Monitor until completion:

```bash
voyager verify --watch
```

**Output:**
- Real-time status updates
- Progress bar for each contract
- Final summary when complete
- Exit code 0 on success, non-zero on failure

### With Verbose Output

See detailed logs:

```bash
voyager verify --watch --verbose
```

**Shows:**
- File collection details
- Build output
- API requests/responses
- Detailed error messages
- Useful for debugging failures

### With Rate Limiting

Add delays between submissions:

```bash
voyager verify --watch --batch-delay 5
```

**Output:**
```
[1/5] Verifying: Token
  ✓ Submitted - Job ID: abc-123-def

[2/5] Verifying: Staking
  ⏳ Waiting 5 seconds before next submission...
  ✓ Submitted - Job ID: ghi-456-jkl

[3/5] Verifying: Rewards
  ⏳ Waiting 5 seconds before next submission...
  ✓ Submitted - Job ID: mno-789-pqr
```

### With Fail-Fast Mode

Stop on first failure:

```bash
voyager verify --fail-fast --watch
```

**Behavior:**
```
[1/5] Verifying: Token
  ✗ Failed - Error: Compilation failed

Batch verification stopped due to failure (--fail-fast enabled)

════════════════════════════════════════
Batch Verification Summary
════════════════════════════════════════
Total contracts:  5
Submitted:        1
Succeeded:        0
Failed:           1
Pending:          0
════════════════════════════════════════

Remaining contracts not processed: 4
```

### Combined Options

Use multiple flags together:

```bash
voyager verify --watch --batch-delay 3 --verbose --notify
```

**This enables:**
- Real-time monitoring (`--watch`)
- 3-second delays between submissions (`--batch-delay 3`)
- Detailed logging (`--verbose`)
- Desktop notification when complete (`--notify`)

## Output Examples

### Submission Phase

As each contract is submitted:

```
[1/5] Verifying: Token
  ✓ Files collected: 5 files
  ✓ Project built successfully
  ✓ Submitted - Job ID: abc-123-def-456

[2/5] Verifying: Staking
  ✓ Using cached build
  ✓ Submitted - Job ID: ghi-789-jkl-012

[3/5] Verifying: Rewards
  ✓ Using cached build
  ✓ Submitted - Job ID: mno-345-pqr-678

[4/5] Verifying: Governance
  ✓ Using cached build
  ✓ Submitted - Job ID: stu-901-vwx-234

[5/5] Verifying: Treasury
  ✓ Using cached build
  ✓ Submitted - Job ID: yza-567-bcd-890
```

**Note:** "Using cached build" appears when all contracts use the same source code (common in batch mode).

### Watch Phase

Real-time monitoring output:

```
════════════════════════════════════════
Batch Verification Summary
════════════════════════════════════════
Total contracts:  5
Submitted:        5
Succeeded:        0
Failed:           0
Pending:          5
════════════════════════════════════════

⏳ Watching 5 verification job(s)...

  ✓ 0 Succeeded | ⏳ 5 Pending | ✗ 0 Failed

[2 seconds later...]

  ✓ 2 Succeeded | ⏳ 3 Pending | ✗ 0 Failed

[4 seconds later...]

  ✓ 4 Succeeded | ⏳ 1 Pending | ✗ 0 Failed

[6 seconds later...]

  ✓ 5 Succeeded | ⏳ 0 Pending | ✗ 0 Failed

✓ All verifications completed successfully!
```

### Summary Output

Final batch summary:

```
════════════════════════════════════════
Batch Verification Summary
════════════════════════════════════════
Total contracts:  5
Submitted:        5
Succeeded:        5
Failed:           0
Pending:          0
════════════════════════════════════════

Contract Details:
  ✓ Success Token (Job: abc-123-def)
      View: https://voyager.online/class/0x044dc2b3...

  ✓ Success Staking (Job: ghi-789-jkl)
      View: https://voyager.online/class/0x055dc2b3...

  ✓ Success Rewards (Job: mno-345-pqr)
      View: https://voyager.online/class/0x066dc2b3...

  ✓ Success Governance (Job: stu-901-vwx)
      View: https://voyager.online/class/0x077dc2b3...

  ✓ Success Treasury (Job: yza-567-bcd)
      View: https://voyager.online/class/0x088dc2b3...

All verifications completed in 1m 23s
```

### Partial Failure Output

When some contracts fail:

```
════════════════════════════════════════
Batch Verification Summary
════════════════════════════════════════
Total contracts:  5
Submitted:        5
Succeeded:        3
Failed:           2
Pending:          0
════════════════════════════════════════

Contract Details:
  ✗ Failed Token - Compilation failed: cannot find 'unknown_module' in 'starknet'
      Job ID: abc-123-def

  ✓ Success Staking (Job: ghi-789-jkl)
      View: https://voyager.online/class/0x055dc2b3...

  ✓ Success Rewards (Job: mno-345-pqr)
      View: https://voyager.online/class/0x066dc2b3...

  ✗ Failed Governance - Class hash not found on network
      Job ID: stu-901-vwx

  ✓ Success Treasury (Job: yza-567-bcd)
      View: https://voyager.online/class/0x088dc2b3...

⚠ 2 contracts failed verification. Run with --verbose for details.
```

## Monitoring Batch Progress

### Real-Time Monitoring with Watch Mode

Enable watch mode for live updates:

```toml
[voyager]
watch = true  # In config
```

Or via CLI:
```bash
voyager verify --watch
```

**Output shows:**
- Submission progress (1/5, 2/5, etc.)
- Live status counts
- Progress updates every 2 seconds
- Final summary

### Manual Status Checks

Check individual job status:

```bash
# Check specific job from batch
voyager status --network mainnet --job abc-123-def-456

# Or use history commands
voyager history status --job abc-123-def-456 --refresh
```

### Progress Tracking with History

View batch in history:

```bash
# List recent verifications
voyager history list --limit 10

# Filter by status
voyager history list --status success
voyager history list --status fail

# Generate statistics
voyager history stats
```

**Example output:**
```
╭──────────────────────────────────────────────────────────╮
│ Recent Verifications                                     │
├──────────────────────────────────────────────────────────┤
│ [1] Token                                                │
│     Status:    ✓ Success                                 │
│     Job:       abc-123-def                               │
│     Network:   mainnet                                   │
│     Submitted: 2025-11-06 14:30:00                       │
│                                                          │
│ [2] Staking                                              │
│     Status:    ✓ Success                                 │
│     Job:       ghi-789-jkl                               │
│     Network:   mainnet                                   │
│     Submitted: 2025-11-06 14:30:05                       │
│                                                          │
│ [3] Rewards                                              │
│     Status:    ✓ Success                                 │
│     Job:       mno-345-pqr                               │
│     Network:   mainnet                                   │
│     Submitted: 2025-11-06 14:30:10                       │
╰──────────────────────────────────────────────────────────╯
```

### Understanding Progress Indicators

**Submission Phase:**
- `[1/5]` - Contract 1 of 5 being submitted
- `✓ Submitted` - Successfully submitted to verification service
- `✗ Failed` - Submission failed (e.g., invalid class hash)

**Watch Phase:**
- `✓ N Succeeded` - N contracts verified successfully
- `⏳ N Pending` - N contracts still compiling/verifying
- `✗ N Failed` - N contracts failed verification

**Final Status:**
- `✓ Success` - Contract verified successfully
- `✗ Failed` - Contract verification failed
- `⏳ Pending` - Still in progress (shouldn't happen in final state)

## Handling Failures

### Continue-on-Error (Default)

By default, batch verification continues even when contracts fail:

```bash
voyager verify --watch
```

**Behavior:**
- All contracts are attempted
- Failures are logged
- Summary shows all results
- Exit code non-zero if any failed

**Use when:**
- You want maximum coverage
- Failures are independent
- You'll fix issues after reviewing all results

**Example:**
```
[1/5] Verifying: Token
  ✗ Failed - Compilation error

[2/5] Verifying: Staking
  ✓ Submitted - Job ID: ghi-789-jkl

[3/5] Verifying: Rewards
  ✓ Submitted - Job ID: mno-345-pqr

[4/5] Verifying: Governance
  ✓ Submitted - Job ID: stu-901-vwx

[5/5] Verifying: Treasury
  ✓ Submitted - Job ID: yza-567-bcd

Final: 4 succeeded, 1 failed
```

### Fail-Fast Mode

Stop on first failure:

```bash
voyager verify --fail-fast --watch
```

**Behavior:**
- Stops immediately when a contract fails
- Remaining contracts are NOT submitted
- Useful for ordered deployments
- Exit code non-zero immediately

**Use when:**
- Contracts have dependencies
- Order matters (e.g., Token must verify before Staking)
- You want to fix issues before continuing
- In CI/CD where you want fast failures

**Example:**
```
[1/5] Verifying: Token
  ✗ Failed - Compilation error

Batch verification stopped due to failure (--fail-fast enabled)

Remaining contracts not processed:
  - Staking
  - Rewards
  - Governance
  - Treasury
```

### Retry Strategies

#### Strategy 1: Fix and Re-run Entire Batch

```bash
# Fix the issue in code
vim src/token.cairo

# Rebuild
scarb build

# Run batch again
voyager verify --watch
```

**Note:** Previously verified contracts will show "already verified" and skip quickly.

#### Strategy 2: Verify Failed Contracts Only

```bash
# Edit .voyager.toml to remove successful contracts
# Keep only failed ones

[[contracts]]
class-hash = "0x044dc2..."
contract-name = "Token"  # This one failed

# Run batch with only failed contracts
voyager verify --watch
```

#### Strategy 3: Individual Retry

```bash
# Verify failed contract individually
voyager verify \
    --network mainnet \
    --class-hash 0x044dc2b3239382230d8b1e943df23b96f52eebcac93efe6e8bde92f9a2f1da18 \
    --contract-name Token \
    --watch --verbose
```

### Debugging Failed Contracts

Use verbose mode to see detailed errors:

```bash
voyager verify --watch --verbose
```

**Verbose output shows:**
```
[1/5] Verifying: Token
  ✓ Files collected: 5 files
    - src/lib.cairo
    - src/token.cairo
    - src/staking.cairo
    - src/rewards.cairo
    - src/governance.cairo

  Building project...

  Error: Compilation failed

  Compiler output:
  error: Type `unknown_module::UnknownType` not found.
   --> src/token.cairo:2:5
      |
   2  |     use unknown_module::UnknownType;
      |         ^^^^^^^^^^^^^^^

  ✗ Failed - Compilation failed
```

**Common failure causes:**
1. **Compilation errors** - Syntax errors, missing imports
2. **Invalid class hash** - Typo or wrong network
3. **Class hash not found** - Contract not deployed yet
4. **Network errors** - API timeouts, connectivity issues
5. **License errors** - Invalid SPDX identifier

## Advanced Patterns

### Rate-Limited Batch

For large batches, add delays to avoid overwhelming the API:

```toml
[voyager]
network = "mainnet"
license = "MIT"
watch = true

# 20 contracts to verify
[[contracts]]
class-hash = "0x001..."
contract-name = "Contract01"

[[contracts]]
class-hash = "0x002..."
contract-name = "Contract02"

# ... (18 more)

[[contracts]]
class-hash = "0x020..."
contract-name = "Contract20"
```

**Run with rate limiting:**
```bash
voyager verify --batch-delay 10 --watch
```

**This will:**
- Submit one contract
- Wait 10 seconds
- Submit next contract
- Repeat until all submitted
- Then monitor all jobs concurrently

**Recommended delays for API rate limiting:**
- 10+ contracts: 5-10 second delay
- 20+ contracts: 10-15 second delay
- 50+ contracts: 15-20 second delay

### Conditional Verification

Verify only specific contracts from a batch using temporary config:

```bash
# Create temporary config for subset
cat > .voyager.tmp.toml <<EOF
[voyager]
network = "mainnet"
license = "MIT"
watch = true

[[contracts]]
class-hash = "0x044dc2..."
contract-name = "Token"

[[contracts]]
class-hash = "0x055dc2..."
contract-name = "Staking"
# Only these two
EOF

# Verify subset
cp .voyager.tmp.toml .voyager.toml
voyager verify
rm .voyager.tmp.toml
```

### Multi-Network Batches

Verify same contracts on different networks:

**Mainnet config (`.voyager.mainnet.toml`):**
```toml
[voyager]
network = "mainnet"
license = "MIT"

[[contracts]]
class-hash = "0x044dc2..."  # Mainnet hash
contract-name = "Token"

[[contracts]]
class-hash = "0x055dc2..."  # Mainnet hash
contract-name = "Staking"
```

**Sepolia config (`.voyager.sepolia.toml`):**
```toml
[voyager]
network = "sepolia"
license = "MIT"

[[contracts]]
class-hash = "0x066dc2..."  # Sepolia hash
contract-name = "Token"

[[contracts]]
class-hash = "0x077dc2..."  # Sepolia hash
contract-name = "Staking"
```

**Usage:**
```bash
# Verify on testnet first
cp .voyager.sepolia.toml .voyager.toml
voyager verify --watch

# Then on mainnet
cp .voyager.mainnet.toml .voyager.toml
voyager verify --watch
```

### Workspace + Batch

Combine workspace projects with batch verification:

```toml
[voyager]
network = "mainnet"
license = "MIT"
watch = true

[workspace]
default-package = "core"

# Contracts from different packages
[[contracts]]
class-hash = "0x044dc2..."
contract-name = "CoreToken"
package = "core"

[[contracts]]
class-hash = "0x055dc2..."
contract-name = "CoreGovernance"
package = "core"

[[contracts]]
class-hash = "0x066dc2..."
contract-name = "UtilsHelper"
package = "utils"

[[contracts]]
class-hash = "0x077dc2..."
contract-name = "NFTCollection"
package = "nft"

[[contracts]]
class-hash = "0x088dc2..."
contract-name = "Marketplace"
# Uses default-package = "core"
```

**Project structure:**
```
workspace/
├── .voyager.toml          # Batch config above
├── Scarb.toml             # Workspace root
└── packages/
    ├── core/
    │   ├── Scarb.toml
    │   └── src/
    ├── utils/
    │   ├── Scarb.toml
    │   └── src/
    └── nft/
        ├── Scarb.toml
        └── src/
```

**Verification:**
```bash
voyager verify --watch
```

All contracts from all packages verified in one batch!

## Best Practices

### 1. Test Individually First

Before batch verification, verify one contract works:

```bash
# Test single contract first
voyager verify \
    --network mainnet \
    --class-hash 0x044dc2b3239382230d8b1e943df23b96f52eebcac93efe6e8bde92f9a2f1da18 \
    --contract-name Token \
    --watch --verbose

# If successful, proceed with batch
voyager verify
```

**Why:** Catches configuration issues early without wasting time on entire batch.

### 2. Use --dry-run to Preview

Preview batch before submission:

```bash
voyager verify --dry-run
```

**Output shows:**
- Which contracts will be verified
- What files will be included
- Configuration summary
- No actual submission

### 3. Enable Watch Mode

Always use watch mode to see final results:

```bash
voyager verify --watch
```

**Benefits:**
- Real-time progress updates
- Immediate feedback on failures
- Don't need to manually check status later
- See full summary at end

### 4. Add Delays for Rate Limiting

For large batches, use delays:

```bash
# 10+ contracts: use 5-10 second delay
voyager verify --batch-delay 5 --watch

# 20+ contracts: use 10-15 second delay
voyager verify --batch-delay 10 --watch
```

**Prevents:**
- API rate limiting errors
- Server overload
- Network timeouts

### 5. Use Fail-Fast During Development

During development, stop on first failure:

```bash
voyager verify --fail-fast --watch
```

**Benefits:**
- Quick feedback on issues
- Don't waste time submitting bad contracts
- Fix one issue at a time

### 6. Continue-on-Error in Production

For production deployments, get maximum coverage:

```bash
voyager verify --watch
```

**Benefits:**
- All contracts attempted
- See all failures at once
- Maximum verification coverage

### 7. Track with History

Use history commands to monitor batch:

```bash
# View batch in history
voyager history list --limit 10

# Check specific contract
voyager history status --job abc-123-def

# Generate statistics
voyager history stats
```

### 8. Desktop Notifications

Get notified when batch completes:

```bash
voyager verify --watch --notify
```

**Benefits:**
- Continue working on other tasks
- Get notification when complete
- No need to monitor terminal

**Setup notifications:** See [Desktop Notifications](../advanced/notifications.md)

### 9. Version Control Your Config

Commit `.voyager.toml` to share with team:

```bash
git add .voyager.toml
git commit -m "Add batch verification config for DeFi protocol"
git push
```

**Benefits:**
- Team consistency
- Reproducible verifications
- Track changes over time
- Easy onboarding for new team members

### 10. Document Class Hashes

Keep track of deployments in comments:

```toml
[voyager]
network = "mainnet"
license = "MIT"

# Token contract - deployed 2025-11-06
[[contracts]]
class-hash = "0x044dc2b3239382230d8b1e943df23b96f52eebcac93efe6e8bde92f9a2f1da18"
contract-name = "Token"

# Staking contract - deployed 2025-11-06
[[contracts]]
class-hash = "0x055dc2b3239382230d8b1e943df23b96f52eebcac93efe6e8bde92f9a2f1da19"
contract-name = "Staking"

# Rewards contract - deployed 2025-11-06
[[contracts]]
class-hash = "0x066dc2b3239382230d8b1e943df23b96f52eebcac93efe6e8bde92f9a2f1da20"
contract-name = "Rewards"
```

## Troubleshooting

### Rate Limiting Errors

**Problem:** "Rate limit exceeded" or "Too many requests"

**Solution:**
```bash
# Add delays between submissions
voyager verify --batch-delay 10 --watch
```

**Prevention:**
- Use `--batch-delay` for large batches
- Recommended: 5-10 seconds for 10+ contracts

### Partial Failures

**Problem:** Some contracts verify, others fail

**Solution:**
```bash
# Use verbose mode to see why some failed
voyager verify --watch --verbose

# Check failed contracts individually
voyager verify \
    --network mainnet \
    --class-hash 0x<FAILED_HASH> \
    --contract-name FailedContract \
    --watch --verbose
```

**Then:**
1. Fix issues in failed contracts
2. Update `.voyager.toml` to include only failed contracts
3. Re-run batch

### Configuration Errors

**Problem:** "No contracts defined" or "Invalid configuration"

**Solution:**
1. Check `.voyager.toml` syntax:
```toml
# Correct
[[contracts]]
class-hash = "0x123..."
contract-name = "Token"

# Wrong - single bracket
[contracts]  # ❌ Should be [[contracts]]
```

2. Validate TOML:
```bash
cat .voyager.toml | toml-lint
```

3. Use example config:
```bash
cp .voyager.toml.example .voyager.toml
```

### Network Timeouts

**Problem:** "Request timeout" or "Network error"

**Solution:**
```bash
# Add delays to reduce load
voyager verify --batch-delay 10 --watch

# Verify smaller batches
# Split large batch into multiple runs
```

### Mixed Success/Failure Handling

**Problem:** How to handle batch with both successes and failures?

**Solution:**

**View summary:**
```bash
voyager verify --watch
# See which succeeded and which failed
```

**Retry only failures:**
1. Note which contracts failed from summary
2. Edit `.voyager.toml` to include only failed contracts
3. Run batch again

**Example:**
```toml
# Original batch: 5 contracts
# 3 succeeded, 2 failed (Token and Governance)
# Updated config with only failures:

[voyager]
network = "mainnet"
license = "MIT"

[[contracts]]
class-hash = "0x044dc2..."
contract-name = "Token"  # Failed, retry

[[contracts]]
class-hash = "0x077dc2..."
contract-name = "Governance"  # Failed, retry
```

### Batch Mode Not Detected

**Problem:** Running single verification instead of batch

**Solution:**

**Check:**
1. `.voyager.toml` has `[[contracts]]` array
2. Not using `--class-hash` or `--contract-name` flags
3. File is in current or parent directory

**Verify:**
```bash
# Should show batch mode
voyager verify --dry-run
```

## Complete Working Example

Here's a full end-to-end example with all files:

### Project Structure

```
defi-protocol/
├── Scarb.toml
├── Scarb.lock
├── .voyager.toml
├── deployment.json
└── src/
    ├── lib.cairo
    ├── token.cairo
    ├── staking.cairo
    ├── rewards.cairo
    ├── governance.cairo
    └── treasury.cairo
```

### Full .voyager.toml

```toml
[voyager]
# Network configuration
network = "mainnet"

# License (SPDX identifier)
license = "MIT"

# Enable watch mode for real-time monitoring
watch = true

# Include Scarb.lock for reproducible builds
lock-file = true

# Verbose output for debugging
verbose = false

# Desktop notifications when batch completes
notify = true

# Token Contract
[[contracts]]
class-hash = "0x044dc2b3239382230d8b1e943df23b96f52eebcac93efe6e8bde92f9a2f1da18"
contract-name = "Token"

# Staking Contract
[[contracts]]
class-hash = "0x055dc2b3239382230d8b1e943df23b96f52eebcac93efe6e8bde92f9a2f1da19"
contract-name = "Staking"

# Rewards Contract
[[contracts]]
class-hash = "0x066dc2b3239382230d8b1e943df23b96f52eebcac93efe6e8bde92f9a2f1da20"
contract-name = "Rewards"

# Governance Contract
[[contracts]]
class-hash = "0x077dc2b3239382230d8b1e943df23b96f52eebcac93efe6e8bde92f9a2f1da21"
contract-name = "Governance"

# Treasury Contract
[[contracts]]
class-hash = "0x088dc2b3239382230d8b1e943df23b96f52eebcac93efe6e8bde92f9a2f1da22"
contract-name = "Treasury"
```

### All Contracts Listed

See Step 3 above for full contract implementations.

### Expected Output from Start to Finish

```bash
$ voyager verify
```

**Output:**

```
Starting batch verification for 5 contracts...

[1/5] Verifying: Token
  ✓ Files collected: 5 files
    - src/lib.cairo
    - src/token.cairo
    - src/staking.cairo
    - src/rewards.cairo
    - src/governance.cairo
    - src/treasury.cairo
  ✓ Project built successfully
  ✓ Verification job submitted

  Job ID: abc-123-def-456
  Class Hash: 0x044dc2b3239382230d8b1e943df23b96f52eebcac93efe6e8bde92f9a2f1da18

[2/5] Verifying: Staking
  ✓ Using cached build
  ✓ Verification job submitted

  Job ID: ghi-789-jkl-012
  Class Hash: 0x055dc2b3239382230d8b1e943df23b96f52eebcac93efe6e8bde92f9a2f1da19

[3/5] Verifying: Rewards
  ✓ Using cached build
  ✓ Verification job submitted

  Job ID: mno-345-pqr-678
  Class Hash: 0x066dc2b3239382230d8b1e943df23b96f52eebcac93efe6e8bde92f9a2f1da20

[4/5] Verifying: Governance
  ✓ Using cached build
  ✓ Verification job submitted

  Job ID: stu-901-vwx-234
  Class Hash: 0x077dc2b3239382230d8b1e943df23b96f52eebcac93efe6e8bde92f9a2f1da21

[5/5] Verifying: Treasury
  ✓ Using cached build
  ✓ Verification job submitted

  Job ID: yza-567-bcd-890
  Class Hash: 0x088dc2b3239382230d8b1e943df23b96f52eebcac93efe6e8bde92f9a2f1da22

════════════════════════════════════════════════════════════════
Batch Verification Summary
════════════════════════════════════════════════════════════════
Total contracts:  5
Submitted:        5
Succeeded:        0
Failed:           0
Pending:          5
════════════════════════════════════════════════════════════════

Contract Details:
  ⏳ Submitted Token (Job: abc-123-def-456)
  ⏳ Submitted Staking (Job: ghi-789-jkl-012)
  ⏳ Submitted Rewards (Job: mno-345-pqr-678)
  ⏳ Submitted Governance (Job: stu-901-vwx-234)
  ⏳ Submitted Treasury (Job: yza-567-bcd-890)

⏳ Watching 5 verification job(s)...

  ✓ 0 Succeeded | ⏳ 5 Pending | ✗ 0 Failed

[Updating every 2 seconds...]

  ✓ 1 Succeeded | ⏳ 4 Pending | ✗ 0 Failed

  ✓ 2 Succeeded | ⏳ 3 Pending | ✗ 0 Failed

  ✓ 3 Succeeded | ⏳ 2 Pending | ✗ 0 Failed

  ✓ 4 Succeeded | ⏳ 1 Pending | ✗ 0 Failed

  ✓ 5 Succeeded | ⏳ 0 Pending | ✗ 0 Failed

✓ All verifications completed successfully!

════════════════════════════════════════════════════════════════
Final Batch Verification Summary
════════════════════════════════════════════════════════════════
Total contracts:  5
Submitted:        5
Succeeded:        5
Failed:           0
Pending:          0
════════════════════════════════════════════════════════════════

Contract Details:
  ✓ Success Token (Job: abc-123-def-456)
      Class: 0x044dc2b3239382230d8b1e943df23b96f52eebcac93efe6e8bde92f9a2f1da18
      View:  https://voyager.online/class/0x044dc2b3239382230d8b1e943df23b96f52eebcac93efe6e8bde92f9a2f1da18

  ✓ Success Staking (Job: ghi-789-jkl-012)
      Class: 0x055dc2b3239382230d8b1e943df23b96f52eebcac93efe6e8bde92f9a2f1da19
      View:  https://voyager.online/class/0x055dc2b3239382230d8b1e943df23b96f52eebcac93efe6e8bde92f9a2f1da19

  ✓ Success Rewards (Job: mno-345-pqr-678)
      Class: 0x066dc2b3239382230d8b1e943df23b96f52eebcac93efe6e8bde92f9a2f1da20
      View:  https://voyager.online/class/0x066dc2b3239382230d8b1e943df23b96f52eebcac93efe6e8bde92f9a2f1da20

  ✓ Success Governance (Job: stu-901-vwx-234)
      Class: 0x077dc2b3239382230d8b1e943df23b96f52eebcac93efe6e8bde92f9a2f1da21
      View:  https://voyager.online/class/0x077dc2b3239382230d8b1e943df23b96f52eebcac93efe6e8bde92f9a2f1da21

  ✓ Success Treasury (Job: yza-567-bcd-890)
      Class: 0x088dc2b3239382230d8b1e943df23b96f52eebcac93efe6e8bde92f9a2f1da22
      View:  https://voyager.online/class/0x088dc2b3239382230d8b1e943df23b96f52eebcac93efe6e8bde92f9a2f1da22

════════════════════════════════════════════════════════════════
All 5 contracts verified successfully in 1m 47s
════════════════════════════════════════════════════════════════

Desktop notification sent: "Batch verification completed: 5/5 succeeded"
```

**Verification complete!** Visit Voyager to see all contracts with verified badges.

## Next Steps

Now that you've mastered batch verification:

1. **[CI/CD Integration](../advanced/ci-cd.md)** - Automate batch verification in your deployment pipeline
2. **[Configuration Reference](../configuration/config-file.md)** - Deep dive into all configuration options
3. **[History Management](../commands/history.md)** - Track and analyze verification history
4. **[Workspace Projects](./workspace-project.md)** - Combine workspaces with batch verification
5. **[Desktop Notifications](../advanced/notifications.md)** - Setup notifications for batch completion

## Additional Resources

- **[Batch Verification Reference](../verification/batch-verification.md)** - Complete batch mode documentation
- **[Configuration File Guide](../configuration/config-file.md)** - Configuration file reference
- **[CLI Options Reference](../configuration/cli-options.md)** - All command-line flags
- **[Troubleshooting Guide](../troubleshooting/README.md)** - Comprehensive error resolution
- **[Simple Contract Example](./simple-contract.md)** - Basic single-contract verification
- **[Workspace Example](./workspace-project.md)** - Multi-package project verification
- **[Dojo Example](./dojo-project.md)** - Dojo project verification

---

**Ready to automate?** Continue to [CI/CD Integration](../advanced/ci-cd.md) to learn how to integrate batch verification into your deployment pipeline.
