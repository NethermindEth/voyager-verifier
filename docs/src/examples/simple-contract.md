# Simple Contract Example

This example walks through verifying a basic Starknet contract from scratch. It's perfect for first-time users or as a quick reference for standard verification workflows.

## Overview

You'll learn how to:
- Set up a basic Scarb project
- Write a simple Cairo contract
- Deploy and get a class hash
- Verify the contract using voyager-verifier
- Check verification status

**Time Required:** 10-15 minutes

**Difficulty:** Beginner

## Project Structure

We'll create a simple balance contract with this structure:

```
hello-starknet/
├── Scarb.toml          # Project configuration
├── Scarb.lock          # Dependency lock file (auto-generated)
├── .voyager.toml       # Optional: Verification config
└── src/
    └── lib.cairo       # Contract implementation
```

## Step 1: Create the Project

Initialize a new Scarb project:

```bash
scarb new hello-starknet
cd hello-starknet
```

This creates a new Cairo project with the basic structure.

## Step 2: Configure Scarb.toml

Update your `Scarb.toml` with the following configuration:

```toml
[package]
name = "hello_starknet"
version = "0.1.0"
edition = "2024_07"
license = "MIT"  # Add your SPDX license identifier

[dependencies]
starknet = ">=2.8.0"

[[target.starknet-contract]]
sierra = true

[profile.release.cairo]
# Add any compiler configurations needed for deployment here
# sierra-replace-ids = true
# inlining-strategy = "avoid"
```

**Important Notes:**
- The `license` field is optional but recommended
- Any compiler configuration for deployment must be under `[profile.release]`
- The remote verifier uses `scarb --release build`

## Step 3: Write the Contract

Replace `src/lib.cairo` with this simple balance contract:

```cairo
/// Interface representing `HelloStarknet` contract.
/// This interface allows modification and retrieval of the contract balance.
#[starknet::interface]
pub trait IHelloStarknet<TContractState> {
    /// Increase contract balance.
    fn increase_balance(ref self: TContractState, amount: felt252);
    /// Retrieve contract balance.
    fn get_balance(self: @TContractState) -> felt252;
}

/// Simple contract for managing balance.
#[starknet::contract]
mod HelloStarknet {
    use starknet::storage::{StoragePointerReadAccess, StoragePointerWriteAccess};

    #[storage]
    struct Storage {
        balance: felt252,
    }

    #[abi(embed_v0)]
    impl HelloStarknetImpl of super::IHelloStarknet<ContractState> {
        fn increase_balance(ref self: ContractState, amount: felt252) {
            assert(amount != 0, 'Amount cannot be 0');
            self.balance.write(self.balance.read() + amount);
        }

        fn get_balance(self: @ContractState) -> felt252 {
            self.balance.read()
        }
    }
}
```

This contract:
- Stores a `balance` value
- Provides `increase_balance()` to increment it
- Provides `get_balance()` to retrieve it
- Includes basic validation

## Step 4: Build the Contract

Verify your contract compiles correctly:

```bash
scarb build
```

**Expected Output:**
```
   Compiling hello_starknet v0.1.0 (~/hello-starknet/Scarb.toml)
    Finished release target(s) in 2 seconds
```

The compiled Sierra JSON will be in `target/dev/hello_starknet_HelloStarknet.contract_class.json`.

## Step 5: Deploy the Contract

Before verifying, you need to deploy your contract and obtain the class hash. There are several ways to deploy:

### Option A: Using Starkli

```bash
# Declare the contract class
starkli declare target/dev/hello_starknet_HelloStarknet.contract_class.json \
    --network mainnet \
    --account ~/.starkli-wallets/deployer/account.json \
    --keystore ~/.starkli-wallets/deployer/keystore.json

# This will return a class hash like:
# Class hash declared: 0x044dc2b3239382230d8b1e943df23b96f52eebcac93efe6e8bde92f9a2f1da18
```

### Option B: Using Starknet Foundry

```bash
sncast declare \
    --contract-name HelloStarknet \
    --url https://rpc.starknet.lava.build \
    --account myaccount

# Save the returned class hash
```

### Option C: Using a Deployment Script

Use your preferred deployment tooling (starknet.py, starknet.js, etc.) and note the class hash from the transaction receipt.

**Save Your Class Hash!** You'll need it for verification. For this example, let's assume:
```
Class Hash: 0x044dc2b3239382230d8b1e943df23b96f52eebcac93efe6e8bde92f9a2f1da18
```

## Step 6: Verify the Contract

Now verify your deployed contract using voyager-verifier.

### Method 1: Interactive Wizard (Recommended for Beginners)

```bash
voyager verify --wizard
```

The wizard will guide you through:
1. **Network selection**: Choose `mainnet`
2. **Class hash**: Enter your class hash
3. **Contract name**: Enter `HelloStarknet`
4. **License**: Confirm `MIT` (auto-detected from Scarb.toml)
5. **Optional features**: Choose any extras (watch mode, notifications, etc.)

### Method 2: Command-Line (Recommended for Automation)

```bash
voyager verify \
    --network mainnet \
    --class-hash 0x044dc2b3239382230d8b1e943df23b96f52eebcac93efe6e8bde92f9a2f1da18 \
    --contract-name HelloStarknet \
    --license MIT \
    --watch
```

**Flag Explanation:**
- `--network mainnet` - Verify on Starknet mainnet
- `--class-hash` - Your deployed class hash
- `--contract-name` - Contract name from your Cairo code
- `--license MIT` - SPDX license identifier (optional if in Scarb.toml)
- `--watch` - Wait and display verification progress

### Method 3: Using Configuration File

Create `.voyager.toml` in your project root:

```toml
[voyager]
network = "mainnet"
license = "MIT"
watch = true
verbose = false
```

Then run:

```bash
voyager verify \
    --class-hash 0x044dc2b3239382230d8b1e943df23b96f52eebcac93efe6e8bde92f9a2f1da18 \
    --contract-name HelloStarknet
```

## Step 7: Monitor Verification Status

### With Watch Mode

If you used `--watch`, you'll see real-time progress:

```
✓ Verification job submitted
  Job ID: abc-123-def-456

⏳ Checking verification status...

 ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100%  ⏱ 00:45

✓ Verification successful!

╭─────────────────────────────────────────╮
│ Verification Status                     │
├─────────────────────────────────────────┤
│ Status:      Success                    │
│ Job ID:      abc-123-def-456            │
│ Class Hash:  0x044dc2b3...              │
│ Contract:    HelloStarknet              │
│ Network:     mainnet                    │
╰─────────────────────────────────────────╯

View on Voyager: https://voyager.online/class/0x044dc2b3...
```

### Without Watch Mode

If you didn't use `--watch`, check status manually:

```bash
# Check status
voyager status --network mainnet --job abc-123-def-456

# Or check from history
voyager history status --job abc-123-def-456 --refresh
```

## Step 8: Verify on Voyager Website

Once verification succeeds, visit [Voyager](https://voyager.online) and search for your class hash. You should see:

- ✅ **Verified** badge next to your contract
- Full source code visible
- Contract name and license information
- Compile-time metadata

## Expected Output Summary

### Successful Verification

```
✓ Files collected: 1 file (src/lib.cairo)
✓ Project built successfully
✓ Verification job submitted: abc-123-def-456
✓ Status: Success
✓ Contract verified on Voyager
```

### Verification Record in History

```bash
voyager history list --limit 1
```

Output:
```
╭──────────────────────────────────────────────────────────╮
│ Recent Verifications                                     │
├──────────────────────────────────────────────────────────┤
│ [1] HelloStarknet                                        │
│     Status:    ✓ Success                                 │
│     Job:       abc-123-def-456                           │
│     Network:   mainnet                                   │
│     Submitted: 2025-11-06 14:30:00                       │
│     Class:     0x044dc2b3...                             │
╰──────────────────────────────────────────────────────────╯
```

## Troubleshooting

### Error: "Compilation failed"

**Problem:** Remote build failed

**Solutions:**
1. Verify local build works: `scarb --release build`
2. Check `[profile.release]` configuration in Scarb.toml
3. Use `--verbose` to see full compiler output:
   ```bash
   voyager status --network mainnet --job <JOB_ID> --verbose
   ```

### Error: "Class hash not found"

**Problem:** Class hash doesn't exist on the network

**Solutions:**
1. Verify the contract was actually declared/deployed
2. Check you're using the correct network (mainnet vs sepolia)
3. Confirm the class hash is correct (no typos)

### Error: "License not specified"

**Problem:** No license provided

**Solutions:**
1. Add `license = "MIT"` to `[package]` in Scarb.toml
2. Or provide via CLI: `--license MIT`
3. Use a valid SPDX identifier from [spdx.org/licenses](https://spdx.org/licenses/)

### Verification Pending for Too Long

**Problem:** Status stuck at "Pending" or "Compiling"

**Solutions:**
1. Wait a few more minutes (complex contracts take longer)
2. Check status with `--verbose` for details
3. Verify the network isn't experiencing issues

## Best Practices

### 1. Always Test Build Locally First

Before submitting verification:

```bash
# Test release build (same as remote verifier)
scarb --release build

# Verify it builds without errors
echo $?  # Should output: 0
```

### 2. Use Configuration Files for Consistent Settings

Create `.voyager.toml` for your project:

```toml
[voyager]
network = "mainnet"
license = "MIT"
watch = true
verbose = true
```

Commit this to version control for your team.

### 3. Enable Watch Mode for Immediate Feedback

Always use `--watch` during development:

```bash
voyager verify --network sepolia \
    --class-hash <HASH> \
    --contract-name MyContract \
    --watch \
    --verbose
```

### 4. Use Dry-Run to Preview Submission

Before actual verification:

```bash
voyager verify --network mainnet \
    --class-hash <HASH> \
    --contract-name HelloStarknet \
    --dry-run
```

This shows exactly what files will be sent.

### 5. Keep Verification Records

The history database tracks all verifications:

```bash
# View recent verifications
voyager history list --limit 10

# Filter by status
voyager history list --status success

# Generate statistics
voyager history stats
```

### 6. Specify License Explicitly

Even if your Scarb.toml has a license, be explicit:

```bash
voyager verify \
    --network mainnet \
    --class-hash <HASH> \
    --contract-name HelloStarknet \
    --license MIT  # Always explicit
```

### 7. Use Desktop Notifications for Long Verifications

For contracts that take time to verify:

```bash
voyager verify \
    --network mainnet \
    --class-hash <HASH> \
    --contract-name HelloStarknet \
    --watch \
    --notify  # Get desktop notification when done
```

Continue working on other tasks and get notified when complete.

## Common Variations

### Verifying on Sepolia (Testnet)

```bash
voyager verify \
    --network sepolia \
    --class-hash <YOUR_SEPOLIA_CLASS_HASH> \
    --contract-name HelloStarknet \
    --watch
```

### Using Custom API Endpoint

```bash
voyager verify \
    --url https://custom-api.example.com/beta \
    --class-hash <HASH> \
    --contract-name HelloStarknet
```

### Including Lock File

For reproducible builds:

```bash
voyager verify \
    --network mainnet \
    --class-hash <HASH> \
    --contract-name HelloStarknet \
    --lock-file  # Include Scarb.lock
```

### Verbose Output for Debugging

```bash
voyager verify \
    --network mainnet \
    --class-hash <HASH> \
    --contract-name HelloStarknet \
    --verbose  # Show detailed logs
```

## Next Steps

Congratulations! You've successfully verified your first contract. Here's what to explore next:

1. **[Workspace Projects](./workspace-project.md)** - Learn to verify multi-package projects
2. **[Batch Verification](./multi-contract.md)** - Verify multiple contracts at once
3. **[CI/CD Integration](./ci-pipeline.md)** - Automate verification in your pipeline
4. **[Configuration Guide](../configuration/README.md)** - Deep dive into all configuration options
5. **[History Tracking](../history/README.md)** - Manage verification history

## Additional Resources

- **[Installation Guide](../getting-started/README.md)** - Install voyager-verifier
- **[Quickstart](../getting-started/quickstart.md)** - Quick reference guide
- **[Command Reference](../commands/verify.md)** - Complete verify command options
- **[Troubleshooting Guide](../troubleshooting/README.md)** - Comprehensive error resolution
- **[Supported Versions](../reference/supported-versions.md)** - Cairo/Scarb compatibility

## FAQ

**Q: Do I need to verify on both mainnet and sepolia?**

A: No. Contracts verified on mainnet automatically appear verified on sepolia.

**Q: How long does verification take?**

A: Typically 30-60 seconds for simple contracts, longer for complex ones.

**Q: Can I verify an already-verified contract?**

A: Yes, but it's unnecessary. The verification status persists.

**Q: What if I update my contract?**

A: Deploy the new version (new class hash) and verify it separately. Each class hash is unique.

**Q: Is verification free?**

A: Yes, verification through Voyager is completely free.

**Q: Can I verify private/proprietary contracts?**

A: Verification makes source code public. Use `license = "All Rights Reserved"` for proprietary code, but note the source will still be visible.

---

**Have questions?** Check the [Troubleshooting Guide](../troubleshooting/README.md) or reach out on [Telegram](https://t.me/StarknetVoyager).
