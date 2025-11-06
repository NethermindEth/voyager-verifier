# Quickstart Guide

This guide will walk you through verifying your first contract in just a few minutes.

## Prerequisites

Before starting, ensure you have:

- ✅ Voyager Verifier installed ([installation guide](./README.md))
- ✅ A Scarb project that builds successfully (`scarb --release build`)
- ✅ A deployed contract with its class hash
- ✅ Your contract name

## Choose Your Path

There are three ways to verify a contract. Choose the one that fits your experience level:

### 🧙 Interactive Wizard (Recommended for First-Time Users)

The easiest way to verify your contract with guided prompts.

[Jump to Wizard Method →](#wizard-method)

### ⌨️ Command Line (For Experienced Users)

Direct command-line verification for those who know what they're doing.

[Jump to CLI Method →](#command-line-method)

### 📦 Batch Verification (For Multiple Contracts)

Verify multiple contracts at once using a configuration file.

[See Batch Verification Guide →](../verification/batch-verification.md)

---

## Wizard Method

The interactive wizard guides you through every step.

### 1. Navigate to Your Project

```bash
cd /path/to/your/scarb/project
```

### 2. Run the Wizard

```bash
voyager verify --wizard
```

### 3. Follow the Prompts

The wizard will ask you for:

1. **Network Selection**
   - Choose: Mainnet, Sepolia, Dev, or Custom
   - Example: `mainnet`

2. **Class Hash**
   - The class hash of your deployed contract
   - Example: `0x044dc2b3239382230d8b1e943df23b96f52eebcac93efe6e8bde92f9a2f1da18`

3. **Package** (for workspace projects only)
   - Select the package to verify
   - Auto-detected for single-package projects

4. **Contract Name**
   - The name of your contract
   - Example: `MyToken`

5. **License** (optional)
   - Auto-detected from `Scarb.toml` if present
   - Can specify manually (e.g., `MIT`, `Apache-2.0`)

6. **Optional Features**
   - Include lock file? (Scarb.lock)
   - Include test files? (from src/ directory)
   - Watch mode? (monitor status in real-time)
   - Verbose output? (detailed error messages)

### 4. Confirm and Submit

Review the summary and confirm to submit your verification.

### 5. Monitor Progress

If you enabled watch mode, the tool will automatically monitor the verification status. Otherwise, use the job ID to check status manually:

```bash
voyager status --network mainnet --job <JOB_ID>
```

---

## Command Line Method

For experienced users who prefer direct commands.

### 1. Navigate to Your Project

```bash
cd /path/to/your/scarb/project
```

### 2. Verify Your Contract

**Mainnet:**

```bash
voyager verify --network mainnet \
  --class-hash 0x044dc2b3239382230d8b1e943df23b96f52eebcac93efe6e8bde92f9a2f1da18 \
  --contract-name MyToken \
  --license MIT \
  --watch
```

**Sepolia (testnet):**

```bash
voyager verify --network sepolia \
  --class-hash 0x044dc2b3239382230d8b1e943df23b96f52eebcac93efe6e8bde92f9a2f1da18 \
  --contract-name MyToken \
  --license MIT \
  --watch
```

**Custom API endpoint:**

```bash
voyager verify --url https://api.custom.com/beta \
  --class-hash 0x044dc2b3239382230d8b1e943df23b96f52eebcac93efe6e8bde92f9a2f1da18 \
  --contract-name MyToken \
  --license MIT \
  --watch
```

### 3. Check Status

If you didn't use `--watch`, check the status manually:

```bash
voyager status --network mainnet --job <JOB_ID>
```

---

## Common Options

### Include Lock File

Include `Scarb.lock` for reproducible builds:

```bash
voyager verify --network mainnet \
  --class-hash 0x044... \
  --contract-name MyToken \
  --lock-file
```

### Include Test Files

Include test files from the `src/` directory:

```bash
voyager verify --network mainnet \
  --class-hash 0x044... \
  --contract-name MyToken \
  --test-files
```

### Watch Mode with Notifications

Monitor verification and get desktop notifications:

```bash
voyager verify --network mainnet \
  --class-hash 0x044... \
  --contract-name MyToken \
  --watch \
  --notify
```

### Verbose Output

Get detailed error messages if verification fails:

```bash
voyager verify --network mainnet \
  --class-hash 0x044... \
  --contract-name MyToken \
  --verbose
```

### Dry Run

Preview what will be submitted without actually verifying:

```bash
voyager verify --network mainnet \
  --class-hash 0x044... \
  --contract-name MyToken \
  --dry-run
```

---

## Workspace Projects

For projects with multiple packages, specify the package:

```bash
voyager verify --network mainnet \
  --class-hash 0x044... \
  --contract-name MyToken \
  --package my_contract_package
```

---

## Verification Status

### Understanding Status Messages

During verification, you'll see different status messages:

- **Submitted** - Verification job created, waiting to start
- **Compiling** - Remote compiler is building your contract
- **Verifying** - Comparing compiled output with deployed contract
- **Success** - Verification successful! ✅
- **Failed** - Verification failed (use `--verbose` for details) ❌
- **CompileFailed** - Compilation error (use `--verbose` for details) ❌

### Watch Mode

With `--watch`, you'll see a live progress bar:

```
⏳ Verifying contract...
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 45%
Status: Compiling | Elapsed: 1m 23s | Estimated: 3m 0s
```

### Manual Status Check

Without watch mode, check status anytime:

```bash
# Using the status command
voyager status --network mainnet --job abc-123-def

# Or using history
voyager history status --job abc-123-def
```

---

## View Your Verified Contract

Once verification succeeds:

1. Visit [Voyager Explorer](https://voyager.online)
2. Search for your class hash
3. You'll see the **verified** badge ✓
4. View your source code directly in the explorer

**Note:** Contracts verified on mainnet automatically appear verified on Sepolia as well.

---

## Example: Complete Workflow

Here's a complete example from start to finish:

```bash
# 1. Navigate to your project
cd ~/projects/my-starknet-token

# 2. Ensure it builds
scarb --release build

# 3. Verify on mainnet with watch mode
voyager verify --network mainnet \
  --class-hash 0x044dc2b3239382230d8b1e943df23b96f52eebcac93efe6e8bde92f9a2f1da18 \
  --contract-name MyToken \
  --license MIT \
  --watch \
  --notify

# 4. Wait for notification or completion message

# 5. View on Voyager
# Visit: https://voyager.online/class/0x044dc2b3239382230d8b1e943df23b96f52eebcac93efe6e8bde92f9a2f1da18
```

---

## Troubleshooting

### Common Issues

**Contract not building?**
```bash
# Test your build first
scarb --release build

# Check for errors and fix them
```

**Module file not found error?**

If you get errors about missing test files:
```bash
# Include test files in verification
voyager verify --network mainnet \
  --class-hash 0x044... \
  --contract-name MyToken \
  --test-files
```

**Want more details on errors?**
```bash
# Use verbose mode
voyager status --network mainnet --job <JOB_ID> --verbose
```

**Need to preview before submitting?**
```bash
# Use dry run mode
voyager verify --network mainnet \
  --class-hash 0x044... \
  --contract-name MyToken \
  --dry-run
```

For more troubleshooting help, see the [Troubleshooting Guide](../troubleshooting/README.md).

---

## Next Steps

Now that you've verified your first contract, explore more advanced features:

- **[Configuration Files](../configuration/config-file.md)** - Reduce command verbosity with `.voyager.toml`
- **[Batch Verification](../verification/batch-verification.md)** - Verify multiple contracts at once
- **[History Tracking](../history/README.md)** - View and manage verification history
- **[Watch Mode](../verification/watch-mode.md)** - Learn more about monitoring verifications
- **[Command Reference](../commands/README.md)** - Complete command documentation

---

## Quick Reference

### Minimal Command
```bash
voyager verify --network mainnet \
  --class-hash <HASH> \
  --contract-name <NAME>
```

### Recommended Command
```bash
voyager verify --network mainnet \
  --class-hash <HASH> \
  --contract-name <NAME> \
  --license MIT \
  --watch
```

### Full-Featured Command
```bash
voyager verify --network mainnet \
  --class-hash <HASH> \
  --contract-name <NAME> \
  --license MIT \
  --lock-file \
  --watch \
  --notify \
  --verbose
```

Happy verifying! 🚀
