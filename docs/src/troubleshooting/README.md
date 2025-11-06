# Troubleshooting Guide

Having issues with Voyager Verifier? This guide helps you quickly diagnose and resolve problems.

## Quick Problem Solver

```
Verification Failed?
        ↓
┌─────────────────────────────────┐
│ Check Error Code                │
│ → See Error Codes Reference     │
└─────────────────────────────────┘
        ↓
┌─────────────────────────────────┐
│ Common Error?                   │
│ → See Common Errors Guide       │
└─────────────────────────────────┘
        ↓
┌─────────────────────────────────┐
│ Need More Details?              │
│ → Use Verbose Mode              │
└─────────────────────────────────┘
        ↓
┌─────────────────────────────────┐
│ Still Stuck?                    │
│ → Follow Debugging Workflow     │
└─────────────────────────────────┘
        ↓
┌─────────────────────────────────┐
│ Need Help?                      │
│ → Contact Support               │
└─────────────────────────────────┘
```

---

## Troubleshooting Resources

### 1. [Common Errors](common-errors.md)
**Quick fixes for frequent problems**

Start here if you're encountering a common issue:
- Compilation errors
- Verification failures
- Configuration problems
- Network and API errors
- File and project errors
- Class hash issues

**When to Use:** You have an error and want a quick solution.

### 2. [Debugging Guide](debugging.md)
**Systematic troubleshooting workflow**

Follow the step-by-step debugging process:
- 6-step debugging workflow
- Debugging tools (dry-run, verbose, local testing, history)
- Common debugging scenarios
- Advanced debugging techniques

**When to Use:** Quick fixes didn't work and you need a systematic approach.

### 3. [Verbose Mode](verbose-mode.md)
**Understanding detailed output**

Learn how to use `--verbose` for detailed error information:
- Enabling verbose mode
- Interpreting verbose output
- Common verbose patterns
- Debugging with verbose mode

**When to Use:** You need more details about what's failing.

### 4. [Getting Support](support.md)
**How to get help**

Find support resources:
- Self-help documentation
- Telegram community
- GitHub issues
- Bug reporting guidelines

**When to Use:** You've tried everything and need human assistance.

---

## Quick Tips

### Compilation Failed?

```bash
# Build locally first
scarb --release build

# Check for syntax errors
scarb check
```

### Verification Failed?

```bash
# Use verbose mode to see details
voyager status --network mainnet --job <JOB_ID> --verbose

# Preview what will be submitted
voyager verify --dry-run ...
```

### Module Not Found?

```bash
# Include test files if needed
voyager verify --network mainnet \
  --class-hash 0x044dc2b3... \
  --contract-name MyContract \
  --test-files
```

### Class Hash Mismatch?

```bash
# Include Scarb.lock for reproducibility
voyager verify --network mainnet \
  --class-hash 0x044dc2b3... \
  --contract-name MyContract \
  --lock-file
```

### Network Issues?

```bash
# Check API status
curl https://api.voyager.online/api-docs

# Try a different network
voyager verify --network sepolia ...
```

### Job Taking Too Long?

```bash
# Check job status
voyager status --network mainnet --job <JOB_ID>

# View recent jobs
voyager history --network mainnet --limit 5
```

---

## Error Code Quick Reference

| Error Code | Category | Description |
|------------|----------|-------------|
| E001-E003 | Workspace | Package not found, no packages, workspace errors |
| E004-E009 | Verification | API submission, polling, job failures |
| E010-E014 | Dependencies | Resolution failures, missing dependencies |
| E015-E024 | Contract/Target | Invalid contract names, target not found |
| E025-E029 | File System | File not found, read errors, path issues |
| E030-E039 | Class Hash | Hash mismatch, parsing errors, format issues |
| E040-E042 | Config | Config file errors, parsing failures |

**See [Error Codes Reference](../reference/error-codes.md) for complete details.**

---

## Common Scenarios

### Scenario 1: First-Time Verification

**Problem:** Not sure where to start?

**Solution:**
```bash
# 1. Build your contract
cd my-project
scarb --release build

# 2. Get your class hash from deployment
# Example: 0x044dc2b3...

# 3. Verify with basic command
voyager verify --network mainnet \
  --class-hash 0x044dc2b3... \
  --contract-name MyContract

# 4. Check status
voyager status --network mainnet --job <JOB_ID>
```

**Learn More:** [Getting Started Guide](../getting-started/README.md)

### Scenario 2: Test Files Missing

**Problem:** Error E005 - Module file not found (test files)

**Solution:**
```bash
# Include test files in verification
voyager verify --network mainnet \
  --class-hash 0x044dc2b3... \
  --contract-name MyContract \
  --test-files
```

**Learn More:** [Test Files Guide](../advanced/test-files.md)

### Scenario 3: Class Hash Mismatch

**Problem:** Error E030 - Compiled hash doesn't match expected

**Solution:**
```bash
# 1. Include Scarb.lock for reproducibility
voyager verify --network mainnet \
  --class-hash 0x044dc2b3... \
  --contract-name MyContract \
  --lock-file

# 2. Ensure exact same versions
cat Scarb.toml  # Check Cairo/Scarb versions

# 3. Use dry-run to debug
voyager verify --dry-run ... --verbose
```

**Learn More:** [Lock Files Guide](../advanced/lock-files.md)

### Scenario 4: Multi-Package Workspace

**Problem:** Which package to verify in a workspace?

**Solution:**
```bash
# List available packages
scarb metadata

# Verify specific package
voyager verify --network mainnet \
  --class-hash 0x044dc2b3... \
  --contract-name MyContract \
  --package my_package
```

**Learn More:** [Multi-Package Guide](../core-features/multi-package.md)

### Scenario 5: Custom Network/Endpoint

**Problem:** Need to verify on custom network?

**Solution:**
```bash
# Use custom endpoint
voyager verify --network custom \
  --endpoint https://api.custom.com \
  --class-hash 0x044dc2b3... \
  --contract-name MyContract
```

**Learn More:** [Custom Endpoints Guide](../advanced/custom-endpoints.md)

---

## Debugging Checklist

Before asking for help, complete this checklist:

- [ ] **Read the error message** - What error code (E###) are you seeing?
- [ ] **Check [Common Errors](common-errors.md)** - Is your error listed?
- [ ] **Use verbose mode** - Run with `--verbose` flag
- [ ] **Try dry-run** - Use `--dry-run` to preview submission
- [ ] **Verify locally** - Can you build with `scarb build`?
- [ ] **Check versions** - Are Cairo/Scarb versions correct?
- [ ] **Review command** - Are all required flags present?
- [ ] **Test network** - Is the API endpoint responding?
- [ ] **Check history** - Have similar verifications succeeded before?

---

## Troubleshooting Tools

### 1. Verbose Mode

Get detailed error information:

```bash
voyager verify --verbose ...
voyager status --verbose ...
```

**See:** [Verbose Mode Guide](verbose-mode.md)

### 2. Dry-Run Mode

Preview submission without sending:

```bash
voyager verify --dry-run ...
```

**See:** [Debugging Guide](debugging.md#dry-run-mode)

### 3. History Command

Check previous verifications:

```bash
# Recent jobs
voyager history --network mainnet --limit 10

# Successful jobs only
voyager history --network mainnet --status verified

# Specific contract
voyager history --network mainnet --contract MyContract
```

**See:** [History Command Guide](../core-features/history.md)

### 4. Local Testing

Test before submitting:

```bash
# Build locally
scarb --release build

# Check for errors
scarb check

# Run tests
scarb test
```

---

## Prevention Tips

### ✅ Best Practices

1. **Always build locally first**
   ```bash
   scarb --release build
   ```

2. **Use lock files for reproducibility**
   ```bash
   # Commit Scarb.lock to version control
   git add Scarb.lock
   ```

3. **Test with dry-run before submitting**
   ```bash
   voyager verify --dry-run ...
   ```

4. **Use verbose mode when debugging**
   ```bash
   voyager verify --verbose ...
   ```

5. **Keep versions consistent**
   ```toml
   # In Scarb.toml
   [dependencies]
   starknet = "2.8.2"
   ```

6. **Include necessary files**
   ```bash
   # Include tests if they're imported
   voyager verify --test-files ...
   ```

---

## Getting Help

### Self-Help First

1. Check [Common Errors](common-errors.md)
2. Review [Error Codes Reference](../reference/error-codes.md)
3. Use [Debugging Workflow](debugging.md)
4. Try [Verbose Mode](verbose-mode.md)

### Community Support

- **Telegram:** [https://t.me/StarknetVoyager](https://t.me/StarknetVoyager)
- **GitHub Issues:** [https://github.com/NethermindEth/voyager-verifier/issues](https://github.com/NethermindEth/voyager-verifier/issues)

**See:** [Getting Support Guide](support.md)

---

## See Also

### Troubleshooting Resources
- [Common Errors](common-errors.md) - Quick fixes for frequent problems
- [Debugging Guide](debugging.md) - Systematic troubleshooting workflow
- [Verbose Mode](verbose-mode.md) - Understanding detailed output
- [Getting Support](support.md) - How to get help

### Reference Material
- [Error Codes](../reference/error-codes.md) - Complete error reference (E001-E042)
- [Supported Versions](../reference/supported-versions.md) - Version compatibility
- [File Collection](../reference/file-collection.md) - What files are included

### Feature Guides
- [Core Features](../core-features/README.md) - Essential functionality
- [Advanced Features](../advanced/README.md) - Advanced usage patterns
- [Getting Started](../getting-started/README.md) - Initial setup and usage
