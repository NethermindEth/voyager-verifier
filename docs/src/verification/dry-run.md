# Dry Run Mode

Dry run mode allows you to preview what files would be collected and submitted for verification without actually sending them to the API. This is essential for debugging, validation, and understanding what your verification payload will contain.

## Overview

Dry run mode provides:

- **File preview** - See exactly which files will be included
- **Metadata display** - View contract and configuration details
- **Payload inspection** - Preview the complete verification payload
- **Zero API consumption** - No requests sent to the server
- **Safe testing** - Validate configuration without side effects
- **Debug tool** - Identify file collection issues before submission

## Basic Usage

Add the `--dry-run` flag to any `verify` command:

```bash
voyager verify --network mainnet \
  --class-hash 0x044dc2b3239382230d8b1e943df23b96f52eebcac93efe6e8bde92f9a2f1da18 \
  --contract-name MyToken \
  --dry-run
```

## What Gets Displayed

### 1. Configuration Summary

Shows the verification configuration that would be used:

```
════════════════════════════════════════════════════════
Dry Run: Verification Preview
════════════════════════════════════════════════════════

Configuration:
  Network:      mainnet
  API Endpoint: https://api.voyager.online/beta
  Class Hash:   0x044dc2b3239382230d8b1e943df23b96f52eebcac93efe6e8bde92f9a2f1da18
  Contract:     MyToken
  License:      MIT
  Package:      my_project
  Lock File:    No
  Test Files:   No
```

### 2. Project Information

Displays detected project metadata:

```
Project Details:
  Project Type: Scarb
  Project Path: /home/user/projects/my-contract
  Scarb Version: 2.11.2
  Cairo Version: 2.11.2
  Package Name:  my_project
```

### 3. File List

Shows all files that would be included in the verification:

```
Files to be submitted (5 files):
  ├── Scarb.toml (245 bytes)
  ├── src/lib.cairo (1,234 bytes)
  ├── src/contract.cairo (5,678 bytes)
  ├── src/utils.cairo (890 bytes)
  └── src/events.cairo (456 bytes)

Total size: 8,503 bytes (8.3 KB)
```

### 4. File Content Preview (Optional)

With `--verbose`, shows file contents:

```
File Contents:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
File: Scarb.toml
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
[package]
name = "my_project"
version = "0.1.0"
license = "MIT"

[dependencies]
starknet = ">=2.11.2"
...
```

## Complete Examples

### Basic Dry Run

Simple preview with default options:

```bash
voyager verify --network mainnet \
  --class-hash 0x044dc2b3... \
  --contract-name MyToken \
  --dry-run
```

### Dry Run with Lock File

Preview including `Scarb.lock`:

```bash
voyager verify --network mainnet \
  --class-hash 0x044dc2b3... \
  --contract-name MyToken \
  --lock-file \
  --dry-run
```

**Output includes:**
```
Files to be submitted (6 files):
  ├── Scarb.toml (245 bytes)
  ├── Scarb.lock (3,456 bytes)  # ← Lock file included
  ├── src/lib.cairo (1,234 bytes)
  ├── src/contract.cairo (5,678 bytes)
  ├── src/utils.cairo (890 bytes)
  └── src/events.cairo (456 bytes)
```

### Dry Run with Test Files

Preview including test files from `src/`:

```bash
voyager verify --network mainnet \
  --class-hash 0x044dc2b3... \
  --contract-name MyToken \
  --test-files \
  --dry-run
```

**Output includes:**
```
Files to be submitted (7 files):
  ├── Scarb.toml (245 bytes)
  ├── src/lib.cairo (1,234 bytes)
  ├── src/contract.cairo (5,678 bytes)
  ├── src/utils.cairo (890 bytes)
  ├── src/events.cairo (456 bytes)
  ├── src/test_helpers.cairo (678 bytes)  # ← Test file included
  └── src/tests.cairo (912 bytes)         # ← Test file included
```

### Verbose Dry Run

Show detailed file contents:

```bash
voyager verify --network mainnet \
  --class-hash 0x044dc2b3... \
  --contract-name MyToken \
  --dry-run \
  --verbose
```

### Workspace Dry Run

Preview verification for a specific package:

```bash
voyager verify --network mainnet \
  --class-hash 0x044dc2b3... \
  --contract-name TokenContract \
  --package token \
  --dry-run
```

**Output includes:**
```
Configuration:
  Network:      mainnet
  API Endpoint: https://api.voyager.online/beta
  Class Hash:   0x044dc2b3...
  Contract:     TokenContract
  Package:      token  # ← Package specified
  License:      MIT

Project Details:
  Project Type: Scarb (Workspace)
  Packages:     token, nft, marketplace
  Selected:     token
```

## Use Cases

### 1. Debug File Collection Issues

**Problem:** Verification fails with "Module file not found" errors.

**Solution:** Use dry run to see which files are being included:

```bash
voyager verify --network mainnet \
  --class-hash 0x044dc2b3... \
  --contract-name MyToken \
  --dry-run
```

Check the file list to ensure all required modules are present. If test files are missing, add `--test-files`.

### 2. Verify Test File Inclusion

**Problem:** Contract references test utilities but they're not included.

**Solution:** Compare dry run output with and without `--test-files`:

```bash
# Without test files
voyager verify --network mainnet \
  --class-hash 0x044dc2b3... \
  --contract-name MyToken \
  --dry-run

# With test files
voyager verify --network mainnet \
  --class-hash 0x044dc2b3... \
  --contract-name MyToken \
  --test-files \
  --dry-run
```

### 3. Check Lock File Inclusion

**Problem:** Verification builds with different dependency versions.

**Solution:** Verify `Scarb.lock` is included:

```bash
voyager verify --network mainnet \
  --class-hash 0x044dc2b3... \
  --contract-name MyToken \
  --lock-file \
  --dry-run
```

Look for `Scarb.lock` in the file list.

### 4. Validate Configuration

**Problem:** Unsure if config file settings are being applied correctly.

**Solution:** Run dry run to see effective configuration:

```bash
# With .voyager.toml in place
voyager verify --class-hash 0x044dc2b3... \
  --contract-name MyToken \
  --dry-run
```

The configuration summary shows the merged settings from config file and CLI arguments.

### 5. Preview Workspace Package Selection

**Problem:** Multiple packages, need to verify correct one is selected.

**Solution:** Dry run with package specification:

```bash
voyager verify --network mainnet \
  --class-hash 0x044dc2b3... \
  --contract-name MyToken \
  --package token \
  --dry-run
```

Check the "Selected" package in the output.

### 6. Estimate Payload Size

**Problem:** Need to know verification payload size before submission.

**Solution:** Check the total size in dry run output:

```
Total size: 8,503 bytes (8.3 KB)
```

Useful for understanding data transfer requirements.

### 7. Audit Before Production Deployment

**Problem:** Want to double-check everything before mainnet verification.

**Solution:** Run comprehensive dry run:

```bash
voyager verify --network mainnet \
  --class-hash 0x044dc2b3... \
  --contract-name ProductionContract \
  --license MIT \
  --lock-file \
  --dry-run \
  --verbose
```

Review all configuration, files, and contents before actual submission.

## Detailed Output Sections

### Configuration Section

Shows all verification parameters:

| Field | Description |
|-------|-------------|
| **Network** | Target network (mainnet/sepolia/dev) |
| **API Endpoint** | Full API URL being used |
| **Class Hash** | Contract class hash |
| **Contract** | Contract name |
| **License** | SPDX license identifier |
| **Package** | Package name (for workspace projects) |
| **Lock File** | Whether Scarb.lock is included |
| **Test Files** | Whether test files are included |

### Project Details Section

Shows detected project information:

| Field | Description |
|-------|-------------|
| **Project Type** | Scarb, Dojo, or Unknown |
| **Project Path** | Absolute path to project root |
| **Scarb Version** | Detected Scarb version |
| **Cairo Version** | Detected Cairo version |
| **Package Name** | Package identifier from Scarb.toml |
| **Packages** | List of packages (workspace only) |
| **Selected** | Selected package (workspace only) |

### File List Section

Shows all files to be submitted:

- File paths relative to project root
- File sizes in bytes
- Total payload size
- Tree-style formatting for readability

### File Content Section (Verbose Only)

With `--verbose`, displays:

- Full content of each file
- Syntax highlighting (if terminal supports it)
- Clear file separators
- Line numbers (optional)

## Combining with Other Flags

### Dry Run + Verbose

See full file contents:

```bash
voyager verify --network mainnet \
  --class-hash 0x044dc2b3... \
  --contract-name MyToken \
  --dry-run \
  --verbose
```

### Dry Run + Config File

Preview configuration from `.voyager.toml`:

```toml
# .voyager.toml
[voyager]
network = "mainnet"
license = "MIT"
lock-file = true
```

```bash
voyager verify --class-hash 0x044dc2b3... \
  --contract-name MyToken \
  --dry-run
```

### Dry Run + Custom Endpoint

Test custom API configuration:

```bash
voyager verify --url https://api.custom.com/beta \
  --class-hash 0x044dc2b3... \
  --contract-name MyToken \
  --dry-run
```

## Common Patterns

### Pre-Flight Check

Always dry run before actual verification:

```bash
# 1. Preview first
voyager verify --network mainnet \
  --class-hash 0x044dc2b3... \
  --contract-name MyToken \
  --lock-file \
  --dry-run

# 2. If looks good, submit
voyager verify --network mainnet \
  --class-hash 0x044dc2b3... \
  --contract-name MyToken \
  --lock-file \
  --watch
```

### Debug Workflow

Use dry run to troubleshoot issues:

```bash
# 1. Basic dry run
voyager verify --network mainnet \
  --class-hash 0x044dc2b3... \
  --contract-name MyToken \
  --dry-run

# 2. If files missing, try with test files
voyager verify --network mainnet \
  --class-hash 0x044dc2b3... \
  --contract-name MyToken \
  --test-files \
  --dry-run

# 3. Check detailed content
voyager verify --network mainnet \
  --class-hash 0x044dc2b3... \
  --contract-name MyToken \
  --test-files \
  --dry-run \
  --verbose
```

### Configuration Validation

Verify config file behavior:

```bash
# 1. Check what config file provides
voyager verify --class-hash 0x044dc2b3... \
  --contract-name MyToken \
  --dry-run

# 2. Test overrides
voyager verify --class-hash 0x044dc2b3... \
  --contract-name MyToken \
  --network sepolia \
  --dry-run
```

## Benefits

### Safety

- **No API consumption** - Doesn't count against rate limits
- **No side effects** - Nothing is submitted or recorded
- **Risk-free testing** - Experiment without consequences
- **Validation** - Catch issues before submission

### Debugging

- **File visibility** - See exactly what's included
- **Configuration transparency** - Understand effective settings
- **Quick iteration** - Test changes rapidly
- **Problem diagnosis** - Identify missing files or config issues

### Documentation

- **Self-documenting** - Shows what will happen
- **Team communication** - Share expected payload with team
- **Audit trail** - Record what was verified
- **Training** - Learn tool behavior safely

## Limitations

### What Dry Run Doesn't Do

1. **Server-side validation** - Can't catch API-specific errors
2. **Compilation check** - Doesn't verify code compiles on server
3. **Network testing** - Doesn't test API connectivity
4. **Authentication** - Doesn't validate API credentials
5. **Quota checking** - Doesn't verify rate limit status

### When to Use Actual Verification

After dry run looks good, use normal verification to:

- Test actual compilation on remote server
- Validate against Voyager API
- Check for server-side errors
- Complete the verification process

## Troubleshooting

### No Files Listed

**Problem:**
```
Files to be submitted (0 files):
  (none)
```

**Causes:**
- Wrong project path
- Not in a Scarb project
- Missing `Scarb.toml`

**Solutions:**
```bash
# Specify correct path
voyager verify --network mainnet \
  --class-hash 0x044dc2b3... \
  --contract-name MyToken \
  --path /correct/path \
  --dry-run

# Verify Scarb.toml exists
ls Scarb.toml
```

### Missing Test Files

**Problem:** Test files not showing in list.

**Solution:** Add `--test-files` flag:
```bash
voyager verify --network mainnet \
  --class-hash 0x044dc2b3... \
  --contract-name MyToken \
  --test-files \
  --dry-run
```

### Wrong Package Selected

**Problem:** Workspace showing wrong package.

**Solution:** Specify correct package:
```bash
voyager verify --network mainnet \
  --class-hash 0x044dc2b3... \
  --contract-name MyToken \
  --package correct_package \
  --dry-run
```

### Lock File Not Included

**Problem:** `Scarb.lock` missing from file list.

**Solution:** Add `--lock-file` flag:
```bash
voyager verify --network mainnet \
  --class-hash 0x044dc2b3... \
  --contract-name MyToken \
  --lock-file \
  --dry-run
```

## Integration with Workflow

### Development Cycle

```bash
# 1. Make code changes
vim src/contract.cairo

# 2. Test locally
scarb test

# 3. Build locally
scarb build

# 4. Preview verification (dry run)
voyager verify --network sepolia \
  --class-hash 0x123... \
  --contract-name MyContract \
  --dry-run

# 5. Submit verification
voyager verify --network sepolia \
  --class-hash 0x123... \
  --contract-name MyContract \
  --watch
```

### CI/CD Integration

```yaml
# .github/workflows/verify.yml
- name: Dry run verification preview
  run: |
    voyager verify \
      --network mainnet \
      --class-hash ${{ env.CLASS_HASH }} \
      --contract-name MyContract \
      --lock-file \
      --dry-run \
      --verbose > dry-run-output.txt

- name: Upload dry run results
  uses: actions/upload-artifact@v3
  with:
    name: verification-preview
    path: dry-run-output.txt

- name: Actual verification
  run: |
    voyager verify \
      --network mainnet \
      --class-hash ${{ env.CLASS_HASH }} \
      --contract-name MyContract \
      --lock-file \
      --verbose
```

## Next Steps

- **[Command-Line Verification](./command-line.md)** - Learn about all CLI options
- **[Watch Mode](./watch-mode.md)** - Monitor verification progress
- **[Troubleshooting](../troubleshooting/README.md)** - Debug verification issues
- **[Configuration File](../configuration/config-file.md)** - Set up persistent config
