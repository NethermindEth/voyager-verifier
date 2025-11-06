# Common Errors

This page covers the most frequent errors users encounter when using voyager-verifier, with practical solutions and examples.

**Quick Navigation:**
- [Compilation Errors](#compilation-errors)
- [Verification Failures](#verification-failures)
- [Configuration Issues](#configuration-issues)
- [Network & API Errors](#network--api-errors)
- [File & Project Errors](#file--project-errors)
- [Class Hash Issues](#class-hash-issues)

For a complete error code reference, see [Error Codes Reference](../reference/error-codes.md).

---

## Compilation Errors

### Module File Not Found

**Error:**
```
error[E0005]: Module file not found. Expected path: /tmp/targets/.../src/tests.cairo
```

**Common Cause:**
Your `lib.cairo` declares a test module, but test files are excluded by default.

**Quick Fix:**
```bash
# Option 1: Include test files
voyager verify --network mainnet \
  --class-hash 0x044dc2b3... \
  --contract-name MyContract \
  --test-files

# Option 2: Remove the module declaration from lib.cairo
```

**Edit lib.cairo:**
```cairo
// Before
mod contract;
mod tests;  // ← Remove this line

// After
mod contract;
// mod tests;  // Commented out or removed
```

**Why This Happens:**
The verifier excludes test files by default to reduce payload size. If your code references test modules, you need to either include them with `--test-files` or remove the references.

**See Also:** [Test Files Guide](../advanced/test-files.md)

---

### Remote Build Failed But Local Build Succeeds

**Symptoms:**
- `scarb --release build` works locally
- Remote verification fails with compilation errors

**Common Causes:**

1. **Missing dependencies in `[profile.release]`:**
   ```toml
   # ❌ Wrong: Settings in dev profile only
   [profile.dev.cairo]
   sierra-replace-ids = true

   # ✅ Correct: Settings in release profile
   [profile.release.cairo]
   sierra-replace-ids = true
   ```

2. **Local dependencies not available remotely:**
   ```toml
   # ❌ Problem: Local path dependency
   [dependencies]
   utils = { path = "../utils" }  # Not available on remote

   # ✅ Solution: Use git or registry dependency
   [dependencies]
   utils = { git = "https://github.com/org/utils" }
   ```

3. **Cairo version mismatch:**
   - Remote compiler may use different Cairo version
   - Use `--lock-file` to pin versions

**Solutions:**

**1. Check release profile:**
```bash
# Test with release profile locally
scarb --release build
```

**2. Use lock file:**
```bash
voyager verify --network mainnet \
  --class-hash 0x044dc2b3... \
  --contract-name MyContract \
  --lock-file  # Pin dependency versions
```

**3. Use verbose mode to see full error:**
```bash
voyager status --network mainnet --job <JOB_ID> --verbose
```

---

### Syntax Errors After Submission

**Error:**
```
[E004] Compilation failed: syntax error
```

**Quick Checklist:**
1. ✅ Does `scarb build` work locally?
2. ✅ Does `scarb --release build` work locally?
3. ✅ Are all files committed (not using uncommitted changes)?
4. ✅ Are imports correct?

**Common Issues:**

**1. Missing imports:**
```cairo
// ❌ Error: Missing import
mod MyContract {
    fn transfer() {
        ITokenDispatcher { ... }  // ITokenDispatcher not imported
    }
}

// ✅ Fixed: Add import
use token::ITokenDispatcher;

mod MyContract {
    fn transfer() {
        ITokenDispatcher { ... }
    }
}
```

**2. Incorrect module declarations:**
```cairo
// lib.cairo
// ❌ Wrong: Module file doesn't exist
mod utils;

// ✅ Check file exists:
// - src/utils.cairo OR
// - src/utils/mod.cairo
```

---

## Verification Failures

### Class Hash Mismatch

**Error:**
```
[E005] Verification failed: Compiled class hash does not match declared class hash
```

**Cause:**
The source code you submitted doesn't produce the same class hash as the deployed contract.

**Most Common Reasons:**

**1. Wrong source code version:**
```bash
# Check git history for deployed version
git log --oneline
git checkout <deployment-commit>

# Then verify
voyager verify --network mainnet \
  --class-hash 0x044dc2b3... \
  --contract-name MyContract
```

**2. Different dependency versions:**
```bash
# Use lock file to ensure same versions
voyager verify --network mainnet \
  --class-hash 0x044dc2b3... \
  --contract-name MyContract \
  --lock-file
```

**3. Different compiler settings:**
```toml
# Scarb.toml - Ensure these match deployment
[profile.release.cairo]
sierra-replace-ids = true  # Must match deployment settings
inlining-strategy = "default"
```

**4. Code modified after deployment:**
- Even whitespace changes can affect hash
- Use exact same source as deployment

**Debugging Steps:**

1. **Verify you have correct source:**
   ```bash
   # Check current commit
   git log -1

   # If using tags
   git checkout v1.0.0  # Or whatever tag was deployed
   ```

2. **Build locally and compare:**
   ```bash
   scarb --release build

   # Check the class hash in target/release/
   cat target/release/my_project_MyContract.contract_class.json | grep class_hash
   ```

3. **Try with lock file:**
   ```bash
   # Ensure Scarb.lock exists
   ls Scarb.lock

   # Verify with lock file
   voyager verify --network mainnet \
     --class-hash 0x044dc2b3... \
     --contract-name MyContract \
     --lock-file \
     --verbose
   ```

---

### Class Hash Not Declared

**Error:**
```
[E015] Class hash '<hash>' is not declared
```

**Cause:**
The class hash hasn't been declared on the network you're verifying against.

**Solutions:**

**1. Check correct network:**
```bash
# Wrong network?
voyager verify --network mainnet \
  --class-hash 0x044dc2b3...  # But declared on sepolia

# Try sepolia
voyager verify --network sepolia \
  --class-hash 0x044dc2b3...
```

**2. Verify on block explorer:**
- Check [Voyager](https://voyager.online) or [Starkscan](https://starkscan.co)
- Search for your class hash
- Confirm it's declared on the correct network

**3. Declare first if needed:**
```bash
# Using starkli
starkli declare target/release/my_contract_MyContract.contract_class.json

# Wait for confirmation, then verify
voyager verify --network mainnet \
  --class-hash <HASH_FROM_DECLARATION> \
  --contract-name MyContract
```

---

## Configuration Issues

### Invalid TOML Syntax in .voyager.toml

**Error:**
```
[E031] Failed to parse config file
```

**Common Mistakes:**

**1. Wrong field names:**
```toml
# ❌ Wrong: Using underscores
[voyager]
test_files = true
lock_file = true

# ✅ Correct: Using hyphens
[voyager]
test-files = true
lock-file = true
```

**2. Missing quotes for strings:**
```toml
# ❌ Wrong: No quotes
[voyager]
network = mainnet

# ✅ Correct: Quotes for strings
[voyager]
network = "mainnet"
```

**3. Extra quotes for booleans:**
```toml
# ❌ Wrong: Quotes on boolean
[voyager]
watch = "true"

# ✅ Correct: No quotes for boolean
[voyager]
watch = true
```

**4. Typos in field names:**
```toml
# ❌ Wrong: Typo
[voyager]
netwrok = "mainnet"

# ✅ Correct
[voyager]
network = "mainnet"
```

**Quick Fix:**
```bash
# Use example file as template
cp .voyager.toml.example .voyager.toml

# Or validate online
# Copy your config to https://www.toml-lint.com/
```

---

### Workspace Package Not Found

**Error:**
```
[E001] Package '<name>' not found in workspace
```

**Quick Fix:**
```bash
# List available packages
scarb metadata | grep name

# Use correct package name
voyager verify --network mainnet \
  --class-hash 0x044dc2b3... \
  --contract-name MyContract \
  --package correct_name
```

**Check Scarb.toml:**
```toml
[workspace]
members = [
    "package1",
    "package2",
    "package3",  # Use these exact names with --package
]
```

---

### No Contracts Selected

**Error:**
```
[E016] No contracts selected for verification
```

**Cause:**
You didn't specify which contract to verify.

**Solution:**
```bash
# Always specify contract name
voyager verify --network mainnet \
  --class-hash 0x044dc2b3... \
  --contract-name MyContract  # ← Required
```

---

## Network & API Errors

### Connection Failed / Timeout

**Error:**
```
[E999] Network error / Connection timeout
```

**Quick Checks:**

1. **Test internet connection:**
   ```bash
   ping api.voyager.online
   ```

2. **Check DNS:**
   ```bash
   nslookup api.voyager.online
   ```

3. **Test API endpoint:**
   ```bash
   curl -I https://api.voyager.online/beta
   ```

4. **Check firewall:**
   - Ensure HTTPS (port 443) is allowed
   - Check corporate firewall/proxy settings

**Solutions:**

```bash
# Retry request
voyager verify --network mainnet \
  --class-hash 0x044dc2b3... \
  --contract-name MyContract

# If using custom endpoint, verify URL
voyager verify --url https://api.voyager.online/beta \
  --class-hash 0x044dc2b3... \
  --contract-name MyContract
```

---

### Payload Too Large (413)

**Error:**
```
[E002] HTTP request failed: returned status 413
Payload Too Large
```

**Cause:**
Your project files exceed the 10MB API limit.

**Solutions:**

**1. Check project size:**
```bash
# Find large files
find . -type f -size +1M

# Check total source size
du -sh src/
```

**2. Exclude test files:**
```bash
# Don't use --test-files flag
voyager verify --network mainnet \
  --class-hash 0x044dc2b3... \
  --contract-name MyContract
  # Removed --test-files
```

**3. Exclude lock file:**
```bash
# Don't use --lock-file flag
voyager verify --network mainnet \
  --class-hash 0x044dc2b3... \
  --contract-name MyContract
  # Removed --lock-file
```

**4. Remove unnecessary files:**
```bash
# Check .gitignore
echo "target/" >> .gitignore
echo "*.bin" >> .gitignore

# Remove build artifacts
rm -rf target/
```

---

### Invalid API URL

**Error:**
```
[E006] Invalid base URL: example.com
```

**Cause:**
Custom URL is missing protocol or malformed.

**Fix:**
```bash
# ❌ Wrong: Missing protocol
voyager verify --url example.com/api/beta ...

# ✅ Correct: Include https://
voyager verify --url https://example.com/api/beta ...

# OR use predefined network
voyager verify --network mainnet ...
```

---

## File & Project Errors

### Scarb.toml Not Found

**Error:**
```
[E020] Scarb project manifest not found
```

**Solutions:**

**1. Check current directory:**
```bash
ls Scarb.toml  # Should exist
pwd  # Verify you're in project root
```

**2. Specify correct path:**
```bash
voyager verify --network mainnet \
  --class-hash 0x044dc2b3... \
  --contract-name MyContract \
  --path /path/to/project  # Path containing Scarb.toml
```

**3. Initialize new project:**
```bash
scarb init my-project
cd my-project
```

---

### Invalid File Type

**Error:**
```
[E024] File '<path>' has invalid file type (extension: .bin)
```

**Cause:**
Binary or non-Cairo files in project directory.

**Solution:**
```bash
# Remove binary files
rm src/*.bin
rm src/*.exe

# Add to .gitignore
echo "*.bin" >> .gitignore
echo "*.exe" >> .gitignore
echo "*.so" >> .gitignore
echo "target/" >> .gitignore
```

**Allowed Extensions:**
- `.cairo` - Cairo source
- `.toml` - Config files
- `.lock` - Lock files
- `.md`, `.txt` - Documentation
- `.json` - JSON files

---

### File Size Limit Exceeded

**Error:**
```
[E019] File '<path>' exceeds maximum size limit
```

**Solutions:**

**1. Split large files:**
```cairo
// Split into multiple modules
// Large file: src/contract.cairo (> 1MB)

// Split into:
// src/contract/core.cairo
// src/contract/helpers.cairo
// src/contract/mod.cairo
```

**2. Exclude large test files:**
```bash
# Don't include test files if they're large
voyager verify --network mainnet \
  --class-hash 0x044dc2b3... \
  --contract-name MyContract
  # Without --test-files
```

**3. Check for generated content:**
```bash
# Find large files
find src -type f -size +500k

# Remove if they're generated/temporary
```

---

## Class Hash Issues

### Invalid Class Hash Format

**Error:**
```
[E010] Invalid class hash format: '044dc2b3...'
```

**Cause:**
Class hash is missing `0x` prefix or contains invalid characters.

**Common Mistakes:**

**1. Missing 0x prefix:**
```bash
# ❌ Wrong
--class-hash 044dc2b3239382230d8b1e943df23b96f52eebcac93efe6e8bde92f9a2f1da18

# ✅ Correct
--class-hash 0x044dc2b3239382230d8b1e943df23b96f52eebcac93efe6e8bde92f9a2f1da18
```

**2. Invalid characters:**
```bash
# ❌ Wrong: Contains 'z' (not hex)
--class-hash 0x044dc2b3z39382230d8b1e943df23b96f52eebcac93efe6e8bde92f9a2f1da18

# ✅ Correct: Only hex (0-9, a-f)
--class-hash 0x044dc2b3239382230d8b1e943df23b96f52eebcac93efe6e8bde92f9a2f1da18
```

**3. Spaces or special characters:**
```bash
# ❌ Wrong: Contains spaces
--class-hash "0x044dc2b3 239382230d8b1e943df23b96f52eebcac93efe6e8bde92f9a2f1da18"

# ✅ Correct: No spaces
--class-hash 0x044dc2b3239382230d8b1e943df23b96f52eebcac93efe6e8bde92f9a2f1da18
```

---

## Quick Troubleshooting Workflow

When encountering an error, follow these steps:

### 1. Check Local Build First
```bash
# Does it build locally?
scarb --release build

# If local build fails, fix that first
# The remote will have the same error
```

### 2. Use Dry-Run Mode
```bash
# Preview what will be sent
voyager verify --network mainnet \
  --class-hash 0x044dc2b3... \
  --contract-name MyContract \
  --dry-run

# Check the file list is correct
```

### 3. Use Verbose Mode
```bash
# Get detailed error information
voyager status --network mainnet \
  --job <JOB_ID> \
  --verbose

# Read the full compiler output
```

### 4. Check Configuration
```bash
# Verify Scarb.toml
scarb metadata

# Check .voyager.toml if using
cat .voyager.toml
```

### 5. Verify Release Profile
```bash
# Check [profile.release] settings
cat Scarb.toml | grep -A 5 "\[profile.release\]"
```

---

## Most Common Error Combinations

### "Module not found" + Test File

**Pattern:**
```
error[E0005]: Module file not found. Expected path: .../tests.cairo
```

**Solution:**
```bash
voyager verify --network mainnet \
  --class-hash 0x044dc2b3... \
  --contract-name MyContract \
  --test-files  # ← Add this
```

---

### Compilation Passes Locally But Fails Remotely

**Checklist:**
- ✅ `scarb --release build` (not just `scarb build`)
- ✅ Settings in `[profile.release]` not `[profile.dev]`
- ✅ No local-only dependencies
- ✅ Consider using `--lock-file`

**Solution:**
```bash
# Test release build
scarb --release build

# Verify with lock file
voyager verify --network mainnet \
  --class-hash 0x044dc2b3... \
  --contract-name MyContract \
  --lock-file
```

---

### Verification Fails But Compilation Succeeds

**This means:** Code compiles but produces wrong class hash.

**Common causes:**
1. Wrong source version (not matching deployment)
2. Different dependency versions
3. Different compiler settings

**Solution:**
```bash
# 1. Check git version
git log -1

# 2. Use lock file
voyager verify --network mainnet \
  --class-hash 0x044dc2b3... \
  --contract-name MyContract \
  --lock-file \
  --verbose
```

---

## Prevention Tips

### 1. Always Test Release Build Locally
```bash
# Before verifying
scarb --release build
```

### 2. Use Configuration File
```toml
# .voyager.toml
[voyager]
network = "mainnet"
license = "MIT"
lock-file = true
verbose = true
```

### 3. Commit Scarb.lock
```bash
git add Scarb.lock
git commit -m "Add Scarb.lock for reproducible builds"
```

### 4. Document Deployment Settings
```toml
# Scarb.toml - Document why settings are needed
[profile.release.cairo]
# Required for deployment compatibility
sierra-replace-ids = true
```

### 5. Use Dry-Run Before Submission
```bash
# Preview first
voyager verify --network mainnet \
  --class-hash 0x044dc2b3... \
  --contract-name MyContract \
  --dry-run
```

---

## Getting More Help

**Still stuck?**

1. **Use verbose mode:**
   ```bash
   voyager status --network mainnet --job <JOB_ID> --verbose
   ```

2. **Check full error code reference:**
   - [Error Codes Reference](../reference/error-codes.md)

3. **Review debugging guide:**
   - [Debugging Guide](./debugging.md)

4. **Contact support:**
   - Telegram: [@StarknetVoyager](https://t.me/StarknetVoyager)
   - GitHub: [Open an issue](https://github.com/NethermindEth/voyager-verifier/issues)

**When asking for help, include:**
- Error code and message
- Full command you ran
- Output with `--verbose` flag
- Your Scarb.toml (remove sensitive info)
- Output of `scarb --release build`

---

## See Also

- [Error Codes Reference](../reference/error-codes.md) - Complete error code listing
- [Debugging Guide](./debugging.md) - Systematic debugging workflow
- [Verbose Mode](./verbose-mode.md) - Using `--verbose` for detailed output
- [Test Files](../advanced/test-files.md) - Including test files in verification
- [Lock Files](../advanced/lock-files.md) - Using Scarb.lock for reproducible builds
