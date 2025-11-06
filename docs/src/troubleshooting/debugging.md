# Debugging

This guide provides a systematic approach to debugging verification issues with voyager-verifier.

**Quick Navigation:**
- [Debugging Workflow](#debugging-workflow)
- [Debugging Tools](#debugging-tools)
- [Common Debugging Scenarios](#common-debugging-scenarios)
- [Step-by-Step Debugging](#step-by-step-debugging)
- [Advanced Techniques](#advanced-techniques)
- [Prevention Strategies](#prevention-strategies)

---

## Debugging Workflow

Follow this systematic approach when verification fails:

### 1. Identify the Problem
```
Verification Failed
       ↓
What stage failed?
  - Submission?
  - Compilation?
  - Verification?
```

**Questions to ask:**
- Did the submission succeed?
- Did compilation succeed?
- Did verification fail after compilation?

### 2. Gather Information
```bash
# Get detailed error output
voyager status --network mainnet --job <JOB_ID> --verbose

# Check what was submitted
voyager verify --network mainnet \
  --class-hash 0x044dc2b3... \
  --contract-name MyContract \
  --dry-run
```

### 3. Reproduce Locally
```bash
# Can you build locally?
scarb --release build

# Does it match your verification attempt?
```

### 4. Form Hypothesis
Based on the error and local testing:
- "The remote compiler can't find a dependency"
- "Test files are missing"
- "Class hash doesn't match because of version differences"

### 5. Test Hypothesis
```bash
# If hypothesis: "Test files are missing"
voyager verify --network mainnet \
  --class-hash 0x044dc2b3... \
  --contract-name MyContract \
  --test-files  # Test the fix
```

### 6. Verify Fix
```bash
# Did it work?
voyager status --network mainnet --job <NEW_JOB_ID>
```

---

## Debugging Tools

### Tool 1: Dry-Run Mode

**Purpose:** Preview what will be submitted without actually submitting.

**Usage:**
```bash
voyager verify --network mainnet \
  --class-hash 0x044dc2b3... \
  --contract-name MyContract \
  --dry-run
```

**What It Shows:**
```
Dry run - would submit verification for:
  Network: mainnet
  Class Hash: 0x044dc2b3...
  Contract Name: MyContract

Files to be included:
  src/lib.cairo
  src/contract.cairo
  src/utils.cairo
  Scarb.toml

Files excluded (test files):
  src/tests.cairo

Total files: 4
Total size: 125 KB
```

**When to Use:**
- Before first submission
- To check which files will be included
- To verify configuration is correct
- To check file count/size

**Example - Debugging Missing Files:**
```bash
# Run dry-run
voyager verify --network mainnet \
  --class-hash 0x044dc2b3... \
  --contract-name MyContract \
  --dry-run

# Output shows tests.cairo is excluded
# But your lib.cairo declares: mod tests;

# Solution: Add --test-files
voyager verify --network mainnet \
  --class-hash 0x044dc2b3... \
  --contract-name MyContract \
  --test-files \
  --dry-run  # Verify tests.cairo now included
```

---

### Tool 2: Verbose Mode

**Purpose:** Get detailed error messages and compiler output.

**Usage:**
```bash
# Verbose status check
voyager status --network mainnet --job <JOB_ID> --verbose

# Verbose verification (immediate)
voyager verify --network mainnet \
  --class-hash 0x044dc2b3... \
  --contract-name MyContract \
  --verbose
```

**What It Shows:**
- Full compiler output
- Detailed error messages
- Stack traces
- Build logs

**Example Output:**
```
Status: CompileFailed
Error: Compilation failed

Compiler Output:
error[E0005]: Module file not found. Expected path: /tmp/targets/release/src/tests.cairo
 --> src/lib.cairo:2:5
  |
2 | mod tests;
  |     ^^^^^
  |
```

**When to Use:**
- Compilation failed
- Verification failed
- Need to see full compiler output
- Debugging unclear errors

---

### Tool 3: Local Build Testing

**Purpose:** Test if the issue is local or remote.

**Key Commands:**
```bash
# Standard build (what you might run during development)
scarb build

# Release build (what remote compiler uses)
scarb --release build

# Check metadata
scarb metadata

# Validate project
scarb check
```

**Critical:** Always test with `--release` flag:
```bash
# ❌ Wrong: Testing dev build
scarb build  # Uses dev profile

# ✅ Correct: Testing release build
scarb --release build  # Uses release profile (same as remote)
```

**Debugging with Local Build:**
```bash
# 1. Try release build
scarb --release build

# 2. If it fails locally
#    → Fix the local build first
#    → Remote will have same error

# 3. If it succeeds locally but fails remotely
#    → Check release profile settings
#    → Check dependencies
#    → Use --verbose to see remote error
```

---

### Tool 4: History Commands

**Purpose:** Review past verification attempts.

**Usage:**
```bash
# List recent verifications
voyager history list --limit 10

# Check specific job
voyager history status --job <JOB_ID>

# Recheck failed jobs
voyager history recheck --failed

# View statistics
voyager history stats
```

**When to Use:**
- Compare successful vs failed attempts
- Track patterns in failures
- Verify same configuration
- Check past successful builds

---

## Common Debugging Scenarios

### Scenario 1: "Module Not Found" Error

**Error:**
```
error[E0005]: Module file not found. Expected path: .../src/tests.cairo
```

**Debugging Process:**

**Step 1: Check what's declared**
```bash
cat src/lib.cairo
# Shows: mod tests;
```

**Step 2: Check if file exists locally**
```bash
ls src/tests.cairo
# File exists locally
```

**Step 3: Check what's being submitted**
```bash
voyager verify --network mainnet \
  --class-hash 0x044dc2b3... \
  --contract-name MyContract \
  --dry-run

# Output shows: Files excluded (test files): src/tests.cairo
```

**Step 4: Hypothesis**
"Test files are excluded by default, but lib.cairo declares them"

**Step 5: Test fix**
```bash
voyager verify --network mainnet \
  --class-hash 0x044dc2b3... \
  --contract-name MyContract \
  --test-files  # Include test files
```

**Step 6: Verify**
```bash
voyager status --network mainnet --job <JOB_ID>
# Success!
```

---

### Scenario 2: Builds Locally But Fails Remotely

**Symptom:** `scarb --release build` works, remote compilation fails

**Debugging Process:**

**Step 1: Get remote error**
```bash
voyager status --network mainnet --job <JOB_ID> --verbose
```

**Step 2: Check release profile**
```bash
cat Scarb.toml | grep -A 10 "\[profile.release"
```

**Step 3: Look for common issues**
- Settings in `[profile.dev]` instead of `[profile.release]`
- Local path dependencies
- Missing dependencies

**Example Issue:**
```toml
# ❌ Problem: Settings in wrong profile
[profile.dev.cairo]
sierra-replace-ids = true

# ✅ Fix: Move to release profile
[profile.release.cairo]
sierra-replace-ids = true
```

**Step 4: Test locally with exact release settings**
```bash
# Clean build
rm -rf target/
scarb --release build
```

**Step 5: Resubmit**
```bash
voyager verify --network mainnet \
  --class-hash 0x044dc2b3... \
  --contract-name MyContract
```

---

### Scenario 3: Class Hash Mismatch

**Error:**
```
[E005] Verification failed: Compiled class hash does not match
```

**Debugging Process:**

**Step 1: Build locally and check hash**
```bash
scarb --release build

# Find the contract class file
find target/release -name "*.contract_class.json"

# Check the class hash
cat target/release/my_project_MyContract.contract_class.json | jq -r '.class_hash'
```

**Step 2: Compare hashes**
```bash
# Expected (from deployment):
0x044dc2b3239382230d8b1e943df23b96f52eebcac93efe6e8bde92f9a2f1da18

# Actual (from local build):
0x055dc2b3239382230d8b1e943df23b96f52eebcac93efe6e8bde92f9a2f1da19
# ↑ Different!
```

**Step 3: Identify why hashes differ**

Possible causes:
1. **Wrong source version**
   ```bash
   git log --oneline
   git checkout <deployment-commit>
   ```

2. **Different dependencies**
   ```bash
   # Check if Scarb.lock exists
   ls Scarb.lock

   # Use lock file
   voyager verify --network mainnet \
     --class-hash 0x044dc2b3... \
     --contract-name MyContract \
     --lock-file
   ```

3. **Different compiler settings**
   ```toml
   # Check deployment vs current settings
   [profile.release.cairo]
   sierra-replace-ids = true  # Must match deployment
   ```

**Step 4: Fix and verify**
```bash
# After fixing issue, rebuild
scarb --release build

# Check hash matches now
cat target/release/my_project_MyContract.contract_class.json | jq -r '.class_hash'
# Should match: 0x044dc2b3...

# Submit verification
voyager verify --network mainnet \
  --class-hash 0x044dc2b3... \
  --contract-name MyContract \
  --lock-file
```

---

## Step-by-Step Debugging

### Debug Checklist

Use this checklist for systematic debugging:

#### Phase 1: Local Validation
```bash
# ✅ 1. Does standard build work?
scarb build

# ✅ 2. Does release build work?
scarb --release build

# ✅ 3. Is project metadata valid?
scarb metadata

# ✅ 4. Are you in the right directory?
ls Scarb.toml
```

#### Phase 2: Configuration Check
```bash
# ✅ 5. Check release profile settings
cat Scarb.toml | grep -A 10 "\[profile.release"

# ✅ 6. Check dependencies
cat Scarb.toml | grep -A 20 "\[dependencies"

# ✅ 7. Check for local path dependencies
cat Scarb.toml | grep "path ="

# ✅ 8. Verify lock file if using
ls Scarb.lock
```

#### Phase 3: Dry-Run Validation
```bash
# ✅ 9. Preview submission
voyager verify --network mainnet \
  --class-hash 0x044dc2b3... \
  --contract-name MyContract \
  --dry-run

# ✅ 10. Check file list is complete
# Look for missing files in output
```

#### Phase 4: Submission & Monitoring
```bash
# ✅ 11. Submit verification
voyager verify --network mainnet \
  --class-hash 0x044dc2b3... \
  --contract-name MyContract \
  --verbose

# ✅ 12. Check status with verbose
voyager status --network mainnet --job <JOB_ID> --verbose
```

#### Phase 5: Error Analysis
```bash
# ✅ 13. Read error message carefully
# ✅ 14. Check error code in documentation
# ✅ 15. Compare with similar successful verifications
voyager history list --limit 5
```

---

## Advanced Techniques

### Technique 1: Comparing Builds

Compare successful vs failed attempts:

```bash
# List history
voyager history list --format json > history.json

# Find successful verification
jq '.[] | select(.status == "Success")' history.json

# Find failed verification
jq '.[] | select(.status == "CompileFailed")' history.json

# Compare parameters
```

---

### Technique 2: Incremental Testing

Test changes incrementally:

```bash
# Baseline (minimal flags)
voyager verify --network mainnet \
  --class-hash 0x044dc2b3... \
  --contract-name MyContract

# Test with lock file
voyager verify --network mainnet \
  --class-hash 0x044dc2b3... \
  --contract-name MyContract \
  --lock-file

# Test with test files
voyager verify --network mainnet \
  --class-hash 0x044dc2b3... \
  --contract-name MyContract \
  --test-files

# Test with both
voyager verify --network mainnet \
  --class-hash 0x044dc2b3... \
  --contract-name MyContract \
  --lock-file \
  --test-files
```

---

### Technique 3: Binary Search Debugging

For large projects, isolate the problem:

**Step 1: Divide**
```bash
# Test minimal contract
# Comment out half the code
# Does it build?
```

**Step 2: Conquer**
```bash
# If minimal works:
#   → Problem is in commented code
# If minimal fails:
#   → Problem is in active code
```

**Step 3: Repeat**
Keep dividing until you find the problematic code.

---

### Technique 4: Environment Matching

Ensure local matches remote:

```bash
# Check Cairo version
scarb --version

# Check dependencies
cat Scarb.lock | grep -A 5 "starknet"

# Use exact same scarb version as remote
asdf install scarb 2.11.4
asdf local scarb 2.11.4
```

---

## Prevention Strategies

### 1. Pre-Submission Checklist

Before every verification:

```bash
# 1. Local release build
scarb --release build

# 2. Dry-run preview
voyager verify --network mainnet \
  --class-hash 0x044dc2b3... \
  --contract-name MyContract \
  --dry-run

# 3. Check file list makes sense
# 4. Verify class hash format
# 5. Confirm correct network
```

---

### 2. Configuration Best Practices

**Use configuration file:**
```toml
# .voyager.toml
[voyager]
network = "mainnet"
license = "MIT"
lock-file = true  # Reproducible builds
verbose = true    # Always get details
```

**Document compiler settings:**
```toml
# Scarb.toml
[profile.release.cairo]
# IMPORTANT: These settings must match deployment
sierra-replace-ids = true
inlining-strategy = "default"
```

---

### 3. Version Control Integration

**Tag deployments:**
```bash
# When deploying
git tag -a v1.0.0-mainnet -m "Mainnet deployment"
git push --tags

# When verifying
git checkout v1.0.0-mainnet
voyager verify --network mainnet \
  --class-hash 0x044dc2b3... \
  --contract-name MyContract
```

**Commit lock files:**
```bash
git add Scarb.lock
git commit -m "Add Scarb.lock for v1.0.0"
```

---

### 4. Testing in Stages

**Stage 1: Development (Sepolia)**
```bash
# Test verification process on testnet first
voyager verify --network sepolia \
  --class-hash $DEV_HASH \
  --contract-name MyContract \
  --verbose
```

**Stage 2: Production (Mainnet)**
```bash
# Once process is proven, use on mainnet
voyager verify --network mainnet \
  --class-hash $PROD_HASH \
  --contract-name MyContract \
  --lock-file
```

---

### 5. Automation & CI/CD

**GitHub Actions Example:**
```yaml
- name: Test Verification (Dry-Run)
  run: |
    voyager verify \
      --network sepolia \
      --class-hash ${{ secrets.DEV_CLASS_HASH }} \
      --contract-name MyContract \
      --dry-run
```

This catches issues before actual deployment.

---

## Debugging Command Reference

### Quick Reference Table

| Scenario | Command | Purpose |
|----------|---------|---------|
| Preview submission | `--dry-run` | See what files will be sent |
| Get full error | `--verbose` | See complete compiler output |
| Test local build | `scarb --release build` | Verify builds locally |
| Check history | `voyager history list` | Review past attempts |
| Recheck failed | `voyager history recheck --failed` | Update status of old jobs |
| Compare builds | `voyager history list --format json` | Analyze patterns |
| Test incrementally | Add flags one at a time | Isolate problematic flag |
| Check metadata | `scarb metadata` | Validate project structure |

---

## Debugging Examples

### Example 1: Full Debug Session

**Problem:** Verification fails with compilation error

```bash
# Step 1: Get error details
$ voyager status --network mainnet --job abc-123 --verbose
Status: CompileFailed
Error: Module file not found: src/tests.cairo

# Step 2: Check local
$ ls src/tests.cairo
src/tests.cairo  # File exists locally!

# Step 3: Check what's submitted
$ voyager verify --network mainnet \
    --class-hash 0x044dc2b3... \
    --contract-name MyContract \
    --dry-run
Files excluded (test files):
  src/tests.cairo  # Aha! Excluded by default

# Step 4: Fix
$ voyager verify --network mainnet \
    --class-hash 0x044dc2b3... \
    --contract-name MyContract \
    --test-files  # Include test files

# Step 5: Verify fix
$ voyager status --network mainnet --job def-456
Status: Success ✅
```

---

### Example 2: Hash Mismatch Debug

**Problem:** Verification fails - hash mismatch

```bash
# Step 1: Build locally
$ scarb --release build

# Step 2: Check local hash
$ cat target/release/my_project_MyContract.contract_class.json | jq -r '.class_hash'
0x055dc2b3...  # Different from expected!

# Step 3: Check git history
$ git log --oneline
abc1234 (HEAD) Updated contract  # Current
def5678 Deployed to mainnet      # Deployment

# Step 4: Checkout deployment version
$ git checkout def5678

# Step 5: Rebuild
$ scarb --release build

# Step 6: Check hash again
$ cat target/release/my_project_MyContract.contract_class.json | jq -r '.class_hash'
0x044dc2b3...  # Matches! ✅

# Step 7: Verify
$ voyager verify --network mainnet \
    --class-hash 0x044dc2b3... \
    --contract-name MyContract \
    --lock-file

# Success! ✅
```

---

## Getting Help

If debugging doesn't resolve your issue:

1. **Document your debugging steps:**
   - What you tried
   - What results you got
   - Full error messages with `--verbose`

2. **Gather information:**
   ```bash
   # System info
   voyager --version
   scarb --version

   # Project info
   cat Scarb.toml

   # Error output
   voyager status --network mainnet --job <JOB_ID> --verbose
   ```

3. **Check resources:**
   - [Error Codes Reference](../reference/error-codes.md)
   - [Common Errors](./common-errors.md)
   - [Verbose Mode Guide](./verbose-mode.md)

4. **Ask for help:**
   - Telegram: [@StarknetVoyager](https://t.me/StarknetVoyager)
   - GitHub: [Create an issue](https://github.com/NethermindEth/voyager-verifier/issues)

**Include in your report:**
- Full command you ran
- Output with `--verbose`
- Your Scarb.toml
- Output of `scarb --release build`
- Steps you've already tried

---

## See Also

- [Common Errors](./common-errors.md) - Frequent problems and quick fixes
- [Verbose Mode](./verbose-mode.md) - Detailed guide to `--verbose` flag
- [Error Codes Reference](../reference/error-codes.md) - Complete error listing
- [Dry-Run Mode](../verification/dry-run.md) - Preview verification submissions
- [Getting Support](./support.md) - How to get help
