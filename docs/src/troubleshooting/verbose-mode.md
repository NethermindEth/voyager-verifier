# Verbose Mode

The `--verbose` flag provides detailed error messages and compiler output to help diagnose verification issues.

**Quick Navigation:**
- [Overview](#overview)
- [Enabling Verbose Mode](#enabling-verbose-mode)
- [What Verbose Mode Shows](#what-verbose-mode-shows)
- [Reading Verbose Output](#reading-verbose-output)
- [Common Scenarios](#common-scenarios)
- [Best Practices](#best-practices)

---

## Overview

### What is Verbose Mode?

Verbose mode displays detailed information that is normally hidden, including:
- Full compiler output
- Complete error messages with context
- Stack traces
- Build process logs
- API response details

### When to Use Verbose Mode

Use `--verbose` when:
- ✅ Compilation fails and you need to see the compiler error
- ✅ Verification fails and you need detailed information
- ✅ You want to understand what went wrong
- ✅ The default error message is unclear
- ✅ Reporting an issue and need complete logs

**Don't use verbose mode when:**
- ❌ Everything is working fine (adds unnecessary output)
- ❌ You only need a quick status check

---

## Enabling Verbose Mode

### Method 1: Command-Line Flag

Add `--verbose` or `-v` to any command:

```bash
# Verbose verification
voyager verify --network mainnet \
  --class-hash 0x044dc2b3... \
  --contract-name MyContract \
  --verbose

# Verbose status check
voyager status --network mainnet --job <JOB_ID> --verbose

# Short form with -v
voyager status --network mainnet --job <JOB_ID> -v
```

### Method 2: Configuration File

Set as default in `.voyager.toml`:

```toml
[voyager]
network = "mainnet"
license = "MIT"
verbose = true  # Always use verbose mode
```

Then run without the flag:

```bash
voyager verify --class-hash 0x044dc2b3... --contract-name MyContract
# Automatically uses verbose mode
```

### Method 3: Environment-Specific Configs

Use verbose in development, not in production:

```toml
# .voyager.dev.toml
[voyager]
network = "sepolia"
verbose = true  # Verbose for development

# .voyager.prod.toml
[voyager]
network = "mainnet"
verbose = false  # Quiet for production
```

---

## What Verbose Mode Shows

### Standard Output vs Verbose Output

**Without `--verbose` (default):**
```
Status: CompileFailed
Error: Compilation failed
```

**With `--verbose`:**
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

Compilation failed with exit code: 1
```

### Information Displayed

**1. Full Compiler Output**
```
Compiler Output:
   Compiling my_project v0.1.0 (/tmp/targets/release/Scarb.toml)
error[E0005]: Module file not found. Expected path: /tmp/targets/release/src/tests.cairo
 --> src/lib.cairo:2:5
  |
2 | mod tests;
  |     ^^^^^
  |
```

**2. Error Context**
```
Error: Compilation failed

Context:
  Working directory: /tmp/targets/release
  Command: scarb --release build
  Exit code: 1
```

**3. Build Process Details**
```
Build Information:
  Cairo version: 2.11.4
  Scarb version: 2.11.4
  Profile: release
  Target: starknet-contract
```

**4. File Information**
```
Files included:
  src/lib.cairo (245 bytes)
  src/contract.cairo (1,832 bytes)
  Scarb.toml (412 bytes)

Total: 3 files, 2,489 bytes
```

**5. API Response Details**
```
API Response:
  Status Code: 200
  Job ID: abc-123-def-456
  Estimated time: 2-3 minutes
```

---

## Reading Verbose Output

### Structure of Verbose Output

Verbose output follows this structure:

```
1. Status Summary
   Status: CompileFailed

2. High-Level Error
   Error: Compilation failed

3. Detailed Information
   Compiler Output:
   [Full compiler error messages]

4. Context Information
   [Build settings, environment, etc.]
```

### Identifying the Problem

**Step 1: Read the status**
```
Status: CompileFailed  ← What stage failed?
```

**Step 2: Read the high-level error**
```
Error: Compilation failed  ← What type of error?
```

**Step 3: Find the specific error in compiler output**
```
Compiler Output:
error[E0005]: Module file not found  ← Specific error
```

**Step 4: Locate the source**
```
 --> src/lib.cairo:2:5  ← File and line number
```

**Step 5: Understand the context**
```
2 | mod tests;  ← The problematic code
  |     ^^^^^
```

---

## Common Scenarios

### Scenario 1: Module Not Found Error

**Command:**
```bash
voyager status --network mainnet --job abc-123 --verbose
```

**Verbose Output:**
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

For more information about this error, try `rustc --explain E0005`.
error: could not compile `my_project` (lib) due to 1 previous error
```

**Interpretation:**
- **Problem:** Module `tests` is declared in `lib.cairo` but file is missing
- **Location:** `src/lib.cairo` line 2, column 5
- **File expected:** `src/tests.cairo`
- **Solution:** Add `--test-files` flag or remove module declaration

---

### Scenario 2: Syntax Error

**Verbose Output:**
```
Status: CompileFailed
Error: Compilation failed

Compiler Output:
error: expected ';', found `}`
 --> src/contract.cairo:15:1
  |
14 |     let x = 5
   |              - help: add `;` here
15 | }
   | ^

error: aborting due to previous error
```

**Interpretation:**
- **Problem:** Missing semicolon
- **Location:** `src/contract.cairo` line 14
- **Fix:** Add semicolon after `let x = 5`

---

### Scenario 3: Import Error

**Verbose Output:**
```
Status: CompileFailed
Error: Compilation failed

Compiler Output:
error[E0433]: failed to resolve: use of undeclared crate or module `utils`
 --> src/contract.cairo:1:5
  |
1 | use utils::helpers;
  |     ^^^^^ use of undeclared crate or module `utils`

error: aborting due to previous error
```

**Interpretation:**
- **Problem:** Module `utils` doesn't exist or isn't declared
- **Location:** `src/contract.cairo` line 1
- **Solution:** Check `lib.cairo` has `mod utils;` or fix import path

---

### Scenario 4: Dependency Error

**Verbose Output:**
```
Status: CompileFailed
Error: Compilation failed

Compiler Output:
error: failed to download dependency `starknet`
  |
  = note: unable to get packages from source

Caused by:
  failed to parse manifest at `/tmp/targets/release/Scarb.toml`

Caused by:
  could not resolve dependency: starknet = "2.99.0"
```

**Interpretation:**
- **Problem:** Dependency version doesn't exist
- **Version:** `2.99.0` is not available
- **Solution:** Use valid version (e.g., `2.11.4`)

---

### Scenario 5: Verification Failure (Hash Mismatch)

**Verbose Output:**
```
Status: VerifyFailed
Error: Verification failed

Details:
  Expected class hash: 0x044dc2b3239382230d8b1e943df23b96f52eebcac93efe6e8bde92f9a2f1da18
  Compiled class hash: 0x055dc2b3239382230d8b1e943df23b96f52eebcac93efe6e8bde92f9a2f1da19

The compiled contract does not match the declared class hash.

Possible causes:
  - Source code doesn't match deployed contract
  - Different dependency versions
  - Different compiler settings
  - Different Cairo/Scarb version
```

**Interpretation:**
- **Problem:** Compiled hash doesn't match expected hash
- **Root cause:** Source code or environment mismatch
- **Solution:** Use `--lock-file`, check git version, verify compiler settings

---

## Verbose Output Examples

### Example 1: Successful Verification

**Command:**
```bash
voyager verify --network mainnet \
  --class-hash 0x044dc2b3... \
  --contract-name MyContract \
  --verbose
```

**Output:**
```
Submitting verification request...

Files included:
  src/lib.cairo (245 bytes)
  src/contract.cairo (1,832 bytes)
  src/utils.cairo (567 bytes)
  Scarb.toml (412 bytes)

Total: 4 files, 3,056 bytes

API Request:
  Endpoint: https://api.voyager.online/beta/verify
  Network: mainnet
  Class Hash: 0x044dc2b3239382230d8b1e943df23b96f52eebcac93efe6e8bde92f9a2f1da18
  Contract Name: MyContract

API Response:
  Status: 200 OK
  Job ID: abc-123-def-456
  Estimated time: 2-3 minutes

✅ Verification request submitted successfully!
Job ID: abc-123-def-456

Use the following command to check status:
  voyager status --network mainnet --job abc-123-def-456
```

---

### Example 2: Failed Compilation with Stack Trace

**Command:**
```bash
voyager status --network mainnet --job abc-123 --verbose
```

**Output:**
```
Status: CompileFailed
Error: Compilation failed

Compiler Output:
   Compiling my_project v0.1.0 (/tmp/targets/release/Scarb.toml)
error[E0425]: cannot find value `undefined_var` in this scope
  --> src/contract.cairo:23:13
   |
23 |     let x = undefined_var;
   |             ^^^^^^^^^^^^^ not found in this scope

error[E0308]: mismatched types
  --> src/contract.cairo:45:5
   |
45 |     return x + y
   |     ^^^^^^^^^^^^ expected `felt252`, found `()`
   |
   = note: expected type `felt252`
              found unit type `()`

error: aborting due to 2 previous errors

For more information about this error, try `rustc --explain E0425`.
error: could not compile `my_project` (lib) due to 2 previous errors

Build Information:
  Cairo version: 2.11.4
  Scarb version: 2.11.4
  Profile: release
  Working directory: /tmp/targets/release
  Exit code: 1
```

**Key Information:**
- Two errors found
- First error: undefined variable (line 23)
- Second error: type mismatch (line 45)
- Cairo/Scarb versions shown
- Exit code indicates failure

---

### Example 3: Network/API Error

**Command:**
```bash
voyager verify --network mainnet \
  --class-hash 0x044dc2b3... \
  --contract-name MyContract \
  --verbose
```

**Output:**
```
Submitting verification request...

Files included:
  src/lib.cairo (245 bytes)
  src/contract.cairo (1,832 bytes)
  Scarb.toml (412 bytes)

Total: 3 files, 2,494 bytes

API Request:
  Endpoint: https://api.voyager.online/beta/verify
  Method: POST
  Content-Type: multipart/form-data
  Content-Length: 3,125 bytes

API Response:
  Status: 413 Payload Too Large
  Error: Request entity too large

Details:
  Maximum allowed size: 10MB
  Your payload size: 12.5MB

Suggestion:
  - Remove test files (use verification without --test-files)
  - Remove lock file (use verification without --lock-file)
  - Check for large files in project

Error: [E002] HTTP request failed: https://api.voyager.online/beta/verify returned status 413
```

**Key Information:**
- Payload too large (12.5MB > 10MB limit)
- Detailed request information shown
- Suggestions for fixing the issue

---

## Practical Use Cases

### Use Case 1: Debugging Compilation Failures

**Problem:** Verification fails with "Compilation failed"

**Without verbose:**
```bash
$ voyager status --network mainnet --job abc-123
Status: CompileFailed
Error: Compilation failed
```
❌ Not helpful - what's wrong?

**With verbose:**
```bash
$ voyager status --network mainnet --job abc-123 --verbose
Status: CompileFailed
Error: Compilation failed

Compiler Output:
error[E0005]: Module file not found. Expected path: /tmp/targets/release/src/tests.cairo
 --> src/lib.cairo:2:5
```
✅ Clear! Missing tests.cairo file

**Solution:**
```bash
voyager verify --network mainnet \
  --class-hash 0x044dc2b3... \
  --contract-name MyContract \
  --test-files
```

---

### Use Case 2: Understanding Verification Failures

**Problem:** Verification fails - why?

**With verbose:**
```bash
$ voyager status --network mainnet --job abc-123 --verbose
Status: VerifyFailed
Error: Verification failed

Details:
  Expected: 0x044dc2b3...
  Compiled: 0x055dc2b3...

Possible causes:
  - Different source code version
  - Different dependencies
```
✅ Hash mismatch - need to check source version

**Solution:**
```bash
git checkout <deployment-commit>
voyager verify --network mainnet \
  --class-hash 0x044dc2b3... \
  --contract-name MyContract \
  --lock-file
```

---

### Use Case 3: Reporting Issues

**Scenario:** You need to report a bug or ask for help

**Without verbose:** Limited information
```
It fails with "Compilation failed"
```

**With verbose:** Complete information
```bash
$ voyager status --network mainnet --job abc-123 --verbose > error.log

# error.log contains:
# - Full compiler output
# - Error codes and line numbers
# - Build environment details
# - Version information
```

Share `error.log` with support team for faster resolution.

---

### Use Case 4: Comparing Successful vs Failed Builds

**Successful build with verbose:**
```bash
$ voyager status --network mainnet --job success-job --verbose > success.log
```

**Failed build with verbose:**
```bash
$ voyager status --network mainnet --job failed-job --verbose > failed.log
```

**Compare:**
```bash
$ diff success.log failed.log
# Shows exactly what's different
```

---

## Best Practices

### 1. Always Use Verbose for Failures

When something fails, immediately recheck with `--verbose`:

```bash
# Check failed without verbose
$ voyager status --network mainnet --job abc-123
Status: CompileFailed

# Immediately recheck with verbose
$ voyager status --network mainnet --job abc-123 --verbose
# Now you see the actual error!
```

---

### 2. Save Verbose Output to File

For complex issues, save output to a file:

```bash
# Save to file
voyager status --network mainnet --job abc-123 --verbose > debug.log

# Review at your leisure
cat debug.log

# Share with others
# Send debug.log to support
```

---

### 3. Use Verbose in Development

Set verbose in development config:

```toml
# .voyager.dev.toml
[voyager]
network = "sepolia"
verbose = true  # Always verbose in dev
watch = true
```

```bash
# Automatically uses verbose
voyager verify --class-hash 0x044dc2b3... --contract-name MyContract
```

---

### 4. Combine with Other Debug Tools

Use verbose with dry-run for maximum information:

```bash
# Preview what will be sent
voyager verify --network mainnet \
  --class-hash 0x044dc2b3... \
  --contract-name MyContract \
  --dry-run \
  --verbose

# Shows:
# - All files that will be included
# - Full configuration
# - Detailed request preview
```

---

### 5. Don't Use Verbose Unnecessarily

**❌ Don't:** Use verbose for routine successful checks
```bash
# Unnecessary verbose for success
voyager status --network mainnet --job abc-123 --verbose
Status: Success
# ... lots of unnecessary output
```

**✅ Do:** Use verbose only when investigating issues
```bash
# Quick check first
voyager status --network mainnet --job abc-123
Status: CompileFailed

# Then use verbose to debug
voyager status --network mainnet --job abc-123 --verbose
# Now you see why it failed
```

---

## Verbose Mode Checklist

When using verbose mode for debugging:

### Before Using Verbose
- [ ] Try command without verbose first
- [ ] Note if it succeeded or failed
- [ ] Identify what stage failed (submission, compilation, verification)

### With Verbose Output
- [ ] Read the status (CompileFailed, VerifyFailed, etc.)
- [ ] Find the specific error message
- [ ] Note the file and line number
- [ ] Check the compiler output for details
- [ ] Look for suggestions in the output

### After Reviewing Verbose
- [ ] Understand the root cause
- [ ] Identify the fix needed
- [ ] Apply the fix
- [ ] Test again
- [ ] Save verbose output if issue persists

---

## Troubleshooting Verbose Mode

### Issue: Too Much Output

**Problem:** Verbose output is overwhelming

**Solution:**
```bash
# Save to file and search
voyager status --network mainnet --job abc-123 --verbose > output.log
grep "error" output.log
grep "Error" output.log
```

---

### Issue: Output Not Showing

**Problem:** `--verbose` doesn't seem to work

**Check:**
```bash
# Ensure you're using correct syntax
voyager status --network mainnet --job abc-123 --verbose

# Not:
voyager status --network mainnet --job abc-123 verbose  # Missing --
```

---

### Issue: Need Even More Detail

**Problem:** Verbose output still not detailed enough

**Solution:** Check source code or use debugging tools
```bash
# Get scarb's verbose output
scarb --release build --verbose

# Check metadata
scarb metadata
```

---

## Common Verbose Patterns

### Pattern 1: File Not Found
```
error[E0005]: Module file not found
 --> src/lib.cairo:X:Y
```
**Solution:** Add `--test-files` or remove module declaration

### Pattern 2: Syntax Error
```
error: expected ';', found `}`
 --> src/contract.cairo:X:Y
```
**Solution:** Fix syntax in the specified file/line

### Pattern 3: Type Mismatch
```
error[E0308]: mismatched types
 --> src/contract.cairo:X:Y
   expected `felt252`, found `u256`
```
**Solution:** Fix type mismatch

### Pattern 4: Import Error
```
error[E0433]: failed to resolve: use of undeclared module
 --> src/contract.cairo:X:Y
```
**Solution:** Check module declarations and imports

### Pattern 5: Hash Mismatch
```
Expected class hash: 0x044dc2b3...
Compiled class hash: 0x055dc2b3...
```
**Solution:** Use `--lock-file`, check source version

---

## Quick Reference

### Enable Verbose

| Method | Command |
|--------|---------|
| CLI flag | `--verbose` or `-v` |
| Config file | `verbose = true` in `.voyager.toml` |

### Common Commands

| Task | Command |
|------|---------|
| Verbose status | `voyager status --network mainnet --job <ID> --verbose` |
| Verbose verify | `voyager verify --network mainnet ... --verbose` |
| Save to file | `voyager status ... --verbose > output.log` |
| Search output | `voyager status ... --verbose \| grep "error"` |

### What to Look For

1. **Status line** - What stage failed?
2. **Error code** - What type of error? (E0005, E0308, etc.)
3. **File location** - Which file and line?
4. **Error message** - What specifically went wrong?
5. **Suggestions** - What does the output recommend?

---

## See Also

- [Debugging Guide](./debugging.md) - Systematic debugging workflow
- [Common Errors](./common-errors.md) - Frequent problems and solutions
- [Error Codes Reference](../reference/error-codes.md) - Complete error listing
- [Getting Support](./support.md) - How to get help
