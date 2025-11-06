# Test Files

The `--test-files` flag allows you to include test files from your project's `src/` directory in the verification submission, which is necessary when your contract code depends on test utilities or shared test code.

## Overview

### What Are Test Files?

Test files are Cairo source files that contain:
- Test functions (marked with `#[test]`)
- Test utilities and helper functions
- Mock implementations
- Shared test fixtures and setup code

**Example test file (`src/tests.cairo`):**
```cairo
#[cfg(test)]
mod tests {
    use super::{MyContract, IMyContractDispatcher};

    #[test]
    fn test_transfer() {
        // Test implementation
    }

    // Test utility function
    fn setup_contract() -> IMyContractDispatcher {
        // Setup code
    }
}
```

### Why Are They Excluded by Default?

By default, the verifier **excludes** test files from verification submissions because:

1. **Smaller payloads** - Test files can be large and aren't needed for most contracts
2. **Faster verification** - Less code to compile means faster verification
3. **Production focus** - Only production code needs to be verified
4. **Privacy** - Test files may contain internal implementation details

However, some contracts require test files to be included when they depend on test utilities.

## Usage

### Command-Line Flag

Include test files using the `--test-files` flag:

```bash
voyager verify --network mainnet \
  --class-hash 0x044dc2b3239382230d8b1e943df23b96f52eebcac93efe6e8bde92f9a2f1da18 \
  --contract-name MyContract \
  --test-files
```

### Configuration File

Set it as default in `.voyager.toml`:

```toml
[voyager]
network = "mainnet"
license = "MIT"
test-files = true  # Always include test files
```

Then verify without the flag:

```bash
voyager verify --class-hash 0x044dc2b3... --contract-name MyContract
```

### Priority System

The `--test-files` flag follows the standard priority order:

1. **CLI flag** (`--test-files`) - Highest priority
2. **Config file** (`test-files = true` in `.voyager.toml`)
3. **Default value** (`false` - test files excluded)

## When to Use Test Files

### Required Use Cases

#### 1. Contract Depends on Test Utilities

When your main contract imports test utilities:

```cairo
// lib.cairo
mod contract;
mod test_utils;  // Test utilities used by contract

// contract.cairo
use crate::test_utils::setup_environment;

#[starknet::contract]
mod MyContract {
    // Uses test utilities
}
```

**Error without `--test-files`:**
```
error[E0005]: Module file not found. Expected path: /tmp/targets/.../src/test_utils.cairo
```

**Solution:**
```bash
voyager verify --network mainnet \
  --class-hash 0x044dc2b3... \
  --contract-name MyContract \
  --test-files
```

#### 2. Tests Module Declared in lib.cairo

When `lib.cairo` declares a test module:

```cairo
// lib.cairo
mod contract;
mod tests;  // Module declaration
```

```cairo
// tests.cairo
#[cfg(test)]
mod test_cases {
    // Test implementations
}
```

**Error without `--test-files`:**
```
error[E0005]: Module file not found. Expected path: /tmp/targets/.../src/tests.cairo
```

**Solution:**
```bash
voyager verify --network mainnet \
  --class-hash 0x044dc2b3... \
  --contract-name MyContract \
  --test-files
```

#### 3. Shared Test Code Used Across Modules

When multiple contract modules share test utilities:

```
src/
├── lib.cairo
├── token.cairo
├── vault.cairo
└── test_helpers.cairo  # Shared by token and vault
```

```cairo
// lib.cairo
mod token;
mod vault;
mod test_helpers;  // Shared test code
```

**Solution:**
```bash
voyager verify --network mainnet \
  --class-hash 0x044dc2b3... \
  --contract-name MyContract \
  --test-files
```

### Optional Use Cases

#### 1. Development/Testing Verification

During development, you might want to verify with all files included:

```bash
voyager verify --network sepolia \
  --class-hash $DEV_HASH \
  --contract-name DevContract \
  --test-files \
  --verbose
```

**Why:** Ensures the entire codebase compiles remotely, not just production code.

#### 2. Comprehensive Code Review

When you want reviewers to see the complete codebase:

```toml
# .voyager.dev.toml
[voyager]
network = "sepolia"
test-files = true
verbose = true
```

### When Test Files Are NOT Needed

#### 1. Production Deployments (Usually)

Most production contracts don't need test files:

```bash
# Production verification - no test files
voyager verify --network mainnet \
  --class-hash $PROD_HASH \
  --contract-name ProductionContract
```

**Why:** Production code should not depend on test utilities.

#### 2. Self-Contained Contracts

When your contract doesn't import test modules:

```cairo
// lib.cairo
mod contract;  // No test module declarations
```

**Why:** No test files are referenced, so they're not needed.

#### 3. Tests in Dedicated Directory

When tests are in a `tests/` directory (outside `src/`):

```
project/
├── src/
│   └── lib.cairo      # No test references
└── tests/
    └── integration.cairo  # Separate test directory
```

**Why:** The verifier only collects from `src/` directory, so `tests/` is automatically excluded.

## File Detection Patterns

### What Gets Included

When `--test-files` is enabled, the verifier includes files matching these patterns within the `src/` directory:

1. **Files with "test" in the name:**
   - `test.cairo`
   - `tests.cairo`
   - `test_utils.cairo`
   - `test_helpers.cairo`
   - `mock_test.cairo`

2. **Files in "test" or "tests" directories within src/:**
   - `src/test/helpers.cairo`
   - `src/tests/fixtures.cairo`

3. **Files with "tests" in the path:**
   - `src/utils/tests.cairo`
   - `src/tests/unit.cairo`

### What Gets Excluded (Always)

Even with `--test-files` enabled, these are always excluded:

1. **Directories outside src/:**
   - `tests/` (root-level tests directory)
   - `test/` (root-level test directory)

2. **Build artifacts:**
   - `target/`
   - `Scarb.lock` (unless `--lock-file` is used)

3. **Hidden files:**
   - `.git/`
   - `.gitignore`

## How It Works

### Without Test Files (Default)

When `--test-files` is **not** specified:

1. Verifier scans `src/` directory
2. **Excludes** files matching test patterns:
   - Files with "test" in name
   - Files in "test" or "tests" subdirectories
3. Collects remaining `.cairo` files
4. Sends to remote API

**Example files collected:**
```
src/lib.cairo         ✅ Included
src/contract.cairo    ✅ Included
src/tests.cairo       ❌ Excluded (has "tests" in name)
src/test_utils.cairo  ❌ Excluded (has "test" in name)
```

### With Test Files

When `--test-files` **is** specified:

1. Verifier scans `src/` directory
2. **Includes** all `.cairo` files (including test patterns)
3. Collects all files
4. Sends to remote API

**Example files collected:**
```
src/lib.cairo         ✅ Included
src/contract.cairo    ✅ Included
src/tests.cairo       ✅ Included (test files enabled)
src/test_utils.cairo  ✅ Included (test files enabled)
```

## Common Scenarios

### Scenario 1: Missing Test Module Error

**Problem:**
```
error[E0005]: Module file not found. Expected path: /tmp/targets/.../src/tests.cairo
```

**Diagnosis:**
Your `lib.cairo` declares a test module:
```cairo
mod tests;
```

**Solution:**
Either include test files OR remove the module declaration:

**Option A - Include test files:**
```bash
voyager verify --network mainnet \
  --class-hash 0x044dc2b3... \
  --contract-name MyContract \
  --test-files
```

**Option B - Remove module declaration:**
```cairo
// lib.cairo
// mod tests;  // Comment out or remove
mod contract;
```

### Scenario 2: Test Utilities Used in Contract

**Problem:**
Your contract imports from a test utility file:
```cairo
// contract.cairo
use crate::test_helpers::mock_environment;
```

**Solution:**
Include test files or refactor to not depend on test utilities:

**Option A - Include test files:**
```bash
voyager verify --network mainnet \
  --class-hash 0x044dc2b3... \
  --contract-name MyContract \
  --test-files
```

**Option B - Refactor (recommended for production):**
```cairo
// Move mock_environment to production code or use conditional compilation
#[cfg(test)]
use crate::test_helpers::mock_environment;
```

### Scenario 3: Development vs Production

**During Development:**
```toml
# .voyager.dev.toml
[voyager]
network = "sepolia"
test-files = true  # Include everything during dev
verbose = true
```

**For Production:**
```toml
# .voyager.prod.toml
[voyager]
network = "mainnet"
test-files = false  # Exclude test files in production
lock-file = true
```

## Dry-Run Preview

Use `--dry-run` to see which files will be included:

### Without Test Files

```bash
voyager verify --network mainnet \
  --class-hash 0x044dc2b3... \
  --contract-name MyContract \
  --dry-run
```

**Output:**
```
Files to be included:
  src/lib.cairo
  src/contract.cairo
  src/utils.cairo

Files excluded (test files):
  src/tests.cairo
  src/test_utils.cairo
```

### With Test Files

```bash
voyager verify --network mainnet \
  --class-hash 0x044dc2b3... \
  --contract-name MyContract \
  --test-files \
  --dry-run
```

**Output:**
```
Files to be included:
  src/lib.cairo
  src/contract.cairo
  src/utils.cairo
  src/tests.cairo
  src/test_utils.cairo
```

## Best Practices

### 1. Avoid Dependencies on Test Code

**Recommended:** Keep production code independent of test utilities:

```cairo
// ✅ Good - no test dependencies
mod contract;
mod utils;

// ❌ Bad - depends on test code
mod contract;
mod test_helpers;  // Used by contract
```

### 2. Use Conditional Compilation

For code that should only exist in tests:

```cairo
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_function() {
        // Test code
    }
}
```

**Why:** The `#[cfg(test)]` attribute ensures test code is only compiled during testing.

### 3. Separate Test Directories

Put tests outside `src/` directory:

```
project/
├── src/
│   ├── lib.cairo
│   └── contract.cairo
└── tests/
    └── integration.cairo  # Automatically excluded
```

**Why:** Tests in `tests/` directory are never collected, even with `--test-files`.

### 4. Use Test Files Only When Necessary

**Development:**
```toml
[voyager]
network = "sepolia"
test-files = true  # OK for development
```

**Production:**
```toml
[voyager]
network = "mainnet"
test-files = false  # Recommended for production
```

### 5. Document Test File Requirements

In your project README:

```markdown
## Verification

If verification fails with "Module file not found" for test files:

```bash
voyager verify --network mainnet \
  --class-hash $HASH \
  --contract-name MyContract \
  --test-files
```

Or remove test module declarations from `lib.cairo`.
```

## Configuration Examples

### Development Environment

```toml
# .voyager.dev.toml
[voyager]
network = "sepolia"
license = "MIT"
test-files = true   # Include all test files
verbose = true
watch = true
```

### Production Environment

```toml
# .voyager.prod.toml
[voyager]
network = "mainnet"
license = "Apache-2.0"
test-files = false  # Exclude test files
lock-file = true
watch = false
```

### Contract with Test Dependencies

```toml
# .voyager.toml
[voyager]
network = "mainnet"
license = "MIT"
test-files = true   # Required for this contract
lock-file = true
```

## Troubleshooting

### Module Not Found Errors

**Problem:** Verification fails with module not found errors

```
error[E0005]: Module file not found. Expected path: /tmp/targets/.../src/tests.cairo
```

**Solutions:**

1. **Include test files:**
   ```bash
   voyager verify --network mainnet \
     --class-hash 0x044dc2b3... \
     --contract-name MyContract \
     --test-files
   ```

2. **Remove module declaration:**
   ```cairo
   // lib.cairo - remove or comment out:
   // mod tests;
   ```

3. **Check file exists locally:**
   ```bash
   ls src/tests.cairo
   # Ensure the file exists
   ```

### Test Files Not Helping

**Problem:** Including `--test-files` doesn't fix compilation errors

**Diagnosis:** The error might not be related to test files:

```bash
# Run with verbose to see full error
voyager verify --network mainnet \
  --class-hash 0x044dc2b3... \
  --contract-name MyContract \
  --test-files \
  --verbose
```

**Common causes:**
- Syntax errors in code
- Missing dependencies
- Incompatible Cairo version
- Wrong compiler settings

### Too Many Files Included

**Problem:** Verification payload is very large with test files

**Solution:** Review what's being included with dry-run:

```bash
voyager verify --network mainnet \
  --class-hash 0x044dc2b3... \
  --contract-name MyContract \
  --test-files \
  --dry-run | grep "src/"
```

Consider refactoring to reduce test file dependencies.

## Comparison with Lock Files

| Feature | Test Files (`--test-files`) | Lock Files (`--lock-file`) |
|---------|----------------------------|---------------------------|
| **Purpose** | Include test source files | Pin dependency versions |
| **Default** | Excluded | Excluded |
| **Files** | `**/test*.cairo` in `src/` | `Scarb.lock` |
| **Use Case** | Contracts depending on test utilities | Reproducible builds |
| **Production** | ⚠️ Usually not needed | ✅ Recommended |
| **Development** | ✅ Often needed | ⚠️ Optional |
| **File Size Impact** | Can be large | Usually small |

## See Also

- [Lock Files](./lock-files.md) - Including Scarb.lock for reproducible builds
- [Dry-Run Mode](../verification/dry-run.md) - Preview what files will be included
- [Configuration File Guide](../configuration/config-file.md) - Complete configuration system
- [CLI Options Reference](../configuration/cli-options.md) - All command-line flags
- [Troubleshooting](../../troubleshooting/common-errors.md) - Common error solutions
