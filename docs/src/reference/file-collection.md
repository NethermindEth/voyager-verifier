# File Collection

This reference documents which files are collected and included when submitting contract verification requests.

## Quick Reference

| File Type | Included by Default | Flag Required | Max Size | Notes |
|-----------|---------------------|---------------|----------|-------|
| **Cairo source files** (.cairo) | ✅ Yes | None | 20MB each | Excluding tests by default |
| **Scarb.toml** (package) | ✅ Yes | None | 20MB | Always included |
| **Scarb.toml** (workspace) | ✅ Yes (if workspace) | None | 20MB | Auto-detected |
| **Scarb.lock** | ❌ No | `--lock-file` | 20MB | Optional for reproducibility |
| **Test files** (.cairo in tests/) | ❌ No | `--test-files` | 20MB each | In src/ directory only |
| **Documentation** (.md, .txt) | ✅ Yes (if found) | None | 20MB each | LICENSE, README, etc. |
| **Rust files** (.rs) | ✅ Yes (proc-macro only) | None | 20MB each | For procedural macro packages |

---

## Collection Overview

### Collection Process

```
Start Verification
       ↓
1. Collect Source Files
   └─ All .cairo files in src/
   └─ Exclude tests/* by default
   └─ Include tests if --test-files
       ↓
2. Add Manifest Files
   └─ Package Scarb.toml
   └─ Workspace Scarb.toml (if workspace)
       ↓
3. Add Optional Files
   └─ Scarb.lock (if --lock-file)
   └─ Documentation files
       ↓
4. Validate Files
   └─ Check file types
   └─ Check file sizes (max 20MB)
       ↓
5. Find Contract File
   └─ Search for #[starknet::contract]
   └─ Fallback to heuristics
       ↓
Submit to API
```

---

## Source Files

### Cairo Source Files (.cairo)

**Default Behavior:**

All `.cairo` files in the `src/` directory are collected:

```bash
my-project/
├── src/
│   ├── lib.cairo        ✅ Included
│   ├── contract.cairo   ✅ Included
│   ├── utils.cairo      ✅ Included
│   └── tests/
│       └── test_contract.cairo  ❌ Excluded (by default)
```

**Collection Rules:**

1. **Recursive Search**: All Cairo files under `src/` are found recursively
2. **Test Exclusion**: Files in `test/` or `tests/` directories are excluded by default
3. **Target Filtering**: Only files relevant to the specified package are included

**Example:**

```bash
# Collect only production Cairo files
voyager verify --network mainnet \
  --class-hash 0x044dc2b3... \
  --contract-name MyContract

# Files collected:
# ✅ src/lib.cairo
# ✅ src/contract.cairo
# ✅ src/utils.cairo
# ❌ src/tests/test_contract.cairo (excluded)
```

---

## Manifest Files

### Package Scarb.toml

**Always Included:**

The package's `Scarb.toml` is always included in verification submissions.

```toml
# Scarb.toml - Always included
[package]
name = "my_contract"
version = "0.1.0"

[dependencies]
starknet = "2.8.4"
```

**Why It's Needed:**

- Defines package metadata (name, version, license)
- Specifies Cairo version
- Lists dependencies
- Contains Dojo version (if applicable)

### Workspace Scarb.toml

**Included for Workspace Projects:**

If your project is part of a Scarb workspace, both manifests are included:

```bash
my-workspace/
├── Scarb.toml           ✅ Workspace manifest (included)
└── packages/
    └── my_contract/
        └── Scarb.toml   ✅ Package manifest (included)
```

**Workspace Detection:**

Voyager automatically detects workspace setups by comparing manifest paths:

```rust
// From file_collector.rs
let is_workspace = workspace_manifest != manifest_path;
```

**Example Workspace:**

```toml
# Workspace Scarb.toml (root)
[workspace]
members = [
    "packages/contracts",
    "packages/tokens",
]

[workspace.package]
version = "0.1.0"
```

---

## Lock File

### Scarb.lock

**Optional - Requires `--lock-file` Flag:**

The lock file is only included when explicitly requested:

```bash
voyager verify --network mainnet \
  --class-hash 0x044dc2b3... \
  --contract-name MyContract \
  --lock-file
```

**When to Use Lock Files:**

✅ **Use when:**
- You want reproducible builds
- Dependency versions matter
- You're getting class hash mismatches
- You've committed Scarb.lock to version control

❌ **Don't use when:**
- Testing with latest dependencies
- Lock file doesn't exist
- You want flexible dependency resolution

**Lock File Behavior:**

```bash
# If --lock-file is set but file doesn't exist:
⚠️ --lock-file flag enabled but Scarb.lock not found at /path/to/Scarb.lock

# If file exists:
✅ Including Scarb.lock file: /path/to/Scarb.lock
```

**Example Lock File:**

```toml
# Scarb.lock
version = 1

[[package]]
name = "my_contract"
version = "0.1.0"
dependencies = [
    "starknet 2.8.4 (registry+https://...)",
]

[[package]]
name = "starknet"
version = "2.8.4"
source = "registry+https://..."
```

---

## Test Files

### Test File Detection

**Excluded by Default:**

Test files in `src/test/` or `src/tests/` are excluded unless `--test-files` is specified:

```bash
my-project/
├── src/
│   ├── lib.cairo               ✅ Included
│   ├── contract.cairo          ✅ Included
│   ├── tests/
│   │   └── test_contract.cairo ❌ Excluded (default)
│   └── test/
│       └── test_utils.cairo    ❌ Excluded (default)
```

### Including Test Files

**Use `--test-files` Flag:**

```bash
voyager verify --network mainnet \
  --class-hash 0x044dc2b3... \
  --contract-name MyContract \
  --test-files

# Now includes:
# ✅ src/lib.cairo
# ✅ src/contract.cairo
# ✅ src/tests/test_contract.cairo
# ✅ src/test/test_utils.cairo
```

**When Test Files Are Required:**

Test files must be included if:

1. **Your contract imports test modules:**
   ```cairo
   // src/lib.cairo
   mod contract;
   #[cfg(test)]
   mod tests;  // Error E005 without --test-files
   ```

2. **Test code is referenced in production:**
   ```cairo
   // src/lib.cairo
   use my_contract::tests::TestHelper;  // Requires --test-files
   ```

3. **Compilation fails with E005:**
   ```
   Error[E005]: Module file not found. Expected path: /tmp/.../src/tests.cairo
   Solution: Add --test-files flag
   ```

### Test File Location Rules

**Only src/ Tests Are Included:**

```bash
my-project/
├── src/
│   └── tests/
│       └── test_contract.cairo  ✅ Included with --test-files
├── tests/
│   └── integration_test.cairo   ❌ Never included
└── test/
    └── e2e_test.cairo           ❌ Never included
```

**Detection Logic:**

```rust
// From resolver.rs
let is_in_src = path_str.contains("/src/");
let has_test_in_path = path_str.contains("/test") || path_str.contains("/tests/");

if is_in_src && has_test_in_path {
    return include_test_files;  // Only if --test-files flag is set
}
```

---

## Procedural Macro Packages

### Rust Files for Proc Macros

**Special Case for Cairo Proc Macro Packages:**

If your package is a procedural macro package (defined with `cairo-plugin = true` in Cargo.toml), Rust files are also collected:

```bash
my-proc-macro/
├── Cargo.toml          ✅ Included
├── Scarb.toml          ✅ Included
└── src/
    ├── lib.rs          ✅ Included
    └── utils.rs        ✅ Included
```

**Cargo.toml Validation:**

```toml
# Cargo.toml
[package]
name = "my_proc_macro"
version = "0.1.0"
edition = "2021"

[lib]
crate-type = ["cdylib"]  # Required
proc-macro = true        # Required

[dependencies]
cairo-lang-macro = "*"   # Required
```

**Files Collected:**

1. **Cargo.toml** - Rust package manifest
2. **Cargo.lock** - Rust dependency lock file (if exists)
3. **All .rs files** in src/
4. **Scarb.toml** - Cairo package manifest

---

## File Type Validation

### Allowed File Types

**Voyager validates file types before submission:**

```rust
// From file_collector.rs
let allowed_extensions = ["cairo", "toml", "lock", "md", "txt", "json"];
```

**Valid File Extensions:**

| Extension | Type | Example |
|-----------|------|---------|
| `.cairo` | Cairo source | `src/contract.cairo` |
| `.toml` | Configuration | `Scarb.toml`, `Cargo.toml` |
| `.lock` | Lock files | `Scarb.lock`, `Cargo.lock` |
| `.md` | Documentation | `README.md`, `CHANGELOG.md` |
| `.txt` | Text files | `LICENSE.txt`, `NOTICE.txt` |
| `.json` | JSON data | `metadata.json` |
| `.rs` | Rust source | `src/lib.rs` (proc-macro only) |

**Files Without Extensions:**

These common project files are allowed without extensions:

- `LICENSE`
- `README`
- `CHANGELOG`
- `NOTICE`
- `AUTHORS`
- `CONTRIBUTORS`

**Example:**

```bash
my-project/
├── LICENSE              ✅ Allowed (no extension)
├── README               ✅ Allowed (no extension)
├── README.md            ✅ Allowed (.md)
├── Scarb.toml           ✅ Allowed (.toml)
├── notes.txt            ✅ Allowed (.txt)
├── config.yaml          ❌ Rejected (.yaml not allowed)
└── image.png            ❌ Rejected (.png not allowed)
```

**Error on Invalid Type:**

```
Error[E026]: Invalid file type '.yaml' for file: config.yaml
Allowed extensions: cairo, toml, lock, md, txt, json
Allowed files without extension: LICENSE, README, CHANGELOG, NOTICE, AUTHORS, CONTRIBUTORS
```

---

## File Size Limits

### Maximum File Size: 20MB

**All files are validated against a 20MB size limit:**

```rust
// From file_collector.rs
const MAX_FILE_SIZE: usize = 1024 * 1024 * 20; // 20MB limit
```

**Size Validation:**

```bash
# Files under 20MB pass validation
✅ src/contract.cairo (145 KB)
✅ Scarb.toml (2 KB)
✅ README.md (15 KB)

# Files over 20MB are rejected
❌ src/huge_contract.cairo (25 MB)
```

**Error on Size Limit:**

```
Error[E027]: File size exceeds limit
File: src/huge_contract.cairo
Size: 25 MB
Maximum allowed: 20 MB

Suggestion: Split large files into smaller modules
```

**Best Practices:**

1. **Keep contracts modular**: Split large contracts into smaller files
2. **Avoid generated code**: Don't include large auto-generated files
3. **Remove unnecessary documentation**: Keep docs concise

---

## Contract File Detection

### Finding the Main Contract

**Voyager automatically finds the main contract file:**

### Detection Strategy

**1. Pattern-Based Search (Primary):**

Searches for the actual contract definition:

```cairo
#[starknet::contract]
mod MyContract {
    // ...
}
```

**2. Heuristic Fallback:**

If pattern search fails, tries these paths (case-insensitive):

```bash
src/mycontract.cairo
src/contract.cairo
src/lib.cairo
src/main.cairo
<first .cairo file found>
```

**Example:**

```bash
# Contract name: MyToken

# Search order:
1. Find #[starknet::contract] + mod MyToken  ✅ src/token.cairo
2. If not found: src/mytoken.cairo
3. If not found: src/contract.cairo
4. If not found: src/lib.cairo
5. If not found: src/main.cairo
6. If not found: first .cairo file
```

**Explicit Contract File Location:**

```cairo
// src/token.cairo
#[starknet::contract]
mod MyToken {
    // Voyager will find this even if filename doesn't match
    // because it searches for the pattern
}
```

---

## Common File Collection Scenarios

### Scenario 1: Simple Single Package

```bash
my-contract/
├── Scarb.toml
├── src/
│   ├── lib.cairo
│   └── contract.cairo
└── Scarb.lock

# Default collection:
voyager verify --network mainnet \
  --class-hash 0x... \
  --contract-name MyContract

# Files included:
✅ Scarb.toml
✅ src/lib.cairo
✅ src/contract.cairo
❌ Scarb.lock (not included by default)
```

### Scenario 2: Workspace Project

```bash
my-workspace/
├── Scarb.toml  (workspace manifest)
└── packages/
    └── my_contract/
        ├── Scarb.toml  (package manifest)
        └── src/
            └── lib.cairo

# Default collection:
voyager verify --network mainnet \
  --class-hash 0x... \
  --contract-name MyContract \
  --package my_contract

# Files included:
✅ Scarb.toml (workspace)
✅ packages/my_contract/Scarb.toml
✅ packages/my_contract/src/lib.cairo
```

### Scenario 3: Contract with Tests

```bash
my-contract/
├── Scarb.toml
└── src/
    ├── lib.cairo
    ├── contract.cairo
    └── tests/
        └── test_contract.cairo

# Without --test-files:
voyager verify --network mainnet \
  --class-hash 0x... \
  --contract-name MyContract

# Files included:
✅ Scarb.toml
✅ src/lib.cairo
✅ src/contract.cairo
❌ src/tests/test_contract.cairo

# With --test-files:
voyager verify --network mainnet \
  --class-hash 0x... \
  --contract-name MyContract \
  --test-files

# Files included:
✅ Scarb.toml
✅ src/lib.cairo
✅ src/contract.cairo
✅ src/tests/test_contract.cairo
```

### Scenario 4: Reproducible Build with Lock File

```bash
my-contract/
├── Scarb.toml
├── Scarb.lock
└── src/
    └── lib.cairo

# With --lock-file:
voyager verify --network mainnet \
  --class-hash 0x... \
  --contract-name MyContract \
  --lock-file

# Files included:
✅ Scarb.toml
✅ Scarb.lock
✅ src/lib.cairo
```

### Scenario 5: Procedural Macro Package

```bash
my-proc-macro/
├── Cargo.toml
├── Cargo.lock
├── Scarb.toml
└── src/
    ├── lib.rs
    └── utils.rs

# Default collection (auto-detected as proc-macro):
voyager verify --network mainnet \
  --class-hash 0x... \
  --contract-name MyMacro

# Files included:
✅ Cargo.toml
✅ Cargo.lock
✅ Scarb.toml
✅ src/lib.rs
✅ src/utils.rs
```

---

## Dry-Run: Preview File Collection

### Using --dry-run Flag

**Preview which files will be collected:**

```bash
voyager verify --network mainnet \
  --class-hash 0x044dc2b3... \
  --contract-name MyContract \
  --dry-run
```

**Output Shows:**

```
📦 Files to be submitted:
  ✅ Scarb.toml
  ✅ src/lib.cairo
  ✅ src/contract.cairo
  ✅ src/utils.cairo

📊 Summary:
  Total files: 4
  Total size: 47.3 KB
  Contract file: src/contract.cairo

🔍 Validation:
  ✅ All files under 20MB
  ✅ All file types valid
  ✅ Contract file found

✨ Dry-run successful - no files were submitted
```

---

## File Collection Errors

### E005: Module File Not Found

**Error:**
```
Error[E005]: Module file not found. Expected path: /tmp/.../src/tests.cairo
```

**Cause:** Contract imports a test module but `--test-files` flag not set

**Solution:**
```bash
voyager verify --test-files ...
```

**See:** [Error Codes E005](error-codes.md#e005)

### E026: Invalid File Type

**Error:**
```
Error[E026]: Invalid file type '.yaml' for file: config.yaml
```

**Cause:** File has an unsupported extension

**Solution:** Only include files with allowed extensions (cairo, toml, lock, md, txt, json)

### E027: File Size Limit Exceeded

**Error:**
```
Error[E027]: File size exceeds limit
File: src/huge_contract.cairo
Size: 25 MB
Maximum allowed: 20 MB
```

**Cause:** Individual file exceeds 20MB limit

**Solution:**
1. Split large files into modules
2. Remove unnecessary code or comments
3. Refactor into smaller components

### E028: File Not Found

**Error:**
```
Error[E028]: File not found: src/contract.cairo
```

**Cause:** Expected file doesn't exist at the specified path

**Solution:**
1. Verify file path is correct
2. Check file was created
3. Ensure proper casing (case-sensitive)

---

## Best Practices

### ✅ File Collection Best Practices

1. **Commit Lock Files**
   ```bash
   git add Scarb.lock
   git commit -m "Add lock file for reproducibility"
   ```

2. **Use --test-files Only When Needed**
   ```bash
   # Only if tests are actually imported
   voyager verify --test-files ...
   ```

3. **Keep Files Under 20MB**
   ```cairo
   // Split large contracts:
   mod contract_part1;
   mod contract_part2;
   ```

4. **Use Dry-Run to Preview**
   ```bash
   # Always check before submitting
   voyager verify --dry-run ...
   ```

5. **Organize Source Files**
   ```bash
   src/
   ├── lib.cairo     # Main entry
   ├── contract.cairo  # Contract code
   ├── utils.cairo    # Utilities
   └── tests/        # Tests (separate)
   ```

6. **Include Minimal Documentation**
   ```bash
   # Included documentation:
   ✅ LICENSE
   ✅ README.md (keep concise)
   ❌ docs/ (not submitted)
   ❌ examples/ (not submitted)
   ```

---

## FAQ

### Q: Are test files included by default?

**A:** No. Test files in `src/test/` or `src/tests/` are excluded by default. Use `--test-files` to include them.

### Q: Is Scarb.lock included automatically?

**A:** No. Use `--lock-file` flag to include it. Recommended for reproducible builds.

### Q: What files are always included?

**A:**
- All `.cairo` files in `src/` (except tests)
- Package `Scarb.toml`
- Workspace `Scarb.toml` (if workspace)

### Q: Can I include custom configuration files?

**A:** Only files with allowed extensions (.cairo, .toml, .lock, .md, .txt, .json) are accepted.

### Q: What's the maximum file size?

**A:** 20MB per file. Split larger files into modules.

### Q: How do I see which files will be submitted?

**A:** Use `--dry-run` flag to preview file collection without submitting.

### Q: Are files outside src/ included?

**A:** Only manifest files (Scarb.toml) and optional files (Scarb.lock, LICENSE, README.md) are included from the project root.

---

## See Also

- [Error Codes](error-codes.md) - File collection errors (E005, E025-E029)
- [Test Files Guide](../advanced/test-files.md) - Using `--test-files` flag
- [Lock Files Guide](../advanced/lock-files.md) - Using `--lock-file` flag
- [Common Errors](../troubleshooting/common-errors.md) - File-related issues
- [Multi-Package Guide](../core-features/multi-package.md) - Workspace file collection
