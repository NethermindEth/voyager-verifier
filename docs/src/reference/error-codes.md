# Error Codes

This page provides a complete reference of all error codes in voyager-verifier with descriptions, causes, and solutions.

## Error Code Format

All error codes follow the format `[EXXX]` where `XXX` is a three-digit number. Error codes help you quickly identify and resolve issues.

**Quick Navigation:**
- [Workspace & Package Errors (E001-E003)](#workspace--package-errors)
- [Verification Errors (E004-E009)](#verification-errors)
- [Class Hash Errors (E010-E011)](#class-hash-errors)
- [Dependency & Resolution Errors (E012-E014)](#dependency--resolution-errors)
- [Contract & Target Errors (E015-E017)](#contract--target-errors)
- [File System Errors (E018-E019, E022-E024)](#file-system-errors)
- [Project Configuration Errors (E020-E021, E025-E028)](#project-configuration-errors)
- [Config File Errors (E030-E032)](#config-file-errors)
- [History Database Errors (E040-E042)](#history-database-errors)
- [General Errors (E999)](#general-errors)

---

## Workspace & Package Errors

### E001: Package Not Found in Workspace

**Error Message:**
```
[E001] Package '<name>' not found in workspace.
```

**Cause:**
You specified a package name that doesn't exist in the current workspace.

**Common Scenarios:**
- Typo in package name
- Package not listed in workspace members
- Wrong directory (not in workspace root)

**Solutions:**
1. Check available packages:
   ```bash
   scarb metadata
   ```

2. List workspace members in Scarb.toml:
   ```toml
   [workspace]
   members = ["package1", "package2"]
   ```

3. Use correct package name:
   ```bash
   voyager verify --network mainnet \
     --class-hash 0x044dc2b3... \
     --contract-name MyContract \
     --package correct_package_name
   ```

4. Verify you're in the workspace root directory

**Example:**
```bash
# Error: Trying to use non-existent package
voyager verify --network mainnet \
  --class-hash 0x044dc2b3... \
  --contract-name MyContract \
  --package my_contrct  # Typo: should be "my_contract"

# ✅ Solution: Fix package name
voyager verify --network mainnet \
  --class-hash 0x044dc2b3... \
  --contract-name MyContract \
  --package my_contract
```

---

### E002: HTTP Request Failed

**Error Message:**
```
[E002] HTTP request failed: <url> returned status <code>
```

**Cause:**
An HTTP request to the Voyager API failed.

**Common Status Codes:**

**400 Bad Request:**
- Invalid parameters
- Malformed request

**Solution:**
```bash
# Check all required parameters are provided
voyager verify --network mainnet \
  --class-hash 0x044dc2b3... \
  --contract-name MyContract \
  --license MIT
```

**401 Unauthorized:**
- Invalid authentication (rare - most endpoints are public)

**403 Forbidden:**
- Insufficient permissions
- Account access issues

**404 Not Found:**
- Wrong API endpoint
- Service not available
- Invalid URL

**Solution:**
```bash
# Verify the network/URL is correct
voyager verify --network mainnet ...  # Use predefined network
# OR
voyager verify --url https://api.voyager.online/beta ...  # Check custom URL
```

**413 Payload Too Large:**
- Project files exceed 10MB limit

**Solution:**
```bash
# Remove unnecessary files or try without optional files
voyager verify --network mainnet \
  --class-hash 0x044dc2b3... \
  --contract-name MyContract
  # Don't use --test-files or --lock-file if not needed
```

**429 Too Many Requests:**
- Rate limiting triggered

**Solution:**
```bash
# Wait before retrying, or use batch delay
voyager verify --batch-delay 10  # For batch verification
```

**500-599 Server Errors:**
- Voyager API experiencing issues

**Solution:**
- Wait a few minutes and retry
- Check Voyager service status

**Example:**
```bash
# Error: Wrong URL
voyager verify --url https://api.wrong-domain.com/beta ...
# [E002] HTTP request failed: https://api.wrong-domain.com/beta returned status 404

# ✅ Solution: Use correct URL
voyager verify --network mainnet ...
```

---

### E003: Contract Not Found in Manifest

**Error Message:**
```
[E003] Contract '<name>' not found in manifest file.
```

**Cause:**
The specified contract name doesn't exist in the `[tool.voyager]` section of Scarb.toml or couldn't be auto-detected.

**Common Scenarios:**
- Typo in contract name
- Contract not defined in manifest
- Missing `[tool.voyager]` section

**Solutions:**
1. Check available contracts in Scarb.toml:
   ```toml
   [tool.voyager.contracts]
   MyToken = "0x044dc2b3..."
   MyNFT = "0x055dc2b3..."
   ```

2. Use correct contract name:
   ```bash
   voyager verify --network mainnet \
     --class-hash 0x044dc2b3... \
     --contract-name MyToken  # Must match manifest
   ```

3. Add contract to manifest if missing:
   ```toml
   [tool.voyager.contracts]
   MyContract = "0x044dc2b3239382230d8b1e943df23b96f52eebcac93efe6e8bde92f9a2f1da18"
   ```

**Example:**
```bash
# Error: Contract name doesn't match manifest
voyager verify --network mainnet \
  --class-hash 0x044dc2b3... \
  --contract-name MyTokin  # Typo

# ✅ Solution: Use exact name from manifest
voyager verify --network mainnet \
  --class-hash 0x044dc2b3... \
  --contract-name MyToken
```

---

## Verification Errors

### E004: Compilation Failed

**Error Message:**
```
[E004] Compilation failed: <details>
```

**Cause:**
The remote compiler failed to build your contract.

**Common Causes:**
- Syntax errors in Cairo code
- Missing dependencies
- Import errors
- Module not found
- Incompatible Cairo version

**Solutions:**

1. **Test local build first:**
   ```bash
   scarb --release build
   ```
   The remote compiler uses the same command. If it fails locally, it will fail remotely.

2. **Check dependencies:**
   ```toml
   [dependencies]
   starknet = ">=2.11.0"  # Ensure all deps are declared
   ```

3. **Verify imports and modules:**
   ```cairo
   // In lib.cairo
   mod contract;  // Ensure this file exists
   // mod tests;  // Remove if tests.cairo isn't included
   ```

4. **Include test files if needed:**
   ```bash
   voyager verify --network mainnet \
     --class-hash 0x044dc2b3... \
     --contract-name MyContract \
     --test-files  # Include if contract depends on test utilities
   ```

5. **Check release profile settings:**
   ```toml
   [profile.release.cairo]
   sierra-replace-ids = true  # Any compiler settings must be here
   ```

6. **Use verbose mode for details:**
   ```bash
   voyager status --network mainnet --job <JOB_ID> --verbose
   ```

**Example:**
```
error[E0005]: Module file not found. Expected path: /tmp/targets/.../src/tests.cairo
```

**Solution:**
```bash
# Include test files OR remove module declaration
voyager verify --network mainnet \
  --class-hash 0x044dc2b3... \
  --contract-name MyContract \
  --test-files
```

---

### E005: Verification Failed

**Error Message:**
```
[E005] Verification failed: <details>
```

**Cause:**
The contract compiled successfully, but the resulting class hash doesn't match the declared class hash.

**Common Causes:**
- Wrong source code (doesn't match deployed contract)
- Different compiler settings
- Incorrect dependencies or versions
- Modified code after deployment

**Solutions:**

1. **Verify class hash is correct:**
   ```bash
   # Double-check the class hash from deployment
   voyager verify --network mainnet \
     --class-hash 0x044dc2b3239382230d8b1e943df23b96f52eebcac93efe6e8bde92f9a2f1da18 \
     --contract-name MyContract
   ```

2. **Ensure source matches deployment:**
   - Use the exact same code that was deployed
   - Check out the correct git commit if using version control
   - Verify no changes were made after deployment

3. **Use lock file for reproducible builds:**
   ```bash
   voyager verify --network mainnet \
     --class-hash 0x044dc2b3... \
     --contract-name MyContract \
     --lock-file  # Ensure same dependency versions
   ```

4. **Match compiler settings:**
   ```toml
   [profile.release.cairo]
   # Ensure these match deployment settings
   sierra-replace-ids = true
   inlining-strategy = "default"
   ```

5. **Check Cairo version compatibility:**
   - Ensure the same Cairo/Scarb version was used for deployment

**Example:**
```bash
# If verification fails, try with lock file
voyager verify --network mainnet \
  --class-hash 0x044dc2b3... \
  --contract-name MyContract \
  --lock-file \
  --verbose
```

---

### E006: Invalid Base URL

**Error Message:**
```
[E006] Invalid base URL: <url>
```

**Cause:**
The provided custom API URL is invalid or cannot be used as a base URL.

**Solutions:**

1. **Use valid HTTP/HTTPS URL:**
   ```bash
   # ✅ Correct format
   voyager verify --url https://api.example.com/beta \
     --class-hash 0x044dc2b3... \
     --contract-name MyContract

   # ❌ Wrong: Missing protocol
   voyager verify --url api.example.com/beta ...
   ```

2. **Use predefined network instead:**
   ```bash
   voyager verify --network mainnet \
     --class-hash 0x044dc2b3... \
     --contract-name MyContract
   ```

3. **Check URL format:**
   - Must start with `http://` or `https://`
   - Must be a valid URL structure
   - Include proper path if required

**Example:**
```bash
# Error: Invalid URL
voyager verify --url example.com ...
# [E006] Invalid base URL: example.com

# ✅ Solution: Add protocol
voyager verify --url https://example.com/api/beta ...
```

---

### E007: Verification Job Still in Progress

**Error Message:**
```
[E007] Verification job is still in progress
```

**Cause:**
You checked the status of a verification job that hasn't completed yet.

**Solutions:**

1. **Wait and check again:**
   ```bash
   # Wait a few seconds/minutes
   sleep 30
   voyager status --network mainnet --job <JOB_ID>
   ```

2. **Use watch mode to wait automatically:**
   ```bash
   voyager verify --network mainnet \
     --class-hash 0x044dc2b3... \
     --contract-name MyContract \
     --watch  # Automatically waits for completion
   ```

3. **Check status with auto-refresh:**
   ```bash
   # Polls every few seconds until complete
   voyager status --network mainnet --job <JOB_ID> --wait
   ```

**Note:** This is not an error - it just means the job is still being processed.

---

### E008: Job Not Found

**Error Message:**
```
[E008] Job '<job_id>' not found
```

**Cause:**
The specified job ID doesn't exist or has expired from the server.

**Solutions:**

1. **Check job ID is correct:**
   ```bash
   # Copy the full job ID from verification output
   voyager status --network mainnet --job abc-123-def-456
   ```

2. **Verify using same network/URL:**
   ```bash
   # Job ID is tied to the specific API endpoint
   # Must use same network or URL as verification
   voyager status --network mainnet --job <JOB_ID>
   ```

3. **Check history for recent jobs:**
   ```bash
   voyager history list --limit 10
   ```

4. **Job may have expired:**
   - Jobs may be removed after a certain period
   - Submit a new verification request

**Example:**
```bash
# Error: Wrong network for job ID
voyager verify --network mainnet ...  # Submitted to mainnet
# Output: Job ID: abc-123

voyager status --network sepolia --job abc-123  # Wrong network!
# [E008] Job 'abc-123' not found

# ✅ Solution: Use same network
voyager status --network mainnet --job abc-123
```

---

### E009: Invalid URL Format

**Error Message:**
```
[E009] Invalid URL format: <url>
```

**Cause:**
The custom URL provided has an invalid format.

**Solutions:**

1. **Use proper URL format:**
   ```bash
   # ✅ Correct
   voyager verify --url https://api.example.com/beta ...

   # ❌ Wrong formats
   # Missing protocol: api.example.com
   # Invalid characters: https://api example com
   # Incomplete: https://
   ```

2. **Encode special characters:**
   - Ensure proper URL encoding
   - Avoid spaces and special characters

3. **Use predefined networks:**
   ```bash
   # Simpler and less error-prone
   voyager verify --network mainnet ...
   ```

---

## Class Hash Errors

### E010: Invalid Class Hash Format

**Error Message:**
```
[E010] Invalid class hash format: '<hash>'

Expected format: 0x followed by up to 64 hexadecimal characters
Example: 0x044dc2b3239382230d8b1e943df23b96f52eebcac93efe6e8bde92f9a2f1da18
```

**Cause:**
The provided class hash doesn't match the required format.

**Valid Format:**
- Must start with `0x`
- Followed by 1-64 hexadecimal characters (0-9, a-f, A-F)
- Maximum 66 characters total (including `0x` prefix)

**Solutions:**

1. **Check hash format:**
   ```bash
   # ✅ Valid
   --class-hash 0x044dc2b3239382230d8b1e943df23b96f52eebcac93efe6e8bde92f9a2f1da18

   # ❌ Invalid: Missing 0x prefix
   --class-hash 044dc2b3239382230d8b1e943df23b96f52eebcac93efe6e8bde92f9a2f1da18

   # ❌ Invalid: Contains non-hex characters
   --class-hash 0x044dc2b3239382230d8b1e943df23b96f52eebcac93efe6e8bde92f9a2f1da1z
   ```

2. **Ensure correct characters:**
   - Only hexadecimal: 0-9, a-f, A-F
   - No spaces or special characters

3. **Verify hash from deployment:**
   ```bash
   # Get hash from Starknet deployment output
   # Or from block explorer
   ```

**Example:**
```bash
# Error: Missing 0x prefix
voyager verify --network mainnet \
  --class-hash 044dc2b3239382230d8b1e943df23b96f52eebcac93efe6e8bde92f9a2f1da18 \
  --contract-name MyContract
# [E010] Invalid class hash format

# ✅ Solution: Add 0x prefix
voyager verify --network mainnet \
  --class-hash 0x044dc2b3239382230d8b1e943df23b96f52eebcac93efe6e8bde92f9a2f1da18 \
  --contract-name MyContract
```

---

### E011: Internal Regex Compilation Error

**Error Message:**
```
[E011] Internal regex compilation error

This is an internal error. Please report this issue.
```

**Cause:**
An internal error occurred when compiling regular expressions for class hash validation.

**Solution:**
This is a bug in the verifier. Please:
1. Report the issue on GitHub
2. Include the full command you ran
3. Include your environment details (OS, voyager-verifier version)

---

## Dependency & Resolution Errors

### E012: Invalid Dependency Path

**Error Message:**
```
[E012] Invalid dependency path for '<name>': <path>
```

**Cause:**
A path dependency in Scarb.toml points to an invalid or inaccessible location.

**Common Scenarios:**
- Path doesn't exist
- Incorrect relative path
- Permission issues

**Solutions:**

1. **Check path exists:**
   ```bash
   ls ../my-dependency  # Verify path
   ```

2. **Use correct relative path:**
   ```toml
   [dependencies]
   my_lib = { path = "../my-dependency" }  # Relative from Scarb.toml location
   ```

3. **Verify path format:**
   ```toml
   # ✅ Correct
   my_lib = { path = "../dependency" }
   my_lib = { path = "./local-lib" }

   # ❌ Wrong
   my_lib = { path = "~/dependency" }  # Don't use ~
   ```

**Example:**
```toml
# Error: Path doesn't exist
[dependencies]
utils = { path = "../utils" }  # But ../utils doesn't exist

# ✅ Solution: Fix path
[dependencies]
utils = { path = "../common-utils" }  # Correct path
```

---

### E013: Failed to Read Metadata

**Error Message:**
```
[E013] Failed to read metadata for '<name>' at path: <path>
```

**Cause:**
Cannot read or parse Scarb.toml metadata for a path dependency.

**Solutions:**

1. **Check Scarb.toml exists:**
   ```bash
   ls ../my-dependency/Scarb.toml
   ```

2. **Validate Scarb.toml:**
   ```bash
   cd ../my-dependency
   scarb metadata  # Test if metadata can be read
   ```

3. **Verify file permissions:**
   ```bash
   chmod 644 ../my-dependency/Scarb.toml
   ```

4. **Ensure valid TOML:**
   ```toml
   # Check dependency's Scarb.toml is valid
   [package]
   name = "my_dependency"
   version = "0.1.0"
   ```

---

### E014: Path Contains Invalid UTF-8

**Error Message:**
```
[E014] Path contains invalid UTF-8 characters
```

**Cause:**
A file path contains characters that aren't valid UTF-8.

**Solutions:**

1. **Use ASCII characters only:**
   - Avoid special characters in file names
   - Avoid spaces in directory names
   - Use standard English letters and numbers

2. **Check for hidden characters:**
   - Look for control characters or special Unicode

3. **Rename files/directories:**
   ```bash
   # Example: Rename directory with special chars
   mv "dir with spaces" dir-with-dashes
   ```

---

## Contract & Target Errors

### E015: Class Hash Not Declared

**Error Message:**
```
[E015] Class hash '<hash>' is not declared
```

**Cause:**
The specified class hash hasn't been declared on the network.

**Solutions:**

1. **Verify class hash:**
   ```bash
   # Check on block explorer (Voyager, Starkscan, etc.)
   # Ensure hash is declared on the network
   ```

2. **Check correct network:**
   ```bash
   # Ensure using the right network
   voyager verify --network mainnet ...  # Or sepolia
   ```

3. **Declare class before verification:**
   - Use `starkli` or deployment tool to declare
   - Wait for transaction confirmation
   - Then verify

**Example:**
```bash
# Error: Hash not declared on mainnet
voyager verify --network mainnet \
  --class-hash 0x044dc2b3... \
  --contract-name MyContract
# [E015] Class hash not declared

# ✅ Solution: Check if declared on sepolia instead
voyager verify --network sepolia \
  --class-hash 0x044dc2b3... \
  --contract-name MyContract
```

---

### E016: No Contracts Selected

**Error Message:**
```
[E016] No contracts selected for verification
```

**Cause:**
No contract was specified and none could be auto-detected.

**Solutions:**

1. **Specify contract name:**
   ```bash
   voyager verify --network mainnet \
     --class-hash 0x044dc2b3... \
     --contract-name MyContract  # Required
   ```

2. **Define in manifest:**
   ```toml
   [tool.voyager.contracts]
   MyContract = "0x044dc2b3..."
   ```

3. **Use batch verification:**
   ```toml
   [[contracts]]
   class-hash = "0x044dc2b3..."
   contract-name = "MyContract"
   ```

---

### E017: Multiple Contracts Found

**Error Message:**
```
[E017] Multiple contracts found - only single contract verification is supported
```

**Cause:**
Multiple contracts were detected, but you can only verify one at a time (unless using batch mode).

**Solutions:**

1. **Specify which contract:**
   ```bash
   voyager verify --network mainnet \
     --class-hash 0x044dc2b3... \
     --contract-name MyToken  # Choose one
   ```

2. **Use batch verification for multiple:**
   ```toml
   # .voyager.toml
   [[contracts]]
   class-hash = "0x044dc2b3..."
   contract-name = "MyToken"

   [[contracts]]
   class-hash = "0x055dc2b3..."
   contract-name = "MyNFT"
   ```

   ```bash
   voyager verify  # Verifies all in batch
   ```

---

## File System Errors

### E018: Path Processing Error

**Error Message:**
```
[E018] Path processing error: cannot strip '<prefix>' from '<path>'

This is an internal error. Please report this issue.
```

**Cause:**
Internal error when processing file paths.

**Solution:**
This is a bug. Please report with:
- Full command
- Project structure
- Scarb.toml contents

---

### E019: File Size Limit Exceeded

**Error Message:**
```
[E019] File '<path>' exceeds maximum size limit of <max> bytes (actual: <actual> bytes)
```

**Cause:**
A file in your project is too large (exceeds individual file size limit).

**Solutions:**

1. **Reduce file size:**
   - Split large files into smaller modules
   - Remove unnecessary code or comments
   - Check for generated content

2. **Exclude large files:**
   - Add to `.gitignore`
   - Don't use `--test-files` if tests are large

3. **Check for unexpected files:**
   ```bash
   # Find large files
   find src -type f -size +1M
   ```

**Example:**
```bash
# Error: Large test file
voyager verify --network mainnet \
  --class-hash 0x044dc2b3... \
  --contract-name MyContract \
  --test-files  # Includes large tests.cairo

# ✅ Solution: Don't include test files
voyager verify --network mainnet \
  --class-hash 0x044dc2b3... \
  --contract-name MyContract
```

---

### E022: File System Error

**Error Message:**
```
[E022] File system error
```

**Cause:**
General file system error (permissions, access issues).

**Solutions:**

1. **Check file permissions:**
   ```bash
   chmod 644 Scarb.toml
   chmod 755 src/
   ```

2. **Verify path exists:**
   ```bash
   ls -la <path>
   ```

3. **Check disk space:**
   ```bash
   df -h
   ```

---

### E023: Path Contains Invalid UTF-8

**Error Message:**
```
[E023] Path contains invalid UTF-8 characters
```

**Cause:**
File path contains invalid UTF-8 characters.

**Solution:**
Same as E014 - use ASCII characters only in file paths.

---

### E024: Invalid File Type

**Error Message:**
```
[E024] File '<path>' has invalid file type (extension: <ext>)
```

**Cause:**
A file with an unsupported extension was included.

**Allowed Extensions:**
- `.cairo` - Cairo source files
- `.toml` - Configuration files (Scarb.toml)
- `.lock` - Lock files (Scarb.lock)
- `.md` - Documentation
- `.txt` - Text files
- `.json` - JSON files

**Solutions:**

1. **Remove binary/executable files:**
   ```bash
   # Don't include in project directory
   rm src/binary_file
   ```

2. **Check for unexpected files:**
   ```bash
   find src -type f ! -name "*.cairo"
   ```

3. **Add to .gitignore:**
   ```
   *.bin
   *.exe
   *.so
   ```

---

## Project Configuration Errors

### E020: Scarb Manifest Not Found

**Error Message:**
```
[E020] Scarb project manifest not found at: <path>
```

**Cause:**
Scarb.toml file doesn't exist at the specified path.

**Solutions:**

1. **Check you're in project directory:**
   ```bash
   ls Scarb.toml  # Should exist
   ```

2. **Use correct path:**
   ```bash
   voyager verify --network mainnet \
     --class-hash 0x044dc2b3... \
     --contract-name MyContract \
     --path /correct/path/to/project
   ```

3. **Create new project:**
   ```bash
   scarb init my-project
   cd my-project
   ```

---

### E021: Failed to Read Project Metadata

**Error Message:**
```
[E021] Failed to read project metadata: <error>
```

**Cause:**
Cannot parse Scarb.toml or read project metadata.

**Solutions:**

1. **Validate Scarb.toml:**
   ```bash
   scarb metadata --format-version 1
   ```

2. **Check TOML syntax:**
   ```toml
   # Ensure valid TOML format
   [package]
   name = "my_project"
   version = "0.1.0"

   [dependencies]
   starknet = ">=2.11.0"
   ```

3. **Run scarb check:**
   ```bash
   scarb check
   ```

4. **Update scarb:**
   ```bash
   asdf install scarb latest
   ```

---

### E025: Invalid Project Type

**Error Message:**
```
[E025] Invalid project type specified

Specified: <specified>
Detected: <detected>
```

**Cause:**
Mismatch between specified project type and detected type.

**Solutions:**

1. **Use auto-detection:**
   ```bash
   # Don't specify project type, let it auto-detect
   voyager verify --network mainnet \
     --class-hash 0x044dc2b3... \
     --contract-name MyContract
   ```

2. **Specify correct type:**
   ```bash
   # For Dojo projects
   voyager verify --network mainnet \
     --class-hash 0x044dc2b3... \
     --contract-name MyContract \
     --project-type dojo

   # For Scarb projects
   voyager verify --network mainnet \
     --class-hash 0x044dc2b3... \
     --contract-name MyContract \
     --project-type scarb
   ```

---

### E026: Dojo Project Validation Failed

**Error Message:**
```
[E026] Dojo project validation failed
```

**Cause:**
Project specified as Dojo, but doesn't meet Dojo requirements.

**Solutions:**

1. **Ensure dojo-core dependency:**
   ```toml
   [dependencies]
   dojo = { git = "https://github.com/dojoengine/dojo" }
   ```

2. **Check Dojo project structure:**
   ```
   project/
   ├── Scarb.toml
   ├── src/
   │   └── lib.cairo
   ```

3. **Test with sozo:**
   ```bash
   sozo build
   ```

4. **Use correct project type:**
   ```bash
   # If not actually Dojo, use scarb
   voyager verify --network mainnet \
     --class-hash 0x044dc2b3... \
     --contract-name MyContract \
     --project-type scarb
   ```

---

### E027: Interactive Prompt Failed

**Error Message:**
```
[E027] Interactive prompt failed
```

**Cause:**
Failed to display interactive wizard prompt.

**Solutions:**

1. **Use CLI arguments instead:**
   ```bash
   voyager verify --network mainnet \
     --class-hash 0x044dc2b3... \
     --contract-name MyContract \
     --license MIT
   ```

2. **Specify project type:**
   ```bash
   voyager verify --network mainnet \
     --class-hash 0x044dc2b3... \
     --contract-name MyContract \
     --project-type scarb  # Skip prompt
   ```

3. **Check terminal supports interactive input:**
   - Ensure running in proper terminal
   - Check stdin is available
   - Not running in non-interactive environment

---

### E028: Internal Error

**Error Message:**
```
[E028] Internal error: <message>

This is an internal error that should not occur.
```

**Cause:**
Unexpected internal error.

**Solution:**
Please report this issue with:
- Full command you ran
- Context/what you were doing
- Any relevant logs or output

---

## Config File Errors

### E030: Failed to Read Config File

**Error Message:**
```
[E030] Failed to read config file: <error>
```

**Cause:**
Cannot read `.voyager.toml` configuration file.

**Solutions:**

1. **Check file permissions:**
   ```bash
   chmod 644 .voyager.toml
   ```

2. **Verify file exists:**
   ```bash
   ls -la .voyager.toml
   ```

3. **Check file is accessible:**
   ```bash
   cat .voyager.toml  # Should display contents
   ```

---

### E031: Failed to Parse Config File

**Error Message:**
```
[E031] Failed to parse config file: <error>
```

**Cause:**
`.voyager.toml` file has invalid TOML syntax.

**Solutions:**

1. **Validate TOML syntax:**
   ```toml
   # Ensure proper format
   [voyager]
   network = "mainnet"  # String values in quotes
   watch = true         # Boolean without quotes
   ```

2. **Check field names:**
   ```toml
   # ✅ Correct field names
   [voyager]
   network = "mainnet"
   test-files = true    # Use hyphens, not underscores

   # ❌ Wrong
   [voyager]
   netwrk = "mainnet"   # Typo
   test_files = true    # Underscore instead of hyphen
   ```

3. **Use TOML validator:**
   - Online TOML validator
   - Or use example file as template

4. **Check example file:**
   ```bash
   cp .voyager.toml.example .voyager.toml
   # Edit as needed
   ```

---

### E032: Invalid UTF-8 Path in Config

**Error Message:**
```
[E032] Invalid UTF-8 path: <error>
```

**Cause:**
A path in the config file contains invalid UTF-8 characters.

**Solution:**
Use ASCII characters only in paths configured in `.voyager.toml`.

---

## History Database Errors

### E040: Failed to Access History Database

**Error Message:**
```
[E040] Failed to access history database: <error>
```

**Cause:**
Cannot access or open the history database at `~/.voyager/history.db`.

**Solutions:**

1. **Check directory exists:**
   ```bash
   mkdir -p ~/.voyager
   ```

2. **Check permissions:**
   ```bash
   chmod 755 ~/.voyager
   chmod 644 ~/.voyager/history.db  # If exists
   ```

3. **Check disk space:**
   ```bash
   df -h ~
   ```

4. **Remove corrupted database:**
   ```bash
   # Backup first if needed
   mv ~/.voyager/history.db ~/.voyager/history.db.bak
   # Will be recreated automatically
   ```

---

### E041: Failed to Create History Directory

**Error Message:**
```
[E041] Failed to create history directory: <error>
```

**Cause:**
Cannot create `~/.voyager` directory.

**Solutions:**

1. **Check home directory permissions:**
   ```bash
   chmod 755 ~
   ```

2. **Check disk space:**
   ```bash
   df -h ~
   ```

3. **Manual creation:**
   ```bash
   mkdir -p ~/.voyager
   chmod 755 ~/.voyager
   ```

---

### E042: Unable to Determine Home Directory

**Error Message:**
```
[E042] Unable to determine home directory
```

**Cause:**
Cannot find user's home directory (HOME environment variable not set).

**Solutions:**

1. **Check HOME variable:**
   ```bash
   echo $HOME  # Should show /home/username
   ```

2. **Set HOME if missing:**
   ```bash
   export HOME=/home/username
   ```

3. **Check user has home directory:**
   ```bash
   ls -ld ~
   ```

---

## General Errors

### E999: General/Network Errors

**Error Code:**
```
[E999] <Various error messages>
```

**Cause:**
Generic error code for network errors, I/O errors, or other uncategorized issues.

**Common Causes:**
- Network connectivity issues
- Request timeout
- DNS resolution failures
- SSL/TLS errors
- Generic I/O errors

**Solutions:**

1. **Check internet connection:**
   ```bash
   ping api.voyager.online
   ```

2. **Verify DNS resolution:**
   ```bash
   nslookup api.voyager.online
   ```

3. **Check firewall/proxy:**
   - Ensure HTTPS (port 443) is allowed
   - Configure proxy if needed

4. **Retry the request:**
   ```bash
   # Sometimes transient network issues resolve on retry
   voyager verify --network mainnet \
     --class-hash 0x044dc2b3... \
     --contract-name MyContract
   ```

5. **Use verbose mode:**
   ```bash
   voyager verify --network mainnet \
     --class-hash 0x044dc2b3... \
     --contract-name MyContract \
     --verbose
   ```

---

## Getting Help

If you encounter an error that isn't resolved by this guide:

1. **Use verbose mode** to get detailed error information:
   ```bash
   voyager status --network mainnet --job <JOB_ID> --verbose
   ```

2. **Check the troubleshooting guide**: [Troubleshooting](../troubleshooting/README.md)

3. **Search for similar issues** on GitHub

4. **Contact support**:
   - Telegram: [@StarknetVoyager](https://t.me/StarknetVoyager)
   - GitHub: [Create an issue](https://github.com/NethermindEth/voyager-verifier/issues)

**When reporting errors, include:**
- Error code and full error message
- Full command you ran
- Output with `--verbose` flag
- Your environment (OS, voyager-verifier version, scarb version)
- Relevant configuration files (Scarb.toml, .voyager.toml)

## See Also

- [Common Errors](../troubleshooting/common-errors.md) - Frequent problems and solutions
- [Debugging Guide](../troubleshooting/debugging.md) - Debugging workflow
- [Verbose Mode](../troubleshooting/verbose-mode.md) - Using `--verbose` flag
- [Getting Support](../troubleshooting/support.md) - How to get help
