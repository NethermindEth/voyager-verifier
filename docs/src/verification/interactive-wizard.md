# Interactive Wizard

The interactive wizard provides a guided, step-by-step verification experience for users new to Voyager Verifier or those who don't use it frequently.

## Overview

The wizard mode:

- Prompts you step-by-step for all required information
- Auto-detects licenses from `Scarb.toml`
- Provides helpful explanations for each option
- Validates input before proceeding
- Shows a summary for confirmation before submission
- Recommended for first-time users

## Starting the Wizard

```bash
voyager verify --wizard
```

You can run the wizard from any directory - it will prompt you for the project path if needed.

## Wizard Flow

### Step 1: Network Selection

**Prompt:**
```
Select network:
  1. Mainnet (https://api.voyager.online/beta)
  2. Sepolia (https://sepolia-api.voyager.online/beta)
  3. Dev
  4. Custom (specify URL)

Enter choice [1-4]:
```

**Options:**
- **1** - Mainnet (production Starknet network)
- **2** - Sepolia (testnet for development)
- **3** - Dev (development network)
- **4** - Custom (you'll be asked for a custom API endpoint URL)

**Example:**
```
Enter choice [1-4]: 1
✓ Selected: Mainnet
```

### Step 2: Class Hash

**Prompt:**
```
Enter class hash:
```

**Input:** The class hash of your deployed contract (hexadecimal starting with `0x`)

**Example:**
```
Enter class hash: 0x044dc2b3239382230d8b1e943df23b96f52eebcac93efe6e8bde92f9a2f1da18
✓ Class hash: 0x044dc2b3...da18
```

**Validation:**
- Must start with `0x`
- Must be valid hexadecimal
- Provides immediate feedback if invalid

### Step 3: Package Selection (Workspace Projects Only)

**Prompt (if workspace detected):**
```
Multiple packages found:
  1. token
  2. nft
  3. marketplace

Select package [1-3]:
```

**Behavior:**
- Only shown for workspace projects with multiple packages
- Skipped for single-package projects
- Auto-detected from `Scarb.toml`

**Example:**
```
Select package [1-3]: 1
✓ Selected package: token
```

### Step 4: Contract Name

**Prompt:**
```
Enter contract name:
```

**Input:** The name of the contract to verify (must match your Cairo source code)

**Example:**
```
Enter contract name: MyToken
✓ Contract name: MyToken
```

**Tips:**
- Must match the contract name in your source code
- Case-sensitive
- Should be the module name with the `#[starknet::contract]` attribute

### Step 5: License

**Prompt:**
```
License detected in Scarb.toml: MIT
Use this license? [Y/n]:
```

**Behavior:**
- Auto-detects license from `Scarb.toml` if present
- Prompts for confirmation if detected
- Asks for manual entry if not detected

**If license detected:**
```
Use this license? [Y/n]: y
✓ License: MIT
```

**If no license detected:**
```
No license found in Scarb.toml

Enter SPDX license identifier (or press Enter for "All Rights Reserved"):
MIT
✓ License: MIT
```

**Common licenses:**
- `MIT`
- `Apache-2.0`
- `GPL-3.0`
- `BSD-3-Clause`
- Press Enter for "All Rights Reserved"

See [SPDX License List](https://spdx.org/licenses/) for all valid identifiers.

### Step 6: Optional Features

The wizard asks about optional features:

#### Include Lock File?

**Prompt:**
```
Include Scarb.lock file in verification? [y/N]:
```

**Options:**
- **y** - Include `Scarb.lock` for reproducible builds
- **N** - Don't include (default)

**Use case:** Ensures exact dependency versions match deployment

#### Include Test Files?

**Prompt:**
```
Include test files from src/ directory? [y/N]:
```

**Options:**
- **y** - Include test files if they're needed for compilation
- **N** - Don't include (default)

**Use case:** When test modules are declared in `lib.cairo`

#### Enable Watch Mode?

**Prompt:**
```
Monitor verification status until completion? [Y/n]:
```

**Options:**
- **Y** - Wait and monitor verification status (default, recommended)
- **n** - Submit and exit

**Behavior:**
- **Y** - Displays live progress and waits for final result
- **n** - Returns job ID immediately for manual checking

#### Enable Verbose Output?

**Prompt:**
```
Enable verbose output for detailed error messages? [y/N]:
```

**Options:**
- **y** - Show full compilation output on errors
- **N** - Show condensed error messages (default)

**Use case:** Debugging compilation failures

### Step 7: Confirmation Summary

**Prompt:**
```
════════════════════════════════════════════════════════
Verification Summary
════════════════════════════════════════════════════════
Network:        Mainnet
Class Hash:     0x044dc2b3...da18
Contract Name:  MyToken
Package:        token
License:        MIT
Lock File:      No
Test Files:     No
Watch Mode:     Yes
Verbose:        No
════════════════════════════════════════════════════════

Proceed with verification? [Y/n]:
```

**Review all settings before final confirmation.**

**Options:**
- **Y** - Submit verification (default)
- **n** - Cancel and exit

### Step 8: Submission

After confirmation, the verification is submitted:

```
✓ Verification submitted successfully!
Job ID: abc-123-def-456
Network: mainnet
Class Hash: 0x044dc2b3239382230d8b1e943df23b96f52eebcac93efe6e8bde92f9a2f1da18

⏳ Monitoring verification status...
```

If watch mode is enabled, live progress updates will be shown.

## Complete Example

Here's a complete wizard session:

```bash
$ voyager verify --wizard

Select network:
  1. Mainnet
  2. Sepolia
  3. Dev
  4. Custom

Enter choice [1-4]: 1
✓ Selected: Mainnet

Enter class hash: 0x044dc2b3239382230d8b1e943df23b96f52eebcac93efe6e8bde92f9a2f1da18
✓ Class hash: 0x044dc2b3...da18

Enter contract name: MyToken
✓ Contract name: MyToken

License detected in Scarb.toml: MIT
Use this license? [Y/n]: y
✓ License: MIT

Include Scarb.lock file in verification? [y/N]: y
✓ Lock file: Yes

Include test files from src/ directory? [y/N]: n
✓ Test files: No

Monitor verification status until completion? [Y/n]: y
✓ Watch mode: Yes

Enable verbose output for detailed error messages? [y/N]: n
✓ Verbose: No

════════════════════════════════════════════════════════
Verification Summary
════════════════════════════════════════════════════════
Network:        Mainnet
Class Hash:     0x044dc2b3...da18
Contract Name:  MyToken
License:        MIT
Lock File:      Yes
Test Files:     No
Watch Mode:     Yes
Verbose:        No
════════════════════════════════════════════════════════

Proceed with verification? [Y/n]: y

✓ Verification submitted successfully!
Job ID: abc-123-def-456
Network: mainnet
Class Hash: 0x044dc2b3239382230d8b1e943df23b96f52eebcac93efe6e8bde92f9a2f1da18

⏳ Monitoring verification status...
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 35%
Status: Compiling | Elapsed: 1m 15s | Estimated: 3m 0s
```

## Wizard from Different Locations

### From Project Root

```bash
cd /path/to/my-project
voyager verify --wizard
```

Project is auto-detected from current directory.

### From Outside Project

```bash
voyager verify --wizard --path /path/to/my-project
```

Or the wizard will prompt you for the path:

```
Enter project path (or press Enter for current directory):
/path/to/my-project
```

## Auto-Detection Features

The wizard automatically detects and suggests:

### License Detection

Reads license from `Scarb.toml`:

```toml
[package]
license = "MIT"
```

The wizard will:
1. Detect "MIT" from Scarb.toml
2. Prompt for confirmation
3. Allow override if needed

### Package Detection

For workspace projects, reads from `Scarb.toml`:

```toml
[workspace]
members = ["token", "nft", "marketplace"]
```

The wizard will:
1. List all packages
2. Provide numbered selection
3. Validate selection

### Project Path Detection

- Uses current directory by default
- Validates Scarb.toml exists
- Prompts if not found in current directory

## Input Validation

The wizard validates all inputs:

### Class Hash Validation

**Invalid:**
```
Enter class hash: 044dc2b3...
✗ Error: Class hash must start with 0x

Enter class hash: 0xINVALID
✗ Error: Class hash must be valid hexadecimal

Enter class hash:
```

**Valid:**
```
Enter class hash: 0x044dc2b3239382230d8b1e943df23b96f52eebcac93efe6e8bde92f9a2f1da18
✓ Class hash: 0x044dc2b3...da18
```

### Contract Name Validation

**Invalid:**
```
Enter contract name:
✗ Error: Contract name cannot be empty

Enter contract name:
```

**Valid:**
```
Enter contract name: MyToken
✓ Contract name: MyToken
```

### License Validation

**Invalid:**
```
Enter SPDX license identifier: INVALID-LICENSE
✗ Error: Invalid SPDX license identifier

Enter SPDX license identifier:
```

**Valid:**
```
Enter SPDX license identifier: MIT
✓ License: MIT
```

## Canceling the Wizard

Press `Ctrl+C` at any time to cancel:

```
^C
Verification canceled.
```

No submission is made if you cancel before final confirmation.

## Error Handling

If submission fails, the wizard provides clear error messages:

```
✗ Verification failed: Invalid class hash format

Please check your input and try again.
```

Common errors:
- Invalid class hash format
- Contract not found
- Network unreachable
- Invalid Scarb project

## Advantages of Wizard Mode

**For New Users:**
- No need to memorize command options
- Guided step-by-step process
- Helpful explanations at each step
- Input validation prevents mistakes

**For Occasional Users:**
- Don't need to recall exact command syntax
- Auto-detection reduces typing
- Summary review catches errors before submission

**For All Users:**
- Quick and error-free verification
- Ideal for one-off verifications
- Less prone to typos than command-line

## When to Use Wizard vs CLI

### Use Wizard When:
- First time verifying a contract
- Verifying contracts occasionally
- Want guided experience
- Prefer interactive prompts
- Not automating verification

### Use CLI When:
- Verifying frequently
- Automating in scripts
- Using in CI/CD pipelines
- Prefer direct command control
- Using configuration files

See [Command Line Verification](./command-line.md) for CLI usage.

## Combining Wizard with Config Files

The wizard respects values from `.voyager.toml`:

**Config file:**
```toml
[voyager]
network = "mainnet"
license = "MIT"
```

**Wizard behavior:**
- Pre-selects network from config
- Pre-fills license from config
- Allows override if needed
- CLI args have highest priority

## Tips

1. **Review Summary:** Always review the summary before confirming
2. **Use Watch Mode:** Enable watch mode to see final results
3. **Save Settings:** For repeated verifications, consider using a config file
4. **Keep Info Handy:** Have class hash and contract name ready before starting
5. **Test on Sepolia:** Verify on Sepolia first before mainnet

## See Also

- [Command Line Verification](./command-line.md) - Direct CLI commands
- [Batch Verification](./batch-verification.md) - Verify multiple contracts
- [verify command reference](../commands/verify.md) - Complete command documentation
- [Configuration files](../configuration/config-file.md) - Using .voyager.toml