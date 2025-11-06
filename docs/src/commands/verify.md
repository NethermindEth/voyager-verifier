# verify Command

The `verify` command submits Starknet contracts for verification on the Voyager block explorer.

## Synopsis

```bash
voyager verify [OPTIONS]
```

## Description

The `verify` command collects your contract source files, compiles them remotely using the same configuration you used for deployment, and verifies that the compiled output matches your deployed contract. Upon successful verification, your contract will display a verified badge on Voyager.

## Verification Modes

### Interactive Wizard Mode

Guided step-by-step verification (recommended for first-time users):

```bash
voyager verify --wizard
```

### Command Line Mode

Direct verification with all parameters specified:

```bash
voyager verify --network mainnet \
  --class-hash 0x044dc2b3... \
  --contract-name MyToken
```

### Batch Mode

Verify multiple contracts using `.voyager.toml` configuration:

```bash
voyager verify
```

Batch mode is automatically enabled when `[[contracts]]` array exists in your config file.

## Options

### Required Options

#### `--network <NETWORK>`

Specify the target network.

**Values:**
- `mainnet` - Starknet mainnet
- `sepolia` - Sepolia testnet
- `dev` - Development network

**Example:**
```bash
voyager verify --network mainnet --class-hash 0x044... --contract-name MyToken
```

**Alternative:** Use `--url` for custom endpoints, or configure in `.voyager.toml`.

#### `--url <URL>`

Custom API endpoint URL (alternative to `--network`).

**Example:**
```bash
voyager verify --url https://api.custom.com/beta \
  --class-hash 0x044... \
  --contract-name MyToken
```

**Note:** Cannot be used together with `--network`.

#### `--class-hash <HASH>`

The class hash of your deployed contract.

**Format:** Hexadecimal string starting with `0x`

**Example:**
```bash
voyager verify --network mainnet \
  --class-hash 0x044dc2b3239382230d8b1e943df23b96f52eebcac93efe6e8bde92f9a2f1da18 \
  --contract-name MyToken
```

**Note:** Not required when using `--wizard` or batch mode.

#### `--contract-name <NAME>`

The name of the contract to verify.

**Example:**
```bash
voyager verify --network mainnet \
  --class-hash 0x044... \
  --contract-name MyToken
```

**Note:** Must match the contract name in your Cairo source code. Not required when using `--wizard` or batch mode.

### Optional Options

#### `--wizard`

Launch interactive verification wizard.

**Example:**
```bash
voyager verify --wizard
```

Prompts you step-by-step for all required information.

#### `--path <PATH>`

Path to the Scarb project directory.

**Default:** Current working directory

**Example:**
```bash
voyager verify --network mainnet \
  --class-hash 0x044... \
  --contract-name MyToken \
  --path /path/to/my/project
```

#### `--package <PACKAGE_ID>`

Specify which package to verify (required for workspace projects with multiple packages).

**Example:**
```bash
voyager verify --network mainnet \
  --class-hash 0x044... \
  --contract-name MyToken \
  --package my_contract_package
```

**Alternative:** Configure `default-package` in `.voyager.toml`:

```toml
[workspace]
default-package = "my_contract_package"
```

#### `--license <SPDX_ID>`

SPDX license identifier for your contract.

**Default:**
1. Value from `Scarb.toml` if specified
2. Value from `.voyager.toml` if specified
3. "All Rights Reserved" if not specified

**Example:**
```bash
voyager verify --network mainnet \
  --class-hash 0x044... \
  --contract-name MyToken \
  --license MIT
```

**Common licenses:** `MIT`, `Apache-2.0`, `GPL-3.0`, `BSD-3-Clause`

See [SPDX License List](https://spdx.org/licenses/) for all valid identifiers.

#### `--lock-file`

Include `Scarb.lock` file in verification submission.

**Default:** `false`

**Example:**
```bash
voyager verify --network mainnet \
  --class-hash 0x044... \
  --contract-name MyToken \
  --lock-file
```

**Use case:** Ensures reproducible builds by locking dependency versions.

#### `--test-files`

Include test files from the `src/` directory in verification submission.

**Default:** `false`

**Example:**
```bash
voyager verify --network mainnet \
  --class-hash 0x044... \
  --contract-name MyToken \
  --test-files
```

**Use case:** When your contract depends on test utilities or when test modules are declared in `lib.cairo`.

#### `--watch`

Monitor verification status until completion.

**Default:** `false`

**Example:**
```bash
voyager verify --network mainnet \
  --class-hash 0x044... \
  --contract-name MyToken \
  --watch
```

Displays live progress updates and waits for final result.

#### `--notify`

Send desktop notifications when verification completes.

**Default:** `false`

**Requires:** `--watch` must also be specified

**Example:**
```bash
voyager verify --network mainnet \
  --class-hash 0x044... \
  --contract-name MyToken \
  --watch \
  --notify
```

#### `--dry-run`

Preview what will be submitted without actually sending the verification request.

**Default:** `false`

**Example:**
```bash
voyager verify --network mainnet \
  --class-hash 0x044... \
  --contract-name MyToken \
  --dry-run
```

**Output:** Shows complete API request payload including all metadata and file list.

#### `--verbose`, `-v`

Show detailed error messages and compilation output.

**Default:** `false`

**Example:**
```bash
voyager verify --network mainnet \
  --class-hash 0x044... \
  --contract-name MyToken \
  --verbose
```

#### `--project-type <TYPE>`

Specify project type manually.

**Values:**
- `auto` - Automatic detection (default)
- `scarb` - Standard Scarb project
- `dojo` - Dojo framework project

**Default:** `auto`

**Example:**
```bash
voyager verify --network mainnet \
  --class-hash 0x044... \
  --contract-name MyToken \
  --project-type dojo
```

### Batch Verification Options

#### `--fail-fast`

Stop batch verification on first failure.

**Default:** `false` (continues with remaining contracts)

**Example:**
```bash
voyager verify --fail-fast
```

#### `--batch-delay <SECONDS>`

Add delay between contract submissions in batch mode.

**Default:** No delay

**Example:**
```bash
voyager verify --batch-delay 5
```

**Use case:** Rate limiting for API throttling.

### Output Options

#### `--format <FORMAT>`

Output format for verification results.

**Values:**
- `text` - Human-readable text (default)
- `json` - Machine-readable JSON
- `table` - Formatted table (for batch operations)

**Example:**
```bash
voyager verify --network mainnet \
  --class-hash 0x044... \
  --contract-name MyToken \
  --format json
```

## Configuration File

Options can be set in `.voyager.toml`:

```toml
[voyager]
network = "mainnet"
license = "MIT"
watch = true
test-files = false
lock-file = true
verbose = false
notify = false
project-type = "auto"

[workspace]
default-package = "my_contract"

# Batch verification
[[contracts]]
class-hash = "0x044dc2b3..."
contract-name = "MyToken"
package = "token"  # Optional

[[contracts]]
class-hash = "0x055dc2b3..."
contract-name = "MyNFT"
```

CLI arguments override config file values.

## Examples

### Basic Verification

Minimal command:

```bash
voyager verify --network mainnet \
  --class-hash 0x044dc2b3239382230d8b1e943df23b96f52eebcac93efe6e8bde92f9a2f1da18 \
  --contract-name MyToken
```

### Recommended Verification

With license and watch mode:

```bash
voyager verify --network mainnet \
  --class-hash 0x044dc2b3239382230d8b1e943df23b96f52eebcac93efe6e8bde92f9a2f1da18 \
  --contract-name MyToken \
  --license MIT \
  --watch
```

### Production Verification

Full-featured with all options:

```bash
voyager verify --network mainnet \
  --class-hash 0x044dc2b3239382230d8b1e943df23b96f52eebcac93efe6e8bde92f9a2f1da18 \
  --contract-name MyToken \
  --license MIT \
  --lock-file \
  --watch \
  --notify \
  --verbose
```

### Workspace Project

Specify package:

```bash
voyager verify --network mainnet \
  --class-hash 0x044dc2b3... \
  --contract-name MyToken \
  --package my_contract_package
```

### Custom Endpoint

Using custom API:

```bash
voyager verify --url https://api.custom.com/beta \
  --class-hash 0x044dc2b3... \
  --contract-name MyToken
```

### Dry Run

Preview before submitting:

```bash
voyager verify --network mainnet \
  --class-hash 0x044dc2b3... \
  --contract-name MyToken \
  --dry-run
```

### Batch Verification

Define contracts in `.voyager.toml`:

```toml
[voyager]
network = "mainnet"
license = "MIT"

[[contracts]]
class-hash = "0x044dc2b3..."
contract-name = "Token"

[[contracts]]
class-hash = "0x055dc2b3..."
contract-name = "NFT"
```

Then run:

```bash
voyager verify --watch --batch-delay 5
```

## Output

### Success Output

```
✓ Verification submitted successfully!
Job ID: abc-123-def-456
Network: mainnet
Class Hash: 0x044dc2b3239382230d8b1e943df23b96f52eebcac93efe6e8bde92f9a2f1da18

Check status with:
  voyager status --network mainnet --job abc-123-def-456
```

### Watch Mode Output

```
⏳ Verifying contract...
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 65%
Status: Compiling | Elapsed: 1m 45s | Estimated: 2m 42s

✓ Verification successful!
View on Voyager: https://voyager.online/class/0x044dc2b3...
```

### Batch Mode Output

```
[1/3] Verifying: MyToken
  ✓ Submitted - Job ID: abc-123-def

[2/3] Verifying: MyNFT
  ⏳ Waiting 5 seconds before next submission...
  ✓ Submitted - Job ID: ghi-456-jkl

[3/3] Verifying: MyMarketplace
  ✓ Submitted - Job ID: mno-789-pqr

════════════════════════════════════════════════════════
Batch Verification Summary
════════════════════════════════════════════════════════
Total contracts:  3
Submitted:        3
Succeeded:        0
Failed:           0
Pending:          3
════════════════════════════════════════════════════════
```

## Exit Codes

- **0** - Verification submitted successfully
- **1** - Verification submission failed
- **2** - Invalid arguments or configuration

## Error Handling

Common errors and solutions:

### E001: Invalid class hash format

```
Error: [E001] Invalid class hash format
```

**Solution:** Ensure class hash starts with `0x` and is valid hexadecimal.

### E004: Compilation failed

```
Error: [E004] Compilation failed
```

**Solution:** Use `--verbose` to see full compilation error details.

### E005: Module file not found

```
Error: [E005] Module file not found
```

**Solution:** Include test files with `--test-files` if the missing file is a test module.

For complete error reference, see [Error Codes](../reference/error-codes.md).

## See Also

- [status command](./status.md) - Check verification status
- [history command](./history.md) - View verification history
- [Interactive Wizard](../verification/interactive-wizard.md) - Wizard mode guide
- [Batch Verification](../verification/batch-verification.md) - Batch verification guide
- [Configuration File](../configuration/config-file.md) - Config file reference
- [Troubleshooting](../troubleshooting/README.md) - Troubleshooting guide
