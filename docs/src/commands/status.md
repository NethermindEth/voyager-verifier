# status Command

The `status` command checks the verification status of a submitted job.

## Synopsis

```bash
voyager status --job <JOB_ID> [OPTIONS]
```

## Description

The `status` command queries the Voyager API to retrieve the current status of a verification job. It can perform a one-time status check or continuously monitor the job until completion using watch mode.

## Required Options

### `--job <JOB_ID>`

The verification job ID to check.

**Format:** Job ID string returned by the `verify` command

**Example:**
```bash
voyager status --network mainnet --job abc-123-def-456
```

### Network Selection

One of the following is required:

#### `--network <NETWORK>`

Specify the target network.

**Values:**
- `mainnet` - Starknet mainnet
- `sepolia` - Sepolia testnet
- `dev` - Development network

**Example:**
```bash
voyager status --network mainnet --job abc-123-def
```

#### `--url <URL>`

Custom API endpoint URL (alternative to `--network`).

**Example:**
```bash
voyager status --url https://api.custom.com/beta --job abc-123-def
```

**Note:** Cannot be used together with `--network`. Can be configured in `.voyager.toml`.

## Optional Options

### `--watch`

Monitor job status continuously until completion.

**Default:** `false`

**Example:**
```bash
voyager status --network mainnet --job abc-123-def --watch
```

**Behavior:**
- Polls the API every 2 seconds
- Displays live progress updates
- Exits when job reaches terminal status (Success, Failed, CompileFailed)
- Maximum timeout: 10 minutes (300 retries)

### `--notify`

Send desktop notification when verification completes.

**Default:** `false`

**Requires:** `--watch` must also be specified

**Example:**
```bash
voyager status --network mainnet --job abc-123-def --watch --notify
```

**Platforms:** Linux, macOS, Windows

### `--verbose`, `-v`

Show detailed error messages and compilation output.

**Default:** `false`

**Example:**
```bash
voyager status --network mainnet --job abc-123-def --verbose
```

**Use case:** View full compilation errors when verification fails.

### `--format <FORMAT>`

Output format for status information.

**Values:**
- `text` - Human-readable text (default)
- `json` - Machine-readable JSON

**Default:** `text`

**Example:**
```bash
voyager status --network mainnet --job abc-123-def --format json
```

**JSON Output Example:**
```json
{
  "job_id": "abc-123-def-456",
  "status": "Success",
  "class_hash": "0x044dc2b3239382230d8b1e943df23b96f52eebcac93efe6e8bde92f9a2f1da18",
  "contract_name": "MyToken",
  "network": "mainnet",
  "submitted_at": "2025-01-15T10:30:00Z",
  "completed_at": "2025-01-15T10:32:45Z"
}
```

## Configuration File

Network and other options can be configured in `.voyager.toml`:

```toml
[voyager]
network = "mainnet"
watch = true
verbose = false
```

CLI arguments override config file values.

## Job Status Values

### In-Progress Statuses

**Submitted**
- Job created and queued
- Waiting to start compilation

**Processing**
- Job is being processed
- Source files are being prepared

**Compiling**
- Remote compiler is building your contract
- Using `scarb --release build`

**Compiled**
- Compilation successful
- Performing verification checks

**Verifying**
- Comparing compiled output with deployed contract

### Terminal Statuses

**Success** ✅
- Verification completed successfully
- Contract is now verified on Voyager
- Source code is viewable in the explorer

**Failed** ❌
- Verification failed
- Compiled output doesn't match deployed contract
- Use `--verbose` for details

**CompileFailed** ❌
- Compilation failed on remote server
- Build error in your source code
- Use `--verbose` to see full compiler output

## Examples

### Basic Status Check

One-time status check:

```bash
voyager status --network mainnet --job abc-123-def-456
```

### Watch Mode

Monitor until completion:

```bash
voyager status --network mainnet --job abc-123-def-456 --watch
```

### Watch with Notifications

Get notified when complete:

```bash
voyager status --network mainnet --job abc-123-def-456 --watch --notify
```

### Verbose Output

View detailed error information:

```bash
voyager status --network mainnet --job abc-123-def-456 --verbose
```

### JSON Output

For scripting and CI/CD:

```bash
voyager status --network mainnet --job abc-123-def-456 --format json
```

### Custom Endpoint

Using custom API:

```bash
voyager status --url https://api.custom.com/beta --job abc-123-def-456
```

### Combined Options

Full-featured status check:

```bash
voyager status --network mainnet \
  --job abc-123-def-456 \
  --watch \
  --notify \
  --verbose
```

## Output

### Text Format (Default)

**In-Progress:**
```
⏳ Verifying contract...
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 45%
Status: Compiling | Elapsed: 1m 23s | Estimated: 3m 0s
```

**Success:**
```
✓ Verification successful!

Job ID: abc-123-def-456
Status: Success
Class Hash: 0x044dc2b3239382230d8b1e943df23b96f52eebcac93efe6e8bde92f9a2f1da18
Contract Name: MyToken
Network: mainnet

View on Voyager: https://voyager.online/class/0x044dc2b3...
```

**Failed:**
```
✗ Verification failed

Job ID: abc-123-def-456
Status: Failed
Reason: Compiled output does not match deployed contract

Use --verbose for detailed error output
```

**CompileFailed:**
```
✗ Compilation failed

Job ID: abc-123-def-456
Status: CompileFailed
Error: [E004] Compilation failed: `scarb` command exited with error

Use --verbose to see full compilation output
```

### JSON Format

**Success:**
```json
{
  "job_id": "abc-123-def-456",
  "status": "Success",
  "class_hash": "0x044dc2b3239382230d8b1e943df23b96f52eebcac93efe6e8bde92f9a2f1da18",
  "contract_name": "MyToken",
  "network": "mainnet",
  "submitted_at": "2025-01-15T10:30:00Z",
  "completed_at": "2025-01-15T10:32:45Z",
  "compiler_version": "2.11.4",
  "scarb_version": "2.8.4"
}
```

**Failed:**
```json
{
  "job_id": "abc-123-def-456",
  "status": "Failed",
  "class_hash": "0x044dc2b3...",
  "contract_name": "MyToken",
  "network": "mainnet",
  "submitted_at": "2025-01-15T10:30:00Z",
  "completed_at": "2025-01-15T10:32:45Z",
  "error": "Compiled output does not match deployed contract"
}
```

### Verbose Output

With `--verbose`, failed compilations show full compiler output:

```
✗ Compilation failed

Job ID: abc-123-def-456
Status: CompileFailed

Compilation Output:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
error[E0005]: Module file not found. Expected path: /tmp/targets/.../src/tests.cairo
 --> lib.cairo:3:1
  |
3 | mod tests;
  | ^^^^^^^^^^
  |

Error: Could not compile contract due to previous error
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Suggestion: Include test files with --test-files flag or remove test module declaration
```

## Progress Estimation

When using `--watch`, the progress bar estimates completion time based on:

1. **Historical data** - Average time from your last 10 successful verifications (requires minimum 3 samples)
2. **Stage-based fallback** - If no history available, uses stage-specific estimates:
   - Submitted: ~2 minutes remaining
   - Compiling: ~90 seconds remaining
   - Verifying: ~30 seconds remaining

Progress estimation improves automatically as you verify more contracts.

## Exit Codes

- **0** - Job completed successfully (Success status)
- **1** - Job failed (Failed or CompileFailed status)
- **2** - Invalid arguments or job not found

## Polling Behavior

### Fixed Interval Polling

The `status` command uses fixed 2-second polling intervals (not exponential backoff):

- **Poll interval:** Every 2 seconds
- **Maximum retries:** 300 (10 minutes total)
- **Timeout:** Exits after 10 minutes if job hasn't completed

### Timeout Handling

If job doesn't complete within 10 minutes:

```
⚠ Timeout: Job did not complete within 10 minutes
Current status: Compiling

You can check status later with:
  voyager status --network mainnet --job abc-123-def-456
```

## Using with History

The `status` command automatically updates the local history database when checking job status. For faster local lookups without API calls, use:

```bash
# Check from local history (no API call)
voyager history status --job abc-123-def-456

# Refresh from API and update history
voyager history status --job abc-123-def-456 --network mainnet --refresh
```

See [history command](./history.md) for more details.

## Scripting and Automation

### CI/CD Pipeline

Check status in CI/CD with JSON output:

```bash
#!/bin/bash

JOB_ID=$(voyager verify --network mainnet \
  --class-hash 0x044... \
  --contract-name MyToken \
  --format json | jq -r '.job_id')

# Wait for completion
voyager status --network mainnet --job "$JOB_ID" --watch --format json > result.json

# Check result
STATUS=$(jq -r '.status' result.json)
if [ "$STATUS" = "Success" ]; then
  echo "Verification successful"
  exit 0
else
  echo "Verification failed"
  jq -r '.error' result.json
  exit 1
fi
```

### Loop Until Complete

Manual polling in a script:

```bash
#!/bin/bash

JOB_ID="abc-123-def-456"
while true; do
  STATUS=$(voyager status --network mainnet --job "$JOB_ID" --format json | jq -r '.status')

  case "$STATUS" in
    "Success")
      echo "Verification successful!"
      exit 0
      ;;
    "Failed"|"CompileFailed")
      echo "Verification failed: $STATUS"
      exit 1
      ;;
    *)
      echo "Status: $STATUS - waiting..."
      sleep 5
      ;;
  esac
done
```

## Troubleshooting

### Job Not Found

```
Error: [E020] Job not found: abc-123-def-456
```

**Solutions:**
- Verify the job ID is correct
- Ensure you're using the correct network (`--network` or `--url`)
- Check if the job was submitted to a different network

### Timeout in Watch Mode

If watch mode times out, check status manually later:

```bash
voyager status --network mainnet --job abc-123-def-456
```

Or check from history:

```bash
voyager history status --job abc-123-def-456
```

### Network Connectivity Issues

If API calls fail:

```bash
# Check with verbose output
voyager status --network mainnet --job abc-123-def-456 --verbose

# Try custom endpoint
voyager status --url https://api.voyager.online/beta --job abc-123-def-456
```

## See Also

- [verify command](./verify.md) - Submit contracts for verification
- [history command](./history.md) - View verification history
- [Watch Mode Guide](../verification/watch-mode.md) - Detailed watch mode documentation
- [Output Formats](../advanced/output-formats.md) - Output format reference
- [Troubleshooting](../troubleshooting/README.md) - Common issues and solutions
