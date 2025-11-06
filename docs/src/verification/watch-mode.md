# Watch Mode

Watch mode enables real-time monitoring of verification jobs, automatically polling the API until the job reaches a terminal state (Success, Failed, or CompileFailed).

## Overview

Watch mode provides:

- **Automatic polling** - No need to manually check status
- **Live progress updates** - See real-time verification progress
- **Progress estimation** - Time-based completion estimates
- **Progress bars** - Visual representation of progress
- **Stage-aware status** - Different messages for each verification stage
- **Desktop notifications** - Optional alerts when complete (with `--notify`)
- **Automatic timeout** - Exits after 10 minutes if not complete

## Enabling Watch Mode

### During Verification

Enable watch mode when submitting a verification:

```bash
voyager verify --network mainnet \
  --class-hash 0x044dc2b3... \
  --contract-name MyToken \
  --watch
```

The tool will submit the verification and immediately start monitoring.

### For Existing Jobs

Check status with watch mode for an already-submitted job:

```bash
voyager status --network mainnet \
  --job abc-123-def-456 \
  --watch
```

### In Configuration File

Set watch mode as default in `.voyager.toml`:

```toml
[voyager]
watch = true
```

## How Watch Mode Works

### Polling Mechanism

Watch mode uses **fixed-interval polling**:

- **Poll interval:** Every 2 seconds
- **Maximum retries:** 300 attempts
- **Total timeout:** 10 minutes (600 seconds)
- **No exponential backoff:** Consistent 2-second intervals

**Example timeline:**
```
0s   - Submit verification
2s   - Poll #1 - Status: Submitted
4s   - Poll #2 - Status: Compiling
6s   - Poll #3 - Status: Compiling
...
120s - Poll #60 - Status: Success ✓
```

### Terminal States

Watch mode exits when the job reaches any of these states:

- **Success** ✅ - Verification completed successfully
- **Failed** ❌ - Verification failed (compiled output doesn't match)
- **CompileFailed** ❌ - Compilation failed on remote server

### Non-Terminal States

These states continue polling:

- **Submitted** - Job queued, waiting to start
- **Processing** - Job being processed
- **Compiling** - Remote compilation in progress
- **Compiled** - Compilation complete, starting verification
- **Verifying** - Comparing compiled output with deployed contract

## Progress Display

### Live Progress Bar

Watch mode shows a live progress bar with time estimates:

```
⏳ Verifying contract...
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 45%
Status: Compiling | Elapsed: 1m 23s | Estimated: 3m 0s
```

**Components:**
- **Progress bar** - Visual representation of completion
- **Percentage** - Estimated completion percentage
- **Current status** - Current verification stage
- **Elapsed time** - Time since submission
- **Estimated total** - Estimated total time to completion

### Progress Estimation

Progress is estimated using two methods:

#### 1. Historical Average (Preferred)

Uses your local verification history:

- Queries last 10 successful verifications from `~/.voyager/history.db`
- Calculates average verification time
- Requires minimum 3 samples
- Improves accuracy over time as you verify more contracts

**Example:**
```
Last 10 verifications averaged 2m 45s
Current elapsed: 1m 30s
Estimated completion: 2m 45s
Progress: 54% (1m 30s / 2m 45s)
```

#### 2. Stage-Based Fallback

Used when insufficient history is available:

| Stage | Estimated Remaining Time |
|-------|-------------------------|
| Submitted | ~2 minutes |
| Processing | ~90 seconds |
| Compiling | ~90 seconds |
| Compiled | ~45 seconds |
| Verifying | ~30 seconds |

**Example (no history):**
```
Status: Compiling
Elapsed: 1m 0s
Estimated remaining: 90s
Total estimated: 2m 30s
Progress: 40% (1m / 2m 30s)
```

### Status Messages

Different messages for each stage:

**Submitted:**
```
⏳ Verification submitted, waiting to start...
Status: Submitted | Elapsed: 0m 15s
```

**Compiling:**
```
⏳ Verifying contract...
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 35%
Status: Compiling | Elapsed: 1m 15s | Estimated: 3m 0s
```

**Verifying:**
```
⏳ Verifying contract...
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 85%
Status: Verifying | Elapsed: 2m 30s | Estimated: 3m 0s
```

**Success:**
```
✓ Verification successful!

Job ID: abc-123-def-456
Status: Success
Class Hash: 0x044dc2b3...da18
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

## Timeout Handling

### Maximum Duration

Watch mode has a **10-minute timeout**:

- 300 polls × 2 seconds = 600 seconds (10 minutes)
- Prevents indefinite waiting for stuck jobs
- Provides clear timeout message

### Timeout Behavior

If the job doesn't complete within 10 minutes:

```
⚠ Timeout: Job did not complete within 10 minutes
Current status: Compiling

The job is still processing on the server.
You can check status later with:
  voyager status --network mainnet --job abc-123-def-456

Or check from history:
  voyager history status --job abc-123-def-456
```

**Exit code:** Non-zero (failure)

### After Timeout

The job continues processing on the server even after timeout. You can:

**Check status later:**
```bash
voyager status --network mainnet --job abc-123-def-456
```

**Check from history:**
```bash
voyager history status --job abc-123-def-456
```

**Resume watching:**
```bash
voyager status --network mainnet --job abc-123-def-456 --watch
```

## Desktop Notifications

Combine watch mode with desktop notifications:

```bash
voyager verify --network mainnet \
  --class-hash 0x044dc2b3... \
  --contract-name MyToken \
  --watch \
  --notify
```

**Behavior:**
- Watch mode monitors the verification
- Desktop notification appears when complete
- Notification shows success (✅) or failure (❌)
- Allows you to work on other tasks while waiting

See [Desktop Notifications](../advanced/notifications.md) for details.

## Use Cases

### Interactive Verification

When you want immediate feedback:

```bash
voyager verify --network mainnet \
  --class-hash 0x044dc2b3... \
  --contract-name MyToken \
  --watch
```

**Benefits:**
- No need to remember job ID
- Immediate status updates
- Know results right away

### Background Monitoring with Notifications

For long-running verifications:

```bash
voyager verify --network mainnet \
  --class-hash 0x044dc2b3... \
  --contract-name MyToken \
  --watch \
  --notify
```

**Benefits:**
- Continue working on other tasks
- Get notified when complete
- Don't need to check manually

### Batch Verification Monitoring

Watch all contracts in a batch:

```bash
voyager verify --watch
```

**Output:**
```
⏳ Watching 3 verification job(s)...

  ✓ 2 Succeeded | ⏳ 1 Pending | ✗ 0 Failed
```

See [Batch Verification](./batch-verification.md) for details.

### CI/CD Without Watch Mode

In automated pipelines, **disable** watch mode:

```bash
# Submit and exit immediately
voyager verify --network mainnet \
  --class-hash 0x044dc2b3... \
  --contract-name MyToken

# Check status later in pipeline
voyager status --network mainnet --job $JOB_ID
```

Or use config file:
```toml
[voyager]
watch = false  # Don't block CI pipeline
```

## Comparison: Watch vs No Watch

### With Watch Mode

```bash
voyager verify --network mainnet \
  --class-hash 0x044dc2b3... \
  --contract-name MyToken \
  --watch
```

**Behavior:**
1. Submit verification
2. Display job ID
3. Start polling immediately
4. Show live progress
5. Display final result
6. Exit when complete

**Duration:** Waits until complete (or 10 min timeout)

### Without Watch Mode

```bash
voyager verify --network mainnet \
  --class-hash 0x044dc2b3... \
  --contract-name MyToken
```

**Behavior:**
1. Submit verification
2. Display job ID
3. Exit immediately

**Duration:** < 5 seconds

**Manual checking:**
```bash
voyager status --network mainnet --job abc-123-def-456
```

## Configuration Priority

Watch mode can be configured in multiple ways. Priority order:

1. **CLI flag** (highest priority)
   ```bash
   voyager verify --watch  # Enables
   voyager verify --no-watch  # Disables (if supported)
   ```

2. **Configuration file**
   ```toml
   [voyager]
   watch = true
   ```

3. **Default value** (lowest priority)
   - Default: `false` (watch mode disabled)

**Example:**
```toml
# .voyager.toml
[voyager]
watch = true  # Default: enable watch mode
```

```bash
# Override config file - disable watch mode for this command
voyager verify --network mainnet --class-hash 0x044... --contract-name MyToken
# Uses config file default (watch = true)
```

## Performance Considerations

### Network Usage

Watch mode polls every 2 seconds:

- **Requests:** 1 API call per 2 seconds
- **Max requests:** 300 requests (for 10-minute timeout)
- **Typical requests:** 30-90 requests (1-3 minute verification)

**Network-friendly:** Minimal data transfer, negligible bandwidth usage.

### Rate Limiting

The 2-second interval is designed to be:
- Fast enough for responsive updates
- Slow enough to avoid API rate limits
- Respectful of server resources

## Troubleshooting

### Job Doesn't Complete

If watch mode times out after 10 minutes:

**Possible causes:**
- Server is experiencing high load
- Complex contract taking longer than usual
- Build process encountered an issue

**Solutions:**
1. Check status later:
   ```bash
   voyager status --network mainnet --job abc-123-def-456
   ```

2. Use verbose mode to see detailed errors:
   ```bash
   voyager status --network mainnet --job abc-123-def-456 --verbose
   ```

3. Contact support if job remains stuck

### Progress Bar Not Updating

If the progress bar seems frozen:

**Cause:** Job is in the same stage (normal behavior)

**Solution:** Wait - compilation can take 1-3 minutes depending on contract size.

### Inaccurate Time Estimates

If estimates seem wrong:

**Cause:** Insufficient historical data or unusual verification duration

**Solution:**
- Estimates improve as you verify more contracts
- Historical average based on last 10 successful verifications
- First few verifications use stage-based fallback estimates

## Best Practices

### 1. Use Watch Mode Interactively

For manual verifications, enable watch mode:

```bash
voyager verify --network mainnet \
  --class-hash 0x044... \
  --contract-name MyToken \
  --watch
```

### 2. Disable in CI/CD

In automated pipelines, disable watch mode:

```toml
[voyager]
watch = false
```

### 3. Combine with Notifications

For long verifications, use notifications:

```bash
voyager verify --watch --notify
```

### 4. Check History After Timeout

If watch mode times out, check history:

```bash
voyager history status --job abc-123-def-456
```

### 5. Use Verbose for Failures

If verification fails, use verbose mode:

```bash
voyager status --network mainnet --job abc-123-def-456 --verbose
```

## See Also

- [verify command](../commands/verify.md) - verify command reference
- [status command](../commands/status.md) - status command reference
- [Desktop Notifications](../advanced/notifications.md) - Notification setup
- [Batch Verification](./batch-verification.md) - Monitoring multiple jobs
- [Output Formats](../advanced/output-formats.md) - Alternative output formats