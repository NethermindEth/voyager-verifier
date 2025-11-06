# Rechecking Verification Jobs

Update the status of pending verification jobs by rechecking with the Voyager API.

## Overview

The `history recheck` command allows you to:

- **Update pending jobs** - Check if pending verifications have completed
- **Batch status updates** - Recheck multiple jobs at once
- **Network-specific checks** - Recheck jobs for specific networks
- **Automatic history updates** - Updates stored in local database
- **See what changed** - Summary of status changes

## Basic Usage

### Recheck All Pending Jobs

```bash
voyager history recheck --network <NETWORK>
```

**Example:**
```bash
voyager history recheck --network mainnet
```

**Output:**
```
Rechecking pending verifications...
════════════════════════════════════════════════════════

Checking 3 pending jobs on mainnet...

[1/3] MyToken (abc-123-def-456)
  Status: Pending → Success ✓

[2/3] TestContract (ghi-789-jkl-012)
  Status: Pending → Success ✓

[3/3] NFTContract (mno-345-pqr-678)
  Status: Pending → Failed ✗
  Error: Compilation error in contract code

────────────────────────────────────────────────────────
Summary:
  Total checked: 3
  Completed: 2
  Failed: 1
  Still pending: 0
```

## Command Options

### Required: Network

You must specify the network:

```bash
voyager history recheck --network <NETWORK>
```

**Available networks:**
- `mainnet`
- `sepolia`
- `dev`
- Custom endpoint URLs

### Optional: Job ID

Recheck a specific job:

```bash
voyager history recheck --network <NETWORK> --job <JOB_ID>
```

**Example:**
```bash
voyager history recheck --network mainnet --job abc-123-def-456
```

### Optional: Status Filter

Only recheck jobs with specific status:

```bash
voyager history recheck --network <NETWORK> --status <STATUS>
```

**Example:**
```bash
# Only recheck pending jobs (default)
voyager history recheck --network mainnet --status pending

# Recheck all jobs regardless of status
voyager history recheck --network mainnet --status all
```

## Use Cases

### Use Case 1: Daily Pending Check

Check pending verifications daily:

```bash
# Morning routine
voyager history list --status pending
voyager history recheck --network mainnet
```

### Use Case 2: CI/CD Pipeline

Verify deployment status in CI:

```bash
#!/bin/bash
# deploy-check.sh

# Submit verification
JOB_ID=$(voyager verify \
  --network mainnet \
  --class-hash $CLASS_HASH \
  --contract-name $CONTRACT \
  | grep "Job ID" | awk '{print $3}')

# Wait a bit
sleep 60

# Check status
voyager history recheck --network mainnet --job $JOB_ID

# Verify success
STATUS=$(voyager history list --job $JOB_ID --format json | jq -r '.[0].status')
if [ "$STATUS" != "success" ]; then
  echo "Verification failed or still pending"
  exit 1
fi
```

### Use Case 3: Network-Specific Review

Recheck all pending jobs on specific network:

```bash
# Check sepolia testnet
voyager history recheck --network sepolia

# Check mainnet
voyager history recheck --network mainnet
```

### Use Case 4: After API Downtime

If API was down, recheck all jobs:

```bash
# Recheck all jobs (not just pending)
voyager history recheck --network mainnet --status all
```

### Use Case 5: Weekly Cleanup

Weekly maintenance to update all pending:

```bash
#!/bin/bash
# weekly-recheck.sh

for network in mainnet sepolia; do
  echo "Rechecking $network..."
  voyager history recheck --network $network
done
```

## Understanding Output

### Status Transitions

**Pending → Success:**
```
[1/3] MyToken (abc-123-def-456)
  Status: Pending → Success ✓
  Duration: 4m 27s
```

**Pending → Failed:**
```
[2/3] TestContract (ghi-789-jkl-012)
  Status: Pending → Failed ✗
  Error: Compilation error in contract code
```

**Still Pending:**
```
[3/3] NFTContract (mno-345-pqr-678)
  Status: Pending → Still Pending ⏳
  Note: Compilation in progress
```

### Summary Statistics

```
Summary:
  Total checked: 5
  Completed: 3      # Changed to success
  Failed: 1         # Changed to failed
  Still pending: 1  # Still in progress
```

## Behavior Details

### What Gets Rechecked

**Default behavior:**
- Only jobs with `status = pending` are rechecked
- Only jobs on specified network
- Jobs are checked against Voyager API
- Local database is updated with new status

**With `--status all`:**
- All jobs on specified network are rechecked
- Useful after API issues or data corruption

### API Rate Limiting

Recheck requests are rate-limited:

- **Delay between checks:** 1 second
- **Batch size:** All pending jobs
- **Timeout:** 30 seconds per job

**For large batches:**
```bash
# If you have many pending jobs (>100)
voyager history recheck --network mainnet --limit 50
```

### Network Requirement

Network must be specified because:
- API endpoints differ per network
- Job IDs are network-specific
- Prevents accidental cross-network checks

## Examples

### Example 1: Basic Recheck

```bash
# Check what's pending
voyager history list --status pending

# Output:
# 3 pending verifications found

# Recheck them
voyager history recheck --network mainnet

# Output: Summary of status changes
```

### Example 2: Specific Job

```bash
# Recheck one job
voyager history recheck \
  --network mainnet \
  --job abc-123-def-456

# Output:
# MyToken (abc-123-def-456)
#   Status: Pending → Success ✓
```

### Example 3: All Networks

```bash
# Recheck all networks
for network in mainnet sepolia dev; do
  echo "Checking $network..."
  voyager history recheck --network $network
done
```

### Example 4: After Submission

```bash
# Submit without watch
voyager verify --network mainnet \
  --class-hash 0x123... \
  --contract-name MyContract

# Later, check status
sleep 300  # Wait 5 minutes
voyager history recheck --network mainnet
```

### Example 5: CI Integration

```bash
# In CI pipeline
voyager verify --network mainnet \
  --class-hash $HASH \
  --contract-name $NAME

# Poll for completion
for i in {1..10}; do
  echo "Check $i/10..."
  voyager history recheck --network mainnet

  # Check if done
  STATUS=$(voyager history list --limit 1 --format json | jq -r '.[0].status')
  if [ "$STATUS" = "success" ]; then
    echo "Verification complete!"
    exit 0
  elif [ "$STATUS" = "failed" ]; then
    echo "Verification failed!"
    exit 1
  fi

  sleep 30
done

echo "Verification timeout"
exit 1
```

## Integration with Other Commands

### With `history list`

```bash
# List pending
voyager history list --status pending

# Recheck them
voyager history recheck --network mainnet

# List again to confirm
voyager history list --status pending
```

### With `history status`

```bash
# Recheck specific job
voyager history recheck --network mainnet --job abc-123

# Get detailed status
voyager history status --network mainnet --job abc-123 --verbose
```

### With `watch mode`

Watch mode (`--watch`) automatically checks status, but for jobs submitted without watch:

```bash
# Submit without watch
voyager verify --network mainnet --class-hash 0x123... --contract-name Token

# Manual recheck later
voyager history recheck --network mainnet
```

## Comparison: Recheck vs Watch

### Watch Mode (`--watch`)

**Use when:**
- Submitting new verification
- Want immediate feedback
- Can wait for completion
- Running interactively

**Example:**
```bash
voyager verify --network mainnet \
  --class-hash 0x123... \
  --contract-name Token \
  --watch
```

**Behavior:**
- Automatically polls API
- Shows real-time progress
- Blocks until complete
- Updates history automatically

### Recheck (`history recheck`)

**Use when:**
- Jobs submitted without watch
- Checking old pending jobs
- Batch status updates
- Running in scripts/CI
- After API downtime

**Example:**
```bash
voyager history recheck --network mainnet
```

**Behavior:**
- One-time status check
- Non-blocking
- Updates multiple jobs
- Returns immediately with summary

## Error Handling

### No Pending Jobs

If no pending jobs exist:

```bash
voyager history recheck --network mainnet
```

**Output:**
```
Rechecking pending verifications...
════════════════════════════════════════════════════════

No pending verifications found for mainnet.

All verifications are either completed or failed.
```

### API Error

If API is unavailable:

```bash
voyager history recheck --network mainnet
```

**Output:**
```
Error: Unable to connect to Voyager API
  Network: mainnet
  Endpoint: https://api.voyager.online/beta

Please check:
  - Network connectivity
  - API endpoint status
  - Network name spelling

Retry in a few minutes.
```

### Job Not Found

If job no longer exists on API:

```bash
voyager history recheck --network mainnet --job abc-123
```

**Output:**
```
Warning: Job abc-123 not found on API
  Possible reasons:
  - Job expired (API retention period)
  - Wrong network specified
  - Invalid job ID

Local history will not be updated.
```

## Performance Considerations

### Batch Size

For large numbers of pending jobs:

```bash
# Recheck can be slow with many jobs
voyager history list --status pending  # Check how many

# If >50 jobs, consider limiting
voyager history recheck --network mainnet --limit 50
```

### Frequency

Don't recheck too frequently:

**Good:**
```bash
# Once per hour
*/60 * * * * voyager history recheck --network mainnet
```

**Less good:**
```bash
# Every minute (unnecessary API load)
* * * * * voyager history recheck --network mainnet
```

### Network Timeout

Default timeout is 30 seconds per job:

```bash
# For slow networks, increase timeout
voyager history recheck --network mainnet --timeout 60
```

## Automation Examples

### Cron Job

```bash
# Add to crontab
# Recheck every 6 hours
0 */6 * * * /usr/local/bin/voyager history recheck --network mainnet >> /var/log/voyager-recheck.log 2>&1
```

### Systemd Timer

```ini
# /etc/systemd/system/voyager-recheck.timer
[Unit]
Description=Recheck Voyager verification jobs

[Timer]
OnCalendar=*-*-* 00,06,12,18:00:00
Persistent=true

[Install]
WantedBy=timers.target
```

```ini
# /etc/systemd/system/voyager-recheck.service
[Unit]
Description=Recheck Voyager verification jobs

[Service]
Type=oneshot
ExecStart=/usr/local/bin/voyager history recheck --network mainnet
```

### GitHub Actions

```yaml
name: Recheck Verifications

on:
  schedule:
    - cron: '0 */6 * * *'  # Every 6 hours
  workflow_dispatch:  # Manual trigger

jobs:
  recheck:
    runs-on: ubuntu-latest
    steps:
      - name: Install Voyager
        run: cargo install voyager-verifier

      - name: Recheck Pending Jobs
        run: |
          voyager history recheck --network mainnet
          voyager history recheck --network sepolia
```

## Troubleshooting

### Problem: No Status Changes

**Issue:** Recheck shows no changes, jobs still pending.

**Possible causes:**
1. Jobs are legitimately still processing
2. API is slow
3. Verifications take longer than expected

**Solution:**
```bash
# Wait longer and try again
sleep 300  # 5 minutes
voyager history recheck --network mainnet

# Check specific job with verbose output
voyager history status --network mainnet --job <JOB_ID> --verbose --refresh
```

### Problem: Recheck Takes Too Long

**Issue:** Recheck command hangs or is very slow.

**Solution:**
```bash
# Use limit to reduce batch size
voyager history recheck --network mainnet --limit 10

# Check how many pending jobs exist
voyager history list --status pending | wc -l

# If too many, clean old pending jobs
voyager history clean --status pending --older-than 30
```

### Problem: Wrong Network

**Issue:** Error about job not found.

**Solution:**
```bash
# Verify which network the job was submitted to
voyager history list --format json | jq '.[] | {job: .job_id, network: .network}'

# Use correct network
voyager history recheck --network <CORRECT_NETWORK>
```

## Best Practices

### 1. Regular Rechecking

Set up automated rechecking:

```bash
# Daily recheck via cron
0 9 * * * voyager history recheck --network mainnet
```

### 2. Check Before Cleanup

Before cleaning history, recheck pending jobs:

```bash
# Recheck first
voyager history recheck --network mainnet

# Then clean old records
voyager history clean --older-than 90
```

### 3. Network-Specific

Always recheck per network:

```bash
# Good - explicit network
voyager history recheck --network mainnet

# Won't work - network required
voyager history recheck  # Error: network required
```

### 4. Use in Scripts

Combine with status checking:

```bash
#!/bin/bash
# smart-recheck.sh

# Recheck
voyager history recheck --network mainnet

# Count remaining pending
PENDING=$(voyager history list --status pending --network mainnet --format json | jq 'length')

if [ $PENDING -gt 0 ]; then
  echo "$PENDING verifications still pending"
else
  echo "All verifications complete"
fi
```

### 5. Timeout for Long Jobs

Some verifications take a long time:

```bash
# For complex contracts, be patient
voyager history recheck --network mainnet

# If still pending after recheck, check age
voyager history list --status pending
# If submitted recently (<1 hour), wait longer
```

## Next Steps

- **[History Listing](./listing.md)** - View verification history
- **[Filtering](./filtering.md)** - Advanced history filtering
- **[Statistics](./statistics.md)** - Verification statistics
- **[Cleanup](./cleanup.md)** - Clean old history records
- **[How History Works](./tracking.md)** - Understanding history system
