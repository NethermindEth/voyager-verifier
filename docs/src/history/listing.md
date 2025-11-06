# Viewing History

Learn how to view and list verification history using the `history list` command.

## Overview

The `history list` command displays verification records from your local history database, showing:

- All verification jobs
- Job status and timestamps
- Contract information
- Network details
- Quick filtering options

## Basic Command

### List All Verifications

```bash
voyager history list
```

Shows all verification records, most recent first.

**Example output:**
```
Verification History
════════════════════════════════════════════════════════

[1] MyToken (Success)
Job ID: abc-123-def-456
Network: mainnet
Submitted: 2025-11-06 10:30:45
Completed: 2025-11-06 10:35:12
Duration: 4m 27s
Class Hash: 0x044dc2b3239382230d8b1e943df23b96f52eebcac93efe6e8bde92f9a2f1da18

[2] TestContract (Pending)
Job ID: ghi-789-jkl-012
Network: sepolia
Submitted: 2025-11-06 10:25:30
Status: In Progress

[3] NFTContract (Success)
Job ID: mno-345-pqr-678
Network: mainnet
Submitted: 2025-11-05 15:42:10
Completed: 2025-11-05 15:47:33
Duration: 5m 23s
Class Hash: 0x055dc2b3239382230d8b1e943df23b96f52eebcac93efe6e8bde92f9a2f1da19

────────────────────────────────────────────────────────
Total: 3 verifications
```

## Limiting Results

### Default Behavior

By default, shows **all** verification records.

### Limit Number of Results

```bash
voyager history list --limit <NUMBER>
```

**Examples:**
```bash
# Show last 10 verifications
voyager history list --limit 10

# Show last 5 verifications
voyager history list --limit 5

# Show only most recent
voyager history list --limit 1
```

**Use cases:**
- Quick check of recent verifications
- Avoid overwhelming output
- Performance with large history

## Output Formats

### Default Format (Text)

Human-readable table format:

```bash
voyager history list
```

### Table Format

Compact table view:

```bash
voyager history list --format table
```

**Output:**
```
┌──────────────┬────────┬─────────┬─────────────────────┬──────────┐
│ Contract     │ Status │ Network │ Submitted           │ Duration │
├──────────────┼────────┼─────────┼─────────────────────┼──────────┤
│ MyToken      │ ✓      │ mainnet │ 2025-11-06 10:30:45 │ 4m 27s   │
│ TestContract │ ⏳     │ sepolia │ 2025-11-06 10:25:30 │ -        │
│ NFTContract  │ ✓      │ mainnet │ 2025-11-05 15:42:10 │ 5m 23s   │
└──────────────┴────────┴─────────┴─────────────────────┴──────────┘
```

### JSON Format

Machine-readable format:

```bash
voyager history list --format json
```

**Output:**
```json
[
  {
    "job_id": "abc-123-def-456",
    "contract_name": "MyToken",
    "class_hash": "0x044dc2b3239382230d8b1e943df23b96f52eebcac93efe6e8bde92f9a2f1da18",
    "status": "success",
    "network": "mainnet",
    "submitted_at": "2025-11-06T10:30:45Z",
    "completed_at": "2025-11-06T10:35:12Z",
    "duration_seconds": 267
  },
  {
    "job_id": "ghi-789-jkl-012",
    "contract_name": "TestContract",
    "class_hash": "0x066dc2b3239382230d8b1e943df23b96f52eebcac93efe6e8bde92f9a2f1da20",
    "status": "pending",
    "network": "sepolia",
    "submitted_at": "2025-11-06T10:25:30Z",
    "completed_at": null,
    "duration_seconds": null
  }
]
```

**Use cases:**
- CI/CD pipelines
- Parsing with `jq`
- Integration with other tools
- Automated reporting

## Basic Filtering

### By Status

```bash
voyager history list --status <STATUS>
```

**Available statuses:**
- `success` - Completed successfully
- `failed` - Failed verification
- `pending` - Still in progress

**Examples:**
```bash
# Show only successful verifications
voyager history list --status success

# Show only failed verifications
voyager history list --status failed

# Show only pending verifications
voyager history list --status pending
```

### By Network

```bash
voyager history list --network <NETWORK>
```

**Examples:**
```bash
# Show mainnet verifications only
voyager history list --network mainnet

# Show sepolia verifications only
voyager history list --network sepolia

# Show dev network verifications
voyager history list --network dev
```

### Combined Filters

```bash
# Successful mainnet verifications
voyager history list --status success --network mainnet

# Pending sepolia verifications
voyager history list --status pending --network sepolia

# Last 10 successful mainnet verifications
voyager history list --status success --network mainnet --limit 10
```

## Sorting

### Default Sorting

By default, results are sorted by submission time, **most recent first**.

### Examples

```bash
# Most recent first (default)
voyager history list

# Limit to see most recent
voyager history list --limit 5
```

## Complete Examples

### Example 1: Quick Recent Check

Show last 5 verifications:

```bash
voyager history list --limit 5
```

### Example 2: Mainnet Success Report

All successful mainnet verifications:

```bash
voyager history list --status success --network mainnet
```

### Example 3: Pending Jobs Check

See what's still in progress:

```bash
voyager history list --status pending
```

### Example 4: Last 10 on Sepolia

Recent sepolia testnet verifications:

```bash
voyager history list --network sepolia --limit 10
```

### Example 5: Failed Verifications Audit

Review all failures:

```bash
voyager history list --status failed
```

### Example 6: JSON Export

Export to JSON for processing:

```bash
voyager history list --format json > verifications.json
```

### Example 7: Table View

Compact overview:

```bash
voyager history list --format table --limit 20
```

## Understanding Output

### Status Indicators

- **✓ / Success** - Verification completed successfully
- **✗ / Failed** - Verification failed
- **⏳ / Pending** - Still in progress
- **⏱️ / In Progress** - Currently compiling/processing

### Duration Display

- **4m 27s** - Completed in 4 minutes 27 seconds
- **-** - Not completed yet (pending)
- **< 1s** - Completed very quickly

### Timestamps

All timestamps shown in local timezone:

```
Submitted: 2025-11-06 10:30:45
Completed: 2025-11-06 10:35:12
```

### Class Hash Display

Full hash or truncated depending on format:

```
# Full (in detailed view)
Class Hash: 0x044dc2b3239382230d8b1e943df23b96f52eebcac93efe6e8bde92f9a2f1da18

# Truncated (in table view)
Hash: 0x044dc...da18
```

## Empty History

### First Use

If no verifications have been run:

```bash
voyager history list
```

**Output:**
```
Verification History
════════════════════════════════════════════════════════

No verification history found.

Run 'voyager verify' to create your first verification record.
```

### After Cleanup

After cleaning all records:

```bash
voyager history list
```

**Output:**
```
Verification History
════════════════════════════════════════════════════════

No verification history found.
History has been cleared.
```

## Common Workflows

### Daily Check

Check what you verified today:

```bash
voyager history list --limit 10
```

### Status Review

Check pending verifications:

```bash
voyager history list --status pending
```

Then recheck them:

```bash
voyager history recheck --network mainnet
```

### Network-Specific Review

Review mainnet verifications:

```bash
voyager history list --network mainnet
```

### Failure Investigation

Find failed verifications:

```bash
voyager history list --status failed
```

Then check specific job:

```bash
voyager history status --job <JOB_ID> --network mainnet --refresh --verbose
```

### Export for Reporting

Generate report:

```bash
# JSON format
voyager history list --format json > report.json

# Table format
voyager history list --format table > report.txt

# Default format with filters
voyager history list --network mainnet --status success > mainnet-success.txt
```

## Performance Considerations

### Large History

For databases with thousands of records:

```bash
# Use limit to avoid loading everything
voyager history list --limit 50

# Filter to reduce results
voyager history list --network mainnet --limit 100
```

### Query Speed

- **No filters:** Fast (< 10ms for 1,000 records)
- **With filters:** Very fast (indexed queries)
- **JSON output:** Slightly slower (serialization overhead)

## Integration Examples

### With `jq`

Process JSON output:

```bash
# Count successful verifications
voyager history list --format json | jq '[.[] | select(.status == "success")] | length'

# Extract job IDs
voyager history list --format json | jq -r '.[].job_id'

# Filter by date
voyager history list --format json | jq '.[] | select(.submitted_at > "2025-11-01")'
```

### With `grep`

Filter text output:

```bash
# Find specific contract
voyager history list | grep "MyToken"

# Find mainnet verifications
voyager history list | grep "mainnet"

# Find failed verifications
voyager history list | grep "Failed"
```

### In Scripts

```bash
#!/bin/bash
# check-pending.sh

# Get count of pending verifications
PENDING=$(voyager history list --status pending --format json | jq 'length')

if [ "$PENDING" -gt 0 ]; then
    echo "$PENDING pending verifications found"
    voyager history recheck --network mainnet
else
    echo "No pending verifications"
fi
```

## Troubleshooting

### No Output

**Problem:** Command runs but shows nothing.

**Possible causes:**
1. No verification history exists
2. Filters too restrictive
3. Database is empty

**Solutions:**
```bash
# Remove filters
voyager history list

# Check database exists
ls ~/.voyager/history.db

# Run a verification to populate
voyager verify --network mainnet --class-hash 0x123... --contract-name Test
```

### Too Much Output

**Problem:** Output scrolls off screen.

**Solutions:**
```bash
# Use limit
voyager history list --limit 20

# Use pager
voyager history list | less

# Use filters
voyager history list --network mainnet --status success --limit 10
```

### Formatting Issues

**Problem:** JSON output not formatted properly.

**Solution:** Use `jq` for pretty printing:
```bash
voyager history list --format json | jq '.'
```

### Performance Issues

**Problem:** List command is slow.

**Solutions:**
```bash
# Use limit
voyager history list --limit 100

# Clean old records
voyager history clean --older-than 90

# Vacuum database
sqlite3 ~/.voyager/history.db "VACUUM;"
```

## Best Practices

### 1. Always Use Limits

For quick checks:

```bash
voyager history list --limit 10
```

### 2. Filter Appropriately

Don't list everything when you need specific data:

```bash
# Good
voyager history list --network mainnet --status success --limit 20

# Less good
voyager history list | grep mainnet | grep success
```

### 3. Use JSON for Automation

In scripts and CI/CD:

```bash
voyager history list --format json | jq '.[] | select(.status == "pending")'
```

### 4. Regular Review

Periodically check history:

```bash
# Weekly check
voyager history list --limit 50

# Monthly stats
voyager history stats
```

### 5. Combine with Other Commands

```bash
# List pending, then recheck
voyager history list --status pending
voyager history recheck --network mainnet

# List failed, then investigate
voyager history list --status failed
voyager history status --job <JOB_ID> --network mainnet --refresh --verbose
```

## Next Steps

- **[Filtering](./filtering.md)** - Advanced filtering options
- **[Rechecking Jobs](./recheck.md)** - Update pending verification status
- **[Statistics](./statistics.md)** - View aggregated verification stats
- **[Cleanup](./cleanup.md)** - Manage and clean old records
- **[How History Works](./tracking.md)** - Understanding the history system
