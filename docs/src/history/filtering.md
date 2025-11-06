# Advanced Filtering

Advanced filtering options for querying and searching verification history.

## Overview

Beyond basic filtering, Voyager provides advanced options for:

- **Time-based filtering** - Filter by date ranges
- **Pattern matching** - Search contract names
- **Combined filters** - Multiple criteria at once
- **Result limiting** - Control output size
- **Custom queries** - Direct SQLite access

## Basic Filters (Quick Reference)

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
voyager history list --status success
voyager history list --status failed
voyager history list --status pending
```

### By Network

```bash
voyager history list --network <NETWORK>
```

**Examples:**
```bash
voyager history list --network mainnet
voyager history list --network sepolia
voyager history list --network dev
```

### Limiting Results

```bash
voyager history list --limit <NUMBER>
```

**Examples:**
```bash
voyager history list --limit 10
voyager history list --limit 50
voyager history list --limit 1
```

## Time-Based Filtering

### Recent Verifications

Show verifications from the last N days:

```bash
voyager history list --since <DAYS>
```

**Examples:**
```bash
# Last 7 days
voyager history list --since 7

# Last 24 hours
voyager history list --since 1

# Last 30 days
voyager history list --since 30
```

### Before Specific Date

Show verifications before a date:

```bash
voyager history list --before <DATE>
```

**Date format:** `YYYY-MM-DD`

**Examples:**
```bash
# Before November 1, 2025
voyager history list --before 2025-11-01

# Before October 15, 2025
voyager history list --before 2025-10-15
```

### After Specific Date

Show verifications after a date:

```bash
voyager history list --after <DATE>
```

**Examples:**
```bash
# After November 1, 2025
voyager history list --after 2025-11-01

# After yesterday
voyager history list --after $(date -d "yesterday" +%Y-%m-%d)
```

### Date Range

Combine before and after for a range:

```bash
voyager history list --after <START> --before <END>
```

**Example:**
```bash
# October 2025
voyager history list --after 2025-10-01 --before 2025-10-31

# Last week
voyager history list --after 2025-10-28 --before 2025-11-04
```

## Pattern Matching

### By Contract Name

Search for contracts by name pattern:

```bash
voyager history list --contract-name <PATTERN>
```

**Examples:**
```bash
# Exact match
voyager history list --contract-name MyToken

# Partial match (case-insensitive)
voyager history list --contract-name token

# All contracts starting with "Test"
voyager history list --contract-name "Test*"
```

### By Class Hash

Filter by class hash prefix:

```bash
voyager history list --class-hash <HASH_PREFIX>
```

**Examples:**
```bash
# Full hash
voyager history list --class-hash 0x044dc2b3239382230d8b1e943df23b96f52eebcac93efe6e8bde92f9a2f1da18

# Prefix (first 20 chars)
voyager history list --class-hash 0x044dc2b323938223

# Short prefix
voyager history list --class-hash 0x044d
```

### By Job ID

Find specific job by ID:

```bash
voyager history list --job <JOB_ID>
```

**Examples:**
```bash
# Full job ID
voyager history list --job abc-123-def-456

# Partial job ID
voyager history list --job abc-123
```

## Combined Filters

### Multiple Criteria

Combine filters for precise queries:

```bash
voyager history list \
  --status <STATUS> \
  --network <NETWORK> \
  --since <DAYS> \
  --limit <NUMBER>
```

### Example 1: Recent Mainnet Successes

```bash
voyager history list \
  --status success \
  --network mainnet \
  --since 7 \
  --limit 20
```

Shows last 20 successful mainnet verifications from the past week.

### Example 2: Failed Sepolia Tests

```bash
voyager history list \
  --status failed \
  --network sepolia \
  --since 1
```

Shows all failed sepolia verifications from today.

### Example 3: Specific Contract on Mainnet

```bash
voyager history list \
  --contract-name MyToken \
  --network mainnet \
  --status success
```

Shows all successful MyToken verifications on mainnet.

### Example 4: October Production Deployments

```bash
voyager history list \
  --network mainnet \
  --after 2025-10-01 \
  --before 2025-10-31 \
  --status success
```

Shows all successful mainnet verifications in October.

### Example 5: Recent Pending Jobs

```bash
voyager history list \
  --status pending \
  --since 1 \
  --limit 10
```

Shows up to 10 pending jobs from today.

## Sorting

### By Submission Time (Default)

Most recent first:

```bash
voyager history list
```

### By Duration

Show longest/shortest verifications:

```bash
# Longest first
voyager history list --sort duration --order desc

# Shortest first
voyager history list --sort duration --order asc
```

**Use cases:**
- Identify slow verifications
- Find quick test deployments
- Performance analysis

### By Contract Name

Alphabetically sorted:

```bash
# A-Z
voyager history list --sort contract --order asc

# Z-A
voyager history list --sort contract --order desc
```

## Advanced Use Cases

### Use Case 1: Monthly Report

Generate monthly verification report:

```bash
#!/bin/bash
# monthly-report.sh

MONTH="2025-10"
START="${MONTH}-01"
END="${MONTH}-31"

echo "Verification Report: $MONTH"
echo "================================"
echo ""

echo "Mainnet Verifications:"
voyager history list \
  --network mainnet \
  --after $START \
  --before $END \
  --format table

echo ""
echo "Success Rate:"
voyager history stats \
  --network mainnet \
  --after $START \
  --before $END
```

### Use Case 2: Failed Verification Audit

Find and analyze all failures:

```bash
# List all failures
voyager history list --status failed --format json > failures.json

# Count failures by network
jq -r '.[] | .network' failures.json | sort | uniq -c

# Get failure details
jq '.[] | {contract: .contract_name, network: .network, date: .submitted_at}' failures.json
```

### Use Case 3: Contract Deployment Timeline

Track deployments of a specific contract:

```bash
# Timeline for MyToken
voyager history list \
  --contract-name MyToken \
  --sort time \
  --order asc \
  --format table

# Show all networks
for network in mainnet sepolia dev; do
  echo "MyToken on $network:"
  voyager history list \
    --contract-name MyToken \
    --network $network
done
```

### Use Case 4: Performance Analysis

Find slow verifications:

```bash
# Verifications taking >10 minutes
voyager history list --format json | \
  jq '.[] | select(.duration_seconds > 600) | {contract: .contract_name, duration: .duration_seconds, network: .network}'

# Average duration by network
voyager history list --format json | \
  jq 'group_by(.network) | map({network: .[0].network, avg_duration: (map(.duration_seconds) | add / length)})'
```

### Use Case 5: CI/CD Integration

Check recent deployments in CI:

```bash
#!/bin/bash
# check-deployments.sh

# Get last 10 mainnet verifications
RECENT=$(voyager history list \
  --network mainnet \
  --limit 10 \
  --format json)

# Count failures
FAILURES=$(echo $RECENT | jq '[.[] | select(.status == "failed")] | length')

if [ $FAILURES -gt 0 ]; then
  echo "Warning: $FAILURES failed verifications in last 10"
  exit 1
fi

echo "All recent verifications successful"
```

## Output Format Filtering

### Text Output (Default)

Human-readable format:

```bash
voyager history list --status success --limit 5
```

### Table Output

Compact table view:

```bash
voyager history list --status success --limit 5 --format table
```

### JSON Output

Machine-readable for processing:

```bash
voyager history list --status success --limit 5 --format json
```

**Process with jq:**
```bash
# Extract job IDs
voyager history list --status success --format json | jq -r '.[].job_id'

# Filter by duration
voyager history list --format json | jq '.[] | select(.duration_seconds < 300)'

# Group by network
voyager history list --format json | jq 'group_by(.network)'
```

## Performance Considerations

### Large Result Sets

For databases with many records:

```bash
# Use limit to avoid loading everything
voyager history list --limit 100

# Combine with filters to reduce results
voyager history list --network mainnet --since 7 --limit 50
```

### Query Optimization

**Fast queries:**
- Filtering by status (indexed)
- Filtering by network (indexed)
- Filtering by job ID (indexed)
- Limiting results

**Slower queries:**
- Pattern matching contract names (no index)
- Sorting by duration (requires calculation)
- Date range without limit

**Optimization tips:**
```bash
# Good - specific and limited
voyager history list --status success --network mainnet --limit 20

# Less good - broad query without limit
voyager history list --contract-name "*Token*"

# Better - add limit
voyager history list --contract-name "*Token*" --limit 50
```

## Direct Database Access

### Using SQLite Directly

For complex queries not supported by CLI:

```bash
# Access database
sqlite3 ~/.voyager/history.db
```

**Example queries:**
```sql
-- All verifications from October
SELECT * FROM verifications
WHERE date(submitted_at) BETWEEN '2025-10-01' AND '2025-10-31';

-- Count by status
SELECT status, COUNT(*)
FROM verifications
GROUP BY status;

-- Average duration by network
SELECT network, AVG(duration_seconds) as avg_duration
FROM verifications
WHERE duration_seconds IS NOT NULL
GROUP BY network;

-- Contracts with multiple verifications
SELECT contract_name, COUNT(*) as count
FROM verifications
GROUP BY contract_name
HAVING count > 1
ORDER BY count DESC;
```

### Export Filtered Results

```bash
# Export specific query to CSV
sqlite3 -header -csv ~/.voyager/history.db \
  "SELECT contract_name, network, status, submitted_at
   FROM verifications
   WHERE network = 'mainnet' AND status = 'success'" \
  > mainnet-success.csv
```

## Integration Examples

### With `jq` (JSON Processing)

```bash
# Count by status
voyager history list --format json | \
  jq 'group_by(.status) | map({status: .[0].status, count: length})'

# Find contracts verified on multiple networks
voyager history list --format json | \
  jq 'group_by(.contract_name) | map({contract: .[0].contract_name, networks: [.[].network] | unique})'

# Latest verification per contract
voyager history list --format json | \
  jq 'group_by(.contract_name) | map(max_by(.submitted_at))'
```

### With `grep` (Text Filtering)

```bash
# Find specific contract
voyager history list | grep "MyToken"

# Find mainnet verifications
voyager history list | grep "mainnet"

# Find failures
voyager history list | grep "Failed"
```

### In Bash Scripts

```bash
#!/bin/bash
# check-contract-status.sh

CONTRACT_NAME=$1
NETWORK=${2:-mainnet}

# Find most recent verification
LATEST=$(voyager history list \
  --contract-name "$CONTRACT_NAME" \
  --network "$NETWORK" \
  --limit 1 \
  --format json)

if [ -z "$LATEST" ]; then
  echo "No verifications found for $CONTRACT_NAME on $NETWORK"
  exit 1
fi

STATUS=$(echo $LATEST | jq -r '.[0].status')

if [ "$STATUS" = "success" ]; then
  echo "✓ $CONTRACT_NAME is verified on $NETWORK"
  exit 0
else
  echo "✗ $CONTRACT_NAME verification $STATUS on $NETWORK"
  exit 1
fi
```

## Troubleshooting

### No Results Found

**Problem:** Filter returns no results.

**Possible causes:**
1. Filters too restrictive
2. Incorrect date format
3. Typo in contract name
4. Wrong network name

**Solutions:**
```bash
# Remove filters one by one
voyager history list --network mainnet  # Test network filter
voyager history list --status success   # Test status filter
voyager history list --since 30         # Broaden time range

# Check available data
voyager history list --limit 10  # See what exists
```

### Slow Queries

**Problem:** Query takes a long time.

**Solutions:**
```bash
# Add limit
voyager history list --contract-name "*Token*" --limit 50

# Use more specific filters
voyager history list --network mainnet --since 7 --limit 20

# Avoid pattern matching on large datasets
# Instead of: voyager history list --contract-name "*"
# Use: voyager history list --limit 100
```

### Date Format Issues

**Problem:** Date filter not working.

**Solution:** Use correct format `YYYY-MM-DD`:
```bash
# Correct
voyager history list --after 2025-11-01

# Incorrect
voyager history list --after 11/01/2025  # Wrong format
voyager history list --after 2025-11-1   # Missing zero
```

### Case Sensitivity

**Problem:** Contract name search not finding results.

**Note:** Contract name search is case-insensitive:
```bash
# All equivalent
voyager history list --contract-name MyToken
voyager history list --contract-name mytoken
voyager history list --contract-name MYTOKEN
```

## Best Practices

### 1. Start Broad, Then Narrow

```bash
# Start with broad query
voyager history list --network mainnet --limit 20

# Narrow down
voyager history list --network mainnet --status success --limit 20

# Further narrow
voyager history list --network mainnet --status success --since 7 --limit 20
```

### 2. Always Use Limits

Prevent overwhelming output:

```bash
# Good
voyager history list --status success --limit 50

# Less good
voyager history list --status success  # Could be thousands
```

### 3. Use JSON for Complex Processing

```bash
# For simple viewing: use text
voyager history list --limit 10

# For processing: use JSON
voyager history list --format json | jq '.[] | select(.duration_seconds > 300)'
```

### 4. Combine with Other Commands

```bash
# List pending, then recheck
voyager history list --status pending
voyager history recheck --network mainnet

# List failures, then investigate
voyager history list --status failed --limit 5
# Then check details of specific job
```

### 5. Save Complex Queries

Create aliases for common queries:

```bash
# Add to ~/.bashrc or ~/.zshrc
alias verify-recent="voyager history list --limit 10"
alias verify-mainnet="voyager history list --network mainnet --status success --limit 20"
alias verify-failed="voyager history list --status failed"
alias verify-pending="voyager history list --status pending"
```

## Next Steps

- **[History Listing](./listing.md)** - Basic history viewing
- **[Rechecking Jobs](./recheck.md)** - Update pending verification status
- **[Statistics](./statistics.md)** - Aggregated verification statistics
- **[Cleanup](./cleanup.md)** - Manage and clean old records
- **[How History Works](./tracking.md)** - Understanding the tracking system
