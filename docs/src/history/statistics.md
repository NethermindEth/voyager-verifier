# Verification Statistics

View aggregated statistics and analytics from your verification history.

## Overview

The `history stats` command provides:

- **Success/failure rates** - Overall verification success percentage
- **Network breakdown** - Statistics per network
- **Time-based metrics** - Average duration, total time
- **Volume metrics** - Total verifications, contracts verified
- **Trend analysis** - Performance over time

## Basic Usage

### View All Statistics

```bash
voyager history stats
```

**Example output:**
```
Verification Statistics
════════════════════════════════════════════════════════

Overall Summary
────────────────────────────────────────────────────────
  Total Verifications:  127
  Success Rate:         94.5% (120/127)
  Failed:               5.5% (7/127)
  Pending:              0

Time Period:  2025-09-01 to 2025-11-06 (67 days)

Performance
────────────────────────────────────────────────────────
  Average Duration:     4m 32s
  Fastest:              1m 12s
  Slowest:              12m 45s
  Total Time:           9h 36m

By Network
────────────────────────────────────────────────────────
  mainnet:    85 verifications (94% success)
  sepolia:    38 verifications (97% success)
  dev:        4 verifications (75% success)

Top Contracts
────────────────────────────────────────────────────────
  1. Token            (24 verifications)
  2. NFT              (18 verifications)
  3. Marketplace      (12 verifications)
  4. TestContract     (8 verifications)
  5. GovernanceToken  (6 verifications)
```

## Filtering Statistics

### By Network

```bash
voyager history stats --network <NETWORK>
```

**Example:**
```bash
voyager history stats --network mainnet
```

**Output:**
```
Verification Statistics (mainnet only)
════════════════════════════════════════════════════════

  Total Verifications:  85
  Success Rate:         94.1% (80/85)
  Failed:               5.9% (5/85)

  Average Duration:     4m 45s
  Total Time:           6h 44m
```

### By Time Period

```bash
voyager history stats --since <DAYS>
```

**Examples:**
```bash
# Last 7 days
voyager history stats --since 7

# Last 30 days
voyager history stats --since 30

# This month
voyager history stats --after 2025-11-01
```

### By Date Range

```bash
voyager history stats --after <DATE> --before <DATE>
```

**Example:**
```bash
# October 2025
voyager history stats --after 2025-10-01 --before 2025-10-31
```

## Output Formats

### Text Format (Default)

Human-readable summary:

```bash
voyager history stats
```

### JSON Format

Machine-readable data:

```bash
voyager history stats --format json
```

**Example output:**
```json
{
  "total_verifications": 127,
  "successful": 120,
  "failed": 7,
  "pending": 0,
  "success_rate": 0.945,
  "average_duration_seconds": 272,
  "fastest_duration_seconds": 72,
  "slowest_duration_seconds": 765,
  "total_duration_seconds": 34560,
  "date_range": {
    "start": "2025-09-01T00:00:00Z",
    "end": "2025-11-06T23:59:59Z",
    "days": 67
  },
  "by_network": {
    "mainnet": {
      "total": 85,
      "successful": 80,
      "failed": 5,
      "success_rate": 0.941
    },
    "sepolia": {
      "total": 38,
      "successful": 37,
      "failed": 1,
      "success_rate": 0.974
    },
    "dev": {
      "total": 4,
      "successful": 3,
      "failed": 1,
      "success_rate": 0.750
    }
  },
  "top_contracts": [
    {"name": "Token", "count": 24},
    {"name": "NFT", "count": 18},
    {"name": "Marketplace", "count": 12}
  ]
}
```

## Use Cases

### Use Case 1: Monthly Report

Generate monthly statistics:

```bash
#!/bin/bash
# monthly-stats.sh

MONTH=$(date +%Y-%m)
START="${MONTH}-01"
END="${MONTH}-31"

echo "Verification Report: $MONTH"
voyager history stats --after $START --before $END
```

### Use Case 2: Network Comparison

Compare success rates across networks:

```bash
#!/bin/bash
# network-comparison.sh

for network in mainnet sepolia dev; do
  echo "=== $network ==="
  voyager history stats --network $network
  echo ""
done
```

### Use Case 3: Performance Tracking

Track verification performance over time:

```bash
#!/bin/bash
# performance-trend.sh

echo "Last 7 days:"
voyager history stats --since 7 | grep "Average Duration"

echo "Last 30 days:"
voyager history stats --since 30 | grep "Average Duration"

echo "Last 90 days:"
voyager history stats --since 90 | grep "Average Duration"
```

### Use Case 4: Success Rate Monitoring

Alert if success rate drops:

```bash
#!/bin/bash
# monitor-success.sh

STATS=$(voyager history stats --since 7 --format json)
SUCCESS_RATE=$(echo $STATS | jq -r '.success_rate')

# Alert if success rate < 90%
if (( $(echo "$SUCCESS_RATE < 0.9" | bc -l) )); then
  echo "WARNING: Success rate is ${SUCCESS_RATE}%"
  echo "Last 7 days have had unusually high failure rate"

  # Show recent failures
  voyager history list --status failed --since 7
else
  echo "Success rate healthy: ${SUCCESS_RATE}%"
fi
```

### Use Case 5: CI/CD Dashboard

Display stats in CI dashboard:

```bash
# In CI pipeline
voyager history stats --since 7 --format json > stats.json

# Parse for display
SUCCESS_RATE=$(jq -r '.success_rate * 100' stats.json)
TOTAL=$(jq -r '.total_verifications' stats.json)

echo "Last 7 days: $TOTAL verifications, ${SUCCESS_RATE}% success"
```

## Understanding Metrics

### Success Rate

Percentage of verifications that completed successfully:

```
Success Rate = (Successful / Total) * 100%
```

**Example:**
- Total: 100 verifications
- Successful: 95
- Success Rate: 95%

### Average Duration

Mean time for verifications to complete:

```
Average Duration = Total Time / Completed Verifications
```

**Notes:**
- Excludes pending verifications
- Includes both successful and failed
- Measured from submission to completion

### Time Period

Date range of included verifications:

```
Start: Earliest verification date
End: Latest verification date
Days: Number of days between start and end
```

### Network Breakdown

Statistics grouped by network:

**For each network:**
- Total verifications
- Successful count
- Failed count
- Success rate

### Top Contracts

Most frequently verified contracts:

**Sorted by:**
- Number of verifications (descending)
- Shows contract name and count
- Typically shows top 5-10

## Examples

### Example 1: Quick Overview

```bash
voyager history stats
```

See overall statistics at a glance.

### Example 2: Mainnet Performance

```bash
voyager history stats --network mainnet
```

Focus on production network statistics.

### Example 3: Last Week

```bash
voyager history stats --since 7
```

See recent activity and trends.

### Example 4: Monthly Comparison

```bash
# October
voyager history stats --after 2025-10-01 --before 2025-10-31

# November
voyager history stats --after 2025-11-01 --before 2025-11-30
```

Compare month-over-month performance.

### Example 5: Export for Analysis

```bash
voyager history stats --format json > stats-2025-11.json
```

Save statistics for external analysis.

## Integration Examples

### With Monitoring Tools

```bash
#!/bin/bash
# push-metrics.sh

# Get stats
STATS=$(voyager history stats --since 1 --format json)

# Extract metrics
SUCCESS_RATE=$(echo $STATS | jq -r '.success_rate')
AVG_DURATION=$(echo $STATS | jq -r '.average_duration_seconds')
TOTAL=$(echo $STATS | jq -r '.total_verifications')

# Push to monitoring system (example: Prometheus)
echo "verification_success_rate $SUCCESS_RATE" | curl --data-binary @- http://pushgateway:9091/metrics/job/voyager
echo "verification_avg_duration_seconds $AVG_DURATION" | curl --data-binary @- http://pushgateway:9091/metrics/job/voyager
echo "verification_total $TOTAL" | curl --data-binary @- http://pushgateway:9091/metrics/job/voyager
```

### With Slack/Discord

```bash
#!/bin/bash
# weekly-report.sh

STATS=$(voyager history stats --since 7)

# Post to Slack
curl -X POST -H 'Content-type: application/json' \
  --data "{\"text\":\"Weekly Verification Report\n\`\`\`$STATS\`\`\`\"}" \
  $SLACK_WEBHOOK_URL
```

### In Dashboards

```javascript
// Fetch and display stats
const stats = await fetch('/api/voyager/stats').then(r => r.json());

document.getElementById('success-rate').innerText =
  `${(stats.success_rate * 100).toFixed(1)}%`;

document.getElementById('total-verifications').innerText =
  stats.total_verifications;

document.getElementById('avg-duration').innerText =
  `${Math.round(stats.average_duration_seconds / 60)}m`;
```

## Troubleshooting

### No Statistics Available

**Problem:** Stats command shows "No data available".

**Cause:** No verifications in history.

**Solution:**
```bash
# Check if history exists
voyager history list

# Run some verifications
voyager verify --network sepolia --class-hash 0x123... --contract-name Test
```

### Empty Time Period

**Problem:** Stats show empty for specific time period.

**Solution:**
```bash
# Check what dates exist
voyager history list --limit 10

# Adjust time period
voyager history stats --since 30  # Broaden range
```

### Inaccurate Durations

**Problem:** Duration statistics seem wrong.

**Possible causes:**
1. Pending verifications not updated
2. Clock skew during submission

**Solution:**
```bash
# Recheck pending jobs first
voyager history recheck --network mainnet

# Then view stats
voyager history stats
```

## Performance Considerations

### Large Databases

For databases with thousands of records:

```bash
# Stats calculation on large DB may be slow
# Consider filtering by time period
voyager history stats --since 30  # Last 30 days only
```

### Caching

Statistics are calculated on-demand:

- No caching between runs
- Each call queries the database
- For dashboards, cache results for 5-15 minutes

**Example caching:**
```bash
#!/bin/bash
# cached-stats.sh

CACHE_FILE="/tmp/voyager-stats-cache.json"
CACHE_AGE=300  # 5 minutes

if [ -f "$CACHE_FILE" ]; then
  AGE=$(($(date +%s) - $(stat -c %Y "$CACHE_FILE")))
  if [ $AGE -lt $CACHE_AGE ]; then
    cat "$CACHE_FILE"
    exit 0
  fi
fi

# Regenerate cache
voyager history stats --format json > "$CACHE_FILE"
cat "$CACHE_FILE"
```

## Best Practices

### 1. Regular Monitoring

Check stats regularly:

```bash
# Weekly review
0 9 * * 1 /usr/local/bin/voyager history stats --since 7 | mail -s "Weekly Stats" team@company.com
```

### 2. Set Baselines

Establish normal ranges:

```bash
# Baseline metrics (example)
# Success rate: 90-95%
# Avg duration: 3-5 minutes
# Verify these regularly
```

### 3. Compare Time Periods

Track trends:

```bash
# This month vs last month
voyager history stats --after 2025-11-01
voyager history stats --after 2025-10-01 --before 2025-10-31
```

### 4. Use JSON for Automation

```bash
# Parse JSON in scripts
RATE=$(voyager history stats --format json | jq -r '.success_rate')
```

### 5. Combine with Other Tools

```bash
# Stats + details
voyager history stats --since 7
voyager history list --status failed --since 7
```

## Next Steps

- **[History Listing](./listing.md)** - View individual verification records
- **[Filtering](./filtering.md)** - Advanced history queries
- **[Rechecking Jobs](./recheck.md)** - Update pending jobs
- **[Cleanup](./cleanup.md)** - Manage history database
- **[How History Works](./tracking.md)** - Understanding the system
