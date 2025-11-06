# History Cleanup

Manage and clean old verification records from your local history database.

## Overview

The `history clean` command allows you to:

- **Remove old records** - Delete verifications older than N days
- **Free disk space** - Reduce database size
- **Maintain performance** - Keep database queries fast
- **Selective cleanup** - Clean specific networks or statuses
- **Safe deletion** - Confirmation prompts for safety

## Basic Usage

### Clean Old Records

```bash
voyager history clean --older-than <DAYS>
```

**Example:**
```bash
# Remove records older than 90 days
voyager history clean --older-than 90
```

**Output:**
```
Cleaning History Records
════════════════════════════════════════════════════════

Found 47 records older than 90 days:
  - 42 successful verifications
  - 3 failed verifications
  - 2 pending verifications

Total database size: 2.3 MB
Space to be freed: ~180 KB

⚠️  This action cannot be undone.

Proceed with cleanup? [y/N]: y

Deleting records...
✓ 47 records deleted

Database size after cleanup: 2.1 MB
Space freed: 200 KB
```

## Command Options

### Required: Time Period

Specify how old records must be to delete:

```bash
--older-than <DAYS>
```

**Examples:**
```bash
# 30 days old
voyager history clean --older-than 30

# 6 months old (180 days)
voyager history clean --older-than 180

# 1 year old
voyager history clean --older-than 365
```

### Optional: Network Filter

Clean records for specific network only:

```bash
voyager history clean --older-than <DAYS> --network <NETWORK>
```

**Example:**
```bash
# Clean old sepolia testnet records
voyager history clean --older-than 30 --network sepolia
```

### Optional: Status Filter

Clean records with specific status:

```bash
voyager history clean --older-than <DAYS> --status <STATUS>
```

**Examples:**
```bash
# Clean old successful verifications only
voyager history clean --older-than 90 --status success

# Clean old failed verifications
voyager history clean --older-than 30 --status failed

# Clean old pending verifications (likely abandoned)
voyager history clean --older-than 7 --status pending
```

### Optional: Force (Skip Confirmation)

Skip confirmation prompt:

```bash
voyager history clean --older-than <DAYS> --force
```

**Example:**
```bash
# Clean without prompting (for scripts)
voyager history clean --older-than 90 --force
```

### Optional: Dry Run

Preview what would be deleted without actually deleting:

```bash
voyager history clean --older-than <DAYS> --dry-run
```

**Example:**
```bash
# See what would be deleted
voyager history clean --older-than 90 --dry-run
```

## Use Cases

### Use Case 1: Monthly Cleanup

Regular monthly maintenance:

```bash
# Keep last 90 days of records
voyager history clean --older-than 90
```

### Use Case 2: Testnet Cleanup

Clean testnet records more aggressively:

```bash
# Keep only 30 days of sepolia records
voyager history clean --older-than 30 --network sepolia
```

### Use Case 3: Failed Verification Cleanup

Remove old failed verifications:

```bash
# Remove failed verifications older than 30 days
voyager history clean --older-than 30 --status failed
```

### Use Case 4: Abandoned Pending Jobs

Clean old pending jobs that likely failed:

```bash
# Remove pending jobs older than 7 days
voyager history clean --older-than 7 --status pending
```

### Use Case 5: Automated Cleanup

Set up automated cleanup via cron:

```bash
# Add to crontab - clean monthly
0 0 1 * * /usr/local/bin/voyager history clean --older-than 90 --force
```

## Safety Features

### Confirmation Prompt

By default, cleanup requires confirmation:

```
⚠️  This action cannot be undone.

Proceed with cleanup? [y/N]:
```

**Type `y` to proceed, `n` or Enter to cancel.**

### Dry Run Mode

Preview deletions without making changes:

```bash
voyager history clean --older-than 90 --dry-run
```

**Output:**
```
DRY RUN - No changes will be made
════════════════════════════════════════════════════════

Would delete 47 records older than 90 days:
  - 42 successful verifications
  - 3 failed verifications
  - 2 pending verifications

Estimated space to free: ~180 KB

No records were actually deleted.
```

### No Deletion of Recent Records

Records newer than specified age are never deleted:

```bash
# Only deletes records >90 days old
# Keeps all records ≤90 days old
voyager history clean --older-than 90
```

## Complete Examples

### Example 1: Conservative Cleanup

Keep 180 days (6 months):

```bash
voyager history clean --older-than 180
```

### Example 2: Aggressive Cleanup

Keep only 30 days:

```bash
voyager history clean --older-than 30
```

### Example 3: Network-Specific Cleanup

Different retention per network:

```bash
# Mainnet: keep 180 days (production important)
voyager history clean --older-than 180 --network mainnet

# Sepolia: keep 30 days (testnet less important)
voyager history clean --older-than 30 --network sepolia

# Dev: keep 7 days (local testing)
voyager history clean --older-than 7 --network dev
```

### Example 4: Status-Based Cleanup

Clean failures more aggressively:

```bash
# Keep successful for 180 days
voyager history clean --older-than 180 --status success

# Remove failed after 30 days
voyager history clean --older-than 30 --status failed

# Remove old pending after 7 days
voyager history clean --older-than 7 --status pending
```

### Example 5: Scripted Cleanup

Automated cleanup without user interaction:

```bash
#!/bin/bash
# cleanup-history.sh

# Force flag skips confirmation
voyager history clean --older-than 90 --force

echo "History cleanup complete"
```

## Database Maintenance

### Vacuum Database

After cleanup, vacuum to reclaim space:

```bash
# Clean records
voyager history clean --older-than 90

# Vacuum database to reclaim space
sqlite3 ~/.voyager/history.db "VACUUM;"
```

**Benefits:**
- Defragments database
- Reclaims unused space
- Improves query performance

### Check Database Size

Monitor database growth:

```bash
# Check size before cleanup
ls -lh ~/.voyager/history.db

# Clean
voyager history clean --older-than 90

# Check size after
ls -lh ~/.voyager/history.db
```

### Database Statistics

Get record counts:

```bash
# Total records
sqlite3 ~/.voyager/history.db "SELECT COUNT(*) FROM verifications;"

# By status
sqlite3 ~/.voyager/history.db "SELECT status, COUNT(*) FROM verifications GROUP BY status;"

# By network
sqlite3 ~/.voyager/history.db "SELECT network, COUNT(*) FROM verifications GROUP BY network;"
```

## Best Practices

### 1. Regular Schedule

Set up regular cleanup:

```bash
# Monthly via cron
0 0 1 * * voyager history clean --older-than 90 --force

# Or weekly for aggressive cleanup
0 0 * * 0 voyager history clean --older-than 30 --force
```

### 2. Backup Before Major Cleanup

Backup database before first cleanup:

```bash
# Backup
cp ~/.voyager/history.db ~/.voyager/history-backup-$(date +%Y%m%d).db

# Then clean
voyager history clean --older-than 180
```

### 3. Different Retention Per Network

Production vs testnet retention:

```bash
# Production: keep longer
voyager history clean --older-than 365 --network mainnet

# Testnet: shorter retention
voyager history clean --older-than 30 --network sepolia
```

### 4. Always Dry Run First

Preview before actual cleanup:

```bash
# See what would be deleted
voyager history clean --older-than 90 --dry-run

# If looks good, proceed
voyager history clean --older-than 90
```

### 5. Recheck Before Cleanup

Update pending jobs before cleaning:

```bash
# Recheck pending first
voyager history recheck --network mainnet

# Then clean old records
voyager history clean --older-than 90
```

## Troubleshooting

### Permission Denied

**Problem:** Cannot write to database.

**Solution:**
```bash
# Fix permissions
chmod 644 ~/.voyager/history.db

# Retry cleanup
voyager history clean --older-than 90
```

### Database Locked

**Problem:** Database is locked by another process.

**Solution:**
```bash
# Check for other voyager processes
ps aux | grep voyager

# Kill if stuck
kill <PID>

# Retry cleanup
voyager history clean --older-than 90
```

### No Records Deleted

**Problem:** Cleanup reports 0 records deleted.

**Possible causes:**
1. No records older than specified age
2. All records match filter criteria

**Solution:**
```bash
# Check what exists
voyager history list --limit 10

# Try broader age
voyager history clean --older-than 30
```

### Space Not Freed

**Problem:** Database size didn't decrease after cleanup.

**Solution:**
```bash
# Vacuum database to reclaim space
sqlite3 ~/.voyager/history.db "VACUUM;"

# Check size again
ls -lh ~/.voyager/history.db
```

## Cleanup Strategies

### Strategy 1: Fixed Retention

Keep fixed number of days:

```bash
# Always keep 90 days
voyager history clean --older-than 90 --force
```

**Good for:** Consistent history across time.

### Strategy 2: Tiered Retention

Different retention by network:

```bash
#!/bin/bash
# tiered-cleanup.sh

# Production: 1 year
voyager history clean --older-than 365 --network mainnet --force

# Staging: 90 days
voyager history clean --older-than 90 --network staging --force

# Testnet: 30 days
voyager history clean --older-than 30 --network sepolia --force

# Dev: 7 days
voyager history clean --older-than 7 --network dev --force
```

**Good for:** Different importance levels per network.

### Strategy 3: Status-Based Retention

Keep successes longer than failures:

```bash
#!/bin/bash
# status-retention.sh

# Successes: keep 180 days
voyager history clean --older-than 180 --status success --force

# Failures: keep 60 days
voyager history clean --older-than 60 --status failed --force

# Pending: keep 7 days
voyager history clean --older-than 7 --status pending --force
```

**Good for:** Optimizing disk space while keeping important records.

### Strategy 4: Database Size Limit

Clean until database is under size limit:

```bash
#!/bin/bash
# size-based-cleanup.sh

TARGET_SIZE_MB=50
DB_PATH=~/.voyager/history.db

while true; do
  SIZE_MB=$(du -m "$DB_PATH" | cut -f1)

  if [ $SIZE_MB -le $TARGET_SIZE_MB ]; then
    echo "Database size OK: ${SIZE_MB}MB"
    break
  fi

  echo "Database too large: ${SIZE_MB}MB, cleaning..."
  voyager history clean --older-than 30 --force
  sqlite3 "$DB_PATH" "VACUUM;"

  sleep 1
done
```

**Good for:** Systems with strict disk space limits.

## Automation Examples

### Cron Job

```bash
# Add to crontab
# Clean monthly, keep 90 days
0 0 1 * * /usr/local/bin/voyager history clean --older-than 90 --force >> /var/log/voyager-cleanup.log 2>&1
```

### Systemd Timer

```ini
# /etc/systemd/system/voyager-cleanup.timer
[Unit]
Description=Clean old Voyager history records

[Timer]
OnCalendar=monthly
Persistent=true

[Install]
WantedBy=timers.target
```

```ini
# /etc/systemd/system/voyager-cleanup.service
[Unit]
Description=Clean old Voyager history records

[Service]
Type=oneshot
ExecStart=/usr/local/bin/voyager history clean --older-than 90 --force
ExecStartPost=/usr/bin/sqlite3 /home/user/.voyager/history.db "VACUUM;"
```

### GitHub Actions

```yaml
name: Cleanup History

on:
  schedule:
    - cron: '0 0 1 * *'  # Monthly
  workflow_dispatch:  # Manual trigger

jobs:
  cleanup:
    runs-on: ubuntu-latest
    steps:
      - name: Install Voyager
        run: cargo install voyager-verifier

      - name: Clean Old Records
        run: |
          voyager history clean --older-than 90 --force
          sqlite3 ~/.voyager/history.db "VACUUM;"
```

## Recovery

### Restore from Backup

If cleanup deleted too much:

```bash
# Stop any voyager processes
killall voyager

# Restore from backup
cp ~/.voyager/history-backup-20251106.db ~/.voyager/history.db

# Verify restoration
voyager history list --limit 10
```

### Manual Deletion Undo

SQLite doesn't support undo, but you can:

1. Restore from backup (if available)
2. Re-run verifications (if needed)
3. Export/import from another machine

## Next Steps

- **[History Listing](./listing.md)** - View verification records
- **[Filtering](./filtering.md)** - Find specific records
- **[Rechecking Jobs](./recheck.md)** - Update pending statuses
- **[Statistics](./statistics.md)** - View verification stats
- **[How History Works](./tracking.md)** - Understanding the system
