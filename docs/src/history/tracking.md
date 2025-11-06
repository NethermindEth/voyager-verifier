# How History Works

Voyager Verifier automatically tracks all verification jobs in a local database, providing persistent tracking across sessions and commands.

## Overview

History tracking provides:

- **Automatic tracking** - Every verification is recorded automatically
- **Persistent storage** - History survives across terminal sessions
- **Cross-session access** - Check jobs submitted in previous sessions
- **Status updates** - Track verification progress over time
- **No configuration needed** - Database created automatically on first use
- **Privacy-focused** - All data stored locally on your machine

## Database Location

### Default Location

```
~/.voyager/history.db
```

**Examples by platform:**
- **Linux:** `/home/username/.voyager/history.db`
- **macOS:** `/Users/username/.voyager/history.db`
- **Windows:** `C:\Users\username\.voyager\history.db`

### Database Structure

The history database is a SQLite database containing:
- Verification job records
- Submission timestamps
- Job IDs and status
- Network information
- Contract metadata
- Status update history

## What Gets Tracked

### Tracked Information

For each verification, the following information is stored:

#### Core Information
- **Job ID** - Unique identifier from Voyager API
- **Timestamp** - When verification was submitted
- **Network** - Network used (mainnet, sepolia, etc.)
- **Status** - Current verification status

#### Contract Information
- **Class Hash** - Contract class hash
- **Contract Name** - Name of the contract
- **Package** - Package name (for workspace projects)

#### Metadata
- **License** - SPDX license identifier
- **Project Path** - Location of the project
- **Config Used** - Configuration file location (if any)

#### Status History
- **Initial Status** - Status at submission
- **Status Updates** - All status changes
- **Completion Time** - When verification completed (if finished)

### Example Record

```
Job ID: abc-123-def-456-ghi-789
Status: Success
Network: mainnet
Submitted: 2025-11-06 10:30:45
Completed: 2025-11-06 10:35:12
Duration: 4 minutes 27 seconds

Contract:
  Name: MyToken
  Hash: 0x044dc2b3239382230d8b1e943df23b96f52eebcac93efe6e8bde92f9a2f1da18
  Package: token
  License: MIT
```

## Automatic Tracking

### When Tracking Occurs

History is automatically recorded:

1. **On submission** - When `voyager verify` is executed
2. **During watch** - When using `--watch` mode
3. **On status check** - When checking status manually
4. **On recheck** - When rechecking pending jobs

### No Manual Action Required

You don't need to:
- Enable history tracking
- Initialize the database
- Manually save records
- Configure storage location

Everything happens automatically.

## How Tracking Works

### Submission Flow

```
1. You run: voyager verify --network mainnet --class-hash 0x123... --contract-name Token
2. Job submitted to API
3. API returns job ID
4. Record created in history.db
5. Initial status saved
6. You receive job ID confirmation
```

### Watch Mode Flow

```
1. You run: voyager verify ... --watch
2. Job submitted and recorded
3. Status polling begins
4. Each status update saved to history
5. Final status recorded when complete
```

### Status Check Flow

```
1. You run: voyager history status --job <JOB_ID>
2. Record retrieved from history.db
3. Current status displayed
4. (Optional) Refresh from API with --refresh
5. Updated status saved to history
```

## Database Initialization

### First Use

On first verification:

```bash
voyager verify --network mainnet --class-hash 0x123... --contract-name MyContract
```

**What happens:**
1. Check if `~/.voyager/` directory exists
2. Create directory if needed
3. Check if `history.db` exists
4. Create database with schema if needed
5. Insert first record
6. Continue with verification

**Output:**
```
✓ History database initialized at ~/.voyager/history.db
✓ Verification job submitted successfully
Job ID: abc-123-def-456
```

### Schema Creation

The database schema is automatically created with tables for:
- Verification jobs
- Status updates
- Network configurations
- Metadata

## Cross-Session Persistence

### Same-Day Access

**Morning session:**
```bash
voyager verify --network mainnet --class-hash 0x123... --contract-name Token
Job ID: abc-123-def
```

**Afternoon session:**
```bash
voyager history list
# Shows morning's verification
```

### Multi-Day Access

**Day 1:**
```bash
voyager verify --network mainnet --class-hash 0x123... --contract-name TokenV1
```

**Day 7:**
```bash
voyager history list --limit 10
# Still shows Day 1 verification
```

**Day 30:**
```bash
voyager history list --older-than 30
# Can still access old records
```

## Status Updates

### Automatic Updates

When using `--watch` mode:

```bash
voyager verify --network mainnet \
  --class-hash 0x123... \
  --contract-name MyContract \
  --watch
```

**Status progression saved:**
1. Submitted → recorded
2. Pending → updated
3. In Progress → updated
4. Compiling → updated
5. Success/Failed → updated

Each status change is timestamped and saved.

### Manual Updates

Update status for a specific job:

```bash
voyager history status --job abc-123-def --network mainnet --refresh
```

This:
1. Fetches current status from API
2. Updates record in history.db
3. Displays updated status

### Batch Updates

Update all pending jobs:

```bash
voyager history recheck --network mainnet
```

This:
1. Finds all pending jobs
2. Checks status for each from API
3. Updates all records in database
4. Shows summary of updates

## Data Privacy

### Local Storage

All history data is stored **locally** on your machine:

- ✅ No data sent to external servers (except verification API)
- ✅ No analytics or tracking
- ✅ No cloud synchronization
- ✅ Full control over your data

### Database Access

Only you can access the database:

- **Readable by:** Your user account only
- **Writable by:** Your user account only
- **Network access:** None
- **Shared access:** None (unless you explicitly share the file)

### Data Retention

You control retention:

- Keep forever (default)
- Clean old records manually
- Delete specific entries
- Delete entire database

## Performance Considerations

### Database Size

Typical sizes:
- **10 verifications:** ~50 KB
- **100 verifications:** ~500 KB
- **1,000 verifications:** ~5 MB
- **10,000 verifications:** ~50 MB

### Query Performance

- **List operations:** Fast (< 1ms for 1,000 records)
- **Filter operations:** Fast (< 10ms for 10,000 records)
- **Status checks:** Instant (indexed by job ID)
- **Statistics:** Fast (aggregated queries optimized)

### Maintenance

No regular maintenance required, but you can:

```bash
# Clean old records to reduce size
voyager history clean --older-than 90

# Vacuum database to reclaim space (manual)
sqlite3 ~/.voyager/history.db "VACUUM;"
```

## Multi-Machine Setup

### Separate Databases

Each machine has its own database:

```
Machine A: ~/.voyager/history.db (contains jobs from Machine A)
Machine B: ~/.voyager/history.db (contains jobs from Machine B)
```

### Syncing (Optional)

To sync history across machines, manually copy the database:

```bash
# On Machine A
scp ~/.voyager/history.db machine-b:~/.voyager/history.db

# Or use rsync
rsync -avz ~/.voyager/history.db machine-b:~/.voyager/
```

**Warning:** This overwrites Machine B's history.

### Merging (Advanced)

To merge histories from multiple machines:

```bash
# Use SQLite commands (advanced users only)
sqlite3 ~/.voyager/history.db "ATTACH 'machine-b-history.db' AS other;"
sqlite3 ~/.voyager/history.db "INSERT OR IGNORE INTO verifications SELECT * FROM other.verifications;"
```

## Troubleshooting

### Database Not Found

**Error:**
```
Error: History database not found
```

**Cause:** Database file deleted or moved

**Solution:** Database will be recreated on next verification:
```bash
voyager verify --network mainnet --class-hash 0x123... --contract-name Test
```

### Corrupted Database

**Error:**
```
Error: Database file is corrupted
```

**Solutions:**

**Option 1 - Backup and recreate:**
```bash
# Backup corrupted file
cp ~/.voyager/history.db ~/.voyager/history.db.backup

# Remove corrupted database
rm ~/.voyager/history.db

# Run verification to create new database
voyager verify --network mainnet --class-hash 0x123... --contract-name Test
```

**Option 2 - Repair with SQLite:**
```bash
sqlite3 ~/.voyager/history.db ".recover" | sqlite3 ~/.voyager/history-recovered.db
mv ~/.voyager/history-recovered.db ~/.voyager/history.db
```

### Permission Issues

**Error:**
```
Error: Permission denied: ~/.voyager/history.db
```

**Solution:** Fix permissions:
```bash
chmod 644 ~/.voyager/history.db
```

### Disk Space Full

**Error:**
```
Error: Cannot write to history database: disk full
```

**Solution:** Clean old records:
```bash
voyager history clean --older-than 30
```

## Best Practices

### 1. Regular Cleanup

Clean old records periodically:

```bash
# Monthly cleanup
voyager history clean --older-than 90
```

### 2. Backup Important Records

Before major cleanup:

```bash
# Backup database
cp ~/.voyager/history.db ~/.voyager/history-backup-$(date +%Y%m%d).db

# Then clean
voyager history clean --older-than 180
```

### 3. Monitor Database Size

Check database size:

```bash
ls -lh ~/.voyager/history.db
```

If growing too large, clean old records.

### 4. Use Filtering

Instead of listing all records:

```bash
# Bad - lists everything
voyager history list

# Good - filter what you need
voyager history list --status success --limit 20
voyager history list --network mainnet --limit 10
```

### 5. Recheck Periodically

For pending jobs:

```bash
# Weekly recheck of pending jobs
voyager history recheck --network mainnet
```

## Integration with Workflows

### Development Workflow

```bash
# Submit verification
voyager verify --network sepolia --class-hash 0x123... --contract-name Test

# Later, check all sepolia verifications
voyager history list --network sepolia

# Recheck any pending
voyager history recheck --network sepolia
```

### Production Deployment

```bash
# Submit production verification
voyager verify --network mainnet \
  --class-hash 0x123... \
  --contract-name ProductionContract \
  --watch

# Check history for confirmation
voyager history list --limit 1
```

### CI/CD Pipeline

```bash
# In CI, submit without watch
voyager verify --network mainnet --class-hash $CLASS_HASH --contract-name $CONTRACT

# Later, check from history
voyager history status --job $JOB_ID --network mainnet --refresh
```

### Audit Trail

```bash
# Generate report of all mainnet verifications
voyager history list --network mainnet > mainnet-verifications.txt

# Show statistics
voyager history stats >> mainnet-verifications.txt
```

## Advanced Usage

### Export History

```bash
# Export to JSON (if supported)
voyager history list --format json > history.json

# Or use SQLite directly
sqlite3 ~/.voyager/history.db ".mode json" ".once history.json" "SELECT * FROM verifications;"
```

### Query Specific Time Range

```bash
# Using SQLite directly for custom queries
sqlite3 ~/.voyager/history.db "SELECT * FROM verifications WHERE submitted_at > '2025-11-01';"
```

### Backup Strategy

```bash
#!/bin/bash
# backup-history.sh

DATE=$(date +%Y%m%d)
cp ~/.voyager/history.db ~/.voyager/backups/history-$DATE.db

# Keep only last 30 days of backups
find ~/.voyager/backups/ -name "history-*.db" -mtime +30 -delete
```

## Next Steps

- **[Viewing History](./listing.md)** - List and view verification records
- **[Filtering](./filtering.md)** - Filter history by status, network, date
- **[Rechecking Jobs](./recheck.md)** - Update status for pending verifications
- **[Statistics](./statistics.md)** - View verification success rates
- **[Cleanup](./cleanup.md)** - Manage and clean old records
