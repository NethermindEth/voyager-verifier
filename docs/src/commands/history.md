# history Command

The `history` command manages your local verification history database, allowing you to view, filter, and track past verification jobs.

## Synopsis

```bash
voyager history <SUBCOMMAND> [OPTIONS]
```

## Description

The `history` command provides access to a local SQLite database (`~/.voyager/history.db`) that automatically tracks all verification submissions. This allows you to:

- View past verifications across sessions
- Filter by status, network, or date
- Re-check pending jobs
- Generate verification statistics
- Clean old records

All verification jobs are automatically tracked when using the `verify` command. No additional setup is required.

## Subcommands

### `list`

View all verification jobs with optional filtering.

```bash
voyager history list [OPTIONS]
```

### `status`

View detailed information about a specific job from local database.

```bash
voyager history status --job <JOB_ID> [OPTIONS]
```

### `recheck`

Re-check all pending jobs and update their status.

```bash
voyager history recheck --network <NETWORK> [OPTIONS]
```

### `stats`

Display verification statistics and success rates.

```bash
voyager history stats
```

### `clean`

Remove old records from the history database.

```bash
voyager history clean [OPTIONS]
```

---

## `history list`

List verification jobs from the history database.

### Synopsis

```bash
voyager history list [OPTIONS]
```

### Options

#### `--status <STATUS>`

Filter by verification status.

**Values:**
- `success` - Show only successful verifications
- `fail` - Show only failed verifications
- `pending` - Show only pending/in-progress jobs

**Example:**
```bash
voyager history list --status success
```

#### `--network <NETWORK>`

Filter by network.

**Values:** `mainnet`, `sepolia`, `dev`

**Example:**
```bash
voyager history list --network mainnet
```

#### `--limit <N>`

Limit the number of results.

**Default:** Unlimited

**Example:**
```bash
voyager history list --limit 10
```

### Examples

**List all verifications:**
```bash
voyager history list
```

**List recent 20 verifications:**
```bash
voyager history list --limit 20
```

**List successful mainnet verifications:**
```bash
voyager history list --status success --network mainnet
```

**List pending jobs:**
```bash
voyager history list --status pending
```

### Output

```
Verification History
════════════════════════════════════════════════════════════════

✓ MyToken (0x044dc2b3...da18)
  Job: abc-123-def | Network: mainnet | Submitted: 2025-01-15 10:30

✓ MyNFT (0x055dc2b3...da19)
  Job: ghi-456-jkl | Network: mainnet | Submitted: 2025-01-15 09:15

⏳ MyMarketplace (0x066dc2b3...da20)
  Job: mno-789-pqr | Network: sepolia | Submitted: 2025-01-14 16:45

✗ OldContract (0x077dc2b3...da21)
  Job: stu-012-vwx | Network: mainnet | Submitted: 2025-01-14 14:20

════════════════════════════════════════════════════════════════
Total: 4 verifications
```

---

## `history status`

View detailed information about a specific job from the local database.

### Synopsis

```bash
voyager history status --job <JOB_ID> [OPTIONS]
```

### Options

#### `--job <JOB_ID>` (Required)

The job ID to查询.

**Example:**
```bash
voyager history status --job abc-123-def-456
```

#### `--refresh`

Refresh status from API and update the database.

**Requires:** `--network` or `--url` must be specified

**Example:**
```bash
voyager history status --job abc-123-def-456 --network mainnet --refresh
```

#### `--network <NETWORK>`

Network for API refresh (only used with `--refresh`).

**Example:**
```bash
voyager history status --job abc-123-def --network mainnet --refresh
```

#### `--url <URL>`

Custom API endpoint for refresh (alternative to `--network`).

**Example:**
```bash
voyager history status --job abc-123-def --url https://api.custom.com/beta --refresh
```

### Examples

**View from local database (fast, no API call):**
```bash
voyager history status --job abc-123-def-456
```

**Refresh from API and update database:**
```bash
voyager history status --job abc-123-def-456 --network mainnet --refresh
```

### Output

```
Job Details
════════════════════════════════════════════════════════════════

Job ID:         abc-123-def-456
Status:         Success ✓
Contract Name:  MyToken
Class Hash:     0x044dc2b3239382230d8b1e943df23b96f52eebcac93efe6e8bde92f9a2f1da18
Network:        mainnet

Submitted:      2025-01-15 10:30:00
Completed:      2025-01-15 10:32:45
Duration:       2m 45s

Versions:
  Cairo:        2.11.4
  Scarb:        2.8.4

View on Voyager: https://voyager.online/class/0x044dc2b3...
````

---

## `history recheck`

Re-check all pending jobs and update their status from the API.

### Synopsis

```bash
voyager history recheck --network <NETWORK> [OPTIONS]
```

### Options

#### `--network <NETWORK>` (Required)

Network to query for status updates.

**Example:**
```bash
voyager history recheck --network mainnet
```

#### `--url <URL>`

Custom API endpoint (alternative to `--network`).

**Example:**
```bash
voyager history recheck --url https://api.custom.com/beta
```

### Examples

**Recheck all pending mainnet jobs:**
```bash
voyager history recheck --network mainnet
```

**Recheck all pending sepolia jobs:**
```bash
voyager history recheck --network sepolia
```

### Output

```
Rechecking pending verifications...

[1/3] Checking abc-123-def...
  ✓ Updated: Success

[2/3] Checking ghi-456-jkl...
  ⏳ Still pending: Compiling

[3/3] Checking mno-789-pqr...
  ✗ Updated: Failed

════════════════════════════════════════════════════════════════
Rechecked: 3 jobs
Updated: 2 jobs
Still pending: 1 job
════════════════════════════════════════════════════════════════
```

---

## `history stats`

Display verification statistics from the history database.

### Synopsis

```bash
voyager history stats
```

### Options

No options available for this subcommand.

### Example

```bash
voyager history stats
```

### Output

```
Verification History Statistics
════════════════════════════════════════════════════════════════

Total verifications: 47

✓ Successful:       41 (87%)
✗ Failed:           4 (9%)
⏳ Pending:          2 (4%)

Networks:
  Mainnet:          35 verifications
  Sepolia:          12 verifications

Average verification time: 2m 34s
````

---

## `history clean`

Remove old records from the history database.

### Synopsis

```bash
voyager history clean [OPTIONS]
```

### Options

#### `--older-than <DAYS>`

Delete records older than the specified number of days.

**Example:**
```bash
voyager history clean --older-than 30
```

#### `--all`

Delete all history records (requires confirmation).

**Example:**
```bash
voyager history clean --all
```

### Examples

**Delete records older than 30 days:**
```bash
voyager history clean --older-than 30
```

**Delete records older than 90 days:**
```bash
voyager history clean --older-than 90
```

**Delete all history:**
```bash
voyager history clean --all
```

### Output

**Older than:**
```
Cleaning history records older than 30 days...

Deleted: 15 records
Remaining: 32 records
```

**All (with confirmation):**
```
⚠ Warning: This will delete ALL verification history records.
Are you sure? (yes/no): yes

Deleted: 47 records
History database cleared.
```

---

## History Database

### Location

The history database is stored at:

```
~/.voyager/history.db
```

### What Gets Tracked

For each verification job, the following information is stored:

- Job ID
- Class hash
- Contract name
- Network (mainnet, sepolia, dev)
- Status (Submitted, Processing, Compiling, Success, Failed, etc.)
- Submission timestamp
- Completion timestamp (when applicable)
- Cairo version
- Scarb version
- Dojo version (for Dojo projects)

### Automatic Tracking

History tracking is automatic and transparent:

- When you run `voyager verify`, the job is added to history
- When you run `voyager status`, the job status is updated in history
- When you run `voyager history recheck`, all pending jobs are updated

No manual intervention is required.

### Cross-Session Persistence

The history database persists across terminal sessions and system restarts, allowing you to track verifications over time.

## Use Cases

### Track Project Deployments

Keep a record of all contract verifications for your project:

```bash
# List all verifications for audit purposes
voyager history list

# Filter by network
voyager history list --network mainnet

# View statistics
voyager history stats
```

### Resume After Disconnect

If your terminal disconnects during watch mode:

```bash
# List pending jobs
voyager history list --status pending

# Check specific job
voyager history status --job abc-123-def

# Refresh from API
voyager history status --job abc-123-def --network mainnet --refresh
```

### Clean Up Old Records

Periodically clean old verification records:

```bash
# Monthly cleanup
voyager history clean --older-than 30

# Quarterly cleanup
voyager history clean --older-than 90
```

### Batch Status Updates

Update all pending jobs at once:

```bash
# Check all pending mainnet verifications
voyager history recheck --network mainnet

# Check all pending sepolia verifications
voyager history recheck --network sepolia
```

## Scripting Examples

### Export History to JSON

```bash
#!/bin/bash

# Get all successful verifications
voyager history list --status success --format json > successful_verifications.json
```

### Monitor Pending Jobs

```bash
#!/bin/bash

# Continuously recheck pending jobs every 5 minutes
while true; do
  echo "Rechecking pending jobs..."
  voyager history recheck --network mainnet
  sleep 300
done
```

### Generate Report

```bash
#!/bin/bash

echo "Verification Report - $(date)"
echo "================================"
echo ""

voyager history stats
echo ""

echo "Recent Verifications:"
voyager history list --limit 10
```

## Exit Codes

- **0** - Command completed successfully
- **1** - Command failed or error occurred
- **2** - Invalid arguments

## See Also

- [verify command](./verify.md) - Submit contracts for verification
- [status command](./status.md) - Check verification status
- [History Overview](../history/README.md) - Detailed history documentation
- [Listing](../history/listing.md) - List command details
- [Statistics](../history/statistics.md) - Stats command details
- [Cleanup](../history/cleanup.md) - Clean command details
