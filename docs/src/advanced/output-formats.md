# Output Formats

The voyager-verifier supports multiple output formats to suit different use cases, from human-readable terminal output to machine-parseable JSON for CI/CD pipelines. This guide covers all available formats and when to use each one.

## Overview

Three output formats are available:

- **Text** - Human-readable format with enhanced formatting, progress bars, and colors (default)
- **JSON** - Machine-readable format for programmatic parsing and CI/CD integration
- **Table** - Structured table format for batch operations and quick status overview

## Format Selection

### Command-Line Flag

Use the `--format` flag to specify the output format:

```bash
voyager status --network mainnet --job <JOB_ID> --format json
```

Available format values:
- `text` (default)
- `json`
- `table`

### Configuration File

Set a default format in your `.voyager.toml`:

```toml
[voyager]
network = "mainnet"
format = "json"  # Options: "text", "json", "table"
```

### Priority System

Format selection follows this priority order:

1. **CLI flag** (`--format`) - Highest priority
2. **Config file** (`format` in `.voyager.toml`)
3. **Default value** (`text`) - Lowest priority

## Text Format (Default)

### Description

The text format provides human-readable output with:
- Color-coded status indicators (✅ success, ❌ failure, ⏳ in progress)
- Progress bars with percentage for in-progress jobs
- Time estimation based on historical verification data
- Stage-aware status messages
- Enhanced error reporting

### Use Cases

- **Interactive terminal use** - Ideal for developers running verifications manually
- **Debugging** - Easy to read status and error messages
- **Learning** - Clear presentation of verification workflow stages
- **Watch mode** - Live updates with progress indicators

### Example Output

#### In-Progress Verification

```bash
voyager status --network mainnet --job abc-123-def --format text
```

```
⏳ Verification Status

Job ID: abc-123-def
Status: Processing
Progress: ████████░░░░░░░░░░░░ (40%)
Class Hash: 0x044dc2b3239382230d8b1e943df23b96f52eebcac93efe6e8bde92f9a2f1da18
Contract: MyToken
Started: 2025-01-15 10:30:45 UTC
Last Updated: 2025-01-15 10:31:12 UTC
Elapsed: 27s
Estimated Remaining: ~13s
Cairo Version: 2.11.4
License: MIT

⏳ Verification is in progress...
Use the same command to check progress later.
```

#### Successful Verification

```
✅ Verification Status

Job ID: abc-123-def
Status: Success
Class Hash: 0x044dc2b3239382230d8b1e943df23b96f52eebcac93efe6e8bde92f9a2f1da18
Contract: MyToken
Contract File: token.cairo
Started: 2025-01-15 10:30:45 UTC
Last Updated: 2025-01-15 10:31:23 UTC
Elapsed: 38s
Cairo Version: 2.11.4
License: MIT

✅ Verification successful!
The contract is now verified and visible on Voyager at:
https://voyager.online/class/0x044dc2b3239382230d8b1e943df23b96f52eebcac93efe6e8bde92f9a2f1da18
```

#### Failed Verification

```
❌ Verification Status

Job ID: abc-123-def
Status: CompileFailed
Class Hash: 0x044dc2b3239382230d8b1e943df23b96f52eebcac93efe6e8bde92f9a2f1da18
Contract: MyToken
Started: 2025-01-15 10:30:45 UTC
Last Updated: 2025-01-15 10:31:02 UTC
Elapsed: 17s
Cairo Version: 2.11.4
License: MIT

❌ Verification failed!
Reason: Compilation failed
Message: error[E0005]: Module file not found. Expected path: /tmp/targets/.../src/tests.cairo

Suggestion: Use --test-files flag to include test files, or remove the module declaration from lib.cairo
```

### Progress Indicators

Text format includes dynamic progress bars showing verification stages:

| Status | Progress | Description |
|--------|----------|-------------|
| Submitted | 10% | Job created, waiting in queue |
| Processing | 40% | Picked up by worker, compiling source |
| Compiled | 85% | Compilation done, verifying bytecode |
| Success/Fail | 100% | Verification complete |

### Time Estimation

The text format provides intelligent time estimates:

1. **History-based estimates** - Uses average time from your last 10 successful verifications (requires minimum 3 samples)
2. **Fallback estimates** - Conservative hardcoded estimates if no history available:
   - Queue wait: 2-5 seconds
   - Compilation: 15-30 seconds
   - Verification: 2-5 seconds
   - **Total: ~40 seconds**

## JSON Format

### Description

The JSON format provides structured, machine-readable output suitable for:
- Automated processing and parsing
- CI/CD pipeline integration
- Monitoring and alerting systems
- Programmatic status checking
- Log aggregation

### Use Cases

- **CI/CD pipelines** - Parse verification results in GitHub Actions, GitLab CI, etc.
- **Automation scripts** - Integrate verification into deployment workflows
- **Monitoring** - Feed verification data into monitoring dashboards
- **API integration** - Use verification status in other tools
- **Data analysis** - Track verification metrics over time

### Example Output

```bash
voyager status --network mainnet --job abc-123-def --format json
```

```json
{
  "job_id": "abc-123-def",
  "status": "Success",
  "status_code": 4,
  "is_completed": true,
  "has_failed": false,
  "progress_percentage": 100,
  "class_hash": "0x044dc2b3239382230d8b1e943df23b96f52eebcac93efe6e8bde92f9a2f1da18",
  "contract_name": "MyToken",
  "contract_file": "token.cairo",
  "status_description": null,
  "message": null,
  "error_category": null,
  "created_at": "2025-01-15 10:30:45 UTC",
  "updated_at": "2025-01-15 10:31:23 UTC",
  "elapsed_seconds": 38,
  "estimated_remaining_seconds": null,
  "cairo_version": "2.11.4",
  "dojo_version": null,
  "license": "MIT",
  "address": null,
  "build_tool": "scarb"
}
```

### JSON Schema

| Field | Type | Description |
|-------|------|-------------|
| `job_id` | string | Unique verification job identifier (UUID) |
| `status` | string | Current status (Submitted, Processing, Compiled, Success, Fail, CompileFailed) |
| `status_code` | integer | Numeric status code (0-4) |
| `is_completed` | boolean | Whether verification has finished (success or failure) |
| `has_failed` | boolean | Whether verification failed |
| `progress_percentage` | integer | Progress from 0-100 |
| `class_hash` | string \| null | Contract class hash |
| `contract_name` | string \| null | Contract name |
| `contract_file` | string \| null | Main contract source file |
| `status_description` | string \| null | Detailed status message |
| `message` | string \| null | Error or informational message |
| `error_category` | string \| null | Error categorization |
| `created_at` | string \| null | Job creation timestamp (UTC) |
| `updated_at` | string \| null | Last update timestamp (UTC) |
| `elapsed_seconds` | integer \| null | Time elapsed since job creation |
| `estimated_remaining_seconds` | integer \| null | Estimated time until completion (for in-progress jobs) |
| `cairo_version` | string \| null | Cairo compiler version used |
| `dojo_version` | string \| null | Dojo version (for Dojo projects) |
| `license` | string \| null | SPDX license identifier |
| `address` | string \| null | Contract address (if available) |
| `build_tool` | string \| null | Build tool used (scarb, dojo) |

### Status Code Reference

```
0 = Unknown
1 = Submitted
2 = Processing
3 = Compiled
4 = Success
5 = Fail
6 = CompileFailed
```

### Parsing JSON Output

#### Using jq (Command Line)

Extract specific fields:

```bash
# Get job status
voyager status --network mainnet --job <JOB_ID> --format json | jq -r '.status'

# Check if completed
voyager status --network mainnet --job <JOB_ID> --format json | jq -r '.is_completed'

# Get elapsed time
voyager status --network mainnet --job <JOB_ID> --format json | jq -r '.elapsed_seconds'

# Get class hash if successful
voyager status --network mainnet --job <JOB_ID> --format json | jq -r 'select(.status == "Success") | .class_hash'
```

#### Python Example

```python
import json
import subprocess

# Run verification status command
result = subprocess.run(
    ['voyager', 'status', '--network', 'mainnet', '--job', job_id, '--format', 'json'],
    capture_output=True,
    text=True
)

# Parse JSON output
status = json.loads(result.stdout)

if status['is_completed']:
    if status['has_failed']:
        print(f"❌ Verification failed: {status.get('message', 'Unknown error')}")
        exit(1)
    else:
        print(f"✅ Verification successful!")
        print(f"   Class hash: {status['class_hash']}")
        print(f"   Voyager URL: https://voyager.online/class/{status['class_hash']}")
else:
    progress = status['progress_percentage']
    remaining = status.get('estimated_remaining_seconds', 0)
    print(f"⏳ Verification in progress: {progress}% (est. {remaining}s remaining)")
```

#### JavaScript/Node.js Example

```javascript
const { execSync } = require('child_process');

// Run verification status command
const output = execSync(
  `voyager status --network mainnet --job ${jobId} --format json`,
  { encoding: 'utf-8' }
);

// Parse JSON output
const status = JSON.parse(output);

if (status.is_completed) {
  if (status.has_failed) {
    console.error(`❌ Verification failed: ${status.message || 'Unknown error'}`);
    process.exit(1);
  } else {
    console.log(`✅ Verification successful!`);
    console.log(`   Contract: ${status.contract_name}`);
    console.log(`   Elapsed: ${status.elapsed_seconds}s`);
  }
} else {
  console.log(`⏳ ${status.status}: ${status.progress_percentage}%`);
}
```

#### Bash Script Example

```bash
#!/bin/bash

JOB_ID=$1
NETWORK=${2:-mainnet}

# Get verification status as JSON
STATUS=$(voyager status --network "$NETWORK" --job "$JOB_ID" --format json)

# Parse JSON using jq
IS_COMPLETED=$(echo "$STATUS" | jq -r '.is_completed')
HAS_FAILED=$(echo "$STATUS" | jq -r '.has_failed')
STATUS_TEXT=$(echo "$STATUS" | jq -r '.status')

if [ "$IS_COMPLETED" = "true" ]; then
  if [ "$HAS_FAILED" = "true" ]; then
    echo "❌ Verification failed with status: $STATUS_TEXT"
    exit 1
  else
    CLASS_HASH=$(echo "$STATUS" | jq -r '.class_hash')
    echo "✅ Verification successful!"
    echo "Class hash: $CLASS_HASH"
    echo "View on Voyager: https://voyager.online/class/$CLASS_HASH"
    exit 0
  fi
else
  PROGRESS=$(echo "$STATUS" | jq -r '.progress_percentage')
  echo "⏳ Verification in progress: $STATUS_TEXT ($PROGRESS%)"
  exit 2  # Still in progress
fi
```

## Table Format

### Description

The table format provides structured output in a bordered ASCII table layout. It's designed for:
- Quick visual scanning of status information
- Batch operation results
- Terminal-based dashboards
- Reports and logs

### Use Cases

- **Batch verification** - Compact summary of multiple contract verifications
- **Status overview** - Quick glance at verification details
- **Terminal UIs** - Integration with terminal-based interfaces
- **Log files** - Structured output for log analysis

### Example Output

```bash
voyager status --network mainnet --job abc-123-def --format table
```

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        Verification Job Status                              │
├─────────────────────────┬───────────────────────────────────────────────────┤
│ Job ID                  │ abc-123-def                                       │
│ Status                  │ Success                                           │
│ Class Hash              │ 0x044dc2b3...f1da18                               │
│ Contract                │ MyToken                                           │
│ Started                 │ 2025-01-15 10:30:45 UTC                           │
│ Elapsed                 │ 38s                                               │
│ Cairo Version           │ 2.11.4                                            │
└─────────────────────────┴───────────────────────────────────────────────────┘
```

### Features

- **Fixed-width columns** - Consistent formatting across different outputs
- **Truncated class hashes** - Long hashes are shortened for readability
- **Progress percentage** - Shown for in-progress verifications
- **Clean borders** - Unicode box-drawing characters for clear structure

## Format Comparison

| Feature | Text | JSON | Table |
|---------|------|------|-------|
| Human-readable | ✅ Excellent | ❌ No | ✅ Good |
| Machine-parseable | ❌ No | ✅ Perfect | ⚠️ Limited |
| Progress bars | ✅ Yes | ❌ No | ⚠️ Percentage only |
| Color output | ✅ Yes | ❌ No | ❌ No |
| Time estimates | ✅ Yes | ✅ Yes (numeric) | ✅ Yes |
| Verbose errors | ✅ Yes | ✅ Yes | ⚠️ Limited |
| CI/CD friendly | ⚠️ No | ✅ Perfect | ⚠️ Moderate |
| Batch operations | ✅ Summary | ✅ Array of jobs | ✅ Good |
| File size | Medium | Larger | Compact |

## Batch Verification Output

When verifying multiple contracts in batch mode, the output format displays a summary followed by individual contract results.

### Batch Text Output

```bash
voyager verify  # Reads contracts from .voyager.toml
```

**During submission:**

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

Contract Details:
  ⏳ MyToken (0x044dc2b3...f1da18)
     Status: Submitted
     Job ID: abc-123-def
  ⏳ MyNFT (0x055dc2b3...f1da19)
     Status: Submitted
     Job ID: ghi-456-jkl
  ⏳ MyMarketplace (0x066dc2b3...f1da20)
     Status: Submitted
     Job ID: mno-789-pqr
```

**With watch mode (final results):**

```bash
voyager verify --watch
```

```
⏳ Watching 3 verification job(s)...

  ✓ 3 Succeeded | ⏳ 0 Pending | ✗ 0 Failed

=== Final Summary ===
════════════════════════════════════════════════════════
Batch Verification Summary
════════════════════════════════════════════════════════
Total contracts:  3
Submitted:        3
Succeeded:        3
Failed:           0
Pending:          0
════════════════════════════════════════════════════════

Contract Details:
  ✓ MyToken (0x044dc2b3...f1da18)
    Status: Success
    Job ID: abc-123-def
  ✓ MyNFT (0x055dc2b3...f1da19)
    Status: Success
    Job ID: ghi-456-jkl
  ✓ MyMarketplace (0x066dc2b3...f1da20)
    Status: Success
    Job ID: mno-789-pqr
```

### Understanding Batch Symbols

| Symbol | Meaning |
|--------|---------|
| ✓ | Successfully verified |
| ✗ | Verification failed |
| ⏳ | In progress or pending |

## CI/CD Integration Examples

### GitHub Actions

```yaml
name: Verify Contracts

on:
  push:
    branches: [main]

jobs:
  verify:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Install voyager-verifier
        run: cargo install voyager-verifier

      - name: Verify contract
        id: verify
        run: |
          # Submit verification
          OUTPUT=$(voyager verify \
            --network mainnet \
            --class-hash ${{ secrets.CLASS_HASH }} \
            --contract-name MyContract \
            --format json)

          # Extract job ID
          JOB_ID=$(echo "$OUTPUT" | jq -r '.job_id')
          echo "job_id=$JOB_ID" >> $GITHUB_OUTPUT

      - name: Wait for verification
        run: |
          # Poll until complete (with timeout)
          TIMEOUT=300  # 5 minutes
          ELAPSED=0

          while [ $ELAPSED -lt $TIMEOUT ]; do
            STATUS=$(voyager status \
              --network mainnet \
              --job ${{ steps.verify.outputs.job_id }} \
              --format json)

            IS_COMPLETED=$(echo "$STATUS" | jq -r '.is_completed')

            if [ "$IS_COMPLETED" = "true" ]; then
              HAS_FAILED=$(echo "$STATUS" | jq -r '.has_failed')
              if [ "$HAS_FAILED" = "true" ]; then
                echo "❌ Verification failed"
                echo "$STATUS" | jq '.'
                exit 1
              else
                echo "✅ Verification successful"
                echo "$STATUS" | jq '.'
                exit 0
              fi
            fi

            echo "⏳ Still verifying... ($ELAPSED/$TIMEOUT seconds)"
            sleep 10
            ELAPSED=$((ELAPSED + 10))
          done

          echo "❌ Verification timed out"
          exit 1
```

### GitLab CI

```yaml
verify-contract:
  stage: deploy
  script:
    - cargo install voyager-verifier

    # Submit with watch mode (blocks until complete)
    - |
      voyager verify \
        --network mainnet \
        --class-hash $CLASS_HASH \
        --contract-name MyContract \
        --watch \
        --format json > result.json

    # Check result
    - |
      if [ $(jq -r '.has_failed' result.json) = "true" ]; then
        echo "Verification failed"
        cat result.json
        exit 1
      fi

    - echo "Verification successful"
    - cat result.json

  only:
    - main
```

### Jenkins Pipeline

```groovy
pipeline {
    agent any

    environment {
        CLASS_HASH = credentials('starknet-class-hash')
        CONTRACT_NAME = 'MyContract'
    }

    stages {
        stage('Verify Contract') {
            steps {
                script {
                    // Submit verification
                    def result = sh(
                        script: """
                            voyager verify \
                              --network mainnet \
                              --class-hash ${CLASS_HASH} \
                              --contract-name ${CONTRACT_NAME} \
                              --watch \
                              --format json
                        """,
                        returnStdout: true
                    ).trim()

                    // Parse JSON result
                    def json = readJSON text: result

                    if (json.has_failed) {
                        error("Verification failed: ${json.message}")
                    }

                    echo "✅ Verification successful!"
                    echo "Job ID: ${json.job_id}"
                    echo "Class Hash: ${json.class_hash}"
                }
            }
        }
    }
}
```

### Makefile Integration

```makefile
.PHONY: verify verify-watch verify-check

# Submit verification
verify:
	@echo "📤 Submitting verification..."
	@voyager verify \
		--network mainnet \
		--class-hash $(CLASS_HASH) \
		--contract-name $(CONTRACT_NAME) \
		--format json | tee verify-result.json
	@echo "Job ID: $$(jq -r '.job_id' verify-result.json)"

# Submit and wait for completion
verify-watch:
	@echo "📤 Submitting verification with watch mode..."
	@voyager verify \
		--network mainnet \
		--class-hash $(CLASS_HASH) \
		--contract-name $(CONTRACT_NAME) \
		--watch \
		--format json | tee verify-result.json
	@if [ $$(jq -r '.has_failed' verify-result.json) = "true" ]; then \
		echo "❌ Verification failed"; \
		exit 1; \
	fi
	@echo "✅ Verification successful"

# Check existing job status
verify-check:
	@voyager status \
		--network mainnet \
		--job $(JOB_ID) \
		--format json | jq '.'
```

## Best Practices

### Format Selection Guidelines

1. **Use text format for:**
   - Interactive terminal sessions
   - Manual verification during development
   - Learning and debugging
   - Watch mode with live progress updates

2. **Use JSON format for:**
   - CI/CD pipelines
   - Automated deployment scripts
   - Integration with other tools
   - Monitoring and alerting
   - Data analysis and metrics

3. **Use table format for:**
   - Quick status checks
   - Batch operation overviews
   - Terminal-based UIs
   - Documentation and reports

### Error Handling

Always check the completion status before examining results:

**Good:**
```bash
STATUS=$(voyager status --network mainnet --job $JOB_ID --format json)

if [ $(echo "$STATUS" | jq -r '.is_completed') = "true" ]; then
  if [ $(echo "$STATUS" | jq -r '.has_failed') = "true" ]; then
    echo "Failed: $(echo "$STATUS" | jq -r '.message')"
  else
    echo "Success!"
  fi
else
  echo "Still in progress"
fi
```

**Bad:**
```bash
# Don't assume verification is complete
voyager status --network mainnet --job $JOB_ID --format json | jq -r '.class_hash'
# This might return null if verification is still running
```

### Verbose Mode with JSON

Combine `--verbose` with `--format json` to get detailed error information in structured format:

```bash
voyager status --network mainnet --job $JOB_ID --format json --verbose
```

This includes full compiler output in the `message` field when compilation fails.

## Troubleshooting

### JSON Parsing Errors

**Problem:** `jq` command fails with parse error

**Solution:** Check that the command succeeded first:

```bash
OUTPUT=$(voyager status --network mainnet --job $JOB_ID --format json 2>&1)

if echo "$OUTPUT" | jq -e . >/dev/null 2>&1; then
  # Valid JSON, safe to parse
  STATUS=$(echo "$OUTPUT" | jq -r '.status')
else
  # Not valid JSON, probably an error message
  echo "Error occurred: $OUTPUT"
  exit 1
fi
```

### Empty or Null Fields

**Problem:** JSON fields contain `null` values

**Solution:** Always check for null before using field values:

```bash
# Safe null handling with jq
CLASS_HASH=$(voyager status --network mainnet --job $JOB_ID --format json | \
  jq -r '.class_hash // "not available"')

# Or check explicitly
if [ $(echo "$STATUS" | jq -r '.class_hash') != "null" ]; then
  # Safe to use class_hash
fi
```

### Table Format in Scripts

**Problem:** Table format is hard to parse programmatically

**Solution:** Don't use table format for automated scripts. Use JSON instead:

```bash
# ❌ Don't do this
voyager status --network mainnet --job $JOB_ID --format table | grep "Status"

# ✅ Do this instead
voyager status --network mainnet --job $JOB_ID --format json | jq -r '.status'
```

## See Also

- [Command-Line Verification](../verification/command-line.md) - Direct CLI verification syntax
- [Batch Verification](../verification/batch-verification.md) - Verifying multiple contracts
- [Watch Mode](../verification/watch-mode.md) - Monitoring verification progress
- [Desktop Notifications](./notifications.md) - Getting notified on completion
- [History Listing](../history/listing.md) - Viewing verification history
