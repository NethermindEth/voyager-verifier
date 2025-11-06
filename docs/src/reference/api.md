# API Reference

This reference documents the Voyager API endpoints, request/response formats, and job lifecycle for contract verification.

## Quick Reference

| Endpoint | Method | Purpose | Authentication |
|----------|--------|---------|----------------|
| `/class-verify/{class_hash}` | POST | Submit verification job | None |
| `/class-verify/job/{job_id}` | GET | Get job status | None |
| `/classes/{class_hash}` | GET | Check if class exists | None |

**Base URLs:**
- **Mainnet:** `https://api.voyager.online`
- **Sepolia:** `https://sepolia-api.voyager.online`
- **Dev:** `https://dev-api.voyager.online`
- **Custom:** User-specified endpoint

---

## API Endpoints

### 1. Submit Verification

**Submit a contract for verification**

```http
POST /class-verify/{class_hash}
Host: api.voyager.online
Content-Type: application/json
```

**Path Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `class_hash` | string | Yes | Contract class hash (0x...) |

**Request Body:**

```json
{
  "name": "MyContract",
  "version": "0.1.0",
  "contract_file": "src/contract.cairo",
  "project_dir_path": ".",
  "cairo_version": "2.8.4",
  "scarb_version": "2.8.4",
  "license": "MIT",
  "build_tool": "scarb",
  "dojo_version": null,
  "files": {
    "Scarb.toml": "base64_encoded_content",
    "src/lib.cairo": "base64_encoded_content",
    "src/contract.cairo": "base64_encoded_content"
  }
}
```

**Request Body Fields:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | Yes | Contract/package name |
| `version` | string | Yes | Package version |
| `contract_file` | string | Yes | Relative path to contract file |
| `project_dir_path` | string | Yes | Project directory path (usually ".") |
| `cairo_version` | string | Yes | Cairo version (e.g., "2.8.4") |
| `scarb_version` | string | Yes | Scarb version (e.g., "2.8.4") |
| `license` | string | No | SPDX license identifier |
| `build_tool` | string | Yes | Build tool: "scarb" or "sozo" |
| `dojo_version` | string | No | Dojo version (if Dojo project) |
| `files` | object | Yes | Map of file paths to base64-encoded content |

**Response (Success - 200 OK):**

```json
{
  "job_id": "abc123def456"
}
```

**Response Fields:**

| Field | Type | Description |
|-------|------|-------------|
| `job_id` | string | Unique job identifier for tracking |

**Response (Error - 4xx/5xx):**

```json
{
  "error": "Error message describing what went wrong"
}
```

**Example with cURL:**

```bash
curl -X POST https://api.voyager.online/class-verify/0x044dc2b3... \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Counter",
    "version": "0.1.0",
    "contract_file": "src/lib.cairo",
    "project_dir_path": ".",
    "cairo_version": "2.8.4",
    "scarb_version": "2.8.4",
    "license": "MIT",
    "build_tool": "scarb",
    "dojo_version": null,
    "files": {
      "Scarb.toml": "W3BhY2thZ2VdCm5hbWUgPSAiQ291bnRlciIKdmVyc2lvbiA9ICIwLjEuMCIK...",
      "src/lib.cairo": "I1tzdGFya25ldDo6Y29udHJhY3RdCm1vZCBDb3VudGVyIHsKICAg..."
    }
  }'
```

---

### 2. Get Job Status

**Check the status of a verification job**

```http
GET /class-verify/job/{job_id}
Host: api.voyager.online
```

**Path Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `job_id` | string | Yes | Job ID returned from submission |

**Response (Success - 200 OK):**

```json
{
  "job_id": "abc123def456",
  "status": 4,
  "status_description": "Success",
  "message": "Contract verified successfully",
  "error_category": null,
  "class_hash": "0x044dc2b3...",
  "created_timestamp": 1704067200.0,
  "updated_timestamp": 1704067225.0,
  "address": null,
  "contract_file": "src/contract.cairo",
  "name": "Counter",
  "version": "0.1.0",
  "license": "MIT",
  "dojo_version": null,
  "build_tool": "scarb"
}
```

**Response Fields:**

| Field | Type | Description |
|-------|------|-------------|
| `job_id` | string | Unique job identifier |
| `status` | number | Job status code (see [Job Status Codes](#job-status-codes)) |
| `status_description` | string | Human-readable status |
| `message` | string | Status message or error details |
| `error_category` | string\|null | Error category if failed |
| `class_hash` | string | Contract class hash |
| `created_timestamp` | number | Job creation time (Unix timestamp) |
| `updated_timestamp` | number | Last update time (Unix timestamp) |
| `address` | string\|null | Contract address (if specified) |
| `contract_file` | string | Main contract file path |
| `name` | string | Contract name |
| `version` | string | Package version |
| `license` | string\|null | License identifier |
| `dojo_version` | string\|null | Dojo version (if applicable) |
| `build_tool` | string | Build tool used ("scarb" or "sozo") |

**Response (Not Found - 404):**

```json
{
  "error": "Job not found: abc123def456"
}
```

**Example with cURL:**

```bash
curl https://api.voyager.online/class-verify/job/abc123def456
```

---

### 3. Check Class Exists

**Check if a class hash exists in the explorer**

```http
GET /classes/{class_hash}
Host: api.voyager.online
```

**Path Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `class_hash` | string | Yes | Contract class hash (0x...) |

**Response (Exists - 200 OK):**

```json
{
  "status": "ok"
}
```

**Response (Not Found - 404):**

```json
{
  "error": "Class not found"
}
```

**Example with cURL:**

```bash
curl https://api.voyager.online/classes/0x044dc2b3...
```

---

## Job Status Codes

### Status Values

| Code | Name | Description | Terminal |
|------|------|-------------|----------|
| `0` | Submitted | Job submitted, waiting to be processed | No |
| `1` | Compiled | Contract compiled successfully | No |
| `2` | CompileFailed | Compilation failed | Yes |
| `3` | Fail | Verification failed | Yes |
| `4` | Success | Contract verified successfully | Yes |
| `5` | Processing | Job is being processed | No |
| `Unknown` | Unknown | Unknown status | No |

**Terminal States:**

Jobs in these states are considered complete and won't change:
- `CompileFailed` (2)
- `Fail` (3)
- `Success` (4)

**Non-Terminal States:**

Jobs in these states are still in progress:
- `Submitted` (0)
- `Compiled` (1)
- `Processing` (5)

### Status Meanings

**0 - Submitted:**
```json
{
  "status": 0,
  "status_description": "Submitted",
  "message": "Job submitted and queued for processing"
}
```
Job has been received and is waiting in the queue.

**1 - Compiled:**
```json
{
  "status": 1,
  "status_description": "Compiled",
  "message": "Contract compiled successfully, verifying hash"
}
```
Contract compiled successfully, now comparing class hash.

**2 - CompileFailed:**
```json
{
  "status": 2,
  "status_description": "CompileFailed",
  "message": "error[E0005]: Module file not found...",
  "error_category": "compilation"
}
```
Compilation failed. Check `message` for compiler error details.

**3 - Fail:**
```json
{
  "status": 3,
  "status_description": "Fail",
  "message": "Class hash mismatch: expected 0x123..., got 0x456...",
  "error_category": "verification"
}
```
Verification failed. Common causes:
- Class hash mismatch
- Build configuration mismatch
- Missing dependencies

**4 - Success:**
```json
{
  "status": 4,
  "status_description": "Success",
  "message": "Contract verified successfully"
}
```
Verification completed successfully! Contract is now verified on the explorer.

**5 - Processing:**
```json
{
  "status": 5,
  "status_description": "Processing",
  "message": "Job is being processed"
}
```
Job is actively being processed by the server.

---

## Job Lifecycle

### Typical Successful Flow

```
1. Submitted (0)
      ↓
   [API receives job]
      ↓
2. Processing (5)
      ↓
   [Server compiles contract]
      ↓
3. Compiled (1)
      ↓
   [Server verifies hash]
      ↓
4. Success (4)
   [Verification complete!]
```

### Typical Failure Flow

```
1. Submitted (0)
      ↓
   [API receives job]
      ↓
2. Processing (5)
      ↓
   [Server attempts compilation]
      ↓
3. CompileFailed (2)
   [Compilation errors found]

OR

3. Compiled (1)
      ↓
   [Server verifies hash]
      ↓
4. Fail (3)
   [Hash mismatch]
```

### State Transition Diagram

```
        Submitted (0)
             ↓
        Processing (5)
           ↙   ↘
  CompileFailed  Compiled (1)
       (2)            ↓
                 Verifying...
                   ↙   ↘
              Fail (3)  Success (4)
```

---

## Network Endpoints

### Predefined Networks

**1. Mainnet (Default)**

```
Base URL: https://api.voyager.online
Network: starknet-mainnet
```

Usage:
```bash
voyager verify --network mainnet \
  --class-hash 0x044dc2b3... \
  --contract-name MyContract
```

**2. Sepolia Testnet**

```
Base URL: https://sepolia-api.voyager.online
Network: starknet-sepolia
```

Usage:
```bash
voyager verify --network sepolia \
  --class-hash 0x044dc2b3... \
  --contract-name MyContract
```

**3. Dev Environment**

```
Base URL: https://dev-api.voyager.online
Network: starknet-dev
```

Usage:
```bash
voyager verify --network dev \
  --class-hash 0x044dc2b3... \
  --contract-name MyContract
```

### Custom Endpoints

**For staging/internal environments:**

```bash
voyager verify --network custom \
  --endpoint https://api.custom-environment.com \
  --class-hash 0x044dc2b3... \
  --contract-name MyContract
```

**Custom Endpoint Requirements:**

1. Must be a valid HTTPS URL
2. Must implement the same API endpoints
3. Must accept standard request formats

**Example Custom Endpoint:**

```bash
# Company internal deployment
voyager verify --network custom \
  --endpoint https://starknet-verify.company.com \
  --class-hash 0x044dc2b3... \
  --contract-name MyContract

# Local development server
voyager verify --network custom \
  --endpoint http://localhost:8080 \
  --class-hash 0x044dc2b3... \
  --contract-name MyContract
```

---

## Request/Response Examples

### Complete Verification Flow

**1. Submit Verification:**

```bash
# Using Voyager CLI
voyager verify --network mainnet \
  --class-hash 0x044dc2b3abc123def456... \
  --contract-name Counter

# Output:
# ✨ Verification job submitted successfully!
# 📋 Job ID: abc123def456
# 🔗 Track at: https://voyager.online/contract/0x044dc2b3...
```

**2. Check Status (Immediately):**

```bash
voyager status --network mainnet --job abc123def456

# Output:
# 📊 Job Status: Submitted
# 🕐 Created: 2025-01-01 12:00:00
# ⏳ Status: Job submitted and queued for processing
```

**3. Check Status (After 10 seconds):**

```bash
voyager status --network mainnet --job abc123def456

# Output:
# 📊 Job Status: Compiled
# 🕐 Created: 2025-01-01 12:00:00
# 🔄 Updated: 2025-01-01 12:00:10
# ⚙️  Status: Contract compiled successfully, verifying hash
```

**4. Check Status (After 20 seconds):**

```bash
voyager status --network mainnet --job abc123def456

# Output:
# ✅ Job Status: Success
# 🕐 Created: 2025-01-01 12:00:00
# 🔄 Updated: 2025-01-01 12:00:20
# ✨ Status: Contract verified successfully
# 🔗 View on explorer: https://voyager.online/contract/0x044dc2b3...
```

### Failed Verification Example

**Compilation Failure:**

```json
{
  "job_id": "abc123def456",
  "status": 2,
  "status_description": "CompileFailed",
  "message": "error[E0005]: Module file not found. Expected path: /tmp/targets/release/src/tests.cairo\n --> src/lib.cairo:5:5\n  |\n5 | mod tests;\n  |     ^^^^^\n  |\n\nCompilation failed with exit code: 1",
  "error_category": "compilation"
}
```

**Verification Failure:**

```json
{
  "job_id": "abc123def456",
  "status": 3,
  "status_description": "Fail",
  "message": "Class hash mismatch: expected 0x044dc2b3abc..., got 0x044dc2b3xyz...",
  "error_category": "verification"
}
```

---

## Polling Best Practices

### Recommended Polling Strategy

**Voyager CLI uses exponential backoff with retries:**

```rust
// From client.rs - Retry configuration
ExponentialBuilder::default()
    .with_min_delay(Duration::from_secs(2))
    .with_max_delay(Duration::from_secs(10))
    .with_max_times(200)  // About 30 minutes total
```

**Recommended Manual Polling:**

```bash
#!/bin/bash
# poll-status.sh - Poll job status with exponential backoff

JOB_ID=$1
NETWORK=${2:-mainnet}
MAX_ATTEMPTS=30
DELAY=2

for i in $(seq 1 $MAX_ATTEMPTS); do
  echo "Attempt $i/$MAX_ATTEMPTS..."

  STATUS=$(voyager status --network $NETWORK --job $JOB_ID --json | jq -r '.status')

  # Check if terminal state
  if [ "$STATUS" -eq 2 ] || [ "$STATUS" -eq 3 ] || [ "$STATUS" -eq 4 ]; then
    echo "Job completed with status: $STATUS"
    voyager status --network $NETWORK --job $JOB_ID
    exit 0
  fi

  # Exponential backoff
  sleep $DELAY
  DELAY=$((DELAY * 2))
  if [ $DELAY -gt 60 ]; then
    DELAY=60  # Cap at 60 seconds
  fi
done

echo "Timeout waiting for job completion"
exit 1
```

### Polling Guidelines

1. **Start with 2-second delay**: Initial check after 2 seconds
2. **Exponential backoff**: Double delay each time (2s → 4s → 8s → 16s → ...)
3. **Cap at 60 seconds**: Don't wait more than 60s between polls
4. **Maximum 30 minutes**: Total timeout for job completion
5. **Check terminal states**: Stop polling when status is 2, 3, or 4

### Typical Timing

| Job Result | Typical Duration |
|------------|------------------|
| Success (simple contract) | 5-15 seconds |
| Success (complex contract) | 15-60 seconds |
| CompileFailed | 10-30 seconds |
| Fail (hash mismatch) | 15-45 seconds |
| Stuck in queue | > 2 minutes |

---

## Error Handling

### API Error Responses

**400 Bad Request:**

```json
{
  "error": "Invalid class hash format"
}
```

Cause: Malformed request data
Solution: Validate input parameters

**404 Not Found:**

```json
{
  "error": "Job not found: abc123def456"
}
```

Cause: Invalid job ID or expired job
Solution: Check job ID, jobs may expire after 30 days

**429 Too Many Requests:**

```json
{
  "error": "Rate limit exceeded"
}
```

Cause: Too many requests from the same IP
Solution: Implement exponential backoff

**500 Internal Server Error:**

```json
{
  "error": "Internal server error"
}
```

Cause: Server-side issue
Solution: Retry with exponential backoff, contact support if persistent

### Client-Side Error Handling

**Network Errors:**

```bash
# Voyager CLI handles retries automatically
voyager verify --network mainnet \
  --class-hash 0x044dc2b3... \
  --contract-name MyContract

# If network fails:
# ⚠️  Network error, retrying... (attempt 1/5)
# ⚠️  Network error, retrying... (attempt 2/5)
```

**Timeout Handling:**

```bash
# Set custom timeout (default: 30 minutes)
export VOYAGER_TIMEOUT_MINUTES=60

voyager verify --network mainnet \
  --class-hash 0x044dc2b3... \
  --contract-name MyContract
```

---

## Rate Limiting

### Current Limits

**No official rate limits documented**, but recommended best practices:

1. **Don't spam the API**: Wait for job completion before submitting new jobs
2. **Use exponential backoff**: When polling status
3. **Cache results**: Don't re-verify already verified contracts
4. **Batch operations**: Use history to check existing verifications first

### Checking Before Verification

```bash
# Check history first to avoid duplicate submissions
voyager history --network mainnet \
  --class-hash 0x044dc2b3... \
  --limit 10

# If already verified, no need to submit again
```

---

## API Versioning

### Current API Version

**Version:** v1 (implicit)

**Endpoint Structure:**
```
https://api.voyager.online/class-verify/{class_hash}
https://api.voyager.online/class-verify/job/{job_id}
```

**No version prefix** in current API.

### Future Versioning

Future API versions may use path-based versioning:
```
https://api.voyager.online/v2/class-verify/{class_hash}
```

**Backward Compatibility:**

Current v1 endpoints will continue to work when v2 is introduced.

---

## Security

### HTTPS Only

**All requests must use HTTPS:**

```bash
✅ https://api.voyager.online/class-verify/...
❌ http://api.voyager.online/class-verify/...  # Not allowed
```

### No Authentication Required

**Public API - no API keys needed:**

```bash
# No authentication headers required
curl https://api.voyager.online/class-verify/job/abc123
```

### Data Privacy

**What is stored:**

- Contract source code (for verification)
- Package metadata (name, version, license)
- Build configuration (Cairo/Scarb versions)
- Compilation results

**What is NOT stored:**

- User personal information
- IP addresses (for long term)
- API access logs (beyond operational needs)

### Best Practices

1. **Don't include secrets**: Remove private keys, API keys from source before submission
2. **Review files**: Use `--dry-run` to preview what will be submitted
3. **Use HTTPS**: Always use secure connections
4. **Validate class hashes**: Ensure class hash is correct before submission

---

## See Also

- [Error Codes](error-codes.md) - API error codes (E004-E009)
- [Custom Endpoints Guide](../advanced/custom-endpoints.md) - Using custom API endpoints
- [Status Command](../core-features/status.md) - Checking job status
- [History Command](../core-features/history.md) - Viewing verification history
- [Troubleshooting](../troubleshooting/common-errors.md) - Common API issues
