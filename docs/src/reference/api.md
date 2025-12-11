# API Reference

This reference documents the API interactions used by the Voyager CLI for contract verification.

## Overview

The Voyager CLI communicates with the Voyager verification service to submit contracts for verification and check their status. All API interactions are handled internally by the CLI - users don't need to make direct API calls.

## CLI Commands

### Verify Command

Submit a contract for verification:

```bash
voyager verify --network mainnet \
  --class-hash 0x044dc2b3... \
  --contract-name MyContract
```

### Status Command

Check verification job status:

```bash
voyager status --network mainnet --job abc123def456
```

### Check Command

Check if a class is already verified:

```bash
voyager check --network mainnet --class-hash 0x044dc2b3...
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
Job has been received and is waiting in the queue.

**1 - Compiled:**
Contract compiled successfully, now comparing class hash.

**2 - CompileFailed:**
Compilation failed. Use `--verbose` flag for compiler error details.

**3 - Fail:**
Verification failed. Common causes:
- Class hash mismatch
- Build configuration mismatch
- Missing dependencies

**4 - Success:**
Verification completed successfully! Contract is now verified on the explorer.

**5 - Processing:**
Job is actively being processed by the server.

---

## Job Lifecycle

### Typical Successful Flow

```
1. Submitted (0)
      ↓
   [Job received]
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
   [Job received]
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

## Networks

### Predefined Networks

**1. Mainnet (Default)**

```bash
voyager verify --network mainnet --class-hash 0x...
voyager status --network mainnet --job abc123
voyager check --network mainnet --class-hash 0x...
```

**2. Sepolia Testnet**

```bash
voyager verify --network sepolia --class-hash 0x...
voyager status --network sepolia --job abc123
voyager check --network sepolia --class-hash 0x...
```

**3. Dev Environment**

```bash
voyager verify --network dev --class-hash 0x...
voyager status --network dev --job abc123
voyager check --network dev --class-hash 0x...
```

### Custom Endpoints

For staging/internal environments, use the `--url` flag:

```bash
voyager verify --url https://custom-api.example.com/beta \
  --class-hash 0x... \
  --contract-name MyContract
```

---

## Polling and Watch Mode

### Watch Mode

Use `--watch` to automatically poll until verification completes:

```bash
voyager verify --network mainnet \
  --class-hash 0x... \
  --contract-name MyContract \
  --watch
```

The CLI uses exponential backoff when polling:
- Initial delay: 2 seconds
- Maximum delay: 10 seconds
- Maximum total time: ~30 minutes

### Typical Timing

| Job Result | Typical Duration |
|------------|------------------|
| Success (simple contract) | 5-15 seconds |
| Success (complex contract) | 15-60 seconds |
| CompileFailed | 10-30 seconds |
| Fail (hash mismatch) | 15-45 seconds |

---

## Error Handling

### Common Errors

**Job Not Found (E008):**
```
[E008] Job 'abc123' not found

Suggestions:
  • Check that the job ID is correct
  • Verify the job was submitted successfully
  • The job may have expired from the server
```

**Class Not Found (E012):**
```
[E012] Class '0x...' not found on-chain

Suggestions:
  • Check that the class hash is correct
  • Verify the class has been declared on the network
  • Ensure you're using the correct network
```

### Verbose Mode

Use `--verbose` for detailed error information:

```bash
voyager status --network mainnet --job abc123 --verbose
```

---

## See Also

- [Error Codes](error-codes.md) - Complete list of error codes
- [Custom Endpoints Guide](../advanced/custom-endpoints.md) - Using custom API endpoints
- [Status Command](../commands/status.md) - Checking job status
- [Check Command](../commands/check.md) - Checking verification status
- [Troubleshooting](../troubleshooting/common-errors.md) - Common issues and solutions
