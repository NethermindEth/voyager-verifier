# Check Command

The `check` command allows you to verify if a contract class is already verified on Voyager.

## Basic Usage

```bash
voyager check --network mainnet --class-hash 0x044dc2b3239382230d8b1e943df23b96f52eebcac93efe6e8bde92f9a2f1da18
```

## Options

| Option | Short | Description |
|--------|-------|-------------|
| `--network` | | Network to check (mainnet, sepolia, dev) |
| `--url` | | Custom API endpoint URL |
| `--class-hash` | | Class hash to check (0x-prefixed hex) |
| `--json` | `-j` | Output result as JSON |
| `--verbose` | `-v` | Show detailed error messages |

## Examples

### Check on Mainnet

```bash
voyager check --network mainnet \
  --class-hash 0x044dc2b3239382230d8b1e943df23b96f52eebcac93efe6e8bde92f9a2f1da18
```

**Output (Verified):**
```
✓ Class 0x044dc2b3... is verified
  Name: MyContract
  Version: 0.1.0
  License: MIT
  Contract file: src/lib.cairo
  Verified: 2025-01-15 10:30:45 UTC
```

**Output (Not Verified):**
```
✗ Class 0x044dc2b3... is not verified
```

**Output (Not Found):**
```
! Class 0x044dc2b3... not found on-chain
```

### Check on Sepolia

```bash
voyager check --network sepolia \
  --class-hash 0x044dc2b3239382230d8b1e943df23b96f52eebcac93efe6e8bde92f9a2f1da18
```

### JSON Output

For programmatic use, output as JSON:

```bash
voyager check --network mainnet \
  --class-hash 0x044dc2b3... \
  --json
```

**Output:**
```json
{
  "verified": true,
  "class_hash": "0x044dc2b3...",
  "name": "MyContract",
  "version": "0.1.0",
  "license": "MIT",
  "verified_timestamp": 1705315845.0,
  "contract_file": "src/lib.cairo"
}
```

### Using Custom URL

```bash
voyager check --url https://custom-api.example.com/beta \
  --class-hash 0x044dc2b3...
```

## Use Cases

### Pre-verification Check

Before submitting a verification request, check if the class is already verified:

```bash
# Check first
voyager check --network mainnet --class-hash 0x044dc2b3...

# If not verified, submit verification
voyager verify --network mainnet \
  --class-hash 0x044dc2b3... \
  --contract-name MyContract
```

### CI/CD Integration

Use in scripts to conditionally verify:

```bash
#!/bin/bash

CLASS_HASH="0x044dc2b3..."

# Check if already verified
if voyager check --network mainnet --class-hash $CLASS_HASH --json | jq -e '.verified' > /dev/null 2>&1; then
  echo "Contract already verified"
else
  echo "Submitting for verification..."
  voyager verify --network mainnet \
    --class-hash $CLASS_HASH \
    --contract-name MyContract \
    --watch
fi
```

### Batch Verification Status

Check multiple classes:

```bash
#!/bin/bash

CLASS_HASHES=(
  "0x044dc2b3..."
  "0x123abc..."
  "0x456def..."
)

for hash in "${CLASS_HASHES[@]}"; do
  echo "Checking $hash..."
  voyager check --network mainnet --class-hash $hash
done
```

## Response Fields

When a class is verified, the following information is returned:

| Field | Description |
|-------|-------------|
| `verified` | Whether the class is verified (true/false) |
| `class_hash` | The class hash that was checked |
| `name` | Contract name (if verified) |
| `version` | Package version (if verified) |
| `license` | SPDX license identifier (if verified) |
| `verified_timestamp` | Unix timestamp of verification (if verified) |
| `contract_file` | Main contract file path (if verified) |

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success (class found, verified or not) |
| 1 | Class not found on-chain |
| Non-zero | Other error (network failure, etc.) |

## Configuration File

The check command supports configuration via `.voyager.toml`:

```toml
[voyager]
network = "mainnet"
verbose = true
```

Then simply run:

```bash
voyager check --class-hash 0x044dc2b3...
```

## See Also

- [Verify Command](verify.md) - Submit contracts for verification
- [Status Command](status.md) - Check verification job status
- [Configuration](../configuration/config-file.md) - Configuration file reference
