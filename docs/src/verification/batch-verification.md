# Batch Verification

Batch verification allows you to verify multiple contracts in a single command by defining them in your `.voyager.toml` configuration file. This is ideal for multi-contract deployments, workspace projects, and protocol suites.

## Overview

Instead of running separate `verify` commands for each contract, batch verification:

- Submits multiple contracts sequentially
- Tracks all jobs with individual progress
- Continues on error by default (optional fail-fast mode)
- Supports rate limiting with configurable delays
- Provides comprehensive summary output
- Integrates with watch mode for real-time monitoring

## Setting Up Batch Verification

### 1. Create Configuration File

Create or edit `.voyager.toml` in your project root:

```toml
[voyager]
network = "mainnet"
license = "MIT"
watch = true

# Define contracts to verify
[[contracts]]
class-hash = "0x044dc2b3239382230d8b1e943df23b96f52eebcac93efe6e8bde92f9a2f1da18"
contract-name = "MyToken"

[[contracts]]
class-hash = "0x055dc2b3239382230d8b1e943df23b96f52eebcac93efe6e8bde92f9a2f1da19"
contract-name = "MyNFT"

[[contracts]]
class-hash = "0x066dc2b3239382230d8b1e943df23b96f52eebcac93efe6e8bde92f9a2f1da20"
contract-name = "MyMarketplace"
```

### 2. Run Batch Verification

Simply run the verify command without additional arguments:

```bash
voyager verify
```

The tool automatically detects batch mode when the `[[contracts]]` array is present.

## Configuration Format

### Basic Contract Definition

Minimum required fields:

```toml
[[contracts]]
class-hash = "0x044dc2b3..."
contract-name = "MyToken"
```

### With Package (Workspace Projects)

For workspace projects with multiple packages:

```toml
[[contracts]]
class-hash = "0x044dc2b3..."
contract-name = "MyToken"
package = "token"
```

If `package` is omitted, the tool will:
1. Use `workspace.default-package` if configured
2. Auto-detect the package
3. Fail with clear error if ambiguous

### Complete Example

```toml
[voyager]
network = "mainnet"
license = "MIT"
watch = true
lock-file = true
verbose = false

[workspace]
default-package = "contracts"  # Fallback for contracts without package

[[contracts]]
class-hash = "0x044dc2b3239382230d8b1e943df23b96f52eebcac93efe6e8bde92f9a2f1da18"
contract-name = "Token"
package = "token"  # Override default-package

[[contracts]]
class-hash = "0x055dc2b3239382230d8b1e943df23b96f52eebcac93efe6e8bde92f9a2f1da19"
contract-name = "NFT"
package = "nft"

[[contracts]]
class-hash = "0x066dc2b3239382230d8b1e943df23b96f52eebcac93efe6e8bde92f9a2f1da20"
contract-name = "Marketplace"
# Uses default-package: "contracts"
```

## Batch Options

### Watch Mode

Monitor all verifications until completion:

```bash
voyager verify --watch
```

**Behavior:**
- Submits all contracts first
- Then monitors all jobs concurrently
- Shows single-line status updates
- Displays final summary when all complete

**Output:**
```
⏳ Watching 3 verification job(s)...

  ✓ 2 Succeeded | ⏳ 1 Pending | ✗ 0 Failed
```

### Fail-Fast Mode

Stop batch verification on first failure:

```bash
voyager verify --fail-fast
```

**Default behavior** (without `--fail-fast`):
- Continues with remaining contracts if one fails
- Shows all results in summary

**With `--fail-fast`:**
- Stops immediately when a contract verification fails
- Remaining contracts are not submitted
- Useful for critical deployment pipelines

### Batch Delay

Add delay between contract submissions for rate limiting:

```bash
voyager verify --batch-delay 5
```

**Use cases:**
- API rate limiting
- Server load management
- Staggered deployments

**Example with 10-second delay:**
```bash
voyager verify --batch-delay 10 --watch
```

### Combined Options

```bash
voyager verify --watch --batch-delay 5 --verbose
```

## Output Format

### Submission Phase

As each contract is submitted:

```
[1/3] Verifying: MyToken
  ✓ Submitted - Job ID: abc-123-def

[2/3] Verifying: MyNFT
  ⏳ Waiting 5 seconds before next submission...
  ✓ Submitted - Job ID: ghi-456-jkl

[3/3] Verifying: MyMarketplace
  ✓ Submitted - Job ID: mno-789-pqr
```

### Summary Output

After all submissions:

```
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
  ⏳ Submitted MyToken (Job: abc-123-def)
  ⏳ Submitted MyNFT (Job: ghi-456-jkl)
  ⏳ Submitted MyMarketplace (Job: mno-789-pqr)
```

### Watch Mode Output

With `--watch`, live updates during monitoring:

```
⏳ Watching 3 verification job(s)...

  ✓ 1 Succeeded | ⏳ 2 Pending | ✗ 0 Failed

[Updates every 2 seconds...]

  ✓ 2 Succeeded | ⏳ 1 Pending | ✗ 0 Failed

[Final state...]

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
  ✓ Success MyToken (Job: abc-123-def)
  ✓ Success MyNFT (Job: ghi-456-jkl)
  ✓ Success MyMarketplace (Job: mno-789-pqr)
```

### Error Output

If submissions fail:

```
[1/3] Verifying: MyToken
  ✗ Failed - Error: Invalid class hash format

[2/3] Verifying: MyNFT
  ✓ Submitted - Job ID: ghi-456-jkl

[3/3] Verifying: MyMarketplace
  ✓ Submitted - Job ID: mno-789-pqr

════════════════════════════════════════════════════════
Batch Verification Summary
════════════════════════════════════════════════════════
Total contracts:  3
Submitted:        2
Succeeded:        0
Failed:           1
Pending:          2
════════════════════════════════════════════════════════

Contract Details:
  ✗ Failed MyToken - Invalid class hash format
  ⏳ Submitted MyNFT (Job: ghi-456-jkl)
  ⏳ Submitted MyMarketplace (Job: mno-789-pqr)
```

## Use Cases

### Multi-Contract Workspace

Verify all contracts in a workspace project:

```toml
[voyager]
network = "mainnet"
license = "MIT"
watch = true

[workspace]
default-package = "contracts"

[[contracts]]
class-hash = "0x123..."
contract-name = "ERC20Token"

[[contracts]]
class-hash = "0x456..."
contract-name = "ERC721NFT"

[[contracts]]
class-hash = "0x789..."
contract-name = "Marketplace"
```

**Run:**
```bash
voyager verify --watch
```

### Protocol Suite Deployment

Deploy an entire protocol with multiple components:

```toml
[voyager]
network = "mainnet"
license = "Apache-2.0"
watch = true
lock-file = true

[[contracts]]
class-hash = "0xabc..."
contract-name = "CoreProtocol"
package = "core"

[[contracts]]
class-hash = "0xdef..."
contract-name = "GovernanceModule"
package = "governance"

[[contracts]]
class-hash = "0x012..."
contract-name = "TreasuryModule"
package = "treasury"

[[contracts]]
class-hash = "0x345..."
contract-name = "StakingModule"
package = "staking"
```

**Run:**
```bash
voyager verify --watch --batch-delay 3
```

### Rate-Limited Deployment

For APIs with strict rate limits:

```toml
[voyager]
network = "mainnet"
license = "MIT"

[[contracts]]
class-hash = "0x111..."
contract-name = "Contract1"

[[contracts]]
class-hash = "0x222..."
contract-name = "Contract2"

[[contracts]]
class-hash = "0x333..."
contract-name = "Contract3"
```

**Run with 10-second delays:**
```bash
voyager verify --batch-delay 10 --watch
```

### CI/CD Pipeline

Automated verification without blocking:

```toml
[voyager]
network = "mainnet"
license = "MIT"
watch = false  # Don't block CI
verbose = true

[[contracts]]
class-hash = "0xaaa..."
contract-name = "ProductionContract"
```

**Run:**
```bash
voyager verify --format json > results.json
```

## Important Notes

### Automatic Detection

Batch mode is automatically enabled when:
- `[[contracts]]` array exists in `.voyager.toml`
- No `--class-hash` or `--contract-name` arguments provided

### Incompatible Flags

You **cannot** use these flags with batch mode:
- `--class-hash` - Conflicts with config-defined hashes
- `--contract-name` - Conflicts with config-defined names
- `--wizard` - Wizard is for single-contract verification

**Error example:**
```bash
voyager verify --class-hash 0x123... --contract-name MyToken
# Error: Cannot use --class-hash with batch mode. Remove class-hash from command or [[contracts]] from config.
```

### Shared Settings

All contracts in a batch use the same settings from `[voyager]` section:
- Network
- License
- Lock file inclusion
- Test file inclusion
- Verbose mode
- Project type

**Individual package** can be specified per contract in the `[[contracts]]` array.

### Error Handling

**Default (continue-on-error):**
- Failed submissions don't stop the batch
- All contracts are attempted
- Summary shows all results

**With `--fail-fast`:**
- First failure stops the batch
- Remaining contracts are skipped
- Summary shows partial results

### History Tracking

All batch verifications are automatically tracked in the history database:

```bash
# View batch verification history
voyager history list --limit 10

# Check specific job from batch
voyager history status --job abc-123-def
```

## Troubleshooting

### Config File Not Found

```
Error: No configuration file found
```

**Solution:** Create `.voyager.toml` in project root or parent directory.

### No Contracts Defined

```
Error: No contracts defined in configuration file
```

**Solution:** Add `[[contracts]]` array to `.voyager.toml`:

```toml
[[contracts]]
class-hash = "0x..."
contract-name = "MyContract"
```

### Network Not Specified

```
Error: Network must be specified (--network or --url) or configured in .voyager.toml
```

**Solution:** Add network to config:

```toml
[voyager]
network = "mainnet"
```

### Package Ambiguity

```
Error: Multiple packages found. Please specify --package or set workspace.default-package
```

**Solution:** Set default package or specify per contract:

```toml
[workspace]
default-package = "my_package"

# Or specify per contract
[[contracts]]
class-hash = "0x..."
contract-name = "MyContract"
package = "specific_package"
```

### Partial Submission Failure

Some contracts submitted, others failed:

**Solution:** Check the summary output for specific errors:

```bash
# Use verbose mode to see full errors
voyager verify --verbose
```

## Best Practices

### 1. Use Watch Mode

Always use `--watch` for batch verifications to see final results:

```bash
voyager verify --watch
```

### 2. Add Rate Limiting

For large batches, add delays to avoid overwhelming the API:

```bash
voyager verify --batch-delay 5
```

### 3. Enable Verbose for CI/CD

In automated pipelines, enable verbose mode:

```toml
[voyager]
verbose = true
watch = false
```

### 4. Group by Package

For workspaces, organize contracts by package:

```toml
[[contracts]]
class-hash = "0x..."
contract-name = "CoreToken"
package = "core"

[[contracts]]
class-hash = "0x..."
contract-name = "CoreGovernance"
package = "core"

[[contracts]]
class-hash = "0x..."
contract-name = "UtilsHelper"
package = "utils"
```

### 5. Use Fail-Fast for Critical Deployments

When order matters:

```bash
voyager verify --fail-fast
```

### 6. Version Control Config

Commit `.voyager.toml` to share batch configurations:

```bash
git add .voyager.toml
git commit -m "Add batch verification config"
```

## Scripting Examples

### Bash Script

```bash
#!/bin/bash

echo "Starting batch verification..."

if voyager verify --watch --batch-delay 5; then
    echo "✓ All verifications succeeded"
    exit 0
else
    echo "✗ Some verifications failed"
    voyager history list --status fail --limit 5
    exit 1
fi
```

### CI/CD Integration (GitHub Actions)

```yaml
- name: Verify Contracts
  run: |
    voyager verify --watch --format json > results.json

- name: Check Results
  run: |
    FAILED=$(jq '.failed' results.json)
    if [ "$FAILED" -gt 0 ]; then
      echo "Verification failed for $FAILED contract(s)"
      exit 1
    fi
```

## See Also

- [verify command reference](../commands/verify.md) - Complete verify command documentation
- [Configuration file](../configuration/config-file.md) - Configuration file reference
- [Watch mode](./watch-mode.md) - Watch mode details
- [History tracking](../history/README.md) - History management
- [CI/CD integration](../advanced/ci-cd.md) - CI/CD examples