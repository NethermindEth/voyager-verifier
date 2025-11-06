# Reference

Technical reference documentation for Voyager Verifier, including error codes, version support, file collection rules, and API endpoints.

## Reference Material

### [Error Codes](error-codes.md)
**Complete error code reference (E001-E042, E999)**

Comprehensive listing of all error codes with descriptions, causes, solutions, and examples.

- **Workspace & Package Errors** (E001-E003)
- **Verification API Errors** (E004-E009)
- **Dependency Errors** (E010-E014)
- **Contract & Target Errors** (E015-E024)
- **File System Errors** (E025-E029)
- **Class Hash Errors** (E030-E039)
- **Config File Errors** (E040-E042)
- **General Errors** (E999)

**Use when:** You encounter an error code and need detailed information.

### [Supported Versions](supported-versions.md)
**Cairo, Scarb, and Dojo version compatibility**

Version support matrix and upgrade guidance.

- **Cairo Version Support**: Server-determined, up to 2.13.1 (Oct 2025)
- **Scarb Version Support**: 1.x - 2.x
- **Dojo Version Support**: Auto-detected from Scarb.toml, up to 1.8.0 (Oct 2025)
- **Upgrade Guidance**: Step-by-step upgrade procedures

**Use when:** Planning upgrades or checking version compatibility.

### [File Collection](file-collection.md)
**What files are included/excluded in verification**

Detailed rules for file collection and validation.

- **Source Files**: .cairo files (excluding tests by default)
- **Manifest Files**: Scarb.toml, workspace manifests
- **Lock Files**: Scarb.lock (optional with `--lock-file`)
- **Test Files**: Excluded by default (`--test-files` to include)
- **File Types**: Allowed extensions and size limits (20MB)
- **Contract Detection**: How the main contract file is found

**Use when:** Understanding what will be submitted for verification.

### [API Reference](api.md)
**API endpoints, request/response formats, and job lifecycle**

Complete API documentation for developers.

- **Endpoints**: Submit verification, get status, check class
- **Request/Response Formats**: JSON schemas and examples
- **Job Status Codes**: 0-5 and their meanings
- **Job Lifecycle**: State transitions and typical timing
- **Network Endpoints**: Mainnet, Sepolia, Dev, Custom
- **Error Handling**: API error responses and recovery

**Use when:** Integrating with the API or understanding job statuses.

---

## Quick Reference Tables

### Networks

| Network | Base URL | Usage |
|---------|----------|-------|
| **Mainnet** | `https://api.voyager.online` | Production contracts |
| **Sepolia** | `https://sepolia-api.voyager.online` | Testnet contracts |
| **Dev** | `https://dev-api.voyager.online` | Development testing |
| **Custom** | User-specified | Custom deployments |

### Job Status Codes

| Code | Name | Description | Terminal |
|------|------|-------------|----------|
| `0` | Submitted | Job queued | No |
| `1` | Compiled | Compilation success | No |
| `2` | CompileFailed | Compilation failed | Yes |
| `3` | Fail | Verification failed | Yes |
| `4` | Success | Verified successfully | Yes |
| `5` | Processing | Being processed | No |

### File Types

| Type | Included | Flag Required | Max Size |
|------|----------|---------------|----------|
| Cairo source (.cairo) | ✅ Yes | None | 20MB |
| Scarb.toml | ✅ Yes | None | 20MB |
| Scarb.lock | ❌ No | `--lock-file` | 20MB |
| Test files | ❌ No | `--test-files` | 20MB |
| Documentation (.md) | ✅ If found | None | 20MB |

### Version Support

| Component | Support Model | Current |
|-----------|---------------|---------|
| Cairo | Server-determined | Up to 2.13.1 (Oct 2025) |
| Scarb | Client + Server | 1.x - 2.x |
| Dojo | Auto-detected | Up to 1.8.0 (Oct 2025) |
| Client | Semantic Versioning | v2.0.0-alpha.5 |

---

## Error Code Quick Lookup

### Most Common Errors

| Code | Error | Quick Fix |
|------|-------|-----------|
| **E005** | Module not found | Add `--test-files` if importing tests |
| **E007** | Verification failed | Check [Troubleshooting Guide](../troubleshooting/common-errors.md) |
| **E015** | Invalid contract name | Verify contract name matches `#[starknet::contract]` mod |
| **E030** | Class hash mismatch | Use `--lock-file` for reproducibility |
| **E999** | Unexpected error | Check logs with `--verbose` |

### By Category

**Workspace Issues (E001-E003):**
- Package not found
- No packages in workspace
- Workspace errors

**API Issues (E004-E009):**
- Job submission failed
- Job not found
- Verification failed

**Dependency Issues (E010-E014):**
- Resolution failures
- Missing dependencies
- Dependency conflicts

**Contract Issues (E015-E024):**
- Invalid contract names
- Target not found
- Multiple contracts found

**File Issues (E025-E029):**
- File not found
- File read errors
- Invalid file types

**Hash Issues (E030-E039):**
- Hash mismatch
- Parsing errors
- Format issues

**Config Issues (E040-E042):**
- Config file errors
- Parse failures
- Invalid settings

---

## API Endpoints

### Submit Verification

```http
POST /class-verify/{class_hash}
Content-Type: application/json

{
  "name": "MyContract",
  "contract_file": "src/contract.cairo",
  "cairo_version": "2.8.4",
  "scarb_version": "2.8.4",
  "files": { ... }
}
```

**Response:**
```json
{
  "job_id": "abc123def456"
}
```

### Get Job Status

```http
GET /class-verify/job/{job_id}
```

**Response:**
```json
{
  "job_id": "abc123def456",
  "status": 4,
  "status_description": "Success",
  "message": "Contract verified successfully"
}
```

### Check Class Exists

```http
GET /classes/{class_hash}
```

**Response:** 200 OK (exists) or 404 Not Found

---

## File Collection Rules

### Always Included

```
✅ All .cairo files in src/ (except tests)
✅ Package Scarb.toml
✅ Workspace Scarb.toml (if workspace)
✅ Documentation files (LICENSE, README.md, etc.)
```

### Optional (Requires Flags)

```
❌ Scarb.lock → Use --lock-file
❌ Test files (src/tests/) → Use --test-files
```

### Never Included

```
❌ Files outside src/ (except manifests)
❌ Test directories outside src/ (tests/, test/)
❌ Build artifacts (target/)
❌ Hidden files (.git/, .env)
❌ Unsupported file types (.yaml, .png, etc.)
```

### File Size Limits

**Maximum:** 20MB per file

**Validation:**
- File type checking (cairo, toml, lock, md, txt, json)
- Size checking (max 20MB)
- Path validation

---

## Version Compatibility

### Cairo Versions

**Supported:** Up to 2.13.1 (as of October 2025)

**Compatibility:**
- ✅ Cairo 2.13.x - Fully supported (latest)
- ✅ Cairo 2.12.x - Fully supported
- ✅ Cairo 2.11.x - Fully supported
- ✅ Cairo 2.10.x - Fully supported
- ✅ Cairo 2.9.x - Maintained
- ✅ Cairo 2.8.x - Maintained
- ⚠️ Cairo 1.x - Limited support
- 🔄 Newer versions - Check API or request via GitHub/Telegram

**Version Agnostic:** Client doesn't impose version restrictions; server determines support.

### Scarb Versions

**Recommended:** 2.8.x

**Compatibility:**
- ✅ Scarb 2.8.x - Fully tested
- ✅ Scarb 2.7.x - Stable
- ✅ Scarb 2.6.x - Supported
- ⚠️ Scarb 1.x - Limited
- ❌ Scarb 0.x - Not supported

### Dojo Support

**Detection:** Automatic from Scarb.toml

**Formats Supported:**
```toml
# Simple string
dojo = "1.7.1"

# Git tag
dojo = { tag = "v0.7.0" }

# Version table
dojo = { version = "2.0.0" }
```

**All Dojo versions** with valid Scarb.toml format are supported.

---

## Common Reference Scenarios

### Scenario 1: Error Code Lookup

**Problem:** Getting error code E005

**Steps:**
1. Go to [Error Codes](error-codes.md)
2. Find E005 in the list
3. Read cause, solutions, and examples
4. Apply suggested fix

### Scenario 2: Version Check

**Problem:** Unsure if Cairo 2.12.0 is supported

**Steps:**
1. Go to [Supported Versions](supported-versions.md)
2. Check Cairo version compatibility matrix
3. See note about server-side support
4. Test with `--dry-run` on Sepolia first

### Scenario 3: File Not Included

**Problem:** File missing from submission

**Steps:**
1. Go to [File Collection](file-collection.md)
2. Check if file type is allowed
3. Verify file location (must be in src/ or manifest)
4. Use `--dry-run` to preview collection
5. Check if flag needed (`--lock-file`, `--test-files`)

### Scenario 4: API Integration

**Problem:** Building custom verification tool

**Steps:**
1. Go to [API Reference](api.md)
2. Review endpoint documentation
3. Check request/response formats
4. Implement error handling
5. Follow polling best practices

### Scenario 5: Hash Mismatch

**Problem:** Class hash mismatch error

**Steps:**
1. Check [Error Codes](error-codes.md) E030
2. Review [File Collection](file-collection.md) for lock files
3. Use `--lock-file` flag
4. Check [Supported Versions](supported-versions.md) for compatibility
5. Verify exact versions match deployment

---

## Reference FAQs

### Q: Where can I find error code E030?

**A:** See [Error Codes](error-codes.md#e030-class-hash-mismatch) for detailed information on class hash mismatch errors.

### Q: Which files are submitted for verification?

**A:** See [File Collection](file-collection.md) for complete rules. By default: all .cairo files in src/ (except tests) + Scarb.toml + workspace manifest (if applicable).

### Q: What Cairo version should I use?

**A:** See [Supported Versions](supported-versions.md#cairo-version-support). As of 2025, Cairo up to 2.11.4 is fully supported. Newer versions are added with a slight lag.

### Q: How do I check job status via API?

**A:** See [API Reference](api.md#2-get-job-status) for the GET `/class-verify/job/{job_id}` endpoint documentation.

### Q: What does status code 2 mean?

**A:** See [API Reference](api.md#job-status-codes). Status 2 = CompileFailed (compilation error, terminal state).

### Q: Are test files included by default?

**A:** No. See [File Collection](file-collection.md#test-files). Use `--test-files` flag to include them.

### Q: How long does verification take?

**A:** See [API Reference](api.md#typical-timing). Simple contracts: 5-15 seconds. Complex contracts: 15-60 seconds.

### Q: Can I use a custom API endpoint?

**A:** Yes. See [API Reference](api.md#custom-endpoints) for using `--network custom --endpoint <URL>`.

---

## Reference Navigation

### By Topic

**Errors & Troubleshooting:**
- [Error Codes](error-codes.md) - Complete error reference
- [Common Errors](../troubleshooting/common-errors.md) - Solutions for frequent issues
- [Debugging](../troubleshooting/debugging.md) - Systematic troubleshooting

**Versions & Compatibility:**
- [Supported Versions](supported-versions.md) - Version matrices
- [Upgrade Guide](supported-versions.md#version-upgrade-guide) - How to upgrade

**Files & Collection:**
- [File Collection](file-collection.md) - What gets included
- [Test Files](../advanced/test-files.md) - Using `--test-files`
- [Lock Files](../advanced/lock-files.md) - Using `--lock-file`

**API & Integration:**
- [API Reference](api.md) - Complete API docs
- [Custom Endpoints](../advanced/custom-endpoints.md) - Custom deployments

### By Task

**I want to...**

**...understand an error code**
→ [Error Codes](error-codes.md)

**...check version compatibility**
→ [Supported Versions](supported-versions.md)

**...know what files are submitted**
→ [File Collection](file-collection.md)

**...integrate with the API**
→ [API Reference](api.md)

**...fix a verification failure**
→ [Common Errors](../troubleshooting/common-errors.md)

**...upgrade Cairo/Scarb**
→ [Version Upgrade Guide](supported-versions.md#version-upgrade-guide)

**...debug compilation errors**
→ [Debugging](../troubleshooting/debugging.md)

---

## See Also

### Related Documentation

- [Getting Started](../getting-started/README.md) - Initial setup and first verification
- [Core Features](../core-features/README.md) - Essential commands and workflows
- [Advanced Features](../advanced/README.md) - Advanced usage patterns
- [Troubleshooting](../troubleshooting/README.md) - Problem-solving guides

### External Resources

- **Cairo Documentation**: https://book.cairo-lang.org
- **Scarb Documentation**: https://docs.swmansion.com/scarb
- **Dojo Documentation**: https://book.dojoengine.org
- **Starknet Documentation**: https://docs.starknet.io
- **Voyager Explorer**: https://voyager.online

### Community Support

- **Telegram**: https://t.me/StarknetVoyager
- **GitHub Issues**: https://github.com/NethermindEth/voyager-verifier/issues
- **GitHub Releases**: https://github.com/NethermindEth/voyager-verifier/releases
