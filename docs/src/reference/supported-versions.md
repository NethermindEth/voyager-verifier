# Supported Versions

This reference documents version compatibility for Voyager Verifier, including Cairo, Scarb, and Dojo version support.

## Quick Reference

| Component | Support Model | Current Support | Notes |
|-----------|---------------|-----------------|-------|
| **Cairo/Scarb** | Server-determined | Up to 2.13.1 (Oct 2025) | Version agnostic client |
| **Dojo** | Auto-detected | Up to 1.8.0 (Oct 2025) | Extracted from dependencies |
| **Client** | Independent versioning | v2.0.0-alpha.5 | Update via `asdf` |

**Note:** Voyager version and supported toolchain versions are independent. The Voyager team continuously works to support the latest Scarb and Dojo releases.

---

## Cairo Version Support

### Version-Agnostic Design

**Voyager Verifier is version-agnostic** - it does not impose Cairo version restrictions. Version support is determined by the Voyager API server.

```toml
# Your Scarb.toml
[package]
name = "my_contract"
version = "0.1.0"

[dependencies]
starknet = "2.13.1"  # Server determines if supported
```

### Current Support (October 2025)

As of October 2025, the Voyager API supports:
- **Cairo/Scarb 2.x**: Full support up to **2.13.1**
- **Newer versions**: The Voyager team works to keep up with Scarb releases
- **Older versions**: Cairo 1.x and 2.x versions maintained

**If you need a newer version:**
1. Check if it's already supported by testing with `--dry-run`
2. If not available, open an issue on [GitHub](https://github.com/NethermindEth/voyager-verifier/issues)
3. Reach out on [Telegram](https://t.me/StarknetVoyager) for faster response

**Check Current Support:**

```bash
# The API will inform you if your version is unsupported
voyager verify --network mainnet \
  --class-hash 0x044dc2b3... \
  --contract-name MyContract

# If version is unsupported, you'll see:
# Error: Cairo version 2.99.0 is not supported by the API
```

### Version Compatibility Matrix

| Cairo/Scarb Version | Support Status | Notes |
|---------------------|----------------|-------|
| 2.13.x | ✅ Fully Supported | Latest stable (as of Oct 2025) |
| 2.12.x | ✅ Fully Supported | Previous stable |
| 2.11.x | ✅ Fully Supported | Stable |
| 2.10.x | ✅ Fully Supported | Stable |
| 2.9.x | ✅ Fully Supported | Maintained |
| 2.8.x | ✅ Fully Supported | Maintained |
| 2.7.x and older | ✅ Maintained | Legacy support |
| 1.x | ⚠️ Limited Support | Cairo 1.0 era |
| 2.14.x+ | 🔄 Check API / Request | Open GitHub issue if needed |

**Note:** Version support updates are managed server-side. The client does not require updates for new Cairo versions. The Voyager team continuously works to keep up with the latest Scarb releases.

---

## Scarb Version Support

### Client Requirements

Voyager Verifier requires **Scarb** to be installed and accessible:

```bash
# Check your Scarb version
scarb --version

# Example output:
# scarb 2.8.4 (ab1234cd 2024-12-15)
# cairo: 2.8.4 (https://crates.io/crates/cairo-lang-compiler/2.8.4)
```

### Compatible Versions

| Scarb Version | Support Status | Notes |
|---------------|----------------|-------|
| 2.13.x | ✅ Fully Supported | Latest (as of Oct 2025) |
| 2.12.x | ✅ Fully Supported | Previous stable |
| 2.11.x | ✅ Fully Supported | Stable |
| 2.10.x | ✅ Fully Supported | Stable |
| 2.9.x | ✅ Fully Supported | Maintained |
| 2.8.x | ✅ Fully Supported | Maintained |
| 2.7.x and older | ✅ Maintained | Legacy support |
| 1.x | ⚠️ Limited | Legacy |
| 0.x | ❌ Not Supported | Too old |

### Version Detection

The tool automatically detects your Scarb version:

```bash
# Voyager reads from scarb metadata
voyager verify --network mainnet \
  --class-hash 0x044dc2b3... \
  --contract-name MyContract

# Output includes:
# 📦 Using Scarb 2.8.4
# 🏗️  Using Cairo 2.8.4
```

---

## Dojo Version Support

### Auto-Detection

For **Dojo projects**, Voyager automatically detects the Dojo version from your `Scarb.toml`:

```toml
# Scarb.toml
[dependencies]
dojo = "1.7.1"  # Simple string format

# Or:
[dependencies]
dojo = { tag = "v0.7.0" }  # Git tag format

# Or:
[dependencies]
dojo = { version = "2.0.0" }  # Table format
```

### Detection Behavior

**Voyager searches for Dojo version in this order:**

1. **Package Scarb.toml** (if in workspace)
2. **Workspace root Scarb.toml** (fallback)

```bash
# Voyager will log:
🔍 Checking for dojo version in package Scarb.toml: /path/to/package/Scarb.toml
✅ Found dojo version in package Scarb.toml: 1.7.1
```

### Supported Dojo Versions

| Dojo Version | Support Status | Project Type |
|--------------|----------------|--------------|
| 1.8.x | ✅ Fully Supported | Latest (as of Oct 2025) |
| 1.7.x | ✅ Fully Supported | sozo build |
| 1.6.x and older | ✅ Supported | sozo build |
| 0.7.x | ✅ Supported | sozo build |
| 0.6.x and older | ⚠️ Limited | May work |

**Note:** The Voyager team works to keep up with Dojo releases. If you need support for a newer version, open a [GitHub issue](https://github.com/NethermindEth/voyager-verifier/issues) or reach out on [Telegram](https://t.me/StarknetVoyager).

### Manual Project Type Selection

If auto-detection fails, specify manually:

```bash
# Specify Dojo project explicitly
voyager verify --network mainnet \
  --class-hash 0x044dc2b3... \
  --contract-name MyContract \
  --project-type dojo

# Or use interactive prompt:
voyager verify --network mainnet \
  --class-hash 0x044dc2b3... \
  --contract-name MyContract \
  --project-type auto
```

---

## Version Upgrade Guide

### Upgrading Cairo/Scarb

**Check Compatibility First:**

1. **Review Release Notes**: https://github.com/starkware-libs/cairo/releases
2. **Test Locally**: Ensure your project builds with the new version
3. **Verify on Testnet**: Test verification on Sepolia before mainnet

**Upgrade Steps:**

```bash
# 1. Install new Scarb version (includes Cairo) via asdf
asdf install scarb latest
asdf global scarb latest

# Verify installation
scarb --version

# 2. Update Scarb.toml
# Edit your Scarb.toml:
[dependencies]
starknet = "2.13.1"  # Update to new version

# 3. Verify build works
scarb clean
scarb build --release

# 4. Test verification
voyager verify --network sepolia \
  --class-hash 0x... \
  --contract-name MyContract

# 5. If successful, proceed with mainnet
voyager verify --network mainnet \
  --class-hash 0x... \
  --contract-name MyContract
```

### Upgrading Dojo

**Upgrade Dojo Projects:**

```bash
# 1. Update Dojo dependency in Scarb.toml
[dependencies]
dojo = "2.0.0"  # New version

# 2. Update sozo
curl -L https://install.dojoengine.org | bash
dojoup

# 3. Rebuild project
sozo clean
sozo build

# 4. Verify detection works
voyager verify --network sepolia \
  --class-hash 0x... \
  --contract-name MyContract \
  --project-type dojo --dry-run

# Should see:
# ✅ Successfully extracted Dojo version: 2.0.0
# 🔨 Build tool: sozo
```

### Upgrading Voyager Client

**Keep the client updated using asdf:**

```bash
# Check current version
voyager --version

# Update to latest version via asdf
asdf install voyager latest

# Set as global default
asdf global voyager latest

# Verify update
voyager --version
```

**Note:** Voyager version and supported toolchain (Cairo/Scarb/Dojo) versions are independent. You can update Voyager without worrying about toolchain compatibility - version support is managed server-side.

**Alternative: Download from GitHub**

Latest releases are also available at:
https://github.com/NethermindEth/voyager-verifier/releases

---

## Version-Related Issues

### Issue 1: Cairo Version Not Supported

**Problem:**
```
Error: Cairo version 2.99.0 is not supported by the API
```

**Solutions:**

1. **Request Support**: The Voyager team works to keep up with Scarb releases
   - Open a [GitHub issue](https://github.com/NethermindEth/voyager-verifier/issues) requesting the version
   - Reach out on [Telegram](https://t.me/StarknetVoyager) for faster response

2. **Test with dry-run**: Check if the version is already supported
   ```bash
   voyager verify --dry-run --network sepolia \
     --class-hash 0x044dc2b3... \
     --contract-name MyContract
   ```

3. **Use latest supported version** (temporary):
   ```toml
   # Scarb.toml
   [dependencies]
   starknet = "2.13.1"  # Use latest supported (as of Oct 2025)
   ```

### Issue 2: Scarb Metadata Error

**Problem:**
```
Error: Failed to parse scarb metadata
```

**Solutions:**

1. **Update Scarb**:
   ```bash
   asdf install scarb latest
   asdf global scarb latest
   ```

2. **Verify Scarb Works**:
   ```bash
   scarb metadata --format-version 1
   ```

3. **Clean and Rebuild**:
   ```bash
   scarb clean
   scarb build
   ```

### Issue 3: Dojo Version Not Detected

**Problem:**
```
⚠️  Could not extract Dojo version from Scarb.toml - proceeding without version
```

**Solutions:**

1. **Check Dependency Format**:
   ```toml
   # ✅ Correct formats:
   [dependencies]
   dojo = "1.7.1"
   # OR
   dojo = { version = "1.7.1" }
   # OR
   dojo = { tag = "v0.7.0" }
   ```

2. **Specify Project Type Explicitly**:
   ```bash
   voyager verify --project-type dojo ...
   ```

3. **Verify Dojo is Installed**:
   ```bash
   sozo --version
   ```

### Issue 4: Version Mismatch

**Problem:**
```
Error: Class hash mismatch
```

**Solution: Use Lock File for Reproducibility:**

```bash
# Include Scarb.lock to ensure exact dependency versions
voyager verify --network mainnet \
  --class-hash 0x044dc2b3... \
  --contract-name MyContract \
  --lock-file

# Commit lock file to version control
git add Scarb.lock
git commit -m "Add lock file for reproducible builds"
```

---

## Version Checking Tools

### Check All Versions

```bash
#!/bin/bash
# version-check.sh - Check all component versions

echo "=== Voyager Verifier Version Check ==="
echo

echo "📦 Voyager Client:"
voyager --version
echo

echo "🏗️  Scarb:"
scarb --version
echo

echo "🔧 Cairo:"
scarb --version | grep cairo
echo

echo "🎮 Sozo (if installed):"
sozo --version 2>/dev/null || echo "Not installed"
echo

echo "📄 Project Starknet Version (from Scarb.toml):"
grep "starknet = " Scarb.toml | head -1
echo

echo "🔗 Dojo Version (from Scarb.toml):"
grep "dojo = " Scarb.toml || echo "Not a Dojo project"
```

### Version Compatibility Check

```bash
# Quick compatibility check
voyager verify --dry-run \
  --network mainnet \
  --class-hash 0x044dc2b3... \
  --contract-name MyContract \
  --verbose

# Dry-run will validate versions without submitting
```

---

## API Version Support

### Server-Side Version Management

The Voyager API manages version support server-side:

**Version Endpoints:**

```bash
# Check API health (implicit version check)
curl https://api.voyager.online/api-docs

# Verify endpoint (will reject unsupported versions)
curl -X POST https://api.voyager.online/verify \
  -H "Content-Type: application/json" \
  -d '{...}'
```

### Version Update Timeline

**Typical Timeline for New Cairo Releases:**

1. **Day 0**: Cairo version released by Starkware
2. **Days 1-7**: Testing and integration
3. **Week 2**: Voyager API updated with support
4. **Ongoing**: Version available for verification

**Stay Updated:**

- **GitHub Releases**: https://github.com/NethermindEth/voyager-verifier/releases
- **Telegram**: https://t.me/StarknetVoyager
- **API Documentation**: Updated with supported versions

---

## Best Practices

### ✅ Version Management Best Practices

1. **Pin Cairo Versions in Production**
   ```toml
   # Scarb.toml - Use specific versions
   [dependencies]
   starknet = "2.8.4"  # Not "^2.8" or ">=2.8"
   ```

2. **Commit Lock Files**
   ```bash
   git add Scarb.lock
   ```

3. **Test Before Upgrading**
   ```bash
   # Always test on Sepolia first
   voyager verify --network sepolia ...
   ```

4. **Keep Voyager Updated**
   ```bash
   # Update regularly for bug fixes
   asdf install voyager latest
   asdf global voyager latest
   ```

   **Note:** Voyager version is independent of toolchain versions - you can safely update without compatibility concerns.

5. **Document Your Versions**
   ```bash
   # Add to your README.md:
   # Cairo: 2.8.4
   # Scarb: 2.8.4
   # Dojo: 1.7.1 (if applicable)
   ```

6. **Monitor API Changes**
   - Watch for announcements on Telegram
   - Review GitHub release notes
   - Test periodically on testnet

---

## Version FAQ

### Q: What Cairo version should I use?

**A:** Use the latest stable version that's supported by the API. As of October 2025, Cairo/Scarb 2.13.1 is fully supported. Check the [compatibility matrix](#cairo-version-support) above.

### Q: Do I need to upgrade Voyager for new Cairo versions?

**A:** No. Voyager version and toolchain versions are independent. Version support is determined by the API server, not the client. You can safely update Voyager without worrying about Cairo/Scarb compatibility.

### Q: How do I request support for a newer version?

**A:** If a newer version of Cairo/Scarb or Dojo is not yet supported:
1. Test with `--dry-run` first to confirm it's unsupported
2. Open a [GitHub issue](https://github.com/NethermindEth/voyager-verifier/issues)
3. Reach out on [Telegram](https://t.me/StarknetVoyager) for faster response

The Voyager team continuously works to support the latest releases.

### Q: Can I use different Cairo versions in a workspace?

**A:** Yes, each package in a workspace can specify its own `starknet` dependency version in its `Scarb.toml`.

### Q: How do I check if my version is supported?

**A:** Run a verification with `--dry-run` to check compatibility without submitting:
```bash
voyager verify --dry-run ...
```

### Q: What if my Dojo version isn't detected?

**A:** Manually specify `--project-type dojo`. The version is optional; verification works without it.

### Q: Can I verify contracts built with older Cairo versions?

**A:** Yes, the API maintains support for older Cairo versions. Version 1.x and 2.x contracts can be verified.

---

## See Also

- [Error Codes](error-codes.md) - Version-related error codes (E010-E014)
- [File Collection](file-collection.md) - Which files are included in verification
- [Common Errors](../troubleshooting/common-errors.md) - Version-related issues
- [Cairo Documentation](https://book.cairo-lang.org) - Official Cairo docs
- [Scarb Documentation](https://docs.swmansion.com/scarb) - Scarb documentation
- [Dojo Documentation](https://book.dojoengine.org) - Dojo documentation
