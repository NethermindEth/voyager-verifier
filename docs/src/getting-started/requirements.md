# Requirements

Before installing and using Voyager Verifier, ensure your system meets these requirements.

## System Requirements

### Operating System

Voyager Verifier supports:

- **Linux** (Ubuntu, Debian, Fedora, Arch, etc.)
- **macOS** (10.14 Mojave or later)
- **Windows** (via WSL2 recommended, native Windows support available)

### Hardware

Minimum requirements:

- **RAM**: 2GB minimum, 4GB recommended
- **Disk Space**: 500MB for installation and dependencies
- **Network**: Internet connection required for verification API

## Software Prerequisites

### Required

#### Scarb

Voyager Verifier requires `scarb` (Cairo/Starknet development toolchain) to be installed and available in your PATH.

**Installation:**

```bash
asdf install scarb latest
asdf global scarb latest
```

**Verify installation:**

```bash
scarb --version
```

For more details, see the [official Scarb documentation](https://docs.swmansion.com/scarb/).

#### For Cargo Installation

If installing via Cargo, you'll need:

- **Rust toolchain** (stable channel, version 1.70 or later)
- **System dependencies**:
  - **Linux**: `pkg-config`, `libssl-dev` (Ubuntu/Debian) or `openssl-devel` (Fedora/RHEL)
  - **macOS**: `pkg-config`, `openssl` (via Homebrew)
  - **Windows**: Visual Studio Build Tools

### Optional

#### Git

Required if:
- Installing the asdf plugin
- Installing from Git repository
- Contributing to development

**Installation:**
- Linux: `sudo apt-get install git` (Debian/Ubuntu)
- macOS: `brew install git` or Xcode Command Line Tools
- Windows: [Git for Windows](https://git-scm.com/download/win)

#### asdf

Only required for asdf installation method.

See [asdf installation guide](https://asdf-vm.com/guide/getting-started.html).

## Project Requirements

To verify a contract, your project must meet these requirements:

### Successful Build

Your project must build successfully with:

```bash
scarb --release build
```

> **Important**: The remote compiler uses `scarb --release build`, so all compiler configurations must be in the `[profile.release]` section of your `Scarb.toml`.

### Scarb.toml Configuration

**Minimum configuration:**

```toml
[package]
name = "my_project"
version = "0.1.0"

[dependencies]
starknet = ">=2.11.2"

[[target.starknet-contract]]
sierra = true
```

**With release profile (recommended):**

```toml
[package]
name = "my_project"
version = "0.1.0"

[dependencies]
starknet = ">=2.11.2"

[[target.starknet-contract]]
sierra = true

[profile.release.cairo]
# Add any compiler configurations needed for deployment
# For example:
# sierra-replace-ids = true
# inlining-strategy = "avoid"
```

### Deployed Contract

You must have:

- **Class Hash**: The class hash of your deployed contract
- **Contract Name**: The name of the contract to verify
- **Network**: Where the contract is deployed (mainnet, sepolia, etc.)

### License (Optional)

A valid SPDX license identifier. You can specify this:

1. In `Scarb.toml`:
   ```toml
   [package]
   license = "MIT"
   ```

2. Via CLI flag:
   ```bash
   --license MIT
   ```

3. In `.voyager.toml` config file:
   ```toml
   [voyager]
   license = "MIT"
   ```

If not specified, defaults to "All Rights Reserved".

For valid license identifiers, see [SPDX License List](https://spdx.org/licenses/).

## Supported Versions

### Cairo

The verifier is version-agnostic. Support is determined by server availability.

**Currently supported** (as of 2025):
- Cairo up to **2.11.4**
- Newer versions are added with a slight lag after release

### Scarb

The verifier supports all Scarb versions compatible with supported Cairo versions.

**Recommended**:
- Scarb 2.8.0 or later

### Dojo (for Dojo projects)

For Dojo projects:
- Dojo 0.7.0 or later
- Automatic version detection from `Scarb.toml`

## Network Requirements

### API Endpoints

The verifier needs access to:

- **Mainnet API**: `https://api.voyager.online/beta`
- **Sepolia API**: `https://sepolia-api.voyager.online/beta`
- **Custom endpoints**: If using `--url` flag

### Firewall/Proxy

If behind a corporate firewall or proxy:

- Ensure HTTPS outbound traffic is allowed to Voyager API endpoints
- Configure proxy settings if needed (via environment variables: `HTTP_PROXY`, `HTTPS_PROXY`)

## Desktop Notifications (Optional)

For desktop notification support:

- **Linux**: Requires D-Bus and a notification daemon
- **macOS**: Works out of the box
- **Windows**: Works with Windows 10/11 notification system

Can be disabled during build with `--no-default-features` if not needed.

## Verification Checklist

Before attempting verification, ensure:

- [ ] Scarb is installed and in PATH
- [ ] Your project builds with `scarb --release build`
- [ ] You have the class hash of your deployed contract
- [ ] You know your contract name
- [ ] Release profile configuration is in `Scarb.toml` if needed
- [ ] Network connectivity to Voyager API
- [ ] (Optional) License identifier is specified

## Next Steps

Once you've verified all requirements are met:

- Install voyager-verifier using [asdf](./asdf.md) or [Cargo](./cargo.md)
- Proceed to the [Quickstart Guide](./quickstart.md)

## Troubleshooting

If you're missing requirements:

- **Scarb not found**: Install from [Scarb documentation](https://docs.swmansion.com/scarb/)
- **Build fails**: Check your `Scarb.toml` configuration and dependencies
- **Network issues**: Verify firewall/proxy settings
- **Version compatibility**: Update to supported Cairo/Scarb versions

For more help, see the [Troubleshooting Guide](../troubleshooting/README.md).
