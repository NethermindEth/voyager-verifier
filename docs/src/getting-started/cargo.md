# Installation with Cargo

Cargo is Rust's package manager and build tool. If you're a Rust developer or prefer installing from source, this is the method for you.

## Prerequisites

You'll need Rust and Cargo installed on your system. If you don't have them yet:

### Install Rust

The easiest way to install Rust is using rustup:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

Follow the on-screen instructions. After installation, restart your terminal or run:

```bash
source $HOME/.cargo/env
```

Verify the installation:

```bash
rustc --version
cargo --version
```

For more details, see the [official Rust installation guide](https://www.rust-lang.org/tools/install).

## Installation

### Install from crates.io

Install the latest published version from crates.io:

```bash
cargo install voyager-verifier
```

This will download, compile, and install the `voyager` binary to `~/.cargo/bin/`.

### Install Specific Version

To install a specific version:

```bash
cargo install voyager-verifier --version 2.0.0-alpha.5
```

### Install from Git Repository

To install the latest development version directly from the GitHub repository:

```bash
cargo install --git https://github.com/NethermindEth/voyager-verifier.git
```

Install a specific branch:

```bash
cargo install --git https://github.com/NethermindEth/voyager-verifier.git --branch main
```

Install a specific commit:

```bash
cargo install --git https://github.com/NethermindEth/voyager-verifier.git --rev abc123
```

## Build Options

### Without Desktop Notifications

If you want to build without desktop notification support (reduces dependencies):

```bash
cargo install voyager-verifier --no-default-features
```

### With Specific Features

Enable specific features during installation:

```bash
# With notifications (default)
cargo install voyager-verifier --features notifications
```

## Verify Installation

After installation, verify it worked:

```bash
voyager --version
```

You should see:

```
voyager-verifier 2.0.0-alpha.5
```

Check the installation path:

```bash
which voyager
```

Typical output:

```
/home/username/.cargo/bin/voyager
```

## Updating

### Update to Latest Version

To update to the latest published version:

```bash
cargo install voyager-verifier --force
```

The `--force` flag reinstalls the package even if it's already installed.

### Update from Git

If you installed from git, re-run the install command:

```bash
cargo install --git https://github.com/NethermindEth/voyager-verifier.git --force
```

## Uninstalling

To remove voyager-verifier:

```bash
cargo uninstall voyager-verifier
```

## Building from Source

For development or customization, you can clone and build manually:

### Clone the Repository

```bash
git clone https://github.com/NethermindEth/voyager-verifier.git
cd voyager-verifier
```

### Build

Build in release mode:

```bash
cargo build --release
```

The binary will be in `target/release/voyager`.

### Run Without Installing

Run directly without installing:

```bash
cargo run -- --version
```

### Install Local Build

Install the locally built version:

```bash
cargo install --path .
```

## Troubleshooting

### Cargo Not Found

If `cargo` command is not found:

1. Ensure Rust is properly installed
2. Make sure `~/.cargo/bin` is in your PATH
3. Restart your terminal
4. Source the cargo environment: `source $HOME/.cargo/env`

### Compilation Errors

If you encounter build errors:

**Update Rust toolchain:**

```bash
rustup update stable
```

**Install required system dependencies:**

On Ubuntu/Debian:
```bash
sudo apt-get install pkg-config libssl-dev
```

On macOS:
```bash
brew install pkg-config openssl
```

On Fedora/RHEL:
```bash
sudo dnf install pkg-config openssl-devel
```

### Network Issues

If downloads fail:

1. Check your internet connection
2. Check if you're behind a proxy (configure cargo proxy settings)
3. Try using a VPN if crates.io is blocked

### Permission Errors

If you get permission errors during installation:

- Never use `sudo` with cargo install
- Ensure `~/.cargo/bin` is writable by your user
- Check that your Rust installation isn't system-wide (should be user-local)

## Environment Configuration

### Add to PATH

Ensure `~/.cargo/bin` is in your PATH. Add to your shell profile:

**Bash (`~/.bashrc`):**
```bash
export PATH="$HOME/.cargo/bin:$PATH"
```

**Zsh (`~/.zshrc`):**
```zsh
export PATH="$HOME/.cargo/bin:$PATH"
```

**Fish (`~/.config/fish/config.fish`):**
```fish
set -gx PATH $HOME/.cargo/bin $PATH
```

After editing, reload your shell configuration or restart your terminal.

## Next Steps

Now that voyager-verifier is installed, proceed to the [Quickstart Guide](./quickstart.md) to verify your first contract!
