# Installation

Voyager Verifier can be installed using **asdf** for released binaries, or built from source with Cargo.

## Choose Your Installation Method

### asdf (Recommended)

asdf is a version manager that simplifies installation and allows you to manage multiple versions of voyager-verifier. This is the recommended approach for most users.

**Best for:**
- Users who want easy version management
- Teams needing consistent tooling across environments
- Users familiar with version managers like nvm, rbenv, etc.

[Continue to asdf installation →](./asdf.md)

### Cargo from Source

Build directly from source using Cargo. This method is ideal if you're already familiar with the Rust ecosystem or want the latest development version.

**Best for:**
- Rust developers
- Users who want to build from source
- Those needing the absolute latest features

[Continue to Cargo installation →](./cargo.md)

## System Requirements

Before installing, make sure your system meets the [requirements](./requirements.md).

## After Installation

Once installed, verify the installation by running:

```bash
voyager --version
```

You should see output similar to:

```
voyager-verifier 2.0.1
```

## Next Steps

After successful installation, head to the [Quickstart Guide](./quickstart.md) to verify your first contract!

## Troubleshooting Installation

If you encounter issues during installation:

- **asdf users**: Ensure asdf is properly installed and configured in your shell
- **Cargo source builds**: Ensure you have the latest stable Rust toolchain (`rustup update`)
- **Build errors**: Check that you have required system dependencies (OpenSSL, pkg-config)

For more help, see the [Troubleshooting Guide](../troubleshooting/README.md).
