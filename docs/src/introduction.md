# Introduction

Welcome to the Voyager Verifier documentation! This tool is your gateway to verifying Starknet smart contracts on the [Voyager block explorer](https://voyager.online).

## What is Voyager Verifier?

Voyager Verifier is a command-line tool that allows developers to verify their Starknet contract classes on the Voyager block explorer. Once verified, your contracts will display a verified badge on Voyager, allowing users to view and audit the source code directly in the explorer.

## Why Verify Your Contracts?

Contract verification provides several important benefits:

- **Transparency**: Users can audit the source code of contracts they interact with
- **Trust**: Verified contracts build confidence in your project
- **Debugging**: Easier debugging with readable source code in the explorer
- **Community Standards**: Following best practices in the Starknet ecosystem

## Key Features

### Multiple Verification Methods
- **Interactive Wizard** - Guided step-by-step verification for newcomers
- **Command Line** - Direct CLI commands for experienced users
- **Batch Verification** - Verify multiple contracts at once
- **Configuration Files** - Reduce verbosity with `.voyager.toml` config files

### Comprehensive Project Support
- **Scarb Projects** - Full support for standard Scarb-based projects
- **Dojo Projects** - Automatic detection and support for Dojo framework
- **Workspace Projects** - Multi-package workspace support
- **Cairo Versions** - Supports Cairo up to 2.11.4 (with newer versions added as available)

### Advanced Features
- **History Tracking** - Local database tracking all verifications
- **Watch Mode** - Monitor verification status in real-time
- **Desktop Notifications** - Get notified when verification completes
- **Dry Run Mode** - Preview what will be submitted before verification
- **Multiple Networks** - Support for Mainnet, Sepolia, and custom endpoints

### Developer-Friendly
- **Detailed Error Messages** - Clear error codes with actionable solutions
- **Verbose Mode** - Debug compilation issues with full output
- **Multiple Output Formats** - Text, JSON, and table formats for different use cases
- **CI/CD Ready** - Perfect for automation pipelines

## How It Works

The verification process is straightforward:

1. **Prepare Your Project** - Ensure your Scarb project builds successfully
2. **Submit for Verification** - Use the CLI to submit your contract class hash and source code
3. **Monitor Progress** - Track the verification status with built-in polling
4. **View Results** - See your verified contract on Voyager with the verified badge

The verifier collects your source files, compiles them remotely using the same build configuration, and compares the output with the deployed contract. If they match, your contract is marked as verified.

## Network Support

Voyager Verifier supports:

- **Mainnet** - Production Starknet network (default: `https://api.voyager.online/beta`)
- **Sepolia** - Testnet for development (default: `https://sepolia-api.voyager.online/beta`)
- **Dev** - Development network
- **Custom Endpoints** - Specify your own API endpoint URL

> **Note**: Classes verified on mainnet will automatically appear verified on Sepolia as well.

## Requirements

Before using Voyager Verifier, you'll need:

- A working Scarb project that builds successfully with `scarb build`
- The class hash of your deployed contract
- Your contract name
- A valid SPDX license identifier (optional, defaults to "All Rights Reserved")

## Getting Help

If you encounter any issues:

- Check the [Troubleshooting Guide](./troubleshooting/README.md)
- Review [Common Errors](./troubleshooting/common-errors.md)
- Use `--verbose` flag for detailed error output
- Contact [@StarknetVoyager on Telegram](https://t.me/StarknetVoyager)

## Next Steps

Ready to get started? Head over to the [Installation Guide](./getting-started/README.md) to install Voyager Verifier, or jump straight to the [Quickstart Guide](./getting-started/quickstart.md) if you already have it installed.
