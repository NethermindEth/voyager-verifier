# Examples

This section provides practical, end-to-end examples demonstrating how to use voyager-verifier in real-world scenarios. Each example walks through a complete verification workflow, from project setup to successful verification.

## Overview

The examples are organized from simple to complex:

1. **[Simple Contract](./simple-contract.md)** - Basic single-contract verification
2. **[Workspace Project](./workspace-project.md)** - Multi-package Scarb workspace
3. **[Dojo Project](./dojo-project.md)** - Dojo project verification
4. **[Multi-Contract Batch](./multi-contract.md)** - Batch verification for multiple contracts
5. **[CI/CD Pipeline](./ci-pipeline.md)** - Automated verification in CI/CD

## What You'll Learn

Each example includes:

- **Project Setup** - Complete Scarb.toml configuration
- **Contract Code** - Sample contract implementation
- **Verification Steps** - Detailed command-line instructions
- **Expected Output** - What you should see at each step
- **Troubleshooting** - Common issues and solutions
- **Best Practices** - Recommended approaches

## Prerequisites

Before working through these examples, ensure you have:

- [Scarb](https://docs.swmansion.com/scarb) installed (version 2.x+)
- voyager-verifier installed (see [Installation](../getting-started/README.md))
- Basic understanding of Cairo and Starknet development
- A Starknet contract class hash (for verification examples)

For Dojo examples, you'll also need:
- [Dojo](https://book.dojoengine.org/getting-started/quick-start) installed (version 1.x+)

## Example Projects

All examples use realistic project structures:

### Simple Contract
A basic Starknet contract demonstrating core verification features:
- Single contract file
- Standard Scarb project structure
- Basic storage and external functions

### Workspace Project
A multi-package workspace showing:
- Multiple Cairo packages in one repository
- Shared dependencies
- Package selection during verification

### Dojo Project
A Dojo world with models and systems:
- Dojo-specific dependencies
- Multiple contracts and components
- Dojo version detection

### Batch Verification
Verifying multiple contracts at once:
- Configuration file setup
- Batch submission workflow
- Progress monitoring

### CI/CD Integration
Automated verification in continuous integration:
- GitHub Actions workflow
- GitLab CI pipeline
- Environment configuration

## Using These Examples

### For Learning

If you're new to voyager-verifier, we recommend following the examples in order:

1. Start with **[Simple Contract](./simple-contract.md)** to understand the basics
2. Progress to **[Workspace Project](./workspace-project.md)** for multi-package setups
3. Try **[Dojo Project](./dojo-project.md)** if you're using the Dojo framework
4. Learn **[Multi-Contract Batch](./multi-contract.md)** for efficient bulk verification
5. Implement **[CI/CD Pipeline](./ci-pipeline.md)** to automate your workflow

### For Reference

If you're looking for a specific use case:

- **"How do I verify my first contract?"** → [Simple Contract](./simple-contract.md)
- **"My project has multiple packages"** → [Workspace Project](./workspace-project.md)
- **"I'm building with Dojo"** → [Dojo Project](./dojo-project.md)
- **"I need to verify many contracts"** → [Multi-Contract Batch](./multi-contract.md)
- **"I want to automate verification"** → [CI/CD Pipeline](./ci-pipeline.md)

### For Copy-Paste

Each example includes complete, working code that you can:
- Copy directly into your project
- Modify to fit your needs
- Use as a template for similar scenarios

## Example Structure

Each example follows a consistent format:

```
## Overview
Brief description of what you'll build

## Project Structure
Directory layout and file organization

## Setup
Step-by-step project setup instructions

## Contract Code
Complete contract implementation

## Configuration
Scarb.toml and .voyager.toml setup

## Verification
Detailed verification workflow

## Expected Output
What success looks like

## Troubleshooting
Common issues and solutions

## Next Steps
Where to go from here
```

## Additional Resources

- **[Command Reference](../commands/README.md)** - Complete command documentation
- **[Configuration Guide](../configuration/README.md)** - Configuration options
- **[Troubleshooting](../troubleshooting/README.md)** - Error resolution
- **[Best Practices](./simple-contract.md#best-practices)** - Recommended workflows

## Interactive Learning

For an interactive verification experience, try the wizard mode:

```bash
voyager verify --wizard
```

The wizard guides you through the verification process step-by-step, making it perfect for learning and experimentation.

## Getting Help

If you get stuck while working through an example:

1. Check the **Troubleshooting** section in each example
2. Review the [Troubleshooting Guide](../troubleshooting/README.md)
3. Use `--verbose` flag to see detailed error messages
4. Try `--dry-run` to preview what will be submitted
5. Reach out to [@StarknetVoyager on Telegram](https://t.me/StarknetVoyager)

## Contributing Examples

Have a useful verification scenario that's not covered here? Contributions are welcome! See [Contributing to Documentation](../contributing/documentation.md) for guidelines.

---

**Ready to start?** Begin with the [Simple Contract Example](./simple-contract.md) →
