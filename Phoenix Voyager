# voyager-verifier

Contract class verification tool for the [Voyager Starknet block explorer](https://voyager.online).

[![Documentation](https://img.shields.io/badge/docs-mdBook-blue)](https://nethermindeth.github.io/voyager-verifier/)

## Quick Start

### Installation

**With asdf (Recommended):**
```bash
asdf plugin add voyager https://github.com/NethermindEth/asdf-voyager-verifier.git
asdf install voyager latest
```

**With Cargo:**
```bash
cargo install voyager-verifier
```

### Basic Usage

**Interactive wizard (recommended for first-time users):**
```bash
voyager verify --wizard
```

**Command-line mode:**
```bash
voyager verify --network mainnet \
  --class-hash <YOUR_CLASS_HASH> \
  --contract-name <CONTRACT_NAME>
```

**Batch verification:**
```bash
# Define contracts in .voyager.toml, then:
voyager verify
```

## Documentation

For comprehensive documentation, visit **[the official docs](https://nethermindeth.github.io/voyager-verifier/)** which includes:

- [Getting Started Guide](https://nethermindeth.github.io/voyager-verifier/getting-started/)
- [Configuration Reference](https://nethermindeth.github.io/voyager-verifier/configuration/)
- [Batch Verification](https://nethermindeth.github.io/voyager-verifier/advanced/batch-verification.html)
- [Verification History](https://nethermindeth.github.io/voyager-verifier/history/)
- [Troubleshooting](https://nethermindeth.github.io/voyager-verifier/troubleshooting/)
- [CLI Reference](https://nethermindeth.github.io/voyager-verifier/reference/)

## Development

### Building from Source

```bash
git clone https://github.com/NethermindEth/voyager-verifier.git
cd voyager-verifier
cargo build --release
```

### Running Tests

```bash
cargo test
```

### Building Documentation

```bash
cd docs
mdbook serve
# Visit http://localhost:3000
```

## Contributing

We welcome contributions! See [CONTRIBUTING.md](https://nethermindeth.github.io/voyager-verifier/contributing/) for guidelines.

## License

This project is licensed under the Apache-2.0 License - see the [LICENSE](LICENSE) file for details.
