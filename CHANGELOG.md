# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Summary
Major release focused on workflow efficiency, user experience, and automation capabilities.
This release includes comprehensive feature additions and represents a significant evolution
of the voyager-verifier tool.

### Highlights
- 🧙 Interactive verification wizard for guided contract verification
- ⚙️ Improved error handling with proper error types instead of panics
- 📦 Configuration file support with `.voyager.toml` for reduced command-line verbosity

### Added

#### Configuration File Support
- `.voyager.toml` configuration file support for project-level defaults
  - Automatic discovery in current and parent directories
  - All verification options configurable (network, license, watch, test-files, lock-file, verbose, url, project-type)
  - Workspace-specific settings (default-package)
  - CLI arguments always take precedence over config file values
  - Validation with helpful error messages when required fields are missing
  - Example configuration file provided (`.voyager.toml.example`)
  - New config module with comprehensive documentation and tests
  - Error codes E030-E032 for config-related errors

#### Interactive Features
- Interactive verification wizard with `--wizard` flag for guided verification
  - Step-by-step prompts for all verification parameters
  - Auto-detection of licenses from Scarb.toml
  - Package selection for workspace projects
  - Customizable options (lock file, test files, watch mode, verbose output)
  - Summary view with confirmation before submission
  - Input validation with helpful error messages

#### Error Handling
- New `InternalError` variant (E028) for graceful handling of invariant violations
- Comprehensive error messages that guide users to solutions

### Changed
- `class_hash` and `contract_name` are now optional when using `--wizard` mode
- All `expect()` calls replaced with proper error handling using `ok_or_else()`
- Improved logging with safe fallbacks to prevent panics in non-critical operations
- `--url` and `--network` arguments are now optional when values are provided in `.voyager.toml`
- Config file values are loaded and merged before validation, enabling config-driven workflows
- Updated help text for `--url` to mention `.voyager.toml` configuration option

### Fixed
- Removed all `clippy::expect_used` warnings by implementing proper error handling
- Improved error handling edge cases in verification workflow
- Better handling of missing required fields with actionable error messages
- All clippy warnings in config module (derive Eq, use Self, documentation backticks, unwrap usage)
- Config tests now use proper error propagation instead of `.unwrap()` calls

### Removed
- Unused Dockerfile
- Obsolete dojo-support-implementation-plan.md

---

## [1.3.0] - 2024-11-04

### Added
- API client migration from multipart/form-data to JSON format ([#110](https://github.com/NethermindEth/voyager-verifier/pull/110))
  - More efficient data transmission
  - Better error handling and debugging
  - Improved request/response structure

### Changed
- Internal API communication now uses JSON instead of multipart form data
- Enhanced API client reliability and maintainability

---

## [1.2.4] - 2024-11-04

### Changed
- Improved dry-run output formatting and clarity
- Enhanced user experience when previewing verification requests

### Fixed
- Minor improvements to dry-run mode display

---

## [1.2.3] - 2024-11-04

### Added
- Enhanced workspace support for multi-package projects
- Improved Dojo version extraction for workspace scenarios
  - Support for workspace-level Scarb.toml
  - Package-level Scarb.toml priority handling
  - Better fallback mechanisms

### Changed
- Updated dependencies to latest compatible versions for improved security and performance
- Enhanced Dojo project detection and version handling

### Fixed
- Clippy warning: `needless_range_loop` in edit_distance function
- Documentation formatting in file_collector module

---

## [1.2.2] - 2024-10-30

### Added
- Major code refactoring for improved maintainability
  - New verification workflow module (`src/verification.rs`)
  - New file collection module (`src/file_collector.rs`)
  - Enhanced resolver module with package validation
  - Extended project module with detection capabilities

### Changed
- Refactored main.rs to use new modular structure
- Moved CliError to dedicated errors module
- Enhanced Dojo version extraction to support multiple dependency formats:
  - Simple string format: `dojo = "1.7.1"`
  - Git tag format: `dojo = { tag = "v0.7.0" }`
  - Version table format: `dojo = { version = "2.0.0" }`

### Fixed
- Improved error handling consistency across modules
- Better separation of concerns in codebase organization

---

## [1.2.1] - 2024-10-08

### Fixed
- Clippy warnings for improved code quality
- Minor code quality improvements

---

## [1.2.0] - 2024-10-08

### Added
- Verbose flag (`-v`, `--verbose`) for detailed error messages
  - Shows full compilation output on verification failures
  - Helps debugging remote compilation issues
- Comprehensive troubleshooting documentation
  - Common error scenarios and solutions
  - Debugging workflows
  - Best practices guide

### Changed
- Enhanced error output with verbose mode support
- Improved user guidance for troubleshooting verification failures

---

## [1.1.0] - 2024-10-07

### Added
- Automatic filtering of dev-dependencies from Scarb.toml
  - Reduces submission size
  - Improves verification reliability
  - Prevents dev-only dependency conflicts

### Changed
- Scarb.toml files are now sanitized before submission
- Dev dependencies are stripped from manifest files during verification

### Fixed
- Issues with dev-dependencies causing verification failures
- Improved handling of Scarb project dependencies

---

## [1.0.0] - 2024-07-24

### Summary
First major stable release of voyager-verifier with comprehensive contract verification capabilities.

### Added
- Core contract verification functionality
  - Submit contracts for verification on Voyager block explorer
  - Support for Starknet mainnet and Sepolia testnet
  - Custom API endpoint support
- Project type detection and support
  - Scarb projects
  - Dojo projects with automatic detection
  - Workspace project support
- Command-line interface
  - `verify` command for contract submission
  - `status` command for job status checking
  - Watch mode for automatic status polling
- Comprehensive error handling
  - Detailed error messages with error codes (E001-E027)
  - Actionable suggestions for common issues
  - Fuzzy matching for typos in package/contract names
- File collection and validation
  - Automatic source file collection
  - Dependency resolution
  - Procedural macro support
  - File type and size validation
- License management
  - SPDX license identifier support
  - License detection from Scarb.toml
  - Custom license specification
- Dry-run mode for previewing submissions
- Network selection (mainnet, sepolia, custom)
- Class hash validation
- Contract name validation
- Package selection for workspaces

### Documentation
- Comprehensive README with examples
- Installation instructions
- Usage guide
- Troubleshooting section
- Contributing guidelines

---

## [0.4.6] - 2024-07-14
## [0.4.5] - 2024-07-14
## [0.3.2] - 2024-07-11
## [0.3.1] - 2024-07-10
## [0.3.0] - 2024-07-10
## [0.2.6] - 2024-07-07
## [0.2.5] - 2024-07-07
## [0.2.4] - 2024-07-04
## [0.2.1] - 2024-07-03

Beta and pre-release versions. See git history for details.

---

## Versioning Strategy

This project follows [Semantic Versioning](https://semver.org/):

- **MAJOR** version (x.0.0): Incompatible API changes or significant breaking changes
- **MINOR** version (1.x.0): New features in a backward-compatible manner
- **PATCH** version (1.1.x): Backward-compatible bug fixes

### Prerelease Versions
- **alpha** (2.0.0-alpha.x): Early development, features incomplete
- **beta** (2.0.0-beta.x): Feature complete, testing in progress
- **rc** (2.0.0-rc.x): Release candidate, final testing before release

---

## Links

- [Repository](https://github.com/NethermindEth/voyager-verifier)
- [Issue Tracker](https://github.com/NethermindEth/voyager-verifier/issues)
- [Releases](https://github.com/NethermindEth/voyager-verifier/releases)

---

**Maintained by:** Nethermind
**License:** Apache-2.0
