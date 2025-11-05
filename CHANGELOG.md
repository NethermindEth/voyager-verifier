# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Summary
Major release focused on workflow efficiency, user experience, and automation capabilities.
This release includes comprehensive feature additions and represents a significant evolution
of the voyager-verifier tool with persistent history tracking, desktop notifications, and
batch verification support for multi-contract deployments.

### Highlights
- 🧙 Interactive verification wizard for guided contract verification
- ⚙️ Improved error handling with proper error types instead of panics
- 📦 Configuration file support with `.voyager.toml` for reduced command-line verbosity
- 📚 Verification history tracking with local database (`~/.voyager/history.db`)
- 🔔 Desktop notifications for verification completion
- 📊 Enhanced status output with live progress bars and multiple format options
- 🚀 Batch verification for verifying multiple contracts in a single command

### Added

#### Batch Verification
- Config-based batch verification for verifying multiple contracts at once
  - Define contracts in `[[contracts]]` array in `.voyager.toml`
  - Automatic batch mode detection when contracts are defined in config
  - Sequential submission with individual progress tracking
  - Live status monitoring for all jobs with inline updates
  - Continue-on-error by default to verify all contracts even if some fail
- New batch-specific CLI flags:
  - `--fail-fast` - Stop batch verification on first failure (default: continue all)
  - `--batch-delay <SECONDS>` - Add delay between submissions for rate limiting
- Clean, structured output for batch results:
  - Contract name and shortened class hash (e.g., `0x0134aec0...b01069`)
  - Individual status for each contract (Success/Failed/Pending)
  - Job IDs for successful submissions
  - Concise error messages for failed submissions
  - Aggregate summary showing total/submitted/succeeded/failed/pending counts
- Watch mode support for batch verification:
  - Monitors all submitted jobs concurrently
  - Single inline status update showing: `✓ X Succeeded | ⏳ Y Pending | ✗ Z Failed`
  - No verbose retry messages - clean, minimal output
  - Final summary when all jobs complete
- New data structures for batch operations:
  - `BatchContract` - Contract information for batch processing
  - `BatchVerificationResult` - Result for individual contract
  - `BatchVerificationSummary` - Overall batch summary
- Core batch functions in verification module:
  - `submit_batch()` - Submit multiple contracts sequentially
  - `watch_batch()` - Monitor all jobs until completion
  - `display_batch_summary()` - Show formatted results
- Validation for batch mode:
  - Prevents use of `--class-hash` in batch mode
  - Prevents use of `--wizard` in batch mode
  - Clear error messages guiding users to correct usage
- History tracking for all batch verifications
- Comprehensive documentation in README with examples and use cases

#### Enhanced Status Output
- Live status updates with real-time progress during verification
  - Single-line updating display using ANSI escape codes
  - Dynamic progress bar based on elapsed/remaining time ratio
  - Stage-aware status messages (Submitted → Compiling → Verifying)
  - Elapsed time with automatic updates every 2 seconds
- Multiple output format support via `--format` flag
  - `text` (default): Enhanced human-readable output with progress bars
  - `json`: Machine-readable JSON for programmatic parsing and CI/CD integration
  - `table`: Formatted table output for batch operations
- Format option configurable in `.voyager.toml` (CLI flag takes precedence)
- New status_output module (`src/status_output.rs`) with comprehensive formatting utilities
- History-based time estimation for accurate progress predictions
  - Queries last 10 successful verifications from local database
  - Calculates average verification time (requires minimum 3 samples)
  - Two-tier approach: historical averages when available, hardcoded fallbacks otherwise
  - Estimates improve automatically as you verify more contracts
- Fixed 2-second polling interval for consistent status checks
  - Changed from exponential backoff to fixed intervals
  - Maximum 300 retries (10 minutes timeout)
- Live callback mechanism for real-time status updates
  - New `poll_verification_status_with_callback()` API method
  - New `get_job_status_raw()` to fetch full job data for in-progress jobs
  - Callback invoked every poll with current job details
- Cleaner final status output without redundant stage breakdown

#### Verification History & Tracking
- Local SQLite database (`~/.voyager/history.db`) for persistent verification tracking
  - Automatic tracking of all verification submissions
  - Stores job ID, class hash, contract name, network, status, timestamps
  - Tracks Cairo, Scarb, and Dojo versions for each verification
  - Automatic status updates when checking job status
  - Cross-session persistence
- New `history` command with comprehensive subcommands:
  - `voyager history list` - View all verification jobs with filtering
    - Filter by status (`--status success/fail/pending`)
    - Filter by network (`--network mainnet/sepolia/dev`)
    - Limit results (`--limit N`)
    - Sorted by submission time (newest first)
  - `voyager history status --job <id>` - View detailed job information from local database
    - Fast local lookup without API calls
    - `--refresh` flag to update from API and sync database
  - `voyager history recheck` - Batch update all pending jobs
    - Automatically checks `Submitted`, `Processing`, and `Compiled` jobs
    - Updates database with latest status
    - Progress display for each job
  - `voyager history clean` - Manage old records
    - `--older-than N` to delete records older than N days
    - `--all` to delete all records (with confirmation)
  - `voyager history stats` - Display verification statistics
    - Total verifications count
    - Success/failure/pending rates with percentages
    - Color-coded output
- New history module (`src/history.rs`) with:
  - `VerificationRecord` struct for storing job metadata
  - `HistoryDb` for database operations
  - `HistoryStats` for aggregated statistics
  - Error codes E040-E042 for history-related errors
  - Comprehensive unit tests with proper error handling

#### Desktop Notifications
- Optional desktop notification support for verification completion
  - `--notify` flag for `verify` command (requires `--watch`)
  - Cross-platform support (Linux, macOS, Windows)
  - Automatic status detection (success ✅ or failure ❌)
  - Non-intrusive notifications only on completion
  - Terminal states only (Success, Fail, CompileFailed)
- New notifications module (`src/notifications.rs`)
- Optional feature flag `notifications` (enabled by default)
  - Can be disabled with `--no-default-features` for minimal builds
- Uses `notify-rust` crate for cross-platform desktop notifications

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
- All error handling uses proper `Result` types instead of `unwrap()` or `expect()`

### Changed
- `class_hash` and `contract_name` are now optional when using `--wizard` mode or batch mode
  - Required validation now happens after batch mode detection
  - Clearer error messages with tips for wizard or batch mode
- `VerifyArgs` now implements `Clone` trait for batch processing
- All `expect()` calls replaced with proper error handling using `ok_or_else()`
- Improved logging with safe fallbacks to prevent panics in non-critical operations
- `--url` and `--network` arguments are now optional when values are provided in `.voyager.toml`
- Config file values are loaded and merged before validation, enabling config-driven workflows
- Updated help text for `--url` to mention `.voyager.toml` configuration option
- `verify` command now automatically saves job information to history database
- `status` command now automatically updates history database when checking job status
- `VerifyJobStatus` enum now implements `Copy` trait for better ergonomics
- Verification workflow functions refactored to use `HistoryParams` struct instead of 8 individual parameters
- All tests now use proper `Result` return types with `?` operator instead of `unwrap()` or `expect()`
- Updated README with comprehensive documentation for history and notification features
- Status display completely redesigned with live updating single-line format
  - Replaced multi-case status display with unified formatting system
  - Simplified verification.rs `check()` function by removing ~100 lines of legacy display code
  - `check()` now accepts `OutputFormat` parameter for flexible output formatting
- `VerificationJob` now implements `Clone` trait for status caching during polling
- Polling interval changed from exponential backoff to fixed 2-second intervals
- Enhanced dry-run output to display complete API request payload
  - Shows all metadata fields (compiler_version, scarb_version, build_tool, license, etc.)
  - Displays file count and file list instead of full file contents for readability
  - Pretty-printed JSON format for easy inspection
  - Helps users verify exact payload before submission
- Extended `.voyager.toml` configuration structure
  - New `[[contracts]]` array for batch verification
  - Each contract specifies `class-hash`, `contract-name`, and optional `package`
  - New `ContractConfig` struct for contract configuration
  - Config now includes `contracts: Vec<ContractConfig>` field

### Fixed
- Improved contract file detection with pattern-based search and case-insensitive matching
  - Added `find_contract_by_pattern()` to search for `#[starknet::contract]` attribute followed by `mod <ContractName>`
  - Now correctly identifies contract files regardless of file name vs contract name casing mismatch
  - Example: "Core" contract in `src/core/core.cairo` now correctly detected instead of falling back to `lib.cairo`
  - Supports various formatting styles (with/without `pub`, different spacing and line breaks)
  - Fallback heuristics improved with case-insensitive file path matching
  - Better handling of contracts in subdirectories (e.g., `src/core/core.cairo`)
- Removed all `clippy::expect_used` warnings by implementing proper error handling
- Removed all `clippy::unwrap_used` warnings in production and test code
- Improved error handling edge cases in verification workflow
- Better handling of missing required fields with actionable error messages
- All clippy warnings in config module (derive Eq, use Self, documentation backticks, unwrap usage)
- Config tests now use proper error propagation instead of `.unwrap()` calls
- Fixed clippy warning about too many function arguments using parameter struct pattern
- Fixed clippy warning about needless borrow in status update calls
- Fixed clippy warning about manual inspect pattern (using `inspect_err` instead of `map_err`)
- Fixed documentation formatting with proper backticks for `CompileFailed`
- Removed unused imports and variables
- Fixed clippy warning `doc_markdown` by adding backticks to `min_samples` in documentation
- Fixed clippy warning `manual_flatten` by using `.flatten()` iterator in history query
- Removed unused DateTime and Duration imports from verification.rs
- Cleaned up unused Stage and StageStatus types from status output module
- Fixed clippy warnings `needless_continue` and `needless_range_loop` in file_collector module
- Improved batch verification output formatting for clarity
  - Contract name now appears first, followed by shortened class hash
  - Error messages show only first line to avoid overwhelming output
  - Job IDs and status indented for better readability
- Removed verbose polling output in batch watch mode
  - Replaced individual job retry messages with single inline status update
  - Cleaner, less noisy monitoring experience

### Dependencies
- Added `rusqlite` v0.34.0 with bundled SQLite for history database
- Added `dirs` v5.0 for cross-platform home directory detection
- Added `notify-rust` v4.11 (optional) for desktop notifications

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
