//! # Starknet Contract Verifier
//!
//! A Rust library for verifying Starknet smart contracts on block explorers.
//! This library provides functionality to verify contract source code against
//! deployed contracts on Starknet networks.
//!
//! ## Features
//!
//! - **Contract Verification**: Verify deployed contracts against source code
//! - **Multi-network Support**: Support for Mainnet, Sepolia, and custom networks
//! - **Type Safety**: Strong typing for class hashes and contract data
//! - **Error Handling**: Comprehensive error types with actionable suggestions
//! - **License Management**: Automated license detection and validation
//! - **Project Resolution**: Automatic dependency resolution for Scarb projects
//!
//! ## Example Usage
//!
//! ```rust,no_run
//! use verifier::{
//!     api::ApiClient,
//!     class_hash::ClassHash,
//! };
//! use url::Url;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // Create an API client
//! let client = ApiClient::new(Url::parse("https://api.voyager.online/beta")?)?;
//!
//! // Create a class hash
//! let class_hash = ClassHash::new("0x044dc2b3239382230d8b1e943df23b96f52eebcac93efe6e8bde92f9a2f1da18")?;
//!
//! // Check if the class exists
//! let exists = client.get_class(&class_hash)?;
//! println!("Class exists: {}", exists);
//! # Ok(())
//! # }
//! ```

/// API client and types for interacting with verification services
pub mod api;

/// Command-line argument parsing and project configuration
pub mod args;

/// Type-safe class hash handling and validation
pub mod class_hash;

/// Comprehensive error types with actionable suggestions
pub mod errors;

/// License detection and management utilities
pub mod license;

/// Project dependency resolution and source file collection
pub mod resolver;

/// Voyager block explorer integration utilities
pub mod voyager;

/// Project type definitions and detection logic
pub mod project;

/// Verification workflow orchestration
pub mod verification;

/// File collection, validation, and preparation for verification
pub mod file_collector;

/// Interactive verification wizard for guided contract verification
pub mod wizard;

/// Configuration file support for .voyager.toml files
pub mod config;

/// Verification history tracking and local database management
pub mod history;

/// Desktop notification support for verification completion
pub mod notifications;

/// Enhanced status output formatting with progress bars and JSON support
pub mod status_output;
