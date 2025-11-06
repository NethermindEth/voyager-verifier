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
//!     core::class_hash::ClassHash,
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

/// Command-line interface module including arguments, commands, config, and wizard
pub mod cli;

/// Core verification logic including verification orchestration, project detection, and class hash handling
pub mod core;

/// File collection and dependency resolution utilities
pub mod filesystem;

/// Output formatting and notification support
pub mod output;

/// Data persistence and history tracking
pub mod storage;

/// General utilities including errors, license, and Voyager integration
pub mod utils;
