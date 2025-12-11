//! # API Client for Starknet Contract Verification
//!
//! This module provides a comprehensive API client for interacting with Starknet
//! contract verification services. It handles HTTP requests, response parsing,
//! and provides type-safe interfaces for all verification operations.
//!
//! ## Features
//!
//! - **HTTP Client**: Built on `reqwest` with automatic retries and error handling
//! - **Type Safety**: Strong typing for all requests and responses
//! - **Polling**: Automatic polling for long-running verification jobs
//! - **Error Handling**: Comprehensive error types with actionable suggestions
//!
//! ## Example Usage
//!
//! ```rust,no_run
//! use verifier::api::{ApiClient, ClassVerificationInfo};
//! use verifier::core::class_hash::ClassHash;
//! use url::Url;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // Create API client for mainnet
//! let client = ApiClient::new(Url::parse("https://api.voyager.online/beta")?)?;
//!
//! // Check if a class is verified
//! let class_hash = ClassHash::new("0x044dc2b3239382230d8b1e943df23b96f52eebcac93efe6e8bde92f9a2f1da18")?;
//! let info = client.check_class_verification(&class_hash)?;
//! println!("Verified: {}", info.verified);
//!
//! // Get verification job status
//! let job_status = client.get_job_status("job-id")?;
//! # Ok(())
//! # }
//! ```

// Re-export the API module components
pub use self::{
    client::{poll_verification_status_with_callback, ApiClient},
    errors::{ApiClientError, VerificationError},
    models::{
        ClassVerificationInfo, FileInfo, ProjectMetadataInfo, VerificationJob,
        VerificationJobDispatch,
    },
    polling::poll_verification_status,
    types::{JobStatus, Status, VerifyJobStatus},
};

// Module declarations
mod client;
mod errors;
mod models;
mod polling;
mod types;
