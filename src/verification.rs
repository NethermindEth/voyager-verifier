//! Verification workflow orchestration
//!
//! This module contains the core verification workflow functions that orchestrate
//! the process of verifying Starknet smart contracts. It handles:
//!
//! - Submission of verification jobs to the verification service
//! - Execution of the verification process with proper metadata
//! - Polling and checking verification job status
//! - Managing the verification lifecycle from submission to completion

use crate::api::{
    poll_verification_status, ApiClient, ApiClientError, FileInfo, ProjectMetadataInfo,
    VerificationError, VerificationJob, VerifyJobStatus,
};
use crate::args::VerifyArgs;
use crate::errors::CliError;
use crate::file_collector::{log_verification_info, prepare_project_for_verification};
use crate::license;
use crate::project::{determine_project_type, extract_dojo_version, ProjectType};
use crate::resolver::{collect_source_files, gather_packages_and_validate};
use chrono::{DateTime, Utc};
use colored::*;
use log::{debug, info, warn};
use scarb_metadata::PackageMetadata;
use std::time::{Duration, UNIX_EPOCH};

/// Context information for a verification job
///
/// This struct holds all the necessary information gathered during the
/// preparation phase that is needed for executing a verification job.
#[derive(Debug)]
pub struct VerificationContext {
    /// The type of project being verified (Scarb or Dojo)
    pub project_type: ProjectType,
    /// The relative path to the project directory
    pub project_dir_path: String,
    /// The relative path to the main contract file
    pub contract_file: String,
    /// Metadata about the package being verified
    pub package_meta: PackageMetadata,
    /// List of all files to be included in the verification
    pub file_infos: Vec<FileInfo>,
}

/// Submit a verification job
///
/// This function orchestrates the entire verification submission process:
/// 1. Determines the project type (Scarb or Dojo)
/// 2. Gathers packages and validates the selection
/// 3. Collects source files
/// 4. Prepares the project structure for verification
/// 5. Logs verification information
/// 6. Executes the verification (unless in dry-run mode)
///
/// # Arguments
///
/// * `api_client` - The API client for communicating with the verification service
/// * `args` - Command-line arguments containing verification parameters
/// * `license_info` - License information for the contract
///
/// # Returns
///
/// Returns the job ID as a String if successful, or "dry-run" if in dry-run mode.
///
/// # Errors
///
/// Returns a `CliError` if any step of the verification preparation or submission fails.
pub fn submit(
    api_client: &ApiClient,
    args: &VerifyArgs,
    license_info: &license::LicenseInfo,
) -> Result<String, CliError> {
    info!("🚀 Starting verification for project at: {}", args.path);

    // Determine project type early in the process
    let project_type = determine_project_type(args)?;

    // Log the selected build tool
    match project_type {
        ProjectType::Dojo => info!("Using sozo build for Dojo project"),
        ProjectType::Scarb => info!("Using scarb build for Scarb project"),
        ProjectType::Auto => unreachable!("Auto should be resolved by now"),
    }

    let metadata = args.path.metadata();

    // Determine test_files setting - default to true for Dojo projects
    let include_test_files = match project_type {
        ProjectType::Dojo => {
            if !args.test_files {
                info!("🧪 Including test files by default for Dojo project");
            }
            true
        }
        _ => args.test_files,
    };

    // Gather packages and sources
    let packages = gather_packages_and_validate(metadata, args)?;
    let sources = collect_source_files(metadata, &packages, include_test_files)?;

    // Prepare project structure
    let (file_infos, package_meta, contract_file, project_dir_path) =
        prepare_project_for_verification(args, metadata, &packages, sources)?;

    // Log verification info
    log_verification_info(args, metadata, &file_infos, &contract_file, license_info);

    // Execute verification unless dry run is requested
    if !args.dry_run {
        let context = VerificationContext {
            project_type,
            project_dir_path,
            contract_file,
            package_meta,
            file_infos,
        };
        return execute_verification(api_client, args, context, license_info);
    }

    info!("Dry run mode: collected files for verification but skipping submission due to --dry-run flag");
    Ok("dry-run".to_string())
}

/// Execute the verification request
///
/// This function handles the actual submission of a verification job to the API.
/// It:
/// 1. Extracts version information (Cairo, Scarb, and optionally Dojo)
/// 2. Creates project metadata with all necessary information
/// 3. Submits the verification request via the API client
///
/// # Arguments
///
/// * `api_client` - The API client for communicating with the verification service
/// * `args` - Command-line arguments containing verification parameters
/// * `context` - The verification context with all prepared data
/// * `license_info` - License information for the contract
///
/// # Returns
///
/// Returns the verification job ID as a String if successful.
///
/// # Errors
///
/// Returns a `CliError` if the verification submission fails.
pub fn execute_verification(
    api_client: &ApiClient,
    args: &VerifyArgs,
    context: VerificationContext,
    license_info: &license::LicenseInfo,
) -> Result<String, CliError> {
    let metadata = args.path.metadata();
    let cairo_version = metadata.app_version_info.cairo.version.clone();
    let scarb_version = metadata.app_version_info.version.clone();

    // Create project metadata with build tool information
    debug!(
        "Creating ProjectMetadataInfo with project_type: {:?}",
        context.project_type
    );

    // Extract Dojo version if it's a Dojo project
    let dojo_version = if context.project_type == ProjectType::Dojo {
        info!("🔍 Dojo project detected - attempting to extract Dojo version from Scarb.toml");
        debug!(
            "📍 context.project_dir_path (relative): {}",
            context.project_dir_path
        );
        debug!(
            "📍 args.path.root_dir() (absolute): {}",
            args.path.root_dir()
        );

        // Use the absolute path for Dojo version extraction
        let absolute_project_path = args.path.root_dir().to_string();
        let extracted_version = extract_dojo_version(&absolute_project_path);
        match &extracted_version {
            Some(version) => info!("✅ Successfully extracted Dojo version: {version}"),
            None => warn!(
                "⚠️  Could not extract Dojo version from Scarb.toml - proceeding without version"
            ),
        }
        extracted_version
    } else {
        debug!("📦 Regular project (not Dojo) - skipping Dojo version extraction");
        None
    };

    let project_meta = ProjectMetadataInfo::new(
        cairo_version,
        scarb_version,
        context.project_dir_path,
        context.contract_file,
        context.package_meta.name,
        context.project_type,
        dojo_version,
    );
    debug!(
        "Created ProjectMetadataInfo with build_tool: {}, dojo_version: {:?}",
        project_meta.build_tool, project_meta.dojo_version
    );

    api_client
        .verify_class(
            &args.class_hash,
            Some(license_info.display_string().to_string()),
            &args.contract_name,
            project_meta,
            &context.file_infos,
        )
        .map_err(CliError::from)
}

/// Check the status of a verification job
///
/// This function polls the verification service for the status of a job and
/// displays the results to the user. It handles all possible job states:
/// - Success: Displays verification details and Voyager link
/// - Fail/CompileFailed: Shows error messages
/// - Processing/Submitted/Compiled: Shows progress information
///
/// # Arguments
///
/// * `api_client` - The API client for communicating with the verification service
/// * `job_id` - The unique identifier of the verification job
///
/// # Returns
///
/// Returns the `VerificationJob` with full status information if successful.
///
/// # Errors
///
/// Returns a `CliError` if polling the status fails or the API returns an error.
pub fn check(api_client: &ApiClient, job_id: &str) -> Result<VerificationJob, CliError> {
    let status = poll_verification_status(api_client, job_id).map_err(CliError::from)?;

    match status.status() {
        VerifyJobStatus::Success => {
            println!("\n✅ Verification successful!");
            if let Some(name) = status.name() {
                println!("Contract name: {name}");
            }
            if let Some(file) = status.contract_file() {
                println!("Contract file: {file}");
            }
            if let Some(version) = status.version() {
                println!("Cairo version: {version}");
            }
            if let Some(dojo_version) = status.dojo_version() {
                println!("Dojo version: {dojo_version}");
            }
            if let Some(license) = status.license() {
                println!("License: {license}");
            }
            if let Some(address) = status.address() {
                println!("Contract address: {address}");
            }
            println!("Class hash: {}", status.class_hash());
            if let Some(created) = status.created_timestamp() {
                println!("Created: {}", format_timestamp(created));
            }
            if let Some(updated) = status.updated_timestamp() {
                println!("Last updated: {}", format_timestamp(updated));
            }
            println!("\nThe contract is now verified and visible on Voyager at https://voyager.online/class/{} .", status.class_hash());
        }
        VerifyJobStatus::Fail => {
            println!("\n❌ Verification failed!");
            if let Some(desc) = status.status_description() {
                println!("Reason: {desc}");
            }
            if let Some(created) = status.created_timestamp() {
                println!("Started: {}", format_timestamp(created));
            }
            if let Some(updated) = status.updated_timestamp() {
                println!("Failed: {}", format_timestamp(updated));
            }
        }
        VerifyJobStatus::CompileFailed => {
            println!("\n❌ Compilation failed!");
            if let Some(desc) = status.status_description() {
                println!("Reason: {desc}");
            }
            if let Some(created) = status.created_timestamp() {
                println!("Started: {}", format_timestamp(created));
            }
            if let Some(updated) = status.updated_timestamp() {
                println!("Failed: {}", format_timestamp(updated));
            }
        }
        VerifyJobStatus::Processing => {
            println!("\n⏳ Contract verification is being processed...");
            println!("Job ID: {}", status.job_id());
            println!("Status: Processing");
            if let Some(created) = status.created_timestamp() {
                println!("Started: {}", format_timestamp(created));
            }
            if let Some(updated) = status.updated_timestamp() {
                println!("Last updated: {}", format_timestamp(updated));
            }
            println!("\nUse the same command to check progress later.");
        }
        VerifyJobStatus::Submitted => {
            println!("\n⏳ Verification job submitted and waiting for processing...");
            println!("Job ID: {}", status.job_id());
            println!("Status: Submitted");
            if let Some(created) = status.created_timestamp() {
                println!("Submitted: {}", format_timestamp(created));
            }
            println!("\nUse the same command to check progress later.");
        }
        VerifyJobStatus::Compiled => {
            println!("\n⏳ Contract compiled successfully, verification in progress...");
            println!("Job ID: {}", status.job_id());
            println!("Status: Compiled");
            if let Some(created) = status.created_timestamp() {
                println!("Started: {}", format_timestamp(created));
            }
            if let Some(updated) = status.updated_timestamp() {
                println!("Last updated: {}", format_timestamp(updated));
            }
            println!("\nUse the same command to check progress later.");
        }
        _ => {
            println!("\n⏳ Verification in progress...");
            println!("Job ID: {}", status.job_id());
            println!("Status: {}", status.status());
            if let Some(created) = status.created_timestamp() {
                println!("Started: {}", format_timestamp(created));
            }
            if let Some(updated) = status.updated_timestamp() {
                println!("Last updated: {}", format_timestamp(updated));
            }
            println!("\nUse the same command to check progress later.");
        }
    }

    Ok(status)
}

/// Format a Unix timestamp as an RFC3339 string
///
/// Converts a floating-point Unix timestamp into a human-readable RFC3339
/// formatted date-time string. If the timestamp cannot be converted (e.g.,
/// it's out of range), returns the timestamp as a string instead.
///
/// # Arguments
///
/// * `timestamp` - Unix timestamp as a floating-point number
///
/// # Returns
///
/// Returns an RFC3339 formatted string like "2024-01-15T10:30:00+00:00",
/// or the timestamp as a string if conversion fails.
fn format_timestamp(timestamp: f64) -> String {
    let duration = Duration::from_secs_f64(timestamp);
    if let Some(datetime) = UNIX_EPOCH.checked_add(duration) {
        let datetime: DateTime<Utc> = datetime.into();
        datetime.to_rfc3339()
    } else {
        timestamp.to_string()
    }
}

/// Display a verification job ID to the user
///
/// Formats and displays the verification job ID in a visually distinct way
/// with green, bold text for easy identification.
///
/// # Arguments
///
/// * `job_id` - The verification job ID to display
pub fn display_verification_job_id(job_id: &str) {
    println!();
    println!("verification job id: {}", job_id.green().bold());
    println!();
}

/// Display verbose error information
///
/// When verbose mode is enabled, this function displays detailed error output
/// for verification errors, including the raw error message from the service.
///
/// # Arguments
///
/// * `error` - The CLI error to display in verbose mode
pub fn display_verbose_error(error: &CliError) {
    if let CliError::Api(ApiClientError::Verify(verification_error)) = error {
        // Extract the raw message from the error
        let raw_message = match verification_error {
            VerificationError::CompilationFailure(msg)
            | VerificationError::VerificationFailure(msg) => msg,
        };

        eprintln!("\n{}", "--- Detailed Error Output ---".bright_yellow());
        eprintln!("{}", raw_message);
        eprintln!("{}\n", "--- End Error Output ---".bright_yellow());
    }
}
