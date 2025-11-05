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
    ApiClient, ApiClientError, FileInfo, ProjectMetadataInfo, VerificationError, VerificationJob,
    VerifyJobStatus,
};
use crate::args::VerifyArgs;
use crate::errors::CliError;
use crate::file_collector::{log_verification_info, prepare_project_for_verification};
use crate::history::{HistoryDb, VerificationRecord};
use crate::license;
use crate::project::{determine_project_type, extract_dojo_version, ProjectType};
use crate::resolver::{collect_source_files, gather_packages_and_validate};
use colored::*;
use log::{debug, info, warn};
use scarb_metadata::PackageMetadata;

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

    // Validate required fields are present (they should be if not in wizard mode, or populated by wizard)
    let class_hash = args
        .class_hash
        .as_ref()
        .ok_or_else(|| CliError::InternalError {
            message: "class_hash should be present - either from CLI args or wizard".to_string(),
        })?;
    let contract_name = args
        .contract_name
        .as_ref()
        .ok_or_else(|| CliError::InternalError {
            message: "contract_name should be present - either from CLI args or wizard".to_string(),
        })?;

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

    // Dry run: Build and display the full payload that would be sent
    println!("\n✅ Dry run completed successfully!");
    println!("Collected {} file(s) for verification", file_infos.len());
    println!("Contract: {}", contract_name);
    println!("Class hash: {}", class_hash);

    // Build the complete payload
    let cairo_version = metadata.app_version_info.cairo.version.clone();
    let scarb_version = metadata.app_version_info.version.clone();

    // Extract Dojo version if it's a Dojo project (same logic as execute_verification)
    let dojo_version = if project_type == ProjectType::Dojo {
        let workspace_root = args.path.root_dir().to_string();
        let package_root = package_meta.root.to_string();
        let package_root_opt = if package_root != workspace_root {
            Some(package_root.as_str())
        } else {
            None
        };
        extract_dojo_version(&workspace_root, package_root_opt)
    } else {
        None
    };

    // Prepare license value (same logic as in API client)
    let license_str = license_info.display_string().to_string();
    let license_value = if license_str == "MIT" {
        "MIT".to_string()
    } else {
        license_str
    };

    // Build the request payload structure (without file contents for brevity)
    #[derive(serde::Serialize)]
    struct DryRunPayload {
        compiler_version: String,
        scarb_version: String,
        package_name: String,
        name: String,
        contract_file: String,
        #[serde(rename = "contract-name")]
        contract_name: String,
        project_dir_path: String,
        build_tool: String,
        license: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        dojo_version: Option<String>,
        file_count: usize,
        file_list: Vec<String>,
    }

    let payload = DryRunPayload {
        compiler_version: cairo_version.to_string(),
        scarb_version: scarb_version.to_string(),
        package_name: package_meta.name,
        name: contract_name.to_string(),
        contract_file: contract_file.clone(),
        contract_name: contract_file,
        project_dir_path,
        build_tool: project_type.to_string(),
        license: license_value,
        dojo_version,
        file_count: file_infos.len(),
        file_list: file_infos.iter().map(|f| f.name.clone()).collect(),
    };

    // Display the payload as pretty-printed JSON
    println!("\n{}", "=== API Request Payload ===".bright_cyan().bold());
    match serde_json::to_string_pretty(&payload) {
        Ok(json) => println!("{}", json),
        Err(e) => warn!("Failed to serialize payload to JSON: {}", e),
    }
    println!("{}\n", "=== End Payload ===".bright_cyan().bold());

    println!("\n⚠️  No verification was submitted due to --dry-run flag");
    println!("Remove --dry-run to submit for actual verification.\n");
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
    // Extract required fields
    let class_hash = args
        .class_hash
        .as_ref()
        .ok_or_else(|| CliError::InternalError {
            message: "class_hash should be present".to_string(),
        })?;
    let contract_name = args
        .contract_name
        .as_ref()
        .ok_or_else(|| CliError::InternalError {
            message: "contract_name should be present".to_string(),
        })?;

    let metadata = args.path.metadata();
    let cairo_version = metadata.app_version_info.cairo.version.clone();
    let scarb_version = metadata.app_version_info.version.clone();

    // Save version strings for history tracking before they are moved
    let cairo_version_str = cairo_version.to_string();
    let scarb_version_str = scarb_version.to_string();

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
            "📍 args.path.root_dir() (workspace root): {}",
            args.path.root_dir()
        );
        debug!(
            "📍 context.package_meta.root (package root): {}",
            context.package_meta.root
        );

        // Extract from package root first, then fallback to workspace root
        let workspace_root = args.path.root_dir().to_string();
        let package_root = context.package_meta.root.to_string();

        // Only pass package root if it's different from workspace root (i.e., workspace scenario)
        let package_root_opt = if package_root != workspace_root {
            Some(package_root.as_str())
        } else {
            None
        };

        let extracted_version = extract_dojo_version(&workspace_root, package_root_opt);
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

    // Save package name before it's moved
    let package_name = context.package_meta.name.clone();

    let project_meta = ProjectMetadataInfo::new(
        cairo_version,
        scarb_version,
        context.project_dir_path,
        context.contract_file,
        context.package_meta.name,
        context.project_type,
        dojo_version.clone(),
    );
    debug!(
        "Created ProjectMetadataInfo with build_tool: {}, dojo_version: {:?}",
        project_meta.build_tool, project_meta.dojo_version
    );

    let job_id = api_client
        .verify_class(
            class_hash,
            Some(license_info.display_string().to_string()),
            contract_name,
            project_meta,
            &context.file_infos,
        )
        .map_err(CliError::from)?;

    // Determine network from args
    let network = if let Some(ref net) = args.network {
        match net {
            crate::args::NetworkKind::Mainnet => "mainnet",
            crate::args::NetworkKind::Sepolia => "sepolia",
            crate::args::NetworkKind::Dev => "dev",
        }
    } else {
        // Extract from URL if network not specified
        let url = args.network_url.url.as_str();
        if url.contains("sepolia") {
            "sepolia"
        } else if url.contains("dev") {
            "dev"
        } else if url.contains("mainnet") || url.contains("api.voyager.online") {
            "mainnet"
        } else {
            "custom"
        }
    };

    // Save verification record to history database
    if let Err(e) = save_to_history(HistoryParams {
        job_id: &job_id,
        class_hash,
        contract_name,
        network,
        cairo_version: &cairo_version_str,
        scarb_version: &scarb_version_str,
        dojo_version: dojo_version.as_deref(),
        package_name: &package_name,
    }) {
        warn!("Failed to save verification to history: {e}");
        // Don't fail the verification if history save fails
    }

    Ok(job_id)
}

/// Parameters for saving verification history
struct HistoryParams<'a> {
    job_id: &'a str,
    class_hash: &'a crate::class_hash::ClassHash,
    contract_name: &'a str,
    network: &'a str,
    cairo_version: &'a str,
    scarb_version: &'a str,
    dojo_version: Option<&'a str>,
    package_name: &'a str,
}

/// Save a verification record to the history database
fn save_to_history(params: HistoryParams<'_>) -> Result<(), crate::history::HistoryError> {
    let db = HistoryDb::open()?;

    let record = VerificationRecord::new(
        params.job_id.to_string(),
        params.class_hash,
        params.contract_name.to_string(),
        params.network.to_string(),
        VerifyJobStatus::Submitted,
        Some(params.package_name.to_string()),
        params.scarb_version.to_string(),
        params.cairo_version.to_string(),
        params.dojo_version.map(String::from),
    );

    db.insert(&record)?;
    info!("Saved verification record to history database");

    Ok(())
}

/// Update the status of a verification record in the history database
fn update_history_status(
    job_id: &str,
    status: VerifyJobStatus,
) -> Result<(), crate::history::HistoryError> {
    let db = HistoryDb::open()?;

    // Get the existing record to update it
    if let Some(mut record) = db.get_by_job_id(job_id)? {
        record.update_status(status);
        db.update_status(job_id, &record.status, record.completed_at)?;
        debug!("Updated verification history for job {job_id} to status {status}");
    } else {
        debug!("Job {job_id} not found in history database, skipping update");
    }

    Ok(())
}

/// Check the status of a verification job
///
/// This function polls the verification service for the status of a job and
/// displays the results to the user in the specified format. It handles all
/// possible job states and formats output as text, JSON, or table.
///
/// # Arguments
///
/// * `api_client` - The API client for communicating with the verification service
/// * `job_id` - The unique identifier of the verification job
/// * `format` - The output format (Text, Json, or Table)
///
/// # Returns
///
/// Returns the `VerificationJob` with full status information if successful.
///
/// # Errors
///
/// Returns a `CliError` if polling the status fails or the API returns an error.
pub fn check(
    api_client: &ApiClient,
    job_id: &str,
    format: &crate::args::OutputFormat,
) -> Result<VerificationJob, CliError> {
    // Use polling with callback to show status updates during watch
    let format_copy = *format;

    // For text format, show live inline status updates
    if format_copy == crate::args::OutputFormat::Text {
        let callback = |status: &VerificationJob| {
            let inline_status = crate::status_output::format_inline_status(status);
            // Clear line and update with new status
            print!("\r\x1B[2K{}", inline_status);
            use std::io::Write;
            std::io::stdout().flush().ok();
        };

        let status =
            crate::api::poll_verification_status_with_callback(api_client, job_id, Some(&callback))
                .map_err(CliError::from)?;

        // Update history database with latest status
        if let Err(e) = update_history_status(job_id, *status.status()) {
            warn!("Failed to update verification history: {e}");
        }

        // Print newline and show final detailed status
        println!();
        let output = crate::status_output::format_status(&status, format);
        println!("{}", output);

        Ok(status)
    } else {
        // For JSON/table formats, just poll without live updates
        let status = crate::api::poll_verification_status_with_callback(api_client, job_id, None)
            .map_err(CliError::from)?;

        if let Err(e) = update_history_status(job_id, *status.status()) {
            warn!("Failed to update verification history: {e}");
        }

        let output = crate::status_output::format_status(&status, format);
        println!("{}", output);

        Ok(status)
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

// ============================================================================
// Batch Verification Support
// ============================================================================

/// A single contract in a batch verification job
#[derive(Debug, Clone)]
pub struct BatchContract {
    pub class_hash: crate::class_hash::ClassHash,
    pub contract_name: String,
    pub package: Option<String>,
}

/// Result of a batch contract verification
#[derive(Debug, Clone)]
pub struct BatchVerificationResult {
    pub contract: BatchContract,
    pub job_id: Option<String>,
    pub status: Option<VerifyJobStatus>,
    pub error: Option<String>,
}

/// Summary of batch verification
#[derive(Debug, Clone)]
pub struct BatchVerificationSummary {
    pub total: usize,
    pub submitted: usize,
    pub results: Vec<BatchVerificationResult>,
}

/// Submit multiple contracts for verification in batch mode
///
/// This function orchestrates batch verification by:
/// 1. Parsing contracts from config
/// 2. Creating individual `VerifyArgs` for each contract
/// 3. Submitting each contract using existing `submit()` logic
/// 4. Collecting results and returning summary
///
/// # Arguments
///
/// * `api_client` - The API client for communicating with the verification service
/// * `args` - Base verification arguments (network, watch, etc.)
/// * `config` - Configuration containing the list of contracts to verify
/// * `license_info` - License information for the contracts
///
/// # Returns
///
/// Returns a `BatchVerificationSummary` with results for all contracts
///
/// # Errors
///
/// Returns a `CliError` if batch verification fails critically
pub fn submit_batch(
    api_client: &ApiClient,
    args: &VerifyArgs,
    config: &crate::config::Config,
    license_info: &license::LicenseInfo,
) -> Result<BatchVerificationSummary, CliError> {
    info!(
        "🚀 Starting batch verification for {} contracts",
        config.contracts.len()
    );

    let mut results = Vec::new();
    let total = config.contracts.len();

    for (index, contract_config) in config.contracts.iter().enumerate() {
        println!(
            "\n{} Verifying: {}",
            format!("[{}/{}]", index + 1, total).bright_cyan().bold(),
            contract_config.contract_name.bright_white().bold()
        );

        // Parse class hash
        let class_hash = match crate::class_hash::ClassHash::new(&contract_config.class_hash) {
            Ok(hash) => hash,
            Err(e) => {
                let error_msg = format!("Invalid class hash: {}", e);
                println!("  {} {}", "✗".red().bold(), error_msg.red());
                if args.fail_fast {
                    return Err(CliError::from(e));
                }
                // Skip this contract and continue with the next one
                continue;
            }
        };

        // Create individual VerifyArgs for this contract
        let mut contract_args = args.clone();
        contract_args.class_hash = Some(class_hash.clone());
        contract_args.contract_name = Some(contract_config.contract_name.clone());
        contract_args.package = contract_config
            .package
            .clone()
            .or_else(|| contract_args.package.clone());

        // Submit using existing submit() function (reuse all existing logic!)
        let result = match submit(api_client, &contract_args, license_info) {
            Ok(job_id) if job_id != "dry-run" => {
                println!(
                    "  {} Submitted - Job ID: {}",
                    "✓".green().bold(),
                    job_id.green()
                );
                BatchVerificationResult {
                    contract: BatchContract {
                        class_hash: class_hash.clone(),
                        contract_name: contract_config.contract_name.clone(),
                        package: contract_config.package.clone(),
                    },
                    job_id: Some(job_id),
                    status: Some(VerifyJobStatus::Submitted),
                    error: None,
                }
            }
            Ok(_) => {
                // dry-run mode
                BatchVerificationResult {
                    contract: BatchContract {
                        class_hash: class_hash.clone(),
                        contract_name: contract_config.contract_name.clone(),
                        package: contract_config.package.clone(),
                    },
                    job_id: None,
                    status: None,
                    error: None,
                }
            }
            Err(e) => {
                println!("  {} Failed: {}", "✗".red().bold(), e.to_string().red());
                if args.fail_fast {
                    return Err(e);
                }
                BatchVerificationResult {
                    contract: BatchContract {
                        class_hash: class_hash.clone(),
                        contract_name: contract_config.contract_name.clone(),
                        package: contract_config.package.clone(),
                    },
                    job_id: None,
                    status: None,
                    error: Some(e.to_string()),
                }
            }
        };

        results.push(result);

        // Rate limiting delay between submissions
        if index < total - 1 {
            if let Some(delay_secs) = args.batch_delay {
                println!(
                    "  {} Waiting {} seconds before next submission...",
                    "⏳".yellow(),
                    delay_secs
                );
                std::thread::sleep(std::time::Duration::from_secs(delay_secs));
            }
        }
    }

    let submitted = results.iter().filter(|r| r.job_id.is_some()).count();

    Ok(BatchVerificationSummary {
        total,
        submitted,
        results,
    })
}

/// Watch all batch verification jobs until completion
///
/// This function polls all submitted jobs in the batch until they reach
/// a terminal state (Success, Fail, or `CompileFailed`).
///
/// # Arguments
///
/// * `api_client` - The API client for communicating with the verification service
/// * `summary` - The batch summary from initial submission
/// * `output_format` - The desired output format for status display
///
/// # Returns
///
/// Returns an updated `BatchVerificationSummary` with final statuses
///
/// # Errors
///
/// Returns a `CliError` if polling fails critically
pub fn watch_batch(
    api_client: &ApiClient,
    summary: &BatchVerificationSummary,
    output_format: &crate::args::OutputFormat,
) -> Result<BatchVerificationSummary, CliError> {
    let job_ids: Vec<&str> = summary
        .results
        .iter()
        .filter_map(|r| r.job_id.as_deref())
        .collect();

    if job_ids.is_empty() {
        return Ok(summary.clone()); // Nothing to watch
    }

    println!(
        "\n{} Watching {} verification job(s)...\n",
        "⏳".yellow(),
        job_ids.len()
    );

    let mut updated_results = summary.results.clone();
    let mut iteration = 0;

    // Poll all jobs until complete
    loop {
        let mut all_complete = true;
        iteration += 1;

        for result in &mut updated_results {
            if let Some(ref job_id) = result.job_id {
                // Skip if already in terminal state
                if matches!(
                    result.status,
                    Some(VerifyJobStatus::Success)
                        | Some(VerifyJobStatus::Fail)
                        | Some(VerifyJobStatus::CompileFailed)
                ) {
                    continue;
                }

                // Check job status (single API call, no retry)
                match api_client.get_job_status(job_id.to_string()) {
                    Ok(Some(status)) => {
                        let new_status = *status.status();
                        let status_changed = result.status != Some(new_status);
                        result.status = Some(new_status);

                        // Check if still pending
                        if !matches!(
                            new_status,
                            VerifyJobStatus::Success
                                | VerifyJobStatus::Fail
                                | VerifyJobStatus::CompileFailed
                        ) {
                            all_complete = false;
                        }

                        // Log status change
                        if status_changed {
                            debug!("Job {} status changed to {}", job_id, new_status);
                        }
                    }
                    Ok(None) => {
                        // Job still in progress
                        all_complete = false;
                    }
                    Err(e) => {
                        warn!("Failed to check job {}: {}", job_id, e);
                        result.error = Some(e.to_string());
                    }
                }
            }
        }

        // Display status update
        if output_format == &crate::args::OutputFormat::Text {
            print_batch_status_inline(&updated_results, iteration);
        }

        if all_complete {
            println!(); // Newline after inline status
            break;
        }

        std::thread::sleep(std::time::Duration::from_secs(5));
    }

    Ok(BatchVerificationSummary {
        total: summary.total,
        submitted: summary.submitted,
        results: updated_results,
    })
}

/// Print batch verification status inline (for live updates)
fn print_batch_status_inline(results: &[BatchVerificationResult], _iteration: u32) {
    let succeeded = results
        .iter()
        .filter(|r| matches!(r.status, Some(VerifyJobStatus::Success)))
        .count();

    let failed = results
        .iter()
        .filter(|r| {
            matches!(
                r.status,
                Some(VerifyJobStatus::Fail) | Some(VerifyJobStatus::CompileFailed)
            ) || r.error.is_some()
        })
        .count();

    let pending = results
        .iter()
        .filter(|r| {
            matches!(
                r.status,
                Some(VerifyJobStatus::Submitted)
                    | Some(VerifyJobStatus::Processing)
                    | Some(VerifyJobStatus::Compiled)
            )
        })
        .count();

    print!(
        "\r\x1B[2K  {} {} | {} {} | {} {}",
        "✓".green(),
        format!("{} Succeeded", succeeded).green(),
        "⏳".yellow(),
        format!("{} Pending", pending).yellow(),
        "✗".red(),
        format!("{} Failed", failed).red()
    );
    use std::io::Write;
    std::io::stdout().flush().ok();
}

/// Display batch verification summary
///
/// Shows a formatted summary of the batch verification results including
/// total contracts, submission counts, and success/failure statistics.
///
/// # Arguments
///
/// * `summary` - The batch verification summary to display
pub fn display_batch_summary(summary: &BatchVerificationSummary) {
    let succeeded = summary
        .results
        .iter()
        .filter(|r| matches!(r.status, Some(VerifyJobStatus::Success)))
        .count();

    let failed = summary
        .results
        .iter()
        .filter(|r| {
            matches!(
                r.status,
                Some(VerifyJobStatus::Fail) | Some(VerifyJobStatus::CompileFailed)
            ) || r.error.is_some()
        })
        .count();

    let pending = summary
        .results
        .iter()
        .filter(|r| {
            matches!(
                r.status,
                Some(VerifyJobStatus::Submitted)
                    | Some(VerifyJobStatus::Processing)
                    | Some(VerifyJobStatus::Compiled)
            )
        })
        .count();

    println!("\n{}", "═".repeat(60).bright_cyan());
    println!("{}", "Batch Verification Summary".bright_cyan().bold());
    println!("{}", "═".repeat(60).bright_cyan());
    println!("Total contracts:  {}", summary.total);
    println!("Submitted:        {}", summary.submitted.to_string().cyan());
    println!("Succeeded:        {}", succeeded.to_string().green());
    println!("Failed:           {}", failed.to_string().red());
    println!("Pending:          {}", pending.to_string().yellow());
    println!("{}", "═".repeat(60).bright_cyan());

    // Show detailed results
    println!("\n{}", "Contract Details:".bright_white().bold());
    for result in &summary.results {
        let contract_name = result.contract.contract_name.bright_white().bold();
        let class_hash_short = format!(
            "{}...{}",
            &result.contract.class_hash.to_string()[..10],
            &result.contract.class_hash.to_string()
                [result.contract.class_hash.to_string().len() - 6..]
        );

        match (&result.status, &result.error) {
            (Some(VerifyJobStatus::Success), _) => {
                let job_id = result.job_id.as_deref().unwrap_or("-");
                println!(
                    "  {} {} ({})",
                    "✓".green().bold(),
                    contract_name,
                    class_hash_short.bright_black()
                );
                println!("    Job ID: {}", job_id.cyan());
            }
            (Some(VerifyJobStatus::Fail), _) | (Some(VerifyJobStatus::CompileFailed), _) => {
                println!(
                    "  {} {} ({})",
                    "✗".red().bold(),
                    contract_name,
                    class_hash_short.bright_black()
                );
                println!("    Status: {}", "Failed".red());
            }
            (Some(status), _) => {
                let job_id = result.job_id.as_deref().unwrap_or("-");
                println!(
                    "  {} {} ({})",
                    "⏳".yellow(),
                    contract_name,
                    class_hash_short.bright_black()
                );
                println!("    Status: {}", status.to_string().yellow());
                println!("    Job ID: {}", job_id.cyan());
            }
            (None, Some(err)) => {
                println!(
                    "  {} {} ({})",
                    "✗".red().bold(),
                    contract_name,
                    class_hash_short.bright_black()
                );
                // Extract just the first line of the error (before suggestions)
                let error_line = err.lines().next().unwrap_or(err);
                println!("    Error: {}", error_line.red());
            }
            (None, None) => {
                println!(
                    "  {} {} ({})",
                    "○".bright_black(),
                    contract_name,
                    class_hash_short.bright_black()
                );
                println!("    Status: Not submitted");
            }
        }
    }
    println!();
}
