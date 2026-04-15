use crate::{
    api::{ApiClient, ApiClientError},
    cli::{
        args::{OutputFormat, VerifyArgs},
        config::Config,
        wizard,
    },
    core::verification::{check, display_verbose_error, display_verification_job_id, submit},
    utils::{errors::CliError, license},
};
use anyhow::Result;
use log::info;

/// Handles the verify command with both batch and single verification modes
///
/// # Errors
///
/// Returns an error if:
/// - Configuration validation fails
/// - API client creation fails
/// - Verification submission fails
/// - Polling for verification status fails
pub fn handle_verify_command(args: VerifyArgs, config: Option<&Config>) -> Result<()> {
    // Merge config with CLI args (CLI args take precedence)
    let args = if let Some(cfg) = config {
        args.merge_with_config(cfg)
    } else {
        args
    };

    // Detect batch mode - convert Option<&Config> to &Option<Config>
    let config_owned = config.cloned();
    let is_batch = args.is_batch_mode(&config_owned);

    // Validate based on mode
    if !is_batch && !args.wizard {
        // Single verification mode requires class_hash and contract_name
        if args.class_hash.is_none() {
            eprintln!("Error: --class-hash is required for single contract verification");
            eprintln!(
                "Tip: Use --wizard for interactive mode or add [[contracts]] to .voyager.toml for batch mode"
            );
            std::process::exit(1);
        }
        if args.contract_name.is_none() {
            eprintln!("Error: --contract-name is required for single contract verification");
            eprintln!(
                "Tip: Use --wizard for interactive mode or add [[contracts]] to .voyager.toml for batch mode"
            );
            std::process::exit(1);
        }
    }

    if is_batch {
        handle_batch_verification(&args, config_owned.as_ref())?;
    } else {
        handle_single_verification(args)?;
    }

    Ok(())
}

/// Handles batch verification mode for multiple contracts
///
/// # Errors
///
/// Returns an error if:
/// - Validation fails
/// - API client creation fails
/// - Batch submission fails
/// - Watch mode polling fails
fn handle_batch_verification(args: &VerifyArgs, config: Option<&Config>) -> Result<()> {
    // SAFETY: is_batch is only true when config contains [[contracts]], so config must be Some
    let cfg = config.unwrap_or_else(|| {
        unreachable!("Config must exist for batch mode - is_batch_mode() guarantees this")
    });

    // Validate: can't specify --class-hash in batch mode
    if args.class_hash.is_some() {
        eprintln!("Error: Cannot use --class-hash with batch verification.");
        eprintln!("Remove [[contracts]] from .voyager.toml or remove --class-hash flag.");
        std::process::exit(1);
    }

    // Validate: can't use wizard mode with batch
    if args.wizard {
        eprintln!("Error: Cannot use --wizard with batch verification.");
        eprintln!("Remove [[contracts]] from .voyager.toml or remove --wizard flag.");
        std::process::exit(1);
    }

    // Validate URL is set
    if let Err(err) = args.validate() {
        eprintln!("Error: {err}");
        std::process::exit(1);
    }

    let api_client = ApiClient::new(args.network_url.url.clone())?;

    let license_info = license::resolve_license_info(
        args.license,
        args.path.get_license(),
        args.path.manifest_path(),
    );
    license::warn_if_no_license(&license_info);

    // Submit batch
    let summary = crate::core::verification::submit_batch(&api_client, args, cfg, &license_info)
        .inspect_err(|e| {
            if args.verbose {
                display_verbose_error(e);
            }
        })?;

    // Display summary
    crate::core::verification::display_batch_summary(&summary);

    // Watch mode
    if args.watch && summary.submitted > 0 {
        let final_summary =
            crate::core::verification::watch_batch(&api_client, &summary, &OutputFormat::Text)
                .inspect_err(|e| {
                    if args.verbose {
                        display_verbose_error(e);
                    }
                })?;

        println!("\n=== Final Summary ===");
        crate::core::verification::display_batch_summary(&final_summary);
    }

    Ok(())
}

/// Handles single contract verification mode
///
/// # Errors
///
/// Returns an error if:
/// - Validation fails
/// - Wizard mode fails
/// - API client creation fails
/// - Verification submission fails
/// - Watch mode polling fails
/// - Desktop notification fails (non-fatal, logged as warning)
fn handle_single_verification(args: VerifyArgs) -> Result<()> {
    // Validate network URL
    if let Err(err) = args.validate() {
        eprintln!("Error: {err}");
        std::process::exit(1);
    }

    // Check if wizard mode is enabled
    let args = if args.wizard {
        // Run the wizard with the already-loaded project
        wizard::run_wizard(args.path)?
    } else {
        args
    };

    let api_client = ApiClient::new(args.network_url.url.clone())?;

    let license_info = license::resolve_license_info(
        args.license,
        args.path.get_license(),
        args.path.manifest_path(),
    );

    license::warn_if_no_license(&license_info);

    let job_id = submit(&api_client, &args, &license_info).inspect_err(|e| {
        if args.verbose {
            display_verbose_error(e);
        }
        display_error_suggestions(e);
    })?;

    if job_id != "dry-run" {
        display_verification_job_id(&job_id);

        // If --watch flag is enabled, poll for verification result
        if args.watch {
            let status = check(&api_client, &job_id, &OutputFormat::Text).inspect_err(|e| {
                if args.verbose {
                    display_verbose_error(e);
                }
                display_error_suggestions(e);
            })?;
            info!("{status:?}");

            // Send desktop notification if enabled
            #[cfg(feature = "notifications")]
            if args.notify {
                if let Some(ref contract_name) = args.contract_name {
                    if let Err(e) = crate::output::notifications::send_verification_notification(
                        contract_name,
                        *status.status(),
                        &job_id,
                    ) {
                        eprintln!("Warning: Failed to send desktop notification: {e}");
                    }
                }
            }
        }
    }

    Ok(())
}

/// Displays error suggestions based on the error type
fn display_error_suggestions(error: &CliError) {
    if let CliError::Api(ApiClientError::Verify(ref verification_error)) = error {
        eprintln!("\nSuggestions:");
        for suggestion in verification_error.suggestions() {
            eprintln!("  • {suggestion}");
        }
    }
    // RequestFailure errors already include suggestions in their display
}
