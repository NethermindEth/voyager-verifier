use crate::{
    api::{ApiClient, ApiClientError},
    cli::{args::StatusArgs, config::Config},
    core::verification::{check, display_verbose_error},
    utils::errors::CliError,
};
use anyhow::Result;
use log::info;

/// Handles the status command for checking verification job status
///
/// # Errors
///
/// Returns an error if:
/// - Validation fails
/// - API client creation fails
/// - Status check request fails
pub fn handle_status_command(args: StatusArgs, config: Option<&Config>) -> Result<()> {
    // Merge config with CLI args (CLI args take precedence)
    let args = if let Some(cfg) = config {
        args.merge_with_config(cfg)
    } else {
        args
    };

    // Validate that all required fields are set
    if let Err(err) = args.validate() {
        eprintln!("Error: {err}");
        std::process::exit(1);
    }

    let api_client = ApiClient::new(args.network_url.url.clone())?;
    let status = check(&api_client, &args.job, &args.format).inspect_err(|e| {
        if args.verbose {
            display_verbose_error(e);
        }
        display_error_suggestions(e);
    })?;
    info!("{status:?}");

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
