use crate::{
    api::{ApiClient, ApiClientError, ClassVerificationInfo},
    cli::{args::CheckArgs, config::Config},
    output::status::format_timestamp,
    utils::errors::CliError,
};
use anyhow::Result;
use colored::Colorize;

/// Handles the check command for verifying if a class is already verified
///
/// # Errors
///
/// Returns an error if:
/// - Validation fails
/// - API client creation fails
/// - Check request fails
pub fn handle_check_command(args: CheckArgs, config: Option<&Config>) -> Result<()> {
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

    match api_client.check_class_verification(&args.class_hash) {
        Ok(info) => {
            display_verification_info(&args, &info);
            Ok(())
        }
        Err(ApiClientError::ClassNotFound(hash)) => {
            println!(
                "\n{} Class {} {}",
                "!".yellow().bold(),
                hash.cyan(),
                "not found on-chain".yellow()
            );
            println!();
            std::process::exit(1);
        }
        Err(e) => {
            if args.verbose {
                eprintln!("Error details: {e:?}");
            }
            Err(CliError::from(e).into())
        }
    }
}

fn display_verification_info(args: &CheckArgs, info: &ClassVerificationInfo) {
    if args.json {
        // Output as JSON
        println!(
            "{}",
            serde_json::to_string_pretty(&info).unwrap_or_else(|_| format!("{info:?}"))
        );
    } else if info.verified {
        println!(
            "\n{} Class {} is {}",
            "✓".green().bold(),
            args.class_hash.to_string().cyan(),
            "verified".green().bold()
        );
        if let Some(ref name) = info.name {
            println!("  Name: {name}");
        }
        if let Some(ref version) = info.version {
            println!("  Version: {version}");
        }
        if let Some(ref license) = info.license {
            println!("  License: {license}");
        }
        if let Some(ref contract_file) = info.contract_file {
            println!("  Contract file: {contract_file}");
        }
        if let Some(ts) = info.verified_timestamp {
            println!("  Verified: {}", format_timestamp(ts));
        }
        println!();
    } else {
        println!(
            "\n{} Class {} is {}",
            "✗".red().bold(),
            args.class_hash.to_string().cyan(),
            "not verified".yellow().bold()
        );
        println!();
    }
}
