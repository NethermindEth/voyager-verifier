use verifier::args::{Args, Commands};

use clap::Parser;
use log::info;
use verifier::{
    api::{ApiClient, ApiClientError},
    errors::CliError,
    license,
    verification::{check, display_verbose_error, display_verification_job_id, submit},
};

fn main() -> anyhow::Result<()> {
    env_logger::init();
    let Args { command: cmd } = Args::parse();

    match &cmd {
        Commands::Verify(args) => {
            let api_client = ApiClient::new(args.network_url.url.clone())?;

            let license_info = license::resolve_license_info(
                args.license,
                args.path.get_license(),
                args.path.manifest_path(),
            );

            license::warn_if_no_license(&license_info);

            let job_id = submit(&api_client, args, &license_info).map_err(|e| {
                if args.verbose {
                    display_verbose_error(&e);
                }
                if let CliError::Api(ApiClientError::Verify(ref verification_error)) = e {
                    eprintln!("\nSuggestions:");
                    for suggestion in verification_error.suggestions() {
                        eprintln!("  • {suggestion}");
                    }
                } else if let CliError::Api(ApiClientError::Failure(ref _request_failure)) = e {
                    // RequestFailure errors already include suggestions in their display
                }
                e
            })?;
            if job_id != "dry-run" {
                display_verification_job_id(&job_id);

                // If --watch flag is enabled, poll for verification result
                if args.watch {
                    let status = check(&api_client, &job_id).map_err(|e| {
                        if args.verbose {
                            display_verbose_error(&e);
                        }
                        if let CliError::Api(ApiClientError::Verify(ref verification_error)) = e {
                            eprintln!("\nSuggestions:");
                            for suggestion in verification_error.suggestions() {
                                eprintln!("  • {suggestion}");
                            }
                        } else if let CliError::Api(ApiClientError::Failure(ref _request_failure)) =
                            e
                        {
                            // RequestFailure errors already include suggestions in their display
                        }
                        e
                    })?;
                    info!("{status:?}");
                }
            }
        }
        Commands::Status(args) => {
            let api_client = ApiClient::new(args.network_url.url.clone())?;
            let status = check(&api_client, &args.job).map_err(|e| {
                if args.verbose {
                    display_verbose_error(&e);
                }
                if let CliError::Api(ApiClientError::Verify(ref verification_error)) = e {
                    eprintln!("\nSuggestions:");
                    for suggestion in verification_error.suggestions() {
                        eprintln!("  • {suggestion}");
                    }
                } else if let CliError::Api(ApiClientError::Failure(ref _request_failure)) = e {
                    // RequestFailure errors already include suggestions in their display
                }
                e
            })?;
            info!("{status:?}");
        }
    }
    Ok(())
}
