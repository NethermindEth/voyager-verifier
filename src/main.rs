use verifier::args::{Args, Commands};

use clap::Parser;
use log::info;
use verifier::{
    api::{ApiClient, ApiClientError},
    config::Config,
    errors::CliError,
    license,
    verification::{check, display_verbose_error, display_verification_job_id, submit},
    wizard,
};

fn main() -> anyhow::Result<()> {
    env_logger::init();

    // Load configuration file if it exists
    let config = Config::find_and_load().unwrap_or_else(|err| {
        eprintln!("Warning: Failed to load config file: {err}");
        None
    });

    let Args { command: cmd } = Args::parse();

    match cmd {
        Commands::Verify(args) => {
            // Merge config with CLI args (CLI args take precedence)
            let args = if let Some(ref cfg) = config {
                args.merge_with_config(cfg)
            } else {
                args
            };

            // Validate that all required fields are set
            if !args.wizard {
                if let Err(err) = args.validate() {
                    eprintln!("Error: {err}");
                    std::process::exit(1);
                }
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

            let job_id = submit(&api_client, &args, &license_info).map_err(|e| {
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
            // Merge config with CLI args (CLI args take precedence)
            let args = if let Some(ref cfg) = config {
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
