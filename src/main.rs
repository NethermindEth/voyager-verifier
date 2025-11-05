use verifier::args::{Args, Commands, HistoryCommands};

use clap::Parser;
use log::info;
use verifier::{
    api::{ApiClient, ApiClientError},
    config::Config,
    errors::CliError,
    license, notifications,
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

            // Detect batch mode
            let is_batch = args.is_batch_mode(&config);

            // Validate based on mode
            if !is_batch && !args.wizard {
                // Single verification mode requires class_hash and contract_name
                if args.class_hash.is_none() {
                    eprintln!("Error: --class-hash is required for single contract verification");
                    eprintln!("Tip: Use --wizard for interactive mode or add [[contracts]] to .voyager.toml for batch mode");
                    std::process::exit(1);
                }
                if args.contract_name.is_none() {
                    eprintln!(
                        "Error: --contract-name is required for single contract verification"
                    );
                    eprintln!("Tip: Use --wizard for interactive mode or add [[contracts]] to .voyager.toml for batch mode");
                    std::process::exit(1);
                }
            }

            if is_batch {
                // ========== BATCH MODE ==========
                // SAFETY: is_batch is only true when config contains [[contracts]], so config must be Some
                let cfg = config.as_ref().unwrap_or_else(|| {
                    unreachable!(
                        "Config must exist for batch mode - is_batch_mode() guarantees this"
                    )
                });

                // Validate: can't specify --class-hash in batch mode
                if args.class_hash.is_some() {
                    eprintln!("Error: Cannot use --class-hash with batch verification.");
                    eprintln!(
                        "Remove [[contracts]] from .voyager.toml or remove --class-hash flag."
                    );
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
                let summary =
                    verifier::verification::submit_batch(&api_client, &args, cfg, &license_info)
                        .inspect_err(|e| {
                            if args.verbose {
                                display_verbose_error(e);
                            }
                        })?;

                // Display summary
                verifier::verification::display_batch_summary(&summary);

                // Watch mode
                if args.watch && summary.submitted > 0 {
                    let final_summary = verifier::verification::watch_batch(
                        &api_client,
                        &summary,
                        &verifier::args::OutputFormat::Text,
                    )
                    .inspect_err(|e| {
                        if args.verbose {
                            display_verbose_error(e);
                        }
                    })?;

                    println!("\n=== Final Summary ===");
                    verifier::verification::display_batch_summary(&final_summary);
                }
            } else {
                // ========== SINGLE MODE (existing code) ==========
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
                        let status =
                            check(&api_client, &job_id, &verifier::args::OutputFormat::Text)
                                .map_err(|e| {
                                    if args.verbose {
                                        display_verbose_error(&e);
                                    }
                                    if let CliError::Api(ApiClientError::Verify(
                                        ref verification_error,
                                    )) = e
                                    {
                                        eprintln!("\nSuggestions:");
                                        for suggestion in verification_error.suggestions() {
                                            eprintln!("  • {suggestion}");
                                        }
                                    } else if let CliError::Api(ApiClientError::Failure(
                                        ref _request_failure,
                                    )) = e
                                    {
                                        // RequestFailure errors already include suggestions in their display
                                    }
                                    e
                                })?;
                        info!("{status:?}");

                        // Send desktop notification if enabled
                        #[cfg(feature = "notifications")]
                        if args.notify {
                            if let Some(ref contract_name) = args.contract_name {
                                if let Err(e) = notifications::send_verification_notification(
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
            let status = check(&api_client, &args.job, &args.format).map_err(|e| {
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
        Commands::History(args) => {
            handle_history_command(args, config)?;
        }
    }
    Ok(())
}

fn handle_history_command(
    args: verifier::args::HistoryArgs,
    config: Option<Config>,
) -> anyhow::Result<()> {
    use colored::*;
    use verifier::history::HistoryDb;

    match args.command {
        HistoryCommands::List {
            status,
            network,
            limit,
        } => {
            let db = HistoryDb::open().map_err(|e| {
                eprintln!("Failed to open history database: {e}");
                e
            })?;

            let records = db.list(status.as_deref(), network.as_deref(), Some(limit))?;

            if records.is_empty() {
                println!("\nNo verification history found.");
                println!("Verification jobs will be automatically tracked when you use 'voyager verify'.\n");
                return Ok(());
            }

            println!("\n{}", "Verification History".bold().underline());
            println!();

            let records_count = records.len();
            for record in records {
                let status_colored = match record.status.as_str() {
                    "Success" => record.status.green().bold(),
                    "Fail" | "CompileFailed" => record.status.red().bold(),
                    _ => record.status.yellow(),
                };

                println!("{} {}", "Job ID:".bold(), record.job_id);
                println!("  Contract: {}", record.contract_name);
                println!("  Class Hash: {}", record.class_hash);
                println!("  Network: {}", record.network);
                println!("  Status: {status_colored}");
                println!(
                    "  Submitted: {}",
                    record.submitted_at.format("%Y-%m-%d %H:%M:%S UTC")
                );
                if let Some(completed) = record.completed_at {
                    println!("  Completed: {}", completed.format("%Y-%m-%d %H:%M:%S UTC"));
                }
                if let Some(pkg) = record.package_name {
                    println!("  Package: {pkg}");
                }
                println!(
                    "  Cairo: {}, Scarb: {}",
                    record.cairo_version, record.scarb_version
                );
                if let Some(dojo) = record.dojo_version {
                    println!("  Dojo: {dojo}");
                }
                println!();
            }

            println!("Showing {} record(s)", records_count);
            println!();
        }
        HistoryCommands::Status {
            job,
            network,
            network_url,
            refresh,
            verbose,
        } => {
            let db = HistoryDb::open()?;

            // Get record from database
            let record = db.get_by_job_id(&job)?;

            if let Some(mut rec) = record {
                if refresh {
                    // Merge network with config
                    let _network = if network.is_none() {
                        config.as_ref().and_then(|cfg| cfg.parse_network())
                    } else {
                        network
                    };

                    // Validate URL
                    let url = if network_url.url.as_str() == "https://placeholder.invalid/" {
                        if let Some(ref cfg) = config {
                            if let Some(ref url_str) = cfg.voyager.url {
                                reqwest::Url::parse(url_str)?
                            } else {
                                eprintln!("Error: API URL is required. Provide --network, --url, or set 'network' or 'url' in .voyager.toml");
                                std::process::exit(1);
                            }
                        } else {
                            eprintln!("Error: API URL is required. Provide --network, --url, or set 'network' or 'url' in .voyager.toml");
                            std::process::exit(1);
                        }
                    } else {
                        network_url.url
                    };

                    let api_client = ApiClient::new(url)?;
                    let status = verifier::api::poll_verification_status(&api_client, &job)
                        .map_err(|e| {
                            let cli_error = CliError::from(e);
                            if verbose {
                                display_verbose_error(&cli_error);
                            }
                            cli_error
                        })?;

                    // Update the database record
                    rec.update_status(*status.status());
                    db.update_status(&job, &rec.status, rec.completed_at)?;
                } else {
                    // Display from database
                    let status_colored = match rec.status.as_str() {
                        "Success" => rec.status.green().bold(),
                        "Fail" | "CompileFailed" => rec.status.red().bold(),
                        _ => rec.status.yellow(),
                    };

                    println!("\n{} {}", "Job ID:".bold(), rec.job_id);
                    println!("Contract: {}", rec.contract_name);
                    println!("Class Hash: {}", rec.class_hash);
                    println!("Network: {}", rec.network);
                    println!("Status: {status_colored}");
                    println!(
                        "Submitted: {}",
                        rec.submitted_at.format("%Y-%m-%d %H:%M:%S UTC")
                    );
                    if let Some(completed) = rec.completed_at {
                        println!("Completed: {}", completed.format("%Y-%m-%d %H:%M:%S UTC"));
                    }
                    if let Some(pkg) = rec.package_name {
                        println!("Package: {pkg}");
                    }
                    println!("Cairo version: {}", rec.cairo_version);
                    println!("Scarb version: {}", rec.scarb_version);
                    if let Some(dojo) = rec.dojo_version {
                        println!("Dojo version: {dojo}");
                    }
                    println!("\nUse --refresh to update status from the API.\n");
                }
            } else {
                println!("\n❌ Job ID not found in local history: {job}");
                println!("\nThis job may not have been tracked, or it was cleaned from history.\n");
            }
        }
        HistoryCommands::Recheck {
            network,
            network_url,
            verbose,
        } => {
            let db = HistoryDb::open()?;

            // Get all pending jobs
            let pending = db.list(Some("Submitted"), None, None)?;
            let processing = db.list(Some("Processing"), None, None)?;
            let compiled = db.list(Some("Compiled"), None, None)?;

            let all_pending: Vec<_> = pending
                .into_iter()
                .chain(processing)
                .chain(compiled)
                .collect();

            if all_pending.is_empty() {
                println!("\n✅ No pending verification jobs found.\n");
                return Ok(());
            }

            println!("\n🔄 Re-checking {} pending job(s)...\n", all_pending.len());

            // Merge network with config
            let _network = if network.is_none() {
                config.as_ref().and_then(|cfg| cfg.parse_network())
            } else {
                network
            };

            // Validate URL
            let url = if network_url.url.as_str() == "https://placeholder.invalid/" {
                if let Some(ref cfg) = config {
                    if let Some(ref url_str) = cfg.voyager.url {
                        reqwest::Url::parse(url_str)?
                    } else {
                        eprintln!("Error: API URL is required. Provide --network, --url, or set 'network' or 'url' in .voyager.toml");
                        std::process::exit(1);
                    }
                } else {
                    eprintln!("Error: API URL is required. Provide --network, --url, or set 'network' or 'url' in .voyager.toml");
                    std::process::exit(1);
                }
            } else {
                network_url.url
            };

            let api_client = ApiClient::new(url)?;

            let mut updated = 0;
            for mut rec in all_pending {
                print!("Checking {}... ", rec.job_id);
                match verifier::api::poll_verification_status(&api_client, &rec.job_id) {
                    Ok(status) => {
                        let old_status = rec.status.clone();
                        rec.update_status(*status.status());

                        if old_status != rec.status {
                            db.update_status(&rec.job_id, &rec.status, rec.completed_at)?;
                            let status_colored = match rec.status.as_str() {
                                "Success" => rec.status.green().bold(),
                                "Fail" | "CompileFailed" => rec.status.red().bold(),
                                _ => rec.status.yellow(),
                            };
                            println!("{status_colored}");
                            updated += 1;
                        } else {
                            println!("{}", rec.status.yellow());
                        }
                    }
                    Err(e) => {
                        println!("{}", "Error".red());
                        if verbose {
                            let cli_error: CliError = e.into();
                            display_verbose_error(&cli_error);
                        }
                    }
                }
            }

            println!("\n✅ Updated {} job(s).\n", updated);
        }
        HistoryCommands::Clean { older_than, all } => {
            let db = HistoryDb::open()?;

            if all {
                print!("⚠️  Are you sure you want to delete ALL verification history? (y/N): ");
                use std::io::{self, Write};
                io::stdout().flush()?;

                let mut input = String::new();
                io::stdin().read_line(&mut input)?;

                if input.trim().to_lowercase() == "y" {
                    let deleted = db.clean_all()?;
                    println!("\n✅ Deleted {deleted} record(s).\n");
                } else {
                    println!("\n❌ Cancelled.\n");
                }
            } else if let Some(days) = older_than {
                let deleted = db.clean_older_than(days)?;
                println!("\n✅ Deleted {deleted} record(s) older than {days} days.\n");
            } else {
                eprintln!("Error: Either --older-than or --all must be specified");
                std::process::exit(1);
            }
        }
        HistoryCommands::Stats => {
            let db = HistoryDb::open()?;
            let stats = db.get_stats()?;

            println!("\n{}", "Verification History Statistics".bold().underline());
            println!();
            println!("Total verifications: {}", stats.total);
            println!(
                "Successful: {} ({}%)",
                stats.successful.to_string().green().bold(),
                if stats.total > 0 {
                    stats.successful * 100 / stats.total
                } else {
                    0
                }
            );
            println!(
                "Failed: {} ({}%)",
                stats.failed.to_string().red().bold(),
                if stats.total > 0 {
                    stats.failed * 100 / stats.total
                } else {
                    0
                }
            );
            println!(
                "Pending: {} ({}%)",
                stats.pending.to_string().yellow(),
                if stats.total > 0 {
                    stats.pending * 100 / stats.total
                } else {
                    0
                }
            );
            println!();
        }
    }

    Ok(())
}
