use crate::{
    api::ApiClient,
    cli::{
        args::{HistoryArgs, HistoryCommands, Network, NetworkKind},
        config::Config,
    },
    core::verification::display_verbose_error,
    storage::history::{HistoryDb, VerificationRecord},
    utils::errors::CliError,
};
use anyhow::Result;

/// Handles all history-related commands (list, status, recheck, clean, stats)
///
/// # Errors
///
/// Returns an error if:
/// - Database operations fail (opening, reading, writing)
/// - API requests fail when refreshing status or rechecking jobs
/// - I/O operations fail (user input, stdout)
pub fn handle_history_command(args: HistoryArgs, config: Option<&Config>) -> Result<()> {
    match args.command {
        HistoryCommands::List {
            status,
            network,
            limit,
        } => handle_history_list(status.as_deref(), network.as_deref(), limit),
        HistoryCommands::Status {
            job,
            network,
            network_url,
            refresh,
            verbose,
        } => handle_history_status(&job, network, network_url, refresh, verbose, config),
        HistoryCommands::Recheck {
            network,
            network_url,
            verbose,
        } => handle_history_recheck(network, network_url, verbose, config),
        HistoryCommands::Clean { older_than, all } => handle_history_clean(older_than, all),
        HistoryCommands::Stats => handle_history_stats(),
    }
}

fn handle_history_list(status: Option<&str>, network: Option<&str>, limit: usize) -> Result<()> {
    use colored::Colorize;

    let db = HistoryDb::open().map_err(|e| {
        eprintln!("Failed to open history database: {e}");
        e
    })?;

    let records = db.list(status, network, Some(limit))?;

    if records.is_empty() {
        println!("\nNo verification history found.");
        println!(
            "Verification jobs will be automatically tracked when you use 'voyager verify'.\n"
        );
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

    println!("Showing {records_count} record(s)");
    println!();

    Ok(())
}

fn handle_history_status(
    job: &str,
    network: Option<NetworkKind>,
    network_url: Network,
    refresh: bool,
    verbose: bool,
    config: Option<&Config>,
) -> Result<()> {
    let db = HistoryDb::open()?;

    // Get record from database
    let record = db.get_by_job_id(job)?;

    if let Some(mut rec) = record {
        if refresh {
            // Merge network with config
            let _network = if network.is_none() {
                config.as_ref().and_then(|cfg| cfg.parse_network())
            } else {
                network
            };

            let url = super::super::config::resolve_api_url(network_url, config)?;
            let api_client = ApiClient::new(url)?;
            let status = crate::api::poll_verification_status(&api_client, job).map_err(|e| {
                let cli_error = CliError::from(e);
                if verbose {
                    display_verbose_error(&cli_error);
                }
                cli_error
            })?;

            // Update the database record
            rec.update_status(*status.status());
            db.update_status(job, &rec.status, rec.completed_at)?;
        } else {
            display_history_record(&rec);
        }
    } else {
        println!("\n❌ Job ID not found in local history: {job}");
        println!("\nThis job may not have been tracked, or it was cleaned from history.\n");
    }

    Ok(())
}

/// Displays a history record to the console
fn display_history_record(rec: &VerificationRecord) {
    use colored::Colorize;

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
    if let Some(ref pkg) = rec.package_name {
        println!("Package: {pkg}");
    }
    println!("Cairo version: {}", rec.cairo_version);
    println!("Scarb version: {}", rec.scarb_version);
    if let Some(ref dojo) = rec.dojo_version {
        println!("Dojo version: {dojo}");
    }
    println!("\nUse --refresh to update status from the API.\n");
}

fn handle_history_recheck(
    network: Option<NetworkKind>,
    network_url: Network,
    verbose: bool,
    config: Option<&Config>,
) -> Result<()> {
    use colored::Colorize;

    let db = HistoryDb::open()?;

    // Get all pending jobs
    let all_pending = get_all_pending_jobs(&db)?;

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

    let url = super::super::config::resolve_api_url(network_url, config)?;
    let api_client = ApiClient::new(url)?;

    let mut updated = 0;
    for mut rec in all_pending {
        print!("Checking {}... ", rec.job_id);
        match crate::api::poll_verification_status(&api_client, &rec.job_id) {
            Ok(status) => {
                let old_status = rec.status.clone();
                rec.update_status(*status.status());

                if old_status == rec.status {
                    println!("{}", rec.status.yellow());
                } else {
                    db.update_status(&rec.job_id, &rec.status, rec.completed_at)?;
                    let status_colored = match rec.status.as_str() {
                        "Success" => rec.status.green().bold(),
                        "Fail" | "CompileFailed" => rec.status.red().bold(),
                        _ => rec.status.yellow(),
                    };
                    println!("{status_colored}");
                    updated += 1;
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

    println!("\n✅ Updated {updated} job(s).\n");

    Ok(())
}

/// Gets all pending verification jobs from the database
fn get_all_pending_jobs(db: &HistoryDb) -> Result<Vec<VerificationRecord>> {
    let pending = db.list(Some("Submitted"), None, None)?;
    let processing = db.list(Some("Processing"), None, None)?;
    let compiled = db.list(Some("Compiled"), None, None)?;

    Ok(pending
        .into_iter()
        .chain(processing)
        .chain(compiled)
        .collect())
}

fn handle_history_clean(older_than: Option<u32>, all: bool) -> Result<()> {
    use std::io::{self, Write};

    let db = HistoryDb::open()?;

    if all {
        print!("⚠️  Are you sure you want to delete ALL verification history? (y/N): ");
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

    Ok(())
}

fn handle_history_stats() -> Result<()> {
    use colored::Colorize;

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

    Ok(())
}
