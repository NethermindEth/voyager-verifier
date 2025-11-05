//! Enhanced status output formatting for verification jobs
//!
//! This module provides rich formatting options for displaying verification job status:
//! - Enhanced text output with progress bars and stage breakdown
//! - JSON output for programmatic parsing
//! - Table format for batch operations

use crate::api::{VerificationJob, VerifyJobStatus};
use crate::args::OutputFormat;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

/// Format timestamp as human-readable string
pub fn format_timestamp(timestamp: f64) -> String {
    let datetime = DateTime::from_timestamp(timestamp as i64, 0)
        .unwrap_or_else(|| DateTime::<Utc>::from(UNIX_EPOCH));
    datetime.format("%Y-%m-%d %H:%M:%S UTC").to_string()
}

/// Calculate elapsed time in seconds from creation to now
fn calculate_elapsed(created: Option<f64>, _updated: Option<f64>) -> Option<u64> {
    let start = created?;
    // Always use current time for live updates
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|d| d.as_secs() as f64)?;
    Some((now - start) as u64)
}

/// Calculate elapsed time in seconds between two timestamps (for completed jobs)
fn calculate_elapsed_between(created: Option<f64>, updated: Option<f64>) -> Option<u64> {
    let start = created?;
    let end = updated?;
    Some((end - start) as u64)
}

/// Format duration in seconds to human-readable string
fn format_duration(seconds: u64) -> String {
    if seconds < 60 {
        format!("{seconds}s")
    } else if seconds < 3600 {
        let mins = seconds / 60;
        let secs = seconds % 60;
        format!("{mins}m {secs}s")
    } else {
        let hours = seconds / 3600;
        let mins = (seconds % 3600) / 60;
        format!("{hours}h {mins}m")
    }
}

/// Get average verification time from history database
///
/// Queries the last 10 successful verifications and returns their average duration.
/// Returns None if there are fewer than 3 samples.
fn get_average_from_history() -> Option<u64> {
    use crate::history::HistoryDb;

    // Try to open history DB and get average
    HistoryDb::open().ok().and_then(|db| {
        db.get_average_verification_time(10, 3) // Last 10 samples, min 3
            .ok()
            .flatten()
    })
}

/// Estimate remaining time based on current stage and historical data
///
/// This function uses a two-tier approach:
/// 1. **History-based**: Queries the last 10 successful verifications from the local
///    database and calculates an average total time. Requires at least 3 samples.
/// 2. **Fallback (hardcoded)**: Conservative estimates based on observed backend behavior:
///    - Queue wait: 2-5 seconds (status goes from Submitted → `InProgress`)
///    - Compilation: 15-30 seconds (`InProgress` → Compiled)
///    - Verification: 2-5 seconds (Compiled → Success/Fail)
///    - Total: ~40 seconds
fn estimate_remaining_time(status: &VerifyJobStatus, elapsed: u64) -> Option<u64> {
    // Try to get history-based estimate first
    if let Some(avg_total) = get_average_from_history() {
        // Use historical average, adjusted by current stage
        let estimated_total = match status {
            VerifyJobStatus::Submitted => avg_total,
            VerifyJobStatus::Processing => {
                // We're past queue, estimate remaining as 85% of average
                (avg_total * 85) / 100
            }
            VerifyJobStatus::Compiled => {
                // We're past compilation, just verification left (~5-10% of total)
                (avg_total * 10) / 100
            }
            _ => return None,
        };

        return Some(estimated_total.saturating_sub(elapsed));
    }

    // Fallback to hardcoded estimates if no history available
    match status {
        VerifyJobStatus::Submitted => {
            // Total: ~40s (5s queue + 25s compile + 5s verify + 5s buffer)
            Some(40u64.saturating_sub(elapsed))
        }
        VerifyJobStatus::Processing => {
            // Compiling: ~25s + 5s verify + 5s buffer
            Some(35u64.saturating_sub(elapsed))
        }
        VerifyJobStatus::Compiled => {
            // Verifying sierra bytecode: ~5s
            Some(5u64.saturating_sub(elapsed))
        }
        _ => None, // Completed states don't need estimates
    }
}

/// Get progress percentage based on status
/// Based on actual verification flow: Submitted → `InProgress` → Compiling → Compiled → Verifying → Success
const fn get_progress_percentage(status: &VerifyJobStatus) -> u8 {
    match status {
        VerifyJobStatus::Submitted => 10,  // Job created, waiting in queue
        VerifyJobStatus::Processing => 40, // Picked up by worker, compiling
        VerifyJobStatus::Compiled => 85,   // Compilation done, verifying bytecode
        VerifyJobStatus::Success | VerifyJobStatus::CompileFailed | VerifyJobStatus::Fail => 100,
        VerifyJobStatus::Unknown => 0,
    }
}

/// Generate progress bar
fn progress_bar(percentage: u8) -> String {
    let filled = (percentage as usize * 20) / 100;
    let empty = 20 - filled;
    format!(
        "{}{} ({}%)",
        "█".repeat(filled),
        "░".repeat(empty),
        percentage
    )
}

/// Format verification job as enhanced text
pub fn format_text(job: &VerificationJob) -> String {
    let mut output = String::new();

    // Header with status emoji
    let status_emoji = match job.status() {
        VerifyJobStatus::Success => "✅",
        VerifyJobStatus::Fail | VerifyJobStatus::CompileFailed => "❌",
        _ => "⏳",
    };

    output.push_str(&format!("{} Verification Status\n\n", status_emoji));

    // Job details
    output.push_str(&format!("Job ID: {}\n", job.job_id()));
    output.push_str(&format!("Status: {}\n", job.status()));

    // Progress bar for in-progress jobs
    if !job.is_completed() {
        let percentage = get_progress_percentage(job.status());
        output.push_str(&format!("Progress: {}\n", progress_bar(percentage)));
    }

    // Network and contract details
    if let Some(network) = job.class_hash.as_ref() {
        output.push_str(&format!("Class Hash: {}\n", network));
    }
    if let Some(name) = job.name() {
        output.push_str(&format!("Contract: {}\n", name));
    }
    if let Some(file) = job.contract_file() {
        output.push_str(&format!("Contract File: {}\n", file));
    }

    // Time information
    if let Some(created) = job.created_timestamp() {
        output.push_str(&format!("Started: {}\n", format_timestamp(created)));
    }
    if let Some(updated) = job.updated_timestamp() {
        output.push_str(&format!("Last Updated: {}\n", format_timestamp(updated)));
    }

    // Elapsed and estimated time
    // For completed jobs, show actual elapsed time between created and updated
    // For in-progress jobs, show elapsed time from created to now
    let elapsed = if job.is_completed() {
        calculate_elapsed_between(job.created_timestamp(), job.updated_timestamp())
    } else {
        calculate_elapsed(job.created_timestamp(), job.updated_timestamp())
    };

    if let Some(elapsed_secs) = elapsed {
        output.push_str(&format!("Elapsed: {}\n", format_duration(elapsed_secs)));

        if let Some(remaining) = estimate_remaining_time(job.status(), elapsed_secs) {
            if remaining > 0 {
                output.push_str(&format!(
                    "Estimated Remaining: ~{}\n",
                    format_duration(remaining)
                ));
            }
        }
    }

    // Version information
    if let Some(version) = job.version() {
        output.push_str(&format!("Cairo Version: {}\n", version));
    }
    if let Some(dojo_version) = job.dojo_version() {
        output.push_str(&format!("Dojo Version: {}\n", dojo_version));
    }
    if let Some(license) = job.license() {
        output.push_str(&format!("License: {}\n", license));
    }

    // Status-specific messages
    match job.status() {
        VerifyJobStatus::Success => {
            output.push_str(&format!(
                "\n✅ Verification successful!\n\
                The contract is now verified and visible on Voyager at:\n\
                https://voyager.online/class/{}\n",
                job.class_hash()
            ));
        }
        VerifyJobStatus::Fail | VerifyJobStatus::CompileFailed => {
            output.push_str("\n❌ Verification failed!\n");
            if let Some(desc) = job.status_description() {
                output.push_str(&format!("Reason: {}\n", desc));
            }
            if let Some(msg) = job.message() {
                output.push_str(&format!("Message: {}\n", msg));
            }
        }
        _ => {
            output.push_str("\n⏳ Verification is in progress...\n");
            output.push_str("Use the same command to check progress later.\n");
        }
    }

    output
}

/// JSON output structure for programmatic parsing
#[derive(Debug, Serialize, Deserialize)]
pub struct JsonOutput {
    pub job_id: String,
    pub status: String,
    pub status_code: u8,
    pub is_completed: bool,
    pub has_failed: bool,
    pub progress_percentage: u8,
    pub class_hash: Option<String>,
    pub contract_name: Option<String>,
    pub contract_file: Option<String>,
    pub status_description: Option<String>,
    pub message: Option<String>,
    pub error_category: Option<String>,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
    pub elapsed_seconds: Option<u64>,
    pub estimated_remaining_seconds: Option<u64>,
    pub cairo_version: Option<String>,
    pub dojo_version: Option<String>,
    pub license: Option<String>,
    pub address: Option<String>,
    pub build_tool: Option<String>,
}

/// Format verification job as JSON
pub fn format_json(job: &VerificationJob) -> String {
    let elapsed = if job.is_completed() {
        calculate_elapsed_between(job.created_timestamp(), job.updated_timestamp())
    } else {
        calculate_elapsed(job.created_timestamp(), job.updated_timestamp())
    };
    let estimated_remaining = elapsed.and_then(|e| estimate_remaining_time(job.status(), e));

    let output = JsonOutput {
        job_id: job.job_id().to_string(),
        status: job.status().to_string(),
        status_code: *job.status() as u8,
        is_completed: job.is_completed(),
        has_failed: job.has_failed(),
        progress_percentage: get_progress_percentage(job.status()),
        class_hash: job.class_hash.clone(),
        contract_name: job.name().map(String::from),
        contract_file: job.contract_file().map(String::from),
        status_description: job.status_description().map(String::from),
        message: job.message().map(String::from),
        error_category: job.error_category().map(String::from),
        created_at: job.created_timestamp().map(format_timestamp),
        updated_at: job.updated_timestamp().map(format_timestamp),
        elapsed_seconds: elapsed,
        estimated_remaining_seconds: estimated_remaining,
        cairo_version: job.version().map(String::from),
        dojo_version: job.dojo_version().map(String::from),
        license: job.license().map(String::from),
        address: job.address().map(String::from),
        build_tool: job.build_tool().map(String::from),
    };

    serde_json::to_string_pretty(&output).unwrap_or_else(|e| {
        format!(
            "{{\"error\": \"Failed to serialize JSON: {}\"}}",
            e.to_string().replace('"', "\\\"")
        )
    })
}

/// Format verification job as table (primarily for batch operations)
pub fn format_table(job: &VerificationJob) -> String {
    let mut output = String::new();

    // Table header
    output.push_str(
        "┌─────────────────────────────────────────────────────────────────────────────┐\n",
    );
    output.push_str(
        "│                        Verification Job Status                              │\n",
    );
    output.push_str(
        "├─────────────────────────┬───────────────────────────────────────────────────┤\n",
    );

    // Job details in table format
    let add_row = |output: &mut String, key: &str, value: &str| {
        output.push_str(&format!("│ {:<23} │ {:<49} │\n", key, value));
    };

    add_row(&mut output, "Job ID", job.job_id());
    add_row(&mut output, "Status", &job.status().to_string());

    if !job.is_completed() {
        let percentage = get_progress_percentage(job.status());
        add_row(&mut output, "Progress", &format!("{}%", percentage));
    }

    if let Some(hash) = job.class_hash.as_ref() {
        let truncated = if hash.len() > 49 {
            format!("{}...", &hash[..46])
        } else {
            hash.clone()
        };
        add_row(&mut output, "Class Hash", &truncated);
    }

    if let Some(name) = job.name() {
        add_row(&mut output, "Contract", name);
    }

    if let Some(created) = job.created_timestamp() {
        add_row(&mut output, "Started", &format_timestamp(created));
    }

    let elapsed = if job.is_completed() {
        calculate_elapsed_between(job.created_timestamp(), job.updated_timestamp())
    } else {
        calculate_elapsed(job.created_timestamp(), job.updated_timestamp())
    };
    if let Some(elapsed_secs) = elapsed {
        add_row(&mut output, "Elapsed", &format_duration(elapsed_secs));
    }

    if let Some(version) = job.version() {
        add_row(&mut output, "Cairo Version", version);
    }

    // Table footer
    output.push_str(
        "└─────────────────────────┴───────────────────────────────────────────────────┘\n",
    );

    output
}

/// Format a single-line inline status for live updates with progress bar
pub fn format_inline_status(job: &VerificationJob) -> String {
    let stage = match job.status() {
        VerifyJobStatus::Submitted => "Submitted (waiting in queue)",
        VerifyJobStatus::Processing => "Compiling",
        VerifyJobStatus::Compiled => "Verifying bytecode",
        VerifyJobStatus::Success => "Success",
        VerifyJobStatus::CompileFailed => "Compilation failed",
        VerifyJobStatus::Fail => "Verification failed",
        VerifyJobStatus::Unknown => "Unknown",
    };

    let elapsed = calculate_elapsed(job.created_timestamp(), job.updated_timestamp());

    if let Some(elapsed_secs) = elapsed {
        let elapsed_str = format_duration(elapsed_secs);

        // Show progress bar for in-progress jobs
        if let Some(remaining_secs) = estimate_remaining_time(job.status(), elapsed_secs) {
            let total = elapsed_secs + remaining_secs;
            let percentage = if total > 0 {
                ((elapsed_secs as f64 / total as f64) * 100.0) as u8
            } else {
                0
            };

            let bar = progress_bar(percentage);
            return format!("⏳ {} {} [{}]", stage, bar, elapsed_str);
        }

        format!("⏳ {} [{}]", stage, elapsed_str)
    } else {
        format!("⏳ {}", stage)
    }
}

/// Main formatting function that delegates to specific formatters
pub fn format_status(job: &VerificationJob, format: &OutputFormat) -> String {
    match format {
        OutputFormat::Text => format_text(job),
        OutputFormat::Json => format_json(job),
        OutputFormat::Table => format_table(job),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_duration() {
        assert_eq!(format_duration(30), "30s");
        assert_eq!(format_duration(90), "1m 30s");
        assert_eq!(format_duration(3661), "1h 1m");
    }

    #[test]
    fn test_progress_percentage() {
        assert_eq!(get_progress_percentage(&VerifyJobStatus::Submitted), 10);
        assert_eq!(get_progress_percentage(&VerifyJobStatus::Processing), 40);
        assert_eq!(get_progress_percentage(&VerifyJobStatus::Compiled), 85);
        assert_eq!(get_progress_percentage(&VerifyJobStatus::Success), 100);
    }

    #[test]
    fn test_progress_bar() {
        let bar = progress_bar(50);
        assert!(bar.contains("50%"));
        assert!(bar.contains("█"));
        assert!(bar.contains("░"));
    }

    #[test]
    fn test_format_timestamp() {
        let ts = 1704067200.0; // 2024-01-01 00:00:00 UTC
        let formatted = format_timestamp(ts);
        assert!(formatted.contains("2024-01-01"));
    }
}
