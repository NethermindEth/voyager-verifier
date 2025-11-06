//! Desktop notification support for verification completion
//!
//! This module provides optional desktop notification functionality to alert users
//! when verification jobs complete. This is particularly useful when using --watch
//! mode, allowing users to work on other tasks while waiting for verification.

#[cfg(feature = "notifications")]
use notify_rust::Notification;

use crate::api::VerifyJobStatus;

/// Send a desktop notification about verification completion
///
/// This function sends a platform-native desktop notification to inform the user
/// about the verification result. It handles all terminal verification states:
/// - Success: Shows a success notification with green indicator
/// - Fail/CompileFailed: Shows a failure notification with red indicator
///
/// # Arguments
///
/// * `contract_name` - The name of the contract that was verified
/// * `status` - The final verification status
/// * `job_id` - The verification job ID for reference
///
/// # Errors
///
/// Returns an error if the notification system is unavailable or fails to send.
/// Errors are logged but don't interrupt the verification flow.
#[cfg(feature = "notifications")]
pub fn send_verification_notification(
    contract_name: &str,
    status: VerifyJobStatus,
    job_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let (summary, body) = match status {
        VerifyJobStatus::Success => (
            "✅ Verification Successful",
            format!(
                "Contract '{contract_name}' has been successfully verified!\n\nJob ID: {job_id}"
            ),
        ),
        VerifyJobStatus::Fail => (
            "❌ Verification Failed",
            format!("Contract '{contract_name}' verification failed.\n\nJob ID: {job_id}"),
        ),
        VerifyJobStatus::CompileFailed => (
            "❌ Compilation Failed",
            format!("Contract '{contract_name}' compilation failed.\n\nJob ID: {job_id}"),
        ),
        _ => {
            // Don't send notifications for non-terminal states
            return Ok(());
        }
    };

    let mut notification = Notification::new();
    notification
        .summary(summary)
        .body(&body)
        .timeout(notify_rust::Timeout::Milliseconds(6000));

    // Urgency is only supported on Linux (D-Bus notifications)
    #[cfg(target_os = "linux")]
    {
        let urgency = match status {
            VerifyJobStatus::Fail | VerifyJobStatus::CompileFailed => {
                notify_rust::Urgency::Critical
            }
            _ => notify_rust::Urgency::Normal,
        };
        notification.urgency(urgency);
    }

    notification.show()?;

    Ok(())
}

/// Stub function when notifications feature is disabled
#[cfg(not(feature = "notifications"))]
pub fn send_verification_notification(
    _contract_name: &str,
    _status: VerifyJobStatus,
    _job_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    // Notifications disabled - do nothing
    Ok(())
}
