use super::types::VerifyJobStatus;
use crate::core::project::ProjectType;
use semver;
use serde::{Deserialize, Serialize, Serializer};
use std::collections::HashMap;
use std::path::PathBuf;

/// Serialize an optional f64 timestamp as an integer
#[allow(clippy::ref_option, clippy::cast_possible_truncation)]
fn serialize_timestamp_as_i64<S>(value: &Option<f64>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    match value {
        Some(ts) => serializer.serialize_i64(*ts as i64),
        None => serializer.serialize_none(),
    }
}

/// Response from the class verification check endpoint
#[derive(Debug, Deserialize, Serialize)]
pub struct ClassVerificationInfo {
    pub verified: bool,
    pub class_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub license: Option<String>,
    #[serde(
        skip_serializing_if = "Option::is_none",
        serialize_with = "serialize_timestamp_as_i64"
    )]
    pub verified_timestamp: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contract_file: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct Error {
    pub error: String,
}

#[derive(Debug, Deserialize)]
pub struct VerificationJobDispatch {
    pub job_id: String,
}

/// Structured error information from the server
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ServerError {
    pub code: String,
    pub category: String,
    pub message: String,
    #[serde(default)]
    pub details: Option<String>,
    #[serde(default)]
    pub stage: Option<String>,
    #[serde(default)]
    pub suggestions: Vec<String>,
    #[serde(default)]
    pub trace_id: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct VerificationJob {
    pub job_id: String,
    pub status: VerifyJobStatus,
    pub status_description: Option<String>,
    pub message: Option<String>,
    pub error_category: Option<String>,
    pub class_hash: Option<String>,
    pub created_timestamp: Option<f64>,
    pub updated_timestamp: Option<f64>,
    pub address: Option<String>,
    pub contract_file: Option<String>,
    pub name: Option<String>,
    pub version: Option<String>,
    pub license: Option<String>,
    pub dojo_version: Option<String>,
    pub build_tool: Option<String>,
    // New structured error fields
    #[serde(default)]
    pub error_code: Option<String>,
    #[serde(default)]
    pub error_details: Option<String>,
    #[serde(default)]
    pub error_stage: Option<String>,
    #[serde(default)]
    pub error_suggestions: Option<Vec<String>>,
    #[serde(default)]
    pub trace_id: Option<String>,
    /// Nested error object (alternative format from some endpoints)
    #[serde(default)]
    pub error: Option<ServerError>,
}

impl VerificationJob {
    #[must_use]
    pub const fn status(&self) -> &VerifyJobStatus {
        &self.status
    }

    #[must_use]
    pub fn class_hash(&self) -> &str {
        self.class_hash.as_deref().unwrap_or("unknown")
    }

    #[must_use]
    pub fn job_id(&self) -> &str {
        &self.job_id
    }

    #[must_use]
    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    #[must_use]
    pub fn contract_file(&self) -> Option<&str> {
        self.contract_file.as_deref()
    }

    #[must_use]
    pub fn status_description(&self) -> Option<&str> {
        self.status_description.as_deref()
    }

    #[must_use]
    pub fn message(&self) -> Option<&str> {
        self.message.as_deref()
    }

    #[must_use]
    pub fn error_category(&self) -> Option<&str> {
        self.error_category.as_deref()
    }

    #[must_use]
    pub const fn created_timestamp(&self) -> Option<f64> {
        self.created_timestamp
    }

    #[must_use]
    pub const fn updated_timestamp(&self) -> Option<f64> {
        self.updated_timestamp
    }

    #[must_use]
    pub fn address(&self) -> Option<&str> {
        self.address.as_deref()
    }

    #[must_use]
    pub fn version(&self) -> Option<&str> {
        self.version.as_deref()
    }

    #[must_use]
    pub fn license(&self) -> Option<&str> {
        self.license.as_deref()
    }

    #[must_use]
    pub fn dojo_version(&self) -> Option<&str> {
        self.dojo_version.as_deref()
    }

    #[must_use]
    pub fn build_tool(&self) -> Option<&str> {
        self.build_tool.as_deref()
    }

    /// Get the error code from structured error info
    #[must_use]
    pub fn get_error_code(&self) -> Option<&str> {
        // Try nested error object first, then flat fields
        self.error
            .as_ref()
            .map(|e| e.code.as_str())
            .or(self.error_code.as_deref())
    }

    /// Get the error details from structured error info
    #[must_use]
    pub fn get_error_details(&self) -> Option<&str> {
        self.error
            .as_ref()
            .and_then(|e| e.details.as_deref())
            .or(self.error_details.as_deref())
    }

    /// Get the error stage from structured error info
    #[must_use]
    pub fn get_error_stage(&self) -> Option<&str> {
        self.error
            .as_ref()
            .and_then(|e| e.stage.as_deref())
            .or(self.error_stage.as_deref())
    }

    /// Get error suggestions from structured error info
    #[must_use]
    pub fn get_error_suggestions(&self) -> Vec<&str> {
        // Try nested error object first
        if let Some(ref error) = self.error {
            if !error.suggestions.is_empty() {
                return error.suggestions.iter().map(String::as_str).collect();
            }
        }
        // Fall back to flat field
        self.error_suggestions
            .as_ref()
            .map(|s| s.iter().map(String::as_str).collect())
            .unwrap_or_default()
    }

    /// Get trace ID for error correlation
    #[must_use]
    pub fn get_trace_id(&self) -> Option<&str> {
        self.error
            .as_ref()
            .and_then(|e| e.trace_id.as_deref())
            .or(self.trace_id.as_deref())
    }

    /// Check if this job has structured error information
    #[must_use]
    pub const fn has_structured_error(&self) -> bool {
        self.error.is_some() || self.error_code.is_some()
    }

    #[must_use]
    pub const fn is_completed(&self) -> bool {
        matches!(
            self.status,
            VerifyJobStatus::Success | VerifyJobStatus::Fail | VerifyJobStatus::CompileFailed
        )
    }

    #[must_use]
    pub const fn has_failed(&self) -> bool {
        matches!(
            self.status,
            VerifyJobStatus::Fail | VerifyJobStatus::CompileFailed
        )
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct FileInfo {
    pub name: String,
    pub path: PathBuf,
}

#[derive(Debug, Clone)]
pub struct ProjectMetadataInfo {
    pub cairo_version: semver::Version,
    pub scarb_version: semver::Version,
    pub project_dir_path: String,
    pub contract_file: String,
    pub package_name: String,
    pub build_tool: String,           // "scarb" or "sozo"
    pub dojo_version: Option<String>, // Dojo version for Dojo projects
}

impl ProjectMetadataInfo {
    #[must_use]
    pub fn new(
        cairo_version: semver::Version,
        scarb_version: semver::Version,
        project_dir_path: String,
        contract_file: String,
        package_name: String,
        project_type: ProjectType,
        dojo_version: Option<String>,
    ) -> Self {
        Self {
            cairo_version,
            scarb_version,
            project_dir_path,
            contract_file,
            package_name,
            build_tool: if project_type == ProjectType::Dojo {
                log::debug!("Setting build_tool to 'sozo' for Dojo project");
                "sozo".to_string()
            } else {
                log::debug!("Setting build_tool to 'scarb' for non-Dojo project: {project_type:?}");
                "scarb".to_string()
            },
            dojo_version,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct VerificationRequest {
    pub compiler_version: String,
    pub scarb_version: String,
    pub package_name: String,
    pub name: String,
    pub contract_file: String,
    #[serde(rename = "contract-name")]
    pub contract_name: String,
    pub project_dir_path: String,
    pub build_tool: String,
    pub license: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dojo_version: Option<String>,
    pub files: HashMap<String, String>, // filename -> content
}
