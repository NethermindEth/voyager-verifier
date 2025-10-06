use std::{fs, time::Duration};

use backon::{BlockingRetryable, ExponentialBuilder};
use log::{debug, info, warn};
use reqwest::{
    blocking::{self, multipart, Client},
    StatusCode,
};
use url::Url;

use crate::{class_hash::ClassHash, errors::RequestFailure};

use super::errors::{ApiClientError, VerificationError};
use super::models::{
    Error, FileInfo, ProjectMetadataInfo, VerificationJob, VerificationJobDispatch,
};
use super::types::VerifyJobStatus;

// TODO: Option blindness?
type JobStatus = Option<VerificationJob>;

#[derive(Clone)]
pub struct ApiClient {
    base: Url,
    client: Client,
}

/**
 * Currently only `GetJobStatus` and `VerifyClass` are public available apis.
 * In the future, the get class api should be moved to using public apis too.
 * TODO: Change get class api to use public apis.
 */
impl ApiClient {
    /// # Errors
    ///
    /// Fails if provided `Url` cannot be a base. We rely on that
    /// invariant in other methods.
    pub fn new(base: Url) -> Result<Self, ApiClientError> {
        // Test here so that we are sure path_segments_mut succeeds
        if base.cannot_be_a_base() {
            Err(ApiClientError::CannotBeBase(base))
        } else {
            Ok(Self {
                base,
                client: blocking::Client::new(),
            })
        }
    }

    /// # Errors
    ///
    /// Will return `Err` if the URL cannot be a base.
    pub fn get_class_url(&self, class_hash: &ClassHash) -> Result<Url, ApiClientError> {
        let mut url = self.base.clone();
        let url_clone = url.clone();
        url.path_segments_mut()
            .map_err(|_| ApiClientError::CannotBeBase(url_clone))?
            .extend(&["classes", class_hash.as_ref()]);
        Ok(url)
    }

    /// # Errors
    ///
    /// Returns `Err` if the required `class_hash` is not found or on
    /// network failure.
    pub fn get_class(&self, class_hash: &ClassHash) -> Result<bool, ApiClientError> {
        let url = self.get_class_url(class_hash)?;
        let result = self
            .client
            .get(url.clone())
            .send()
            .map_err(ApiClientError::from)?;

        match result.status() {
            StatusCode::OK => Ok(true),
            StatusCode::NOT_FOUND => Ok(false),
            _ => Err(ApiClientError::from(RequestFailure::new(
                url,
                result.status(),
                result.text()?,
            ))),
        }
    }

    /// # Errors
    ///
    /// Will return `Err` if the URL cannot be a base.
    pub fn verify_class_url(&self, class_hash: &ClassHash) -> Result<Url, ApiClientError> {
        let mut url = self.base.clone();
        let url_clone = url.clone();
        url.path_segments_mut()
            .map_err(|_| ApiClientError::CannotBeBase(url_clone))?
            .extend(&["class-verify", class_hash.as_ref()]);
        Ok(url)
    }

    /// Filter out dev-dependencies from Scarb.toml content to prevent
    /// compilation issues on remote servers that don't have cargo installed
    fn filter_scarb_toml_content(content: &str) -> String {
        let mut lines = Vec::new();
        let mut in_dev_deps = false;

        for line in content.lines() {
            // Check if we're entering a dev-dependencies section
            if line.trim_start().starts_with("[dev-dependencies]") {
                in_dev_deps = true;
                // Add a comment instead of the section
                lines.push("# [dev-dependencies] section removed for remote compilation");
                continue;
            }

            // Check if we're entering a new section (but not dev-dependencies)
            if line.trim_start().starts_with('[')
                && !line.trim_start().starts_with("[dev-dependencies]")
            {
                // If we were in dev-deps and hit a new section, add empty line before it
                if in_dev_deps {
                    lines.push("");
                }
                in_dev_deps = false;
                lines.push(line);
                continue;
            }

            // Skip lines that are part of dev-dependencies
            if in_dev_deps {
                continue;
            }

            lines.push(line);
        }

        lines.join("\n")
    }

    /// # Errors
    ///
    /// Will return `Err` on network request failure or if can't
    /// gather file contents for submission.
    pub fn verify_class(
        &self,
        class_hash: &ClassHash,
        license: Option<String>,
        name: &str,
        project_metadata: ProjectMetadataInfo,
        files: &[FileInfo],
    ) -> Result<String, ApiClientError> {
        let mut body = multipart::Form::new()
            .percent_encode_noop()
            .text(
                "compiler_version",
                project_metadata.cairo_version.to_string(),
            )
            .text("scarb_version", project_metadata.scarb_version.to_string())
            .text("package_name", project_metadata.package_name.clone())
            .text("name", name.to_string())
            .text("contract_file", project_metadata.contract_file.clone())
            .text("contract-name", project_metadata.contract_file.clone())
            .text(
                "project_dir_path",
                project_metadata.project_dir_path.clone(),
            )
            .text("build_tool", project_metadata.build_tool.clone());

        // Add Dojo version if available
        if let Some(ref dojo_version) = project_metadata.dojo_version {
            info!("📤 Adding dojo_version to API request: {dojo_version}");
            body = body.text("dojo_version", dojo_version.clone());
        } else {
            debug!("📤 No dojo_version to include in API request");
        }

        info!(
            "🌐 API request payload prepared - build_tool: '{}', dojo_version: {:?}",
            project_metadata.build_tool, project_metadata.dojo_version
        );

        // Add license using raw SPDX identifier
        let license_value = if let Some(lic) = license {
            if lic == "MIT" {
                "MIT".to_string() // Ensure MIT is formatted correctly
            } else {
                lic
            }
        } else {
            "NONE".to_string()
        };

        body = body.text("license", license_value.clone());

        // Send each file as a separate field with files[] prefix
        for file in files {
            let mut file_content = fs::read_to_string(file.path.as_path())?;

            // Filter out dev-dependencies from Scarb.toml files to prevent remote compilation issues
            if file.name == "Scarb.toml" || file.name.ends_with("/Scarb.toml") {
                let original_len = file_content.len();
                file_content = Self::filter_scarb_toml_content(&file_content);
                if original_len != file_content.len() {
                    warn!(
                        "Filtered dev-dependencies from {} (size: {} -> {} bytes)",
                        file.name,
                        original_len,
                        file_content.len()
                    );
                }
            }

            body = body.text(format!("files[{}]", file.name), file_content);
        }

        let url = self.verify_class_url(class_hash)?;

        // Debug log: Complete API payload summary
        debug!("🚀 === API REQUEST PAYLOAD DEBUG ===");
        debug!("🎯 Target URL: {url}");
        debug!("🏗️  Request Method: POST");
        debug!("📦 Content-Type: multipart/form-data");
        debug!("📋 === FORM FIELDS ===");
        debug!("  compiler_version: {}", project_metadata.cairo_version);
        debug!("  scarb_version: {}", project_metadata.scarb_version);
        debug!("  package_name: {}", project_metadata.package_name);
        debug!("  name: {name}");
        debug!("  contract_file: {}", project_metadata.contract_file);
        debug!("  contract-name: {}", project_metadata.contract_file);
        debug!("  project_dir_path: {}", project_metadata.project_dir_path);
        debug!("  build_tool: {}", project_metadata.build_tool);
        if let Some(ref dojo_version) = project_metadata.dojo_version {
            debug!("  dojo_version: {dojo_version}");
        } else {
            debug!("  dojo_version: <not included>");
        }
        debug!("  license: {license_value}");
        debug!("📁 === FILES INCLUDED ===");
        for (index, file) in files.iter().enumerate() {
            let file_size = match fs::metadata(&file.path) {
                Ok(metadata) => metadata.len(),
                Err(_) => 0,
            };
            debug!(
                "  [{:2}] files[{}] -> {} ({} bytes)",
                index + 1,
                file.name,
                file.path.display(),
                file_size
            );
        }
        debug!("📊 Total files: {}", files.len());
        debug!("🚀 === END API REQUEST PAYLOAD ===");

        let response = self
            .client
            .post(url.clone())
            .multipart(body)
            .send()
            .map_err(ApiClientError::Reqwest)?;

        match response.status() {
            StatusCode::OK => (),
            StatusCode::BAD_REQUEST => {
                return Err(ApiClientError::from(RequestFailure::new(
                    url,
                    StatusCode::BAD_REQUEST,
                    response.json::<Error>()?.error,
                )));
            }
            StatusCode::PAYLOAD_TOO_LARGE => {
                return Err(ApiClientError::from(RequestFailure::new(
                    url,
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "Request payload too large. Maximum allowed size is 10MB.".to_string(),
                )));
            }
            status_code => {
                return Err(ApiClientError::from(RequestFailure::new(
                    url,
                    status_code,
                    response.text()?,
                )));
            }
        }

        Ok(response.json::<VerificationJobDispatch>()?.job_id)
    }

    /// # Errors
    ///
    /// Will return `Err` if the URL cannot be a base.
    pub fn get_job_status_url(&self, job_id: impl AsRef<str>) -> Result<Url, ApiClientError> {
        let mut url = self.base.clone();
        let url_clone = url.clone();
        url.path_segments_mut()
            .map_err(|_| ApiClientError::CannotBeBase(url_clone))?
            .extend(&["class-verify", "job", job_id.as_ref()]);
        Ok(url)
    }

    /// # Errors
    ///
    /// Will return `Err` on network error or if the verification has
    /// failed.
    pub fn get_job_status(
        &self,
        job_id: impl Into<String> + Clone,
    ) -> Result<JobStatus, ApiClientError> {
        let url = self.get_job_status_url(job_id.clone().into())?;
        let response = self.client.get(url.clone()).send()?;

        match response.status() {
            StatusCode::OK => (),
            StatusCode::NOT_FOUND => return Err(ApiClientError::JobNotFound(job_id.into())),
            status_code => {
                return Err(ApiClientError::from(RequestFailure::new(
                    url,
                    status_code,
                    response.text()?,
                )));
            }
        }

        let response_text = response.text()?;
        log::debug!("Raw API Response: {response_text}");

        let data: VerificationJob = serde_json::from_str(&response_text).map_err(|e| {
            log::error!("Failed to parse JSON response: {e}");
            log::error!("Response text: {response_text}");
            ApiClientError::from(RequestFailure::new(
                url.clone(),
                StatusCode::OK,
                format!("Failed to parse JSON response: {e}"),
            ))
        })?;

        // Debug logging to see the actual response
        log::debug!("Parsed API Response: job_id={}, status={:?}, status_description={:?}, message={:?}, error_category={:?}",
                   data.job_id, data.status, data.status_description, data.message, data.error_category);

        match data.status {
            VerifyJobStatus::Success => Ok(Some(data)),
            VerifyJobStatus::Fail => {
                let error_message = data
                    .message
                    .or_else(|| data.status_description.clone())
                    .unwrap_or_else(|| "unknown failure".to_owned());

                // Parse specific error types from the server response
                let parsed_error = if error_message.contains("Payload too large")
                    || error_message.contains("payload too large")
                {
                    "Request payload too large. The project files exceed the maximum allowed size of 10MB. Try reducing file sizes or removing unnecessary files."
                } else {
                    &error_message
                };

                Err(ApiClientError::from(
                    VerificationError::VerificationFailure(parsed_error.to_owned()),
                ))
            }
            VerifyJobStatus::CompileFailed => {
                let error_message = data
                    .message
                    .or_else(|| data.status_description.clone())
                    .unwrap_or_else(|| "unknown failure".to_owned());

                // Parse specific error types from the server response
                let parsed_error = if error_message.contains("Payload too large")
                    || error_message.contains("payload too large")
                {
                    "Request payload too large. The project files exceed the maximum allowed size of 10MB. Try reducing file sizes or removing unnecessary files."
                } else if error_message.contains("Couldn't connect to cairo compilation service") {
                    "Cairo compilation service is currently unavailable. Please try again later."
                } else {
                    &error_message
                };

                Err(ApiClientError::from(VerificationError::CompilationFailure(
                    parsed_error.to_owned(),
                )))
            }
            VerifyJobStatus::Submitted
            | VerifyJobStatus::Compiled
            | VerifyJobStatus::Processing
            | VerifyJobStatus::Unknown => Ok(None),
        }
    }

    /// # Errors
    ///
    /// Will return `Err` on network error or if the verification has failed.
    pub fn get_verification_job(&self, job_id: &str) -> Result<VerificationJob, ApiClientError> {
        match self.get_job_status(job_id)? {
            Some(job) => Ok(job),
            None => Err(ApiClientError::InProgress),
        }
    }
}

pub enum Status {
    InProgress,
    Finished(ApiClientError),
}

const fn is_is_progress(status: &Status) -> bool {
    match status {
        Status::InProgress => true,
        Status::Finished(_) => false,
    }
}

/// # Errors
///
/// Will return `Err` on network error or if the verification has
/// failed.
pub fn poll_verification_status(
    api: &ApiClient,
    job_id: &str,
) -> Result<VerificationJob, ApiClientError> {
    let fetch = || -> Result<VerificationJob, Status> {
        let result: Option<VerificationJob> = api
            .get_job_status(job_id.to_owned())
            .map_err(Status::Finished)?;

        result.ok_or(Status::InProgress)
    };

    // So verbose because it has problems with inference
    fetch
        .retry(
            ExponentialBuilder::default()
                .with_max_times(0)
                .with_min_delay(Duration::from_secs(2))
                .with_max_delay(Duration::from_secs(300)) // 5 mins
                .with_max_times(20),
        )
        .when(is_is_progress)
        .notify(|_, dur: Duration| {
            println!("Job: {job_id} didn't finish, retrying in {dur:?}");
        })
        .call()
        .map_err(|err| match err {
            Status::InProgress => ApiClientError::InProgress,
            Status::Finished(e) => e,
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_filter_scarb_toml_removes_dev_dependencies() {
        let input = r#"[package]
name = "test"
version = "0.1.0"

[dependencies]
starknet = "2.10.1"

[dev-dependencies]
assert_macros = "2.10.1"
snforge_std = "0.38.3"

[scripts]
test = "snforge test"
"#;

        let expected = r#"[package]
name = "test"
version = "0.1.0"

[dependencies]
starknet = "2.10.1"

# [dev-dependencies] section removed for remote compilation

[scripts]
test = "snforge test""#;

        let result = ApiClient::filter_scarb_toml_content(input);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_filter_scarb_toml_preserves_other_sections() {
        let input = r#"[package]
name = "test"

[dependencies]
cairo = "2.0.0"

[tool.fmt]
max-line-length = 120
"#;

        let expected = r#"[package]
name = "test"

[dependencies]
cairo = "2.0.0"

[tool.fmt]
max-line-length = 120"#;

        let result = ApiClient::filter_scarb_toml_content(input);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_filter_scarb_toml_handles_no_dev_dependencies() {
        let input = r#"[package]
name = "test"
version = "1.0.0"

[dependencies]
starknet = "2.10.1"
"#;

        // Should remain unchanged except for trailing newline
        let result = ApiClient::filter_scarb_toml_content(input);
        assert_eq!(result, input.lines().collect::<Vec<_>>().join("\n"));
    }

    #[test]
    fn test_filter_scarb_toml_handles_dev_deps_at_end() {
        let input = r#"[package]
name = "test"

[dependencies]
starknet = "2.10.1"

[dev-dependencies]
test_lib = "1.0.0"
another_lib = "2.0.0"
"#;

        let expected = r#"[package]
name = "test"

[dependencies]
starknet = "2.10.1"

# [dev-dependencies] section removed for remote compilation"#;

        let result = ApiClient::filter_scarb_toml_content(input);
        assert_eq!(result, expected);
    }
}
