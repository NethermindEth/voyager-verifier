//! Reusable Voyager verification helpers.
//!
//! This module contains the verifier-specific logic that downstream CLIs need
//! without coupling them to this crate's command-line argument types or local
//! history database.

use crate::{
    api::{VerificationJobDispatch, VerificationRequest},
    core::project::ProjectType,
    filesystem::{
        collector::find_contract_file,
        resolver::{biggest_common_prefix, gather_packages, package_sources_with_test_files},
    },
};
use camino::{Utf8Path, Utf8PathBuf};
use itertools::Itertools;
use reqwest::{Client, StatusCode};
use scarb_metadata::{Metadata, PackageMetadata};
use serde::Deserialize;
use std::{collections::HashMap, fs};
use thiserror::Error;
use url::Url;

pub const MAINNET_API_URL: &str = "https://api.voyager.online/beta";
pub const SEPOLIA_API_URL: &str = "https://sepolia-api.voyager.online/beta";
pub const VERIFY_ENDPOINT: &str = "class-verify";
pub const STATUS_ENDPOINT: &str = "class-verify/job";

#[derive(Debug, Deserialize)]
struct ApiError {
    error: String,
}

#[derive(Debug, Error)]
pub enum VoyagerVerificationError {
    #[error(transparent)]
    SourceCollection(#[from] crate::filesystem::resolver::Error),

    #[error("Package {package_name} not found in scarb metadata")]
    PackageNotFound { package_name: String },

    #[error(
        "More than one package found in scarb metadata - specify package using --package flag"
    )]
    AmbiguousPackage,

    #[error("No packages found in scarb metadata")]
    MissingPackage,

    #[error("Couldn't strip {prefix} from {path}")]
    StripPrefix {
        path: Utf8PathBuf,
        prefix: Utf8PathBuf,
    },

    #[error("Failed to find contract file for {contract_name}: {reason}")]
    ContractFile {
        contract_name: String,
        reason: String,
    },

    #[error("Failed to read {path}: {source}")]
    ReadFile {
        path: Utf8PathBuf,
        source: std::io::Error,
    },

    #[error("Invalid Voyager API URL: {0}")]
    Url(#[from] url::ParseError),

    #[error("Voyager API URL cannot be used as a base: {0}")]
    CannotBeBase(Url),

    #[error(transparent)]
    Request(#[from] reqwest::Error),

    #[error("{0}")]
    Api(String),
}

#[derive(Debug, Clone)]
pub struct VerificationFiles {
    pub prefix: Utf8PathBuf,
    pub files: HashMap<String, Utf8PathBuf>,
}

#[derive(Debug)]
pub struct PreparedVerification {
    pub files: VerificationFiles,
    pub package: PackageMetadata,
    pub request: VerificationRequest,
}

/// Collect all files that should be uploaded to Voyager.
///
/// The returned map uses the relative upload path as the key and the local file
/// path as the value.
///
/// # Errors
///
/// Returns [`VoyagerVerificationError::SourceCollection`] if gathering packages
/// or resolving source files fails, or
/// [`VoyagerVerificationError::StripPrefix`] if a source path cannot be made
/// relative to the common prefix.
pub fn collect_verification_files(
    metadata: &Metadata,
    include_test_files: bool,
) -> Result<VerificationFiles, VoyagerVerificationError> {
    let mut packages = Vec::new();
    gather_packages(metadata, &mut packages)?;

    let mut sources = Vec::new();
    for package in &packages {
        sources.append(&mut package_sources_with_test_files(
            package,
            include_test_files,
        )?);
    }

    let prefix = biggest_common_prefix(&sources, &metadata.workspace.root);
    let manifest_path = &metadata.workspace.manifest_path;
    let manifest =
        manifest_path
            .strip_prefix(&prefix)
            .map_err(|_| VoyagerVerificationError::StripPrefix {
                path: manifest_path.clone(),
                prefix: prefix.clone(),
            })?;

    let mut files: HashMap<String, Utf8PathBuf> = sources
        .iter()
        .map(
            |path| -> Result<(String, Utf8PathBuf), VoyagerVerificationError> {
                let name = path.strip_prefix(&prefix).map_err(|_| {
                    VoyagerVerificationError::StripPrefix {
                        path: path.clone(),
                        prefix: prefix.clone(),
                    }
                })?;
                Ok((name.to_string(), path.clone()))
            },
        )
        .try_collect()?;

    files.insert(manifest.to_string(), manifest_path.clone());

    Ok(VerificationFiles { prefix, files })
}

/// Select the workspace package to verify.
///
/// # Errors
///
/// Returns [`VoyagerVerificationError::AmbiguousPackage`] if the workspace
/// contains more than one package and `package` is `None`,
/// [`VoyagerVerificationError::PackageNotFound`] if the requested package name
/// does not match any workspace member, or
/// [`VoyagerVerificationError::MissingPackage`] if the workspace contains no
/// packages.
pub fn select_package(
    metadata: &Metadata,
    package: Option<&str>,
) -> Result<PackageMetadata, VoyagerVerificationError> {
    let mut workspace_packages = metadata
        .packages
        .iter()
        .filter(|package_meta| metadata.workspace.members.contains(&package_meta.id))
        .cloned()
        .collect_vec();

    if workspace_packages.len() > 1 {
        let package_name = package.ok_or(VoyagerVerificationError::AmbiguousPackage)?;
        workspace_packages
            .into_iter()
            .find(|package_meta| package_meta.name == package_name)
            .ok_or_else(|| VoyagerVerificationError::PackageNotFound {
                package_name: package_name.to_string(),
            })
    } else {
        workspace_packages
            .pop()
            .ok_or(VoyagerVerificationError::MissingPackage)
    }
}

/// Build the full JSON request body expected by Voyager.
///
/// # Errors
///
/// Propagates all errors from [`select_package`] and
/// [`collect_verification_files`]. Additionally returns
/// [`VoyagerVerificationError::ContractFile`] if the contract source file
/// cannot be located, [`VoyagerVerificationError::StripPrefix`] if a path
/// cannot be made relative to the common prefix, and
/// [`VoyagerVerificationError::ReadFile`] if any source file cannot be read
/// from disk.
pub fn prepare_verification_request(
    metadata: &Metadata,
    contract_name: &str,
    package: Option<&str>,
    include_test_files: bool,
    project_type: ProjectType,
    dojo_version: Option<String>,
) -> Result<PreparedVerification, VoyagerVerificationError> {
    let selected_package = select_package(metadata, package)?;
    let files = collect_verification_files(metadata, include_test_files)?;

    let source_paths = files.files.values().cloned().collect_vec();
    let contract_file_path = find_contract_file(&selected_package, &source_paths, contract_name)
        .map_err(|source| VoyagerVerificationError::ContractFile {
            contract_name: contract_name.to_string(),
            reason: source.to_string(),
        })?;
    let contract_file = contract_file_path
        .strip_prefix(&files.prefix)
        .map_err(|_| VoyagerVerificationError::StripPrefix {
            path: contract_file_path.clone(),
            prefix: files.prefix.clone(),
        })?
        .to_string();

    let project_dir_path = project_dir_path(metadata, &files.prefix)?;
    let file_contents = read_file_contents(&files.files)?;

    let request = VerificationRequest {
        compiler_version: metadata.app_version_info.cairo.version.to_string(),
        scarb_version: metadata.app_version_info.version.to_string(),
        package_name: selected_package.name.clone(),
        name: contract_name.to_string(),
        contract_file: contract_file.clone(),
        contract_name: contract_file,
        project_dir_path,
        build_tool: project_type.build_tool().to_string(),
        license: selected_package
            .manifest_metadata
            .license
            .clone()
            .unwrap_or_else(|| "NONE".to_string()),
        dojo_version,
        files: file_contents,
    };

    Ok(PreparedVerification {
        files,
        package: selected_package,
        request,
    })
}

/// Submit a prepared verification request to Voyager and return the job ID.
///
/// # Errors
///
/// Returns [`VoyagerVerificationError::CannotBeBase`] if `base_url` cannot be
/// used as a base URL, [`VoyagerVerificationError::Request`] on network or
/// HTTP-client errors, and [`VoyagerVerificationError::Api`] if the Voyager
/// API responds with a non-OK status.
pub async fn submit_verification_request(
    base_url: &Url,
    class_hash: &str,
    request: &VerificationRequest,
) -> Result<String, VoyagerVerificationError> {
    let client = Client::new();
    submit_verification_request_with_client(&client, base_url, class_hash, request).await
}

/// Submit a prepared verification request with a caller-provided HTTP client.
///
/// # Errors
///
/// Returns [`VoyagerVerificationError::CannotBeBase`] if `base_url` cannot be
/// used as a base URL, [`VoyagerVerificationError::Request`] on network or
/// HTTP-client errors, and [`VoyagerVerificationError::Api`] if the Voyager
/// API responds with a non-OK status.
pub async fn submit_verification_request_with_client(
    client: &Client,
    base_url: &Url,
    class_hash: &str,
    request: &VerificationRequest,
) -> Result<String, VoyagerVerificationError> {
    let url = verification_url(base_url, class_hash)?;
    let response = client.post(url.clone()).json(request).send().await?;

    match response.status() {
        StatusCode::OK => Ok(response.json::<VerificationJobDispatch>().await?.job_id),
        StatusCode::BAD_REQUEST => Err(VoyagerVerificationError::Api(
            response.json::<ApiError>().await?.error,
        )),
        _ => Err(VoyagerVerificationError::Api(response.text().await?)),
    }
}

/// Build a Voyager verification URL from a base API URL and class hash.
///
/// # Errors
///
/// Returns [`VoyagerVerificationError::CannotBeBase`] if `base_url` cannot be
/// used as a base URL for path-segment manipulation.
pub fn verification_url(base_url: &Url, class_hash: &str) -> Result<Url, VoyagerVerificationError> {
    let mut url = base_url.clone();
    let url_clone = url.clone();
    url.path_segments_mut()
        .map_err(|()| VoyagerVerificationError::CannotBeBase(url_clone))?
        .extend(&[VERIFY_ENDPOINT, class_hash]);
    Ok(url)
}

/// Filter out dev-dependencies from Scarb.toml content to prevent compilation
/// issues on remote servers that do not have Cargo installed.
#[must_use]
pub fn filter_scarb_toml_content(content: &str) -> String {
    let mut lines = Vec::new();
    let mut in_dev_deps = false;

    for line in content.lines() {
        if line.trim_start().starts_with("[dev-dependencies]") {
            in_dev_deps = true;
            lines.push("# [dev-dependencies] section removed for remote compilation");
            continue;
        }

        if line.trim_start().starts_with('[')
            && !line.trim_start().starts_with("[dev-dependencies]")
        {
            if in_dev_deps {
                lines.push("");
            }
            in_dev_deps = false;
            lines.push(line);
            continue;
        }

        if in_dev_deps {
            continue;
        }

        lines.push(line);
    }

    lines.join("\n")
}

fn project_dir_path(
    metadata: &Metadata,
    prefix: &Utf8Path,
) -> Result<String, VoyagerVerificationError> {
    let path = metadata.workspace.root.strip_prefix(prefix).map_err(|_| {
        VoyagerVerificationError::StripPrefix {
            path: metadata.workspace.root.clone(),
            prefix: prefix.to_path_buf(),
        }
    })?;

    if path.as_str().is_empty() {
        Ok(".".to_string())
    } else {
        Ok(path.to_string())
    }
}

fn read_file_contents(
    files: &HashMap<String, Utf8PathBuf>,
) -> Result<HashMap<String, String>, VoyagerVerificationError> {
    files
        .iter()
        .map(|(name, path)| {
            let mut contents =
                fs::read_to_string(path).map_err(|source| VoyagerVerificationError::ReadFile {
                    path: path.clone(),
                    source,
                })?;

            if name == "Scarb.toml" || name.ends_with("/Scarb.toml") {
                contents = filter_scarb_toml_content(&contents);
            }

            Ok((name.clone(), contents))
        })
        .try_collect()
}
