//! File collection, validation, and preparation for verification
//!
//! This module handles all file-related operations for verification including:
//! - Building file maps from source files
//! - Validating file types and sizes
//! - Adding manifest files (Scarb.toml, workspace manifests)
//! - Finding contract files
//! - Converting paths to `FileInfo` structures
//! - Logging verification information

use super::resolver;
use crate::api::FileInfo;
use crate::cli::args::VerifyArgs;
use crate::utils::{errors::CliError, license, voyager};
use camino::{Utf8Path, Utf8PathBuf};
use itertools::Itertools;
use log::{debug, info, warn};
use scarb_metadata::PackageMetadata;
use std::collections::HashMap;

/// Prepare project for verification
///
/// This is the main entry point for preparing a project's files for verification.
/// It coordinates:
/// 1. Building a file map with all necessary files
/// 2. Filtering to the target package
/// 3. Finding the contract file
/// 4. Preparing the project directory path
/// 5. Converting to `FileInfo` structures
///
/// # Arguments
///
/// * `args` - Verification arguments
/// * `metadata` - Scarb metadata
/// * `packages` - All packages in the project
/// * `sources` - Source file paths
///
/// # Returns
///
/// Returns a tuple of (`file_infos`, `package_meta`, `contract_file`, `project_dir_path`)
///
/// # Errors
///
/// Returns a `CliError` if any preparation step fails
pub fn prepare_project_for_verification(
    args: &VerifyArgs,
    metadata: &scarb_metadata::Metadata,
    packages: &[PackageMetadata],
    sources: &[Utf8PathBuf],
) -> Result<(Vec<FileInfo>, PackageMetadata, String, String), CliError> {
    let prefix = resolver::biggest_common_prefix(sources, args.path.root_dir());

    // Build file map
    let files = build_file_map(sources, &prefix, metadata, args)?;

    // Filter packages and get the target package
    let filtered_packages: Vec<&PackageMetadata> = args.package.as_ref().map_or_else(
        || packages.iter().collect(),
        |package_id| packages.iter().filter(|p| p.name == *package_id).collect(),
    );

    let package_meta = filtered_packages
        .first()
        .ok_or_else(|| CliError::NoTarget)?;

    // Extract contract name (required field)
    let contract_name = args
        .contract_name
        .as_ref()
        .ok_or_else(|| CliError::InternalError {
            message: "contract_name should be present".to_string(),
        })?;

    // Find contract file
    let contract_file_path = find_contract_file(package_meta, sources, contract_name)?;
    let contract_file =
        contract_file_path
            .strip_prefix(&prefix)
            .map_err(|_| CliError::StripPrefix {
                path: contract_file_path.clone(),
                prefix: prefix.clone(),
            })?;

    // Prepare project directory path
    let project_dir_path = prepare_project_dir_path(package_meta, args, &prefix)?;

    // Convert to FileInfo
    let file_infos = convert_to_file_info(files);

    Ok((
        file_infos,
        (*package_meta).clone(),
        contract_file.to_string(),
        project_dir_path,
    ))
}

/// Build file map
///
/// Creates a map of relative file paths to absolute file paths, including:
/// - Source files
/// - Manifest files (Scarb.toml)
/// - Optional lock file
///
/// Also validates file sizes and types.
///
/// # Arguments
///
/// * `sources` - Source file paths
/// * `prefix` - Common prefix to strip from paths
/// * `metadata` - Scarb metadata
/// * `args` - Verification arguments
///
/// # Returns
///
/// Returns a `HashMap` mapping relative paths to absolute paths
///
/// # Errors
///
/// Returns a `CliError` if file validation fails
pub fn build_file_map(
    sources: &[Utf8PathBuf],
    prefix: &Utf8Path,
    metadata: &scarb_metadata::Metadata,
    args: &VerifyArgs,
) -> Result<HashMap<String, Utf8PathBuf>, CliError> {
    let mut files: HashMap<String, Utf8PathBuf> = sources
        .iter()
        .map(|p| -> Result<(String, Utf8PathBuf), CliError> {
            let name = p.strip_prefix(prefix).map_err(|_| CliError::StripPrefix {
                path: p.clone(),
                prefix: prefix.to_path_buf(),
            })?;
            Ok((name.to_string(), p.clone()))
        })
        .try_collect()?;

    // Add manifest files
    add_manifest_files(&mut files, metadata, prefix)?;

    // Add lock file if requested
    add_lock_file_if_requested(&mut files, args, prefix)?;

    // Validate file sizes
    validate_file_sizes(&files)?;

    Ok(files)
}

/// Validate file sizes
///
/// Ensures all files are under the maximum size limit (20MB).
/// Also validates file types using `validate_file_type`.
///
/// # Arguments
///
/// * `files` - Map of files to validate
///
/// # Errors
///
/// Returns a `CliError` if any file exceeds the size limit or has invalid type
pub fn validate_file_sizes<S: std::hash::BuildHasher>(
    files: &HashMap<String, Utf8PathBuf, S>,
) -> Result<(), CliError> {
    const MAX_FILE_SIZE: usize = 1024 * 1024 * 20; // 20MB limit

    for path in files.values() {
        // Validate file type
        validate_file_type(path)?;

        // Validate file size
        if let Ok(metadata) = std::fs::metadata(path) {
            let size = usize::try_from(metadata.len()).unwrap_or(MAX_FILE_SIZE + 1);
            if size > MAX_FILE_SIZE {
                return Err(CliError::FileSizeLimit {
                    path: path.clone(),
                    max_size: MAX_FILE_SIZE,
                    actual_size: size,
                });
            }
        }
    }
    Ok(())
}

/// Validate file type
///
/// Ensures the file has an allowed extension or is a recognized project file.
///
/// Allowed extensions: cairo, toml, lock, md, txt, json
/// Allowed files without extension: LICENSE, README, CHANGELOG, NOTICE, AUTHORS, CONTRIBUTORS
///
/// # Arguments
///
/// * `path` - Path to the file to validate
///
/// # Errors
///
/// Returns a `CliError` if the file type is not allowed
pub fn validate_file_type(path: &Utf8PathBuf) -> Result<(), CliError> {
    // Get file extension
    let extension = path.extension().unwrap_or("");

    // Define allowed file types
    let allowed_extensions = ["cairo", "toml", "lock", "md", "txt", "json"];

    // Define common project files without extensions
    let allowed_no_extension_files = [
        "LICENSE",
        "README",
        "CHANGELOG",
        "NOTICE",
        "AUTHORS",
        "CONTRIBUTORS",
    ];

    // Check if extension is allowed
    if !allowed_extensions.contains(&extension) {
        // If no extension, check if it's a common project file
        if extension.is_empty() {
            let file_name = path.file_name().unwrap_or("");
            if !allowed_no_extension_files.contains(&file_name) {
                return Err(CliError::InvalidFileType {
                    path: path.clone(),
                    extension: extension.to_string(),
                });
            }
        } else {
            return Err(CliError::InvalidFileType {
                path: path.clone(),
                extension: extension.to_string(),
            });
        }
    }

    Ok(())
}

/// Add manifest files
///
/// Adds the project's Scarb.toml and workspace manifest (if applicable) to the file map.
///
/// # Arguments
///
/// * `files` - File map to add to
/// * `metadata` - Scarb metadata
/// * `prefix` - Common prefix to strip from paths
///
/// # Errors
///
/// Returns a `CliError` if path manipulation fails
pub fn add_manifest_files<S: std::hash::BuildHasher>(
    files: &mut HashMap<String, Utf8PathBuf, S>,
    metadata: &scarb_metadata::Metadata,
    prefix: &Utf8Path,
) -> Result<(), CliError> {
    let manifest_path = voyager::manifest_path(metadata);
    let manifest = manifest_path
        .strip_prefix(prefix)
        .map_err(|_| CliError::StripPrefix {
            path: manifest_path.clone(),
            prefix: prefix.to_path_buf(),
        })?;

    files.insert(manifest.to_string(), manifest_path.clone());

    // Handle workspace manifests
    add_workspace_manifest_if_needed(files, metadata, prefix)?;

    Ok(())
}

/// Add workspace manifest if needed
///
/// If the project is part of a workspace, adds the workspace root Scarb.toml to the file map.
///
/// # Arguments
///
/// * `files` - File map to add to
/// * `metadata` - Scarb metadata
/// * `prefix` - Common prefix to strip from paths
///
/// # Errors
///
/// Returns a `CliError` if path manipulation fails
pub fn add_workspace_manifest_if_needed<S: std::hash::BuildHasher>(
    files: &mut HashMap<String, Utf8PathBuf, S>,
    metadata: &scarb_metadata::Metadata,
    prefix: &Utf8Path,
) -> Result<(), CliError> {
    let workspace_manifest = &metadata.workspace.manifest_path;
    let manifest_path = voyager::manifest_path(metadata);

    // Include workspace manifest if it's different from the package manifest
    // This indicates we're in a workspace subpackage
    let is_workspace = workspace_manifest != manifest_path;

    if is_workspace {
        let workspace_manifest_rel =
            workspace_manifest
                .strip_prefix(prefix)
                .map_err(|_| CliError::StripPrefix {
                    path: workspace_manifest.clone(),
                    prefix: prefix.to_path_buf(),
                })?;
        debug!("Including workspace root manifest: {workspace_manifest}");
        files.insert(
            workspace_manifest_rel.to_string(),
            workspace_manifest.clone(),
        );
    }

    Ok(())
}

/// Add lock file if requested
///
/// If the --lock-file flag is set, adds Scarb.lock to the file map (if it exists).
///
/// # Arguments
///
/// * `files` - File map to add to
/// * `args` - Verification arguments
/// * `prefix` - Common prefix to strip from paths
///
/// # Errors
///
/// Returns a `CliError` if path manipulation fails
pub fn add_lock_file_if_requested<S: std::hash::BuildHasher>(
    files: &mut HashMap<String, Utf8PathBuf, S>,
    args: &VerifyArgs,
    prefix: &Utf8Path,
) -> Result<(), CliError> {
    if args.lock_file {
        let lock_file_path = args.path.root_dir().join("Scarb.lock");
        if lock_file_path.exists() {
            let lock_file_rel =
                lock_file_path
                    .strip_prefix(prefix)
                    .map_err(|_| CliError::StripPrefix {
                        path: lock_file_path.clone(),
                        prefix: prefix.to_path_buf(),
                    })?;
            debug!("Including Scarb.lock file: {lock_file_path}");
            files.insert(lock_file_rel.to_string(), lock_file_path.clone());
        } else {
            warn!("--lock-file flag enabled but Scarb.lock not found at {lock_file_path}");
        }
    }
    Ok(())
}

/// Find contract file
///
/// Locates the main contract file for verification by searching for the actual
/// contract definition in the source code. Searches in order:
/// 1. Pattern-based search: Find `#[starknet::contract]` followed by `mod <ContractName>`
/// 2. Fallback heuristics: Contract-specific paths based on name
/// 3. Main source files (src/lib.cairo, src/main.cairo)
/// 4. First Cairo file in the package
///
/// # Arguments
///
/// * `package_meta` - Package metadata
/// * `sources` - All source files
/// * `contract_name` - Name of the contract to find
///
/// # Returns
///
/// Returns the path to the contract file
///
/// # Errors
///
/// Returns a `CliError` if no suitable contract file is found
pub fn find_contract_file(
    package_meta: &PackageMetadata,
    sources: &[Utf8PathBuf],
    contract_name: &str,
) -> Result<Utf8PathBuf, CliError> {
    // First, search for the actual contract definition pattern
    // Look for #[starknet::contract] followed by mod <ContractName>
    debug!(
        "Searching for contract definition pattern: #[starknet::contract] + mod {contract_name}"
    );

    if let Some(contract_file) =
        find_contract_by_pattern(sources, contract_name, &package_meta.root)
    {
        debug!("Found contract definition in: {contract_file}");
        return Ok(contract_file);
    }

    debug!("Contract definition pattern not found, falling back to heuristics");

    // Fallback: Try to find a file that matches the contract name (case-insensitive)
    let contract_specific_paths = vec![
        format!("src/{}.cairo", contract_name.to_lowercase()),
        format!(
            "src/{}/{}.cairo",
            contract_name.to_lowercase(),
            contract_name.to_lowercase()
        ),
        format!("src/systems/{}.cairo", contract_name.to_lowercase()),
        format!("src/contracts/{}.cairo", contract_name.to_lowercase()),
    ];

    for path in contract_specific_paths {
        let full_path = package_meta.root.join(&path);
        if full_path.exists() {
            debug!("Found contract file via heuristic: {full_path}");
            return Ok(full_path);
        }
    }

    // Find the main source file for the package (conventionally src/lib.cairo or src/main.cairo)
    let possible_main_paths = vec!["src/lib.cairo", "src/main.cairo"];

    for path in possible_main_paths {
        let full_path = package_meta.root.join(path);
        if full_path.exists() {
            warn!(
                "Using fallback main file {path} - could not find specific contract file for {contract_name}"
            );
            return Ok(full_path);
        }
    }

    // If we can't find a main file, use the first source file in the package
    let contract_file_path = sources
        .iter()
        .filter(|path| path.starts_with(&package_meta.root))
        .find(|path| path.extension() == Some("cairo"))
        .cloned()
        .ok_or(CliError::NoTarget)?;

    warn!(
        "Using first Cairo file {contract_file_path} - could not find specific contract file for {contract_name}"
    );
    Ok(contract_file_path)
}

/// Find contract file by searching for the Starknet contract definition pattern
///
/// Searches through all Cairo source files for the pattern:
/// ```cairo
/// #[starknet::contract]
/// pub mod <ContractName> {
/// ```
///
/// # Arguments
///
/// * `sources` - All source files to search
/// * `contract_name` - Name of the contract module to find
/// * `package_root` - Root directory of the package
///
/// # Returns
///
/// Returns the path to the file containing the contract definition, or None if not found
fn find_contract_by_pattern(
    sources: &[Utf8PathBuf],
    contract_name: &str,
    package_root: &Utf8Path,
) -> Option<Utf8PathBuf> {
    // Filter to only Cairo files in this package
    let cairo_files: Vec<&Utf8PathBuf> = sources
        .iter()
        .filter(|path| path.starts_with(package_root))
        .filter(|path| path.extension() == Some("cairo"))
        .collect();

    debug!(
        "Searching {} Cairo files for contract pattern",
        cairo_files.len()
    );

    for file_path in cairo_files {
        match std::fs::read_to_string(file_path) {
            Ok(content) => {
                if contains_contract_definition(&content, contract_name) {
                    debug!("Found contract '{contract_name}' in file: {file_path}");
                    return Some(file_path.clone());
                }
            }
            Err(e) => {
                debug!("Failed to read file {file_path}: {e}");
            }
        }
    }

    None
}

/// Check if file content contains the contract definition pattern
///
/// Looks for `#[starknet::contract]` attribute followed by a module declaration
/// matching the contract name. Handles various formatting patterns.
///
/// # Arguments
///
/// * `content` - File content to search
/// * `contract_name` - Name of the contract module to find
///
/// # Returns
///
/// Returns true if the contract definition is found
fn contains_contract_definition(content: &str, contract_name: &str) -> bool {
    let lines: Vec<&str> = content.lines().collect();

    for (i, line) in lines.iter().enumerate() {
        let trimmed = line.trim();

        // Look for #[starknet::contract] attribute
        if trimmed.starts_with("#[starknet::contract]") {
            // Check the next few lines for the module definition
            let end_index = std::cmp::min(i + 5, lines.len());
            for next_line in lines.iter().skip(i + 1).take(end_index - (i + 1)) {
                let next_line = next_line.trim();

                // Skip empty lines and comments
                if next_line.is_empty() || next_line.starts_with("//") {
                    continue;
                }

                // Look for module declaration: "pub mod ContractName" or "mod ContractName"
                if let Some(module_name) = extract_module_name(next_line) {
                    if module_name == contract_name {
                        return true;
                    }
                    // If we found a different module name, this isn't our contract
                    break;
                }
            }
        }
    }

    false
}

/// Extract module name from a Cairo module declaration line
///
/// Handles patterns like:
/// - `pub mod ContractName {`
/// - `mod ContractName {`
/// - `pub mod ContractName{`
///
/// # Arguments
///
/// * `line` - Line to extract module name from
///
/// # Returns
///
/// Returns the module name if found
fn extract_module_name(line: &str) -> Option<String> {
    let trimmed = line.trim();

    // Remove "pub " prefix if present
    let without_pub = trimmed
        .strip_prefix("pub ")
        .map_or(trimmed, |rest| rest.trim());

    // Check for "mod " prefix
    if let Some(rest) = without_pub.strip_prefix("mod ") {
        let rest = rest.trim();

        // Extract module name (until { or whitespace)
        let name = rest
            .split(|c: char| c == '{' || c.is_whitespace())
            .next()?
            .trim();

        if !name.is_empty() {
            return Some(name.to_string());
        }
    }

    None
}

/// Prepare project directory path
///
/// Always returns "." to indicate the build should run from the workspace/project root.
/// The file structure itself (with proper paths) tells the build tool where packages are located.
///
/// This ensures that workspace builds work correctly - scarb/sozo will automatically
/// discover workspace members and build the correct package based on the file structure.
///
/// # Arguments
///
/// * `package_meta` - Package metadata (unused but kept for API consistency)
/// * `args` - Verification arguments (unused but kept for API consistency)
/// * `prefix` - Common prefix (unused but kept for API consistency)
///
/// # Returns
///
/// Returns "." to indicate root directory
///
/// # Errors
///
/// Never fails (Result for API consistency)
pub fn prepare_project_dir_path(
    _package_meta: &PackageMetadata,
    _args: &VerifyArgs,
    _prefix: &Utf8Path,
) -> Result<String, CliError> {
    // Always use "." (root) - the file paths themselves define the structure
    Ok(".".to_string())
}

/// Convert to `FileInfo`
///
/// Converts a `HashMap` of file paths to a vector of `FileInfo` structures
/// suitable for the API client.
///
/// # Arguments
///
/// * `files` - Map of relative paths to absolute paths
///
/// # Returns
///
/// Returns a vector of `FileInfo` structures
#[must_use]
pub fn convert_to_file_info<S: std::hash::BuildHasher>(
    files: HashMap<String, Utf8PathBuf, S>,
) -> Vec<FileInfo> {
    files
        .into_iter()
        .map(|(name, path)| FileInfo {
            name,
            path: path.into_std_path_buf(),
        })
        .collect_vec()
}

/// Log verification info
///
/// Logs detailed information about the verification job including:
/// - Contract name and file
/// - License information
/// - Cairo and Scarb versions
/// - List of all files being verified
///
/// # Arguments
///
/// * `args` - Verification arguments
/// * `metadata` - Scarb metadata
/// * `file_infos` - List of files to verify
/// * `contract_file` - Path to the contract file
/// * `license_info` - License information
pub fn log_verification_info(
    args: &VerifyArgs,
    metadata: &scarb_metadata::Metadata,
    file_infos: &[FileInfo],
    contract_file: &str,
    license_info: &license::LicenseInfo,
) {
    let cairo_version = &metadata.app_version_info.cairo.version;
    let scarb_version = &metadata.app_version_info.version;

    // This function is only called after validation, so contract_name should always be present
    // If it's not, we'll use a placeholder to avoid panicking during logging
    let contract_name = args.contract_name.as_deref().unwrap_or("<unknown>");

    info!("Verifying contract: {contract_name} from {contract_file}");
    info!("licensed with: {}", license_info.display_string());
    info!("using cairo: {cairo_version} and scarb {scarb_version}");
    info!("These are the files that will be used for verification:");
    for file_info in file_infos {
        info!("{}", file_info.path.display());
    }
}
