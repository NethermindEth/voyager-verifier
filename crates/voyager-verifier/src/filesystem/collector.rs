//! File helpers shared by the reusable Voyager verification API.

use crate::api::FileInfo;
use camino::{Utf8Path, Utf8PathBuf};
use itertools::Itertools;
use log::{debug, warn};
use scarb_metadata::PackageMetadata;
use std::collections::HashMap;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ContractFileError {
    #[error("No Cairo source file found for contract {contract_name}")]
    NotFound { contract_name: String },
}

/// Find the Cairo source file containing a Starknet contract definition.
///
/// The search first looks for `#[starknet::contract]` followed by a module
/// matching `contract_name`, then falls back to common file naming patterns.
///
/// # Errors
///
/// Returns [`ContractFileError::NotFound`] if no Cairo source file can be
/// selected for the contract.
pub fn find_contract_file(
    package_meta: &PackageMetadata,
    sources: &[Utf8PathBuf],
    contract_name: &str,
) -> Result<Utf8PathBuf, ContractFileError> {
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

    for path in ["src/lib.cairo", "src/main.cairo"] {
        let full_path = package_meta.root.join(path);
        if full_path.exists() {
            warn!(
                "Using fallback main file {path} - could not find specific contract file for {contract_name}"
            );
            return Ok(full_path);
        }
    }

    sources
        .iter()
        .filter(|path| path.starts_with(&package_meta.root))
        .find(|path| path.extension() == Some("cairo"))
        .cloned()
        .ok_or_else(|| ContractFileError::NotFound {
            contract_name: contract_name.to_string(),
        })
}

fn find_contract_by_pattern(
    sources: &[Utf8PathBuf],
    contract_name: &str,
    package_root: &Utf8Path,
) -> Option<Utf8PathBuf> {
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

fn contains_contract_definition(content: &str, contract_name: &str) -> bool {
    let lines: Vec<&str> = content.lines().collect();

    for (i, line) in lines.iter().enumerate() {
        let trimmed = line.trim();

        if trimmed.starts_with("#[starknet::contract]") {
            let end_index = std::cmp::min(i + 5, lines.len());
            for next_line in lines.iter().skip(i + 1).take(end_index - (i + 1)) {
                let next_line = next_line.trim();

                if next_line.is_empty() || next_line.starts_with("//") {
                    continue;
                }

                if let Some(module_name) = extract_module_name(next_line) {
                    if module_name == contract_name {
                        return true;
                    }
                    break;
                }
            }
        }
    }

    false
}

fn extract_module_name(line: &str) -> Option<String> {
    let trimmed = line.trim();
    let without_pub = trimmed
        .strip_prefix("pub ")
        .map_or(trimmed, |rest| rest.trim());

    if let Some(rest) = without_pub.strip_prefix("mod ") {
        let rest = rest.trim();
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
