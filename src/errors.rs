use camino::{FromPathBufError, Utf8PathBuf};
use reqwest::StatusCode;
use scarb_metadata::{Metadata, PackageId};
use std::fmt::{self, Formatter};
use thiserror::Error;
use url::Url;

use crate::api::ApiClientError;
use crate::class_hash::ClassHash;
use crate::resolver;
use crate::voyager;

/// Error codes for programmatic handling
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCode {
    /// Package not found in workspace
    E001,
    /// HTTP request failed
    E002,
    /// Contract not found in manifest
    E003,
}

impl ErrorCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::E001 => "E001",
            Self::E002 => "E002",
            Self::E003 => "E003",
        }
    }
}

/// Helper function for fuzzy string matching to suggest alternatives
fn find_closest_match(target: &str, candidates: &[String]) -> Option<String> {
    if candidates.is_empty() {
        return None;
    }

    // Simple fuzzy matching: find the candidate with minimum edit distance
    let mut best_match = None;
    let mut best_distance = usize::MAX;

    for candidate in candidates {
        let distance = edit_distance(target, candidate);
        if distance < best_distance {
            best_distance = distance;
            best_match = Some(candidate.clone());
        }
    }

    // Only suggest if the distance is reasonable (less than half the target length)
    if best_distance <= target.len() / 2 + 1 {
        best_match
    } else {
        None
    }
}

/// Simple edit distance calculation (Levenshtein distance)
fn edit_distance(s1: &str, s2: &str) -> usize {
    let len1 = s1.len();
    let len2 = s2.len();

    if len1 == 0 {
        return len2;
    }
    if len2 == 0 {
        return len1;
    }

    let mut matrix = vec![vec![0; len2 + 1]; len1 + 1];

    for (i, row) in matrix.iter_mut().enumerate().take(len1 + 1) {
        row[0] = i;
    }
    for j in 0..=len2 {
        matrix[0][j] = j;
    }

    for (i, c1) in s1.chars().enumerate() {
        for (j, c2) in s2.chars().enumerate() {
            let cost = if c1 == c2 { 0 } else { 1 };
            matrix[i + 1][j + 1] = std::cmp::min(
                std::cmp::min(
                    matrix[i][j + 1] + 1, // deletion
                    matrix[i + 1][j] + 1, // insertion
                ),
                matrix[i][j] + cost, // substitution
            );
        }
    }

    matrix[len1][len2]
}

#[derive(Debug, Error)]
pub struct MissingPackage {
    pub package_id: PackageId,
    pub available: Vec<PackageId>,
}

impl MissingPackage {
    #[must_use]
    pub fn new(package_id: &PackageId, metadata: &Metadata) -> Self {
        Self {
            package_id: package_id.clone(),
            available: metadata.workspace.members.clone(),
        }
    }

    pub const fn error_code(&self) -> ErrorCode {
        ErrorCode::E001
    }
}

impl fmt::Display for MissingPackage {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        writeln!(
            formatter,
            "[{}] Package '{}' not found in workspace.",
            self.error_code().as_str(),
            self.package_id
        )?;

        if self.available.is_empty() {
            writeln!(formatter, "\nNo packages are available in this workspace.")?;
            writeln!(formatter, "\nSuggestions:")?;
            writeln!(formatter, "  • Check if you're in the correct directory")?;
            writeln!(formatter, "  • Verify that Scarb.toml exists and is valid")?;
            writeln!(
                formatter,
                "  • Run 'scarb metadata' to check workspace structure"
            )?;
        } else {
            writeln!(formatter, "\nAvailable packages in this workspace:")?;
            for package in &self.available {
                writeln!(formatter, "  • {package}")?;
            }

            // Find closest match for suggestion
            let package_names: Vec<String> = self.available.iter().map(|p| p.to_string()).collect();
            if let Some(suggestion) =
                find_closest_match(&self.package_id.to_string(), &package_names)
            {
                writeln!(formatter, "\nDid you mean '{suggestion}'?")?;
            }

            writeln!(formatter, "\nSuggestions:")?;
            writeln!(formatter, "  • Use --package <name> to specify a package")?;
            writeln!(formatter, "  • Check spelling of the package name")?;
            writeln!(formatter, "  • Run 'scarb metadata' to list all packages")?;
        }

        Ok(())
    }
}

#[derive(Debug, Error)]
pub struct RequestFailure {
    pub url: Url,
    pub status: StatusCode,
    pub msg: String,
}

impl RequestFailure {
    pub fn new(url: Url, status: StatusCode, msg: impl Into<String>) -> Self {
        Self {
            url,
            status,
            msg: msg.into(),
        }
    }

    pub const fn error_code(&self) -> ErrorCode {
        ErrorCode::E002
    }
}

impl fmt::Display for RequestFailure {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        writeln!(
            formatter,
            "[{}] HTTP request failed: {} returned status {}",
            self.error_code().as_str(),
            self.url,
            self.status
        )?;

        if !self.msg.is_empty() {
            writeln!(formatter, "\nServer response: {}", self.msg)?;
        }

        writeln!(formatter, "\nSuggestions:")?;
        match self.status.as_u16() {
            400 => {
                writeln!(
                    formatter,
                    "  • Check that all required parameters are provided"
                )?;
                writeln!(formatter, "  • Verify the request format is correct")?;
            }
            401 => {
                writeln!(formatter, "  • Check your authentication credentials")?;
                writeln!(formatter, "  • Verify API key is valid and not expired")?;
            }
            403 => {
                writeln!(
                    formatter,
                    "  • Check that you have permission for this operation"
                )?;
                writeln!(
                    formatter,
                    "  • Verify your account has the required access level"
                )?;
            }
            404 => {
                writeln!(formatter, "  • Check that the URL is correct: {}", self.url)?;
                writeln!(formatter, "  • Verify the resource exists")?;
                writeln!(formatter, "  • Check if the service is running")?;
            }
            413 => {
                writeln!(
                    formatter,
                    "  • The request payload is too large (maximum 10MB)"
                )?;
                writeln!(
                    formatter,
                    "  • Consider reducing the size of your project files"
                )?;
                writeln!(formatter, "  • Remove unnecessary files or large assets")?;
                writeln!(
                    formatter,
                    "  • Try without --test-files or --lock-file flags"
                )?;
                writeln!(
                    formatter,
                    "  • Check for large binary files or dependencies"
                )?;
            }
            429 => {
                writeln!(formatter, "  • Wait a moment before retrying")?;
                writeln!(formatter, "  • Consider reducing request frequency")?;
            }
            500..=599 => {
                writeln!(formatter, "  • The server is experiencing issues")?;
                writeln!(formatter, "  • Try again in a few minutes")?;
                writeln!(formatter, "  • Check service status if available")?;
            }
            _ => {
                writeln!(formatter, "  • Check your internet connection")?;
                writeln!(formatter, "  • Verify the server URL is correct")?;
                writeln!(formatter, "  • Try again in a few moments")?;
            }
        }

        Ok(())
    }
}

#[derive(Debug, Error)]
pub struct MissingContract {
    pub name: String,
    pub available: Vec<String>,
}

impl MissingContract {
    #[must_use]
    pub const fn new(name: String, available: Vec<String>) -> Self {
        Self { name, available }
    }

    pub const fn error_code(&self) -> ErrorCode {
        ErrorCode::E003
    }
}

impl fmt::Display for MissingContract {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        writeln!(
            formatter,
            "[{}] Contract '{}' not found in manifest file.",
            self.error_code().as_str(),
            self.name
        )?;

        if self.available.is_empty() {
            writeln!(
                formatter,
                "\nNo contracts are defined in the manifest file."
            )?;
            writeln!(formatter, "\nSuggestions:")?;
            writeln!(
                formatter,
                "  • Add a [tool.voyager] section to your Scarb.toml"
            )?;
            writeln!(formatter, "  • Define your contracts in the manifest file")?;
            writeln!(
                formatter,
                "  • Check the documentation for contract configuration"
            )?;
        } else {
            writeln!(formatter, "\nAvailable contracts:")?;
            for contract in &self.available {
                writeln!(formatter, "  • {contract}")?;
            }

            // Provide fuzzy match suggestion
            if let Some(suggestion) = find_closest_match(&self.name, &self.available) {
                writeln!(formatter, "\nDid you mean '{suggestion}'?")?;
            }

            writeln!(formatter, "\nSuggestions:")?;
            writeln!(
                formatter,
                "  • Use --contract-name <name> to specify a contract"
            )?;
            writeln!(formatter, "  • Check spelling of the contract name")?;
            writeln!(
                formatter,
                "  • Verify the contract is defined in [tool.voyager] section"
            )?;
        }

        Ok(())
    }
}

/// Main CLI error type that wraps all possible errors
#[derive(Debug, Error)]
pub enum CliError {
    #[error(transparent)]
    Args(#[from] crate::args::ProjectError),

    #[error(transparent)]
    Api(#[from] ApiClientError),

    #[error(transparent)]
    MissingPackage(#[from] MissingPackage),

    #[error("[E015] Class hash '{0}' is not declared\n\nSuggestions:\n  • Verify the class hash is correct\n  • Check that the contract has been declared on the network\n  • Ensure you're using the correct network (mainnet/testnet)\n  • Use a block explorer to verify the class hash exists")]
    NotDeclared(ClassHash),

    #[error("[E016] No contracts selected for verification\n\nSuggestions:\n  • Use --contract-name <name> to specify a contract\n  • Check that contracts are defined in [tool.voyager] section\n  • Verify your Scarb.toml contains contract definitions\n  • Use 'scarb metadata' to list available contracts")]
    NoTarget,

    #[error("[E017] Multiple contracts found - only single contract verification is supported\n\nSuggestions:\n  • Use --contract-name <name> to specify which contract to verify\n  • Choose one from the available contracts\n  • Verify each contract separately")]
    MultipleContracts,

    #[error(transparent)]
    MissingContract(#[from] MissingContract),

    #[error(transparent)]
    Resolver(#[from] resolver::Error),

    #[error("[E018] Path processing error: cannot strip '{prefix}' from '{path}'\n\nThis is an internal error. Please report this issue with:\n  • The full command you ran\n  • Your project structure\n  • The contents of your Scarb.toml")]
    StripPrefix {
        path: Utf8PathBuf,
        prefix: Utf8PathBuf,
    },

    #[error(transparent)]
    Utf8(#[from] FromPathBufError),

    #[error(transparent)]
    Voyager(#[from] voyager::Error),

    #[error("[E019] File '{path}' exceeds maximum size limit of {max_size} bytes (actual: {actual_size} bytes)\n\nSuggestions:\n  • Reduce the file size by removing unnecessary content\n  • Split large files into smaller modules\n  • Check if the file contains generated or temporary content\n  • Use .gitignore to exclude large files that shouldn't be verified")]
    FileSizeLimit {
        path: Utf8PathBuf,
        max_size: usize,
        actual_size: usize,
    },

    #[error("[E024] File '{path}' has invalid file type (extension: {extension})\n\nSuggestions:\n  • Only include Cairo source files (.cairo)\n  • Include project configuration files (.toml, .lock)\n  • Include documentation files (.md, .txt)\n  • Remove binary or executable files from the project\n  • Allowed extensions: .cairo, .toml, .lock, .md, .txt, .json")]
    InvalidFileType {
        path: Utf8PathBuf,
        extension: String,
    },

    #[error("[E025] Invalid project type specified\n\nSpecified: {specified}\nDetected: {detected}\n\nSuggestions:\n{}", suggestions.join("\n  • "))]
    InvalidProjectType {
        specified: String,
        detected: String,
        suggestions: Vec<String>,
    },

    #[error("[E026] Dojo project validation failed\n\nSuggestions:\n  • Ensure dojo-core is listed in dependencies\n  • Check that Scarb.toml is properly configured for Dojo\n  • Verify project structure follows Dojo conventions\n  • Run 'sozo build' to test project compilation")]
    DojoValidationFailed,

    #[error("[E027] Interactive prompt failed\n\nSuggestions:\n  • Use --project-type=scarb or --project-type=dojo to skip prompt\n  • Ensure terminal supports interactive input\n  • Check that stdin is available")]
    InteractivePromptFailed(#[from] dialoguer::Error),
}

impl CliError {
    pub const fn error_code(&self) -> &'static str {
        match self {
            Self::Args(_) => "E020",
            Self::Api(e) => e.error_code(),
            Self::MissingPackage(e) => e.error_code().as_str(),
            Self::NotDeclared(_) => "E015",
            Self::NoTarget => "E016",
            Self::MultipleContracts => "E017",
            Self::MissingContract(e) => e.error_code().as_str(),
            Self::Resolver(e) => e.error_code(),
            Self::StripPrefix { .. } => "E018",
            Self::Utf8(_) => "E023",
            Self::Voyager(_) => "E999",
            Self::FileSizeLimit { .. } => "E019",
            Self::InvalidFileType { .. } => "E024",
            Self::InvalidProjectType { .. } => "E025",
            Self::DojoValidationFailed => "E026",
            Self::InteractivePromptFailed(_) => "E027",
        }
    }
}
