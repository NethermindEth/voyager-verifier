use camino::{FromPathBufError, Utf8PathBuf};
use thiserror::Error;

use voyager_verifier::api::ApiClientError;
use voyager_verifier::core::class_hash::ClassHash;
use voyager_verifier::errors::MissingContract;
use voyager_verifier::filesystem::resolver;
use voyager_verifier::manifest;

/// Main CLI error type that wraps all possible errors
#[derive(Debug, Error)]
pub enum CliError {
    #[error(transparent)]
    Args(#[from] crate::cli::args::ProjectError),

    #[error(transparent)]
    Api(#[from] ApiClientError),

    #[error(transparent)]
    ClassHash(#[from] voyager_verifier::core::class_hash::ClassHashError),

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
    Voyager(#[from] manifest::Error),

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

    #[error("[E028] Internal error: {message}\n\nThis is an internal error that should not occur. Please report this issue with:\n  • The full command you ran\n  • The context in which this error occurred\n  • Any relevant logs or output")]
    InternalError { message: String },
}

impl CliError {
    #[must_use]
    pub const fn error_code(&self) -> &'static str {
        match self {
            Self::Args(_) => "E020",
            Self::Api(e) => e.error_code(),
            Self::ClassHash(e) => e.error_code(),
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
            Self::InternalError { .. } => "E028",
        }
    }
}
