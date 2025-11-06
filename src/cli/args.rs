use camino::Utf8PathBuf;
use regex::Regex;
use reqwest::Url;
use scarb_metadata::{Metadata, MetadataCommand, MetadataCommandError};
use spdx::LicenseId;
use std::{env, fmt::Display, io, path::PathBuf, sync::LazyLock};
use thiserror::Error;

use crate::core::{class_hash::ClassHash, project::ProjectType};

static VALID_NAME_REGEX: LazyLock<Result<Regex, regex::Error>> =
    LazyLock::new(|| Regex::new(r"^[a-zA-Z0-9_-]+$"));

fn get_name_validation_regex() -> Result<&'static Regex, String> {
    VALID_NAME_REGEX
        .as_ref()
        .map_or_else(|_| Err("Internal regex compilation error".to_string()), Ok)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Project(Metadata);

#[derive(Error, Debug)]
pub enum ProjectError {
    #[error("[E020] Scarb project manifest not found at: {0}\n\nSuggestions:\n  • Check that you're in a Scarb project directory\n  • Verify that Scarb.toml exists in the specified path\n  • Run 'scarb init' to create a new project\n  • Use --manifest-path to specify the correct path")]
    MissingManifest(Utf8PathBuf),

    #[error("[E021] Failed to read project metadata: {0}\n\nSuggestions:\n  • Check that Scarb.toml is valid TOML format\n  • Verify all dependencies are properly declared\n  • Run 'scarb metadata --format-version 1' to see the full error\n  • Run 'scarb check' to validate your project\n  • Ensure scarb is installed and up to date")]
    MetadataError(#[from] MetadataCommandError),

    #[error("[E022] File system error\n\nSuggestions:\n  • Check file permissions\n  • Verify the path exists and is accessible\n  • Ensure you have read access to the directory")]
    Io(#[from] io::Error),

    #[error("[E023] Path contains invalid UTF-8 characters\n\nSuggestions:\n  • Use only ASCII characters in file paths\n  • Avoid special characters in directory names\n  • Check for hidden or control characters in the path")]
    Utf8(#[from] camino::FromPathBufError),
}

impl ProjectError {
    #[must_use]
    pub const fn error_code(&self) -> &'static str {
        match self {
            Self::MissingManifest(_) => "E020",
            Self::MetadataError(_) => "E021",
            Self::Io(_) => "E022",
            Self::Utf8(_) => "E023",
        }
    }
}

#[allow(dead_code)]
impl Project {
    /// # Errors
    ///
    /// Returns an error if the manifest file doesn't exist or can't be read
    pub fn new(manifest: &Utf8PathBuf) -> Result<Self, ProjectError> {
        manifest.try_exists().map_err(|err| match err.kind() {
            io::ErrorKind::NotFound => ProjectError::MissingManifest(manifest.clone()),
            _ => ProjectError::from(err),
        })?;

        let root = manifest.parent().ok_or_else(|| {
            ProjectError::Io(io::Error::new(
                io::ErrorKind::NotFound,
                "Couldn't get parent directory of Scarb manifest file",
            ))
        })?;

        let metadata = MetadataCommand::new()
            .json()
            .manifest_path(manifest)
            .current_dir(root)
            .exec()?;

        Ok(Self(metadata))
    }

    #[must_use]
    pub const fn manifest_path(&self) -> &Utf8PathBuf {
        &self.0.workspace.manifest_path
    }

    #[must_use]
    pub const fn root_dir(&self) -> &Utf8PathBuf {
        &self.0.workspace.root
    }

    #[must_use]
    pub const fn metadata(&self) -> &Metadata {
        &self.0
    }

    #[must_use]
    pub fn get_license(&self) -> Option<LicenseId> {
        self.0.packages.first().and_then(|pkg| {
            pkg.manifest_metadata
                .license
                .as_ref()
                .and_then(|license_str| {
                    // Handle common SPDX identifiers directly
                    match license_str.as_str() {
                        "MIT" => spdx::license_id("MIT License"),
                        "Apache-2.0" => spdx::license_id("Apache License 2.0"),
                        "GPL-3.0" => spdx::license_id("GNU General Public License v3.0 only"),
                        "BSD-3-Clause" => spdx::license_id("BSD 3-Clause License"),
                        // Try exact match
                        _ => spdx::license_id(license_str).or_else(|| {
                            // Try imprecise matching
                            spdx::imprecise_license_id(license_str).map(|(lic, _)| lic)
                        }),
                    }
                })
        })
    }

    /// Detect if this is a Dojo project by analyzing dependencies
    ///
    /// # Errors
    ///
    /// Returns an error if the project metadata cannot be analyzed
    pub fn detect_project_type(&self) -> Result<ProjectType, ProjectError> {
        let metadata = self.metadata();

        // Check for dojo-core dependency in any package
        for package in &metadata.packages {
            for dep in &package.dependencies {
                if dep.name == "dojo_core" || dep.name == "dojo-core" || dep.name == "dojo" {
                    return Ok(ProjectType::Dojo);
                }
            }
        }

        // Check for dojo namespace imports in source files
        if self.has_dojo_imports() {
            return Ok(ProjectType::Dojo);
        }

        // Default to Scarb if no Dojo indicators found
        Ok(ProjectType::Scarb)
    }

    /// Check if source files contain Dojo-specific imports
    fn has_dojo_imports(&self) -> bool {
        use std::fs;
        use walkdir::WalkDir;

        let root = self.root_dir();
        let src_dir = root.join("src");

        if !src_dir.exists() {
            return false;
        }

        for entry in WalkDir::new(src_dir)
            .into_iter()
            .filter_map(std::result::Result::ok)
        {
            if entry.path().extension().and_then(|s| s.to_str()) == Some("cairo") {
                if let Ok(content) = fs::read_to_string(entry.path()) {
                    if content.contains("use dojo::")
                        || content.contains("dojo::")
                        || content.contains("#[dojo::")
                    {
                        return true;
                    }
                }
            }
        }

        false
    }
}

impl Display for Project {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.manifest_path())
    }
}

/// # Errors
///
/// Returns an error if the project path is invalid or the manifest cannot be read
pub fn project_value_parser(raw: &str) -> Result<Project, ProjectError> {
    let path = PathBuf::from(raw);

    let absolute = if path.is_absolute() {
        path
    } else {
        let mut cwd = env::current_dir()?;
        cwd.push(path);
        cwd
    };

    let utf8 = Utf8PathBuf::try_from(absolute)?;

    let manifest = if utf8.is_file() {
        utf8
    } else {
        utf8.join("Scarb.toml")
    };

    Project::new(&manifest)
}

#[derive(clap::Parser)]
#[command(name = "voyager")]
#[command(author = "Nethermind")]
#[command(version)]
#[command(about = "Verify Starknet smart contracts on block explorers")]
#[command(long_about = "
A command-line tool for verifying Starknet smart contracts on block explorers.

This tool allows you to verify that the source code of a deployed contract matches
the bytecode on the blockchain. It supports predefined networks (mainnet, sepolia, dev)
and custom API endpoints, automatically handling project dependencies and source file collection.

Examples:
  # Verify a contract on mainnet
  voyager verify --network mainnet \\
    --class-hash 0x044dc2b3239382230d8b1e943df23b96f52eebcac93efe6e8bde92f9a2f1da18 \\
    --contract-name MyContract

  # Verify a contract on development network
  voyager verify --network dev \\
    --class-hash 0x044dc2b3239382230d8b1e943df23b96f52eebcac93efe6e8bde92f9a2f1da18 \\
    --contract-name MyContract

  # Verify using custom API endpoint
  voyager verify --url https://api.custom.com/beta \\
    --class-hash 0x044dc2b3239382230d8b1e943df23b96f52eebcac93efe6e8bde92f9a2f1da18 \\
    --contract-name MyContract

  # Check verification status
  voyager status --network mainnet --job job-id-here

  # Check status using custom API
  voyager status --url https://api.custom.com/beta --job job-id-here
")]
pub struct Args {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(clap::Subcommand)]
#[allow(clippy::large_enum_variant)]
pub enum Commands {
    /// Verify a smart contract against its deployed bytecode
    ///
    /// Submits the contract source code for verification against the deployed
    /// bytecode on the blockchain. By default submits for verification.
    /// Use --dry-run to preview what would be submitted without sending.
    ///
    /// Examples:
    ///   # Using predefined network
    ///   voyager verify --network mainnet \
    ///     --class-hash 0x044dc2b3239382230d8b1e943df23b96f52eebcac93efe6e8bde92f9a2f1da18 \
    ///     --contract-name `MyContract`
    ///
    ///   # Using development network
    ///   voyager verify --network dev \
    ///     --class-hash 0x044dc2b3239382230d8b1e943df23b96f52eebcac93efe6e8bde92f9a2f1da18 \
    ///     --contract-name `MyContract`
    ///
    ///   # Using custom API endpoint
    ///   voyager verify --url <https://api.custom.com/beta> \
    ///     --class-hash 0x044dc2b3239382230d8b1e943df23b96f52eebcac93efe6e8bde92f9a2f1da18 \
    ///     --contract-name `MyContract`
    Verify(VerifyArgs),

    /// Check the status of a verification job
    ///
    /// Queries the verification service for the current status of a submitted
    /// verification job. The job ID is returned when you submit a verification.
    ///
    /// Examples:
    ///   # Using predefined network
    ///   voyager status --network mainnet --job 12345678-1234-1234-1234-123456789012
    ///
    ///   # Using development network
    ///   voyager status --network dev --job 12345678-1234-1234-1234-123456789012
    ///
    ///   # Using custom API endpoint
    ///   voyager status --url <https://api.custom.com/beta> --job 12345678-1234-1234-1234-123456789012
    Status(StatusArgs),

    /// Manage verification history
    ///
    /// Track and query past verification jobs stored locally in ~/.voyager/history.db
    ///
    /// Examples:
    ///   # List all verification jobs
    ///   voyager history list
    ///
    ///   # List successful verifications only
    ///   voyager history list --status success
    ///
    ///   # List jobs for specific network
    ///   voyager history list --network mainnet
    ///
    ///   # Get status of a specific job
    ///   voyager history status --job 12345678-1234-1234-1234-123456789012
    ///
    ///   # Re-check status of pending jobs
    ///   voyager history recheck
    ///
    ///   # Clean old entries
    ///   voyager history clean --older-than 30
    ///
    ///   # Show statistics
    ///   voyager history stats
    History(HistoryArgs),
}

/// # Errors
///
/// Returns an error if the license string is not a valid SPDX license identifier
pub fn license_value_parser(license: &str) -> Result<LicenseId, String> {
    // First try for exact SPDX identifier match
    if let Some(id) = spdx::license_id(license) {
        return Ok(id);
    }

    // For common shorthand identifiers, try to map to the full name
    let mapped_license = match license {
        "MIT" => "MIT License",
        "Apache-2.0" => "Apache License 2.0",
        "GPL-3.0" => "GNU General Public License v3.0 only",
        "BSD-3-Clause" => "BSD 3-Clause License",
        _ => license,
    };

    // Try again with mapped name
    if let Some(id) = spdx::license_id(mapped_license) {
        return Ok(id);
    }

    // Try imprecise matching as a last resort
    if let Some((lic, _)) = spdx::imprecise_license_id(license) {
        return Ok(lic);
    }

    // Provide helpful error with suggestion if available
    let guess = spdx::imprecise_license_id(license)
        .map_or(String::new(), |(lic, _): (LicenseId, usize)| {
            format!(", do you mean: {}?", lic.name)
        });

    Err(format!("Unrecognized license: {license}{guess}"))
}

/// # Errors
///
/// Returns an error if the contract name contains invalid characters
pub fn contract_name_value_parser(name: &str) -> Result<String, String> {
    // Check for minimum length
    if name.is_empty() {
        return Err("Contract name cannot be empty".to_string());
    }

    // Check for maximum length (reasonable limit)
    if name.len() > 100 {
        return Err("Contract name cannot exceed 100 characters".to_string());
    }

    // Check for valid characters: alphanumeric, underscore, hyphen
    let regex = get_name_validation_regex()?;
    if !regex.is_match(name) {
        return Err(
            "Contract name can only contain alphanumeric characters, underscores, and hyphens"
                .to_string(),
        );
    }

    // Check that it doesn't start with a hyphen or underscore
    if name.starts_with('-') || name.starts_with('_') {
        return Err("Contract name cannot start with a hyphen or underscore".to_string());
    }

    // Check that it doesn't end with a hyphen or underscore
    if name.ends_with('-') || name.ends_with('_') {
        return Err("Contract name cannot end with a hyphen or underscore".to_string());
    }

    // Additional security check: reject common system names
    let reserved_names = [
        "con", "aux", "prn", "nul", "com1", "com2", "com3", "com4", "com5", "com6", "com7", "com8",
        "com9", "lpt1", "lpt2", "lpt3", "lpt4", "lpt5", "lpt6", "lpt7", "lpt8", "lpt9",
    ];
    if reserved_names.contains(&name.to_lowercase().as_str()) {
        return Err("Contract name cannot be a reserved system name".to_string());
    }

    Ok(name.to_string())
}

fn package_name_value_parser(name: &str) -> Result<String, String> {
    // Check for minimum length
    if name.is_empty() {
        return Err("Package name cannot be empty".to_string());
    }

    // Check for maximum length (reasonable limit)
    if name.len() > 100 {
        return Err("Package name cannot exceed 100 characters".to_string());
    }

    // Check for valid characters: alphanumeric, underscore, hyphen
    let regex = get_name_validation_regex()?;
    if !regex.is_match(name) {
        return Err(
            "Package name can only contain alphanumeric characters, underscores, and hyphens"
                .to_string(),
        );
    }

    Ok(name.to_string())
}

#[allow(clippy::struct_excessive_bools)]
#[derive(clap::Args, Clone)]
pub struct VerifyArgs {
    /// Network to verify on (mainnet, sepolia, dev). If not specified, --url is required
    #[arg(long, value_enum)]
    pub network: Option<NetworkKind>,

    #[command(flatten)]
    pub network_url: Network,

    /// Perform dry run (preview what would be submitted without sending)
    #[arg(long, default_value_t = false)]
    pub dry_run: bool,

    /// Path to Scarb project directory (default: current directory)
    #[arg(
        long,
        value_name = "DIR",
        value_hint = clap::ValueHint::DirPath,
        value_parser = project_value_parser,
        default_value = "."
    )]
    pub path: Project,

    /// Class hash of the deployed contract to verify
    #[arg(
        long = "class-hash",
        value_name = "HASH",
        value_parser = ClassHash::new
    )]
    pub class_hash: Option<ClassHash>,

    /// Wait indefinitely for verification result (polls until completion)
    #[arg(long, default_value_t = false)]
    pub watch: bool,

    /// SPDX license identifier (e.g., MIT, Apache-2.0)
    #[arg(
        long,
        value_name = "SPDX",
        value_parser = license_value_parser,
    )]
    pub license: Option<LicenseId>,

    /// Name of the contract for verification
    #[arg(
        long = "contract-name",
        value_name = "NAME",
        value_parser = contract_name_value_parser
    )]
    pub contract_name: Option<String>,

    /// Select specific package for verification (required for workspace projects)
    #[arg(
        long,
        value_name = "PACKAGE_ID",
        value_parser = package_name_value_parser
    )]
    pub package: Option<String>,

    /// Include Scarb.lock file in verification submission
    #[arg(long, default_value_t = false)]
    pub lock_file: bool,

    /// Include test files from src/ directory in verification submission
    #[arg(long, default_value_t = false)]
    pub test_files: bool,

    /// Project type for build tool selection
    #[arg(
        long = "project-type",
        value_enum,
        default_value_t = ProjectType::Auto,
        help = "Specify the project type (scarb, dojo, or auto-detect)"
    )]
    pub project_type: ProjectType,

    /// Show detailed error messages from the remote compiler
    #[arg(long, short = 'v', default_value_t = false)]
    pub verbose: bool,

    /// Run interactive verification wizard
    #[arg(long, default_value_t = false)]
    pub wizard: bool,

    /// Send desktop notifications when verification completes (requires --watch)
    #[cfg(feature = "notifications")]
    #[arg(long, default_value_t = false)]
    pub notify: bool,

    /// Stop batch verification on first failure (default: continue all)
    #[arg(long, default_value_t = false)]
    pub fail_fast: bool,

    /// Delay in seconds between batch contract submissions (for rate limiting)
    #[arg(long, value_name = "SECONDS")]
    pub batch_delay: Option<u64>,
}

#[derive(clap::Args)]
pub struct StatusArgs {
    /// Network to verify on (mainnet, sepolia, dev). If not specified, --url is required
    #[arg(long, value_enum)]
    pub network: Option<NetworkKind>,

    #[command(flatten)]
    pub network_url: Network,

    /// Verification job ID (UUID format)
    #[arg(long, value_name = "UUID")]
    pub job: String,

    /// Show detailed error messages from the remote compiler
    #[arg(long, short = 'v', default_value_t = false)]
    pub verbose: bool,

    /// Output format for status information
    #[arg(long, value_enum, default_value = "text")]
    pub format: OutputFormat,
}

#[derive(clap::ValueEnum, Clone, Copy, Debug, Eq, PartialEq)]
pub enum OutputFormat {
    /// Human-readable text with enhanced formatting
    Text,

    /// JSON format for programmatic parsing
    Json,

    /// Table format (primarily for batch operations)
    Table,
}

#[derive(clap::ValueEnum, Clone)]
pub enum NetworkKind {
    /// Target the Mainnet
    Mainnet,

    /// Target Sepolia testnet
    Sepolia,

    /// Target the development network
    Dev,
}

#[derive(Clone)]
pub struct Network {
    /// API endpoint URL
    pub url: Url,
}

impl clap::FromArgMatches for Network {
    fn from_arg_matches(matches: &clap::ArgMatches) -> Result<Self, clap::Error> {
        // Check if wizard mode is enabled
        let wizard_mode = matches.get_one::<bool>("wizard").copied().unwrap_or(false);

        if wizard_mode {
            // In wizard mode, provide a placeholder URL that will be replaced by the wizard
            // SAFETY: Hardcoded URL is guaranteed to be valid
            #[allow(clippy::unwrap_used)]
            Ok(Self {
                url: Url::parse("https://api.voyager.online/beta").unwrap(),
            })
        } else {
            // Get URL from CLI args if provided, otherwise use a placeholder
            // that will be replaced by config file or cause a validation error later
            let url = matches.get_one::<Url>("url").cloned().unwrap_or_else(|| {
                // SAFETY: Hardcoded URL is guaranteed to be valid
                #[allow(clippy::unwrap_used)]
                Url::parse("https://placeholder.invalid").unwrap()
            });

            Ok(Self { url })
        }
    }

    fn from_arg_matches_mut(matches: &mut clap::ArgMatches) -> Result<Self, clap::Error> {
        Self::from_arg_matches(matches)
    }

    fn update_from_arg_matches(&mut self, matches: &clap::ArgMatches) -> Result<(), clap::Error> {
        let mut matches = matches.clone();
        self.update_from_arg_matches_mut(&mut matches)
    }

    fn update_from_arg_matches_mut(
        &mut self,
        matches: &mut clap::ArgMatches,
    ) -> Result<(), clap::Error> {
        // Check if wizard mode is enabled
        let wizard_mode = matches.get_one::<bool>("wizard").copied().unwrap_or(false);

        if !wizard_mode {
            // Get URL from CLI args if provided
            if let Some(url) = matches.get_one::<Url>("url") {
                self.url = url.clone();
            }
            // If not provided, keep existing URL (may be from config or placeholder)
        }
        // In wizard mode, keep the placeholder URL (will be replaced by wizard)
        Ok(())
    }
}

// Can't derive the default value logic, hence hand rolled instance
impl clap::Args for Network {
    fn augment_args(cmd: clap::Command) -> clap::Command {
        cmd.arg(
            clap::Arg::new("url")
                .long("url")
                .help("API endpoint URL (can also be set in .voyager.toml)")
                .value_hint(clap::ValueHint::Url)
                .value_parser(Url::parse)
                .default_value_ifs([
                    ("network", "mainnet", "https://api.voyager.online/beta"),
                    (
                        "network",
                        "sepolia",
                        "https://sepolia-api.voyager.online/beta",
                    ),
                    ("network", "dev", "https://dev-api.voyager.online/beta"),
                ]),
        )
    }

    fn augment_args_for_update(cmd: clap::Command) -> clap::Command {
        cmd.arg(
            clap::Arg::new("url")
                .long("url")
                .help("API endpoint URL (can also be set in .voyager.toml)")
                .value_hint(clap::ValueHint::Url)
                .value_parser(Url::parse)
                .default_value_ifs([
                    ("network", "mainnet", "https://api.voyager.online/beta"),
                    (
                        "network",
                        "sepolia",
                        "https://sepolia-api.voyager.online/beta",
                    ),
                    ("network", "dev", "https://dev-api.voyager.online/beta"),
                ]),
        )
    }
}

impl VerifyArgs {
    /// Detect if batch mode should be used based on config
    #[must_use]
    pub fn is_batch_mode(&self, config: &Option<super::config::Config>) -> bool {
        config.as_ref().is_some_and(|cfg| !cfg.contracts.is_empty())
    }

    /// Merge configuration file values with CLI arguments
    /// CLI arguments take precedence over config file values
    #[must_use]
    pub fn merge_with_config(mut self, config: &super::config::Config) -> Self {
        // Merge network if not provided via CLI
        if self.network.is_none() {
            self.network = config.parse_network();
        }

        // Merge license if not provided via CLI
        if self.license.is_none() {
            if let Some(ref license_str) = config.voyager.license {
                self.license = license_value_parser(license_str).ok();
            }
        }

        // Merge watch flag (only if not explicitly set via CLI)
        // Note: clap sets default_value_t, so we need to check if it was actually provided
        // For now, we'll use the config value if it exists
        if let Some(watch) = config.voyager.watch {
            if !self.watch {
                // Only override if CLI value is false (the default)
                self.watch = watch;
            }
        }

        // Merge test_files flag
        if let Some(test_files) = config.voyager.test_files {
            if !self.test_files {
                self.test_files = test_files;
            }
        }

        // Merge lock_file flag
        if let Some(lock_file) = config.voyager.lock_file {
            if !self.lock_file {
                self.lock_file = lock_file;
            }
        }

        // Merge verbose flag
        if let Some(verbose) = config.voyager.verbose {
            if !self.verbose {
                self.verbose = verbose;
            }
        }

        // Merge notify flag
        #[cfg(feature = "notifications")]
        if let Some(notify) = config.voyager.notify {
            if !self.notify {
                self.notify = notify;
            }
        }

        // Merge package if not provided via CLI
        if self.package.is_none() {
            self.package.clone_from(&config.workspace.default_package);
        }

        // Merge project_type if specified in config
        if let Some(ref project_type_str) = config.voyager.project_type {
            // Only override if still set to Auto
            if matches!(self.project_type, ProjectType::Auto) {
                self.project_type = match project_type_str.to_lowercase().as_str() {
                    "scarb" => ProjectType::Scarb,
                    "dojo" => ProjectType::Dojo,
                    "auto" => ProjectType::Auto,
                    _ => self.project_type, // Keep existing if invalid
                };
            }
        }

        // Merge URL if provided in config and not set via CLI or network flag
        // Check if URL is still the placeholder (means neither --url nor --network was provided)
        if self.network_url.url.as_str() == "https://placeholder.invalid/" {
            if let Some(ref url_str) = config.voyager.url {
                if let Ok(parsed_url) = Url::parse(url_str) {
                    self.network_url.url = parsed_url;
                }
            }
        }

        self
    }

    /// Validate that all required fields are set after config merging
    ///
    /// # Errors
    ///
    /// Returns an error if required fields are missing or invalid
    pub fn validate(&self) -> Result<(), String> {
        // Check if URL is still the placeholder (means no network, no url, and no config)
        if self.network_url.url.as_str() == "https://placeholder.invalid/" {
            return Err(
                "API URL is required. Provide --network, --url, or set 'network' or 'url' in .voyager.toml".to_string()
            );
        }

        Ok(())
    }
}

impl StatusArgs {
    /// Merge configuration file values with CLI arguments
    /// CLI arguments take precedence over config file values
    #[must_use]
    pub fn merge_with_config(mut self, config: &super::config::Config) -> Self {
        // Merge network if not provided via CLI
        if self.network.is_none() {
            self.network = config.parse_network();
        }

        // Merge verbose flag
        if let Some(verbose) = config.voyager.verbose {
            if !self.verbose {
                self.verbose = verbose;
            }
        }

        // Merge format if provided in config and not explicitly set via CLI
        // Check if format is still default "text" (means not explicitly set via CLI)
        if self.format == OutputFormat::Text {
            if let Some(ref format_str) = config.voyager.format {
                match format_str.to_lowercase().as_str() {
                    "json" => self.format = OutputFormat::Json,
                    "table" => self.format = OutputFormat::Table,
                    "text" => self.format = OutputFormat::Text,
                    _ => {} // Keep default if invalid format in config
                }
            }
        }

        // Merge URL if provided in config and not set via CLI or network flag
        // Check if URL is still the placeholder (means neither --url nor --network was provided)
        if self.network_url.url.as_str() == "https://placeholder.invalid/" {
            if let Some(ref url_str) = config.voyager.url {
                if let Ok(parsed_url) = Url::parse(url_str) {
                    self.network_url.url = parsed_url;
                }
            }
        }

        self
    }

    /// Validate that all required fields are set after config merging
    ///
    /// # Errors
    ///
    /// Returns an error if required fields are missing or invalid
    pub fn validate(&self) -> Result<(), String> {
        // Check if URL is still the placeholder (means no network, no url, and no config)
        if self.network_url.url.as_str() == "https://placeholder.invalid/" {
            return Err(
                "API URL is required. Provide --network, --url, or set 'network' or 'url' in .voyager.toml".to_string()
            );
        }

        Ok(())
    }
}

#[derive(clap::Args)]
pub struct HistoryArgs {
    #[command(subcommand)]
    pub command: HistoryCommands,
}

#[derive(clap::Subcommand)]
pub enum HistoryCommands {
    /// List verification jobs from history
    List {
        /// Filter by status (Success, Fail, `CompileFailed`, Submitted, Processing, Compiled)
        #[arg(long)]
        status: Option<String>,

        /// Filter by network (mainnet, sepolia, dev)
        #[arg(long)]
        network: Option<String>,

        /// Limit the number of results
        #[arg(long, default_value = "20")]
        limit: usize,
    },

    /// Get detailed status of a verification job from history
    Status {
        /// Verification job ID (UUID format)
        #[arg(long, value_name = "UUID")]
        job: String,

        /// Network to verify on (mainnet, sepolia, dev). If not specified, --url is required
        #[arg(long, value_enum)]
        network: Option<NetworkKind>,

        #[command(flatten)]
        network_url: Network,

        /// Re-check the status from the API and update local database
        #[arg(long, default_value_t = false)]
        refresh: bool,

        /// Show detailed error messages from the remote compiler
        #[arg(long, short = 'v', default_value_t = false)]
        verbose: bool,
    },

    /// Re-check status of all pending verification jobs
    Recheck {
        /// Network to verify on (mainnet, sepolia, dev). If not specified, --url is required
        #[arg(long, value_enum)]
        network: Option<NetworkKind>,

        #[command(flatten)]
        network_url: Network,

        /// Show detailed error messages from the remote compiler
        #[arg(long, short = 'v', default_value_t = false)]
        verbose: bool,
    },

    /// Clean old verification records from history
    Clean {
        /// Delete records older than N days
        #[arg(long, value_name = "DAYS")]
        older_than: Option<u32>,

        /// Delete all records (use with caution)
        #[arg(long, default_value_t = false)]
        all: bool,
    },

    /// Show verification history statistics
    Stats,
}
