//! Configuration file support for voyager-verifier
//!
//! This module provides support for `.voyager.toml` configuration files to reduce
//! command-line verbosity and enable shareable team configurations.
//!
//! ## File Location
//!
//! The config file is searched for in the following locations (in order):
//! 1. Current working directory: `.voyager.toml`
//! 2. Parent directories (walking up until a config file is found or root is reached)
//!
//! ## Priority
//!
//! Configuration values are merged with the following priority:
//! - CLI arguments (highest priority)
//! - Config file values
//! - Default values (lowest priority)
//!
//! ## Example Configuration
//!
//! ```toml
//! [voyager]
//! network = "mainnet"
//! license = "MIT"
//! watch = true
//! test_files = false
//! lock_file = true
//! verbose = false
//!
//! [workspace]
//! default_package = "my_contract"
//! ```

use camino::Utf8PathBuf;
use serde::{Deserialize, Serialize};
use std::{env, fs, io};
use thiserror::Error;

use super::args::NetworkKind;

/// Configuration file name
pub const CONFIG_FILE_NAME: &str = ".voyager.toml";

#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("[E030] Failed to read config file: {0}\n\nSuggestions:\n  • Check file permissions\n  • Verify the file exists and is accessible\n  • Ensure you have read access to the file")]
    Io(#[from] io::Error),

    #[error("[E031] Failed to parse config file: {0}\n\nSuggestions:\n  • Check that .voyager.toml is valid TOML format\n  • Verify all field names are spelled correctly\n  • Ensure values match expected types (e.g., boolean, string)\n  • Run a TOML validator on your config file")]
    Parse(#[from] toml::de::Error),

    #[error("[E032] Invalid UTF-8 path: {0}\n\nSuggestions:\n  • Use only ASCII characters in file paths\n  • Avoid special characters in directory names")]
    Utf8(#[from] camino::FromPathBufError),
}

impl ConfigError {
    #[must_use]
    pub const fn error_code(&self) -> &'static str {
        match self {
            Self::Io(_) => "E030",
            Self::Parse(_) => "E031",
            Self::Utf8(_) => "E032",
        }
    }
}

/// Configuration for a single contract in batch verification
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub struct ContractConfig {
    /// Class hash of the deployed contract to verify
    pub class_hash: String,

    /// Name of the contract for verification
    pub contract_name: String,

    /// Optional package name (for workspace projects)
    /// If not specified, will use `workspace.default_package` or auto-detect
    pub package: Option<String>,
}

/// Top-level configuration structure
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub struct Config {
    /// Voyager verification settings
    #[serde(default)]
    pub voyager: VoyagerConfig,

    /// Workspace-specific settings
    #[serde(default)]
    pub workspace: WorkspaceConfig,

    /// Batch verification contracts
    /// When this array is non-empty, the verifier runs in batch mode
    #[serde(default)]
    pub contracts: Vec<ContractConfig>,
}

/// Voyager verification configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub struct VoyagerConfig {
    /// Network to verify on (mainnet, sepolia, dev)
    pub network: Option<String>,

    /// SPDX license identifier (e.g., MIT, Apache-2.0)
    pub license: Option<String>,

    /// Wait indefinitely for verification result
    #[serde(default)]
    pub watch: Option<bool>,

    /// Include test files from src/ directory
    #[serde(default)]
    pub test_files: Option<bool>,

    /// Include Scarb.lock file in verification submission
    #[serde(default)]
    pub lock_file: Option<bool>,

    /// Show detailed error messages from the remote compiler
    #[serde(default)]
    pub verbose: Option<bool>,

    /// Custom API endpoint URL
    pub url: Option<String>,

    /// Project type (scarb, dojo, auto)
    pub project_type: Option<String>,

    /// Send desktop notifications when verification completes (requires watch mode)
    #[cfg(feature = "notifications")]
    #[serde(default)]
    pub notify: Option<bool>,

    /// Output format for status information (text, json, table)
    #[serde(default)]
    pub format: Option<String>,
}

/// Workspace-specific configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub struct WorkspaceConfig {
    /// Default package for verification in workspace projects
    pub default_package: Option<String>,
}

impl Config {
    /// Load configuration from a file
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read or parsed as valid TOML
    pub fn from_file(path: &Utf8PathBuf) -> Result<Self, ConfigError> {
        let content = fs::read_to_string(path)?;
        let config: Self = toml::from_str(&content)?;
        Ok(config)
    }

    /// Find and load configuration file by searching current and parent directories
    ///
    /// Returns None if no config file is found (which is not an error)
    ///
    /// # Errors
    ///
    /// Returns an error if a config file is found but cannot be read or parsed
    pub fn find_and_load() -> Result<Option<Self>, ConfigError> {
        if let Some(config_path) = Self::find_config_file()? {
            Ok(Some(Self::from_file(&config_path)?))
        } else {
            Ok(None)
        }
    }

    /// Find the config file by searching current and parent directories
    fn find_config_file() -> Result<Option<Utf8PathBuf>, ConfigError> {
        let mut current = env::current_dir()?;

        loop {
            let config_path = current.join(CONFIG_FILE_NAME);
            if config_path.exists() {
                return Ok(Some(Utf8PathBuf::try_from(config_path)?));
            }

            // Move to parent directory
            match current.parent() {
                Some(parent) => current = parent.to_path_buf(),
                None => return Ok(None), // Reached root without finding config
            }
        }
    }

    /// Convert network string to `NetworkKind` enum
    #[must_use]
    pub fn parse_network(&self) -> Option<NetworkKind> {
        self.voyager
            .network
            .as_ref()
            .and_then(|n| match n.to_lowercase().as_str() {
                "mainnet" => Some(NetworkKind::Mainnet),
                "sepolia" => Some(NetworkKind::Sepolia),
                "dev" => Some(NetworkKind::Dev),
                _ => None,
            })
    }
}

/// Resolves the API URL from CLI args and config
///
/// # Errors
///
/// Returns an error if the URL cannot be parsed
pub fn resolve_api_url(
    network_url: super::args::Network,
    config: Option<&Config>,
) -> anyhow::Result<reqwest::Url> {
    if network_url.url.as_str() == "https://placeholder.invalid/" {
        if let Some(cfg) = config {
            if let Some(ref url_str) = cfg.voyager.url {
                Ok(reqwest::Url::parse(url_str)?)
            } else {
                eprintln!("Error: API URL is required. Provide --network, --url, or set 'network' or 'url' in .voyager.toml");
                std::process::exit(1);
            }
        } else {
            eprintln!("Error: API URL is required. Provide --network, --url, or set 'network' or 'url' in .voyager.toml");
            std::process::exit(1);
        }
    } else {
        Ok(network_url.url)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_parse_minimal_config() -> Result<(), Box<dyn std::error::Error>> {
        let toml = r#"
            [voyager]
            network = "mainnet"
        "#;

        let config: Config = toml::from_str(toml)?;
        assert_eq!(config.voyager.network, Some("mainnet".to_string()));
        assert_eq!(config.voyager.license, None);
        Ok(())
    }

    #[test]
    fn test_parse_full_config() -> Result<(), Box<dyn std::error::Error>> {
        let toml = r#"
            [voyager]
            network = "mainnet"
            license = "MIT"
            watch = true
            test-files = false
            lock-file = true
            verbose = false
            notify = true
            project-type = "scarb"

            [workspace]
            default-package = "my_contract"
        "#;

        let config: Config = toml::from_str(toml)?;
        assert_eq!(config.voyager.network, Some("mainnet".to_string()));
        assert_eq!(config.voyager.license, Some("MIT".to_string()));
        assert_eq!(config.voyager.watch, Some(true));
        assert_eq!(config.voyager.test_files, Some(false));
        assert_eq!(config.voyager.lock_file, Some(true));
        assert_eq!(config.voyager.verbose, Some(false));
        #[cfg(feature = "notifications")]
        assert_eq!(config.voyager.notify, Some(true));
        assert_eq!(config.voyager.project_type, Some("scarb".to_string()));
        assert_eq!(
            config.workspace.default_package,
            Some("my_contract".to_string())
        );
        Ok(())
    }

    #[test]
    fn test_parse_empty_config() -> Result<(), Box<dyn std::error::Error>> {
        let toml = r"
            [voyager]
            [workspace]
        ";

        let config: Config = toml::from_str(toml)?;
        assert_eq!(config.voyager.network, None);
        assert_eq!(config.workspace.default_package, None);
        Ok(())
    }

    #[test]
    fn test_load_from_file() -> Result<(), Box<dyn std::error::Error>> {
        let toml = r#"
            [voyager]
            network = "sepolia"
            license = "Apache-2.0"
        "#;

        let mut tmp_file = NamedTempFile::new()?;
        tmp_file.write_all(toml.as_bytes())?;
        tmp_file.flush()?;

        let path = Utf8PathBuf::try_from(tmp_file.path().to_path_buf())?;
        let config = Config::from_file(&path)?;

        assert_eq!(config.voyager.network, Some("sepolia".to_string()));
        assert_eq!(config.voyager.license, Some("Apache-2.0".to_string()));
        Ok(())
    }

    #[test]
    fn test_parse_network() -> Result<(), Box<dyn std::error::Error>> {
        let toml = r#"
            [voyager]
            network = "mainnet"
        "#;
        let config: Config = toml::from_str(toml)?;
        assert!(matches!(config.parse_network(), Some(NetworkKind::Mainnet)));

        let toml = r#"
            [voyager]
            network = "sepolia"
        "#;
        let config: Config = toml::from_str(toml)?;
        assert!(matches!(config.parse_network(), Some(NetworkKind::Sepolia)));

        let toml = r#"
            [voyager]
            network = "dev"
        "#;
        let config: Config = toml::from_str(toml)?;
        assert!(matches!(config.parse_network(), Some(NetworkKind::Dev)));
        Ok(())
    }

    #[test]
    fn test_invalid_toml() {
        let toml = r#"
            [voyager
            network = "mainnet"
        "#;

        let result: Result<Config, _> = toml::from_str(toml);
        assert!(result.is_err());
    }

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert_eq!(config.voyager.network, None);
        assert_eq!(config.voyager.license, None);
        assert_eq!(config.workspace.default_package, None);
        assert!(config.contracts.is_empty());
    }

    #[test]
    fn test_parse_batch_contracts() -> Result<(), Box<dyn std::error::Error>> {
        let toml = r#"
            [voyager]
            network = "mainnet"

            [[contracts]]
            class-hash = "0x044dc2b3239382230d8b1e943df23b96f52eebcac93efe6e8bde92f9a2f1da18"
            contract-name = "MyToken"
            package = "token"

            [[contracts]]
            class-hash = "0x055dc2b3239382230d8b1e943df23b96f52eebcac93efe6e8bde92f9a2f1da19"
            contract-name = "MyNFT"
        "#;

        let config: Config = toml::from_str(toml)?;
        assert_eq!(config.contracts.len(), 2);
        assert_eq!(
            config.contracts[0].class_hash,
            "0x044dc2b3239382230d8b1e943df23b96f52eebcac93efe6e8bde92f9a2f1da18"
        );
        assert_eq!(config.contracts[0].contract_name, "MyToken");
        assert_eq!(config.contracts[0].package, Some("token".to_string()));
        assert_eq!(
            config.contracts[1].class_hash,
            "0x055dc2b3239382230d8b1e943df23b96f52eebcac93efe6e8bde92f9a2f1da19"
        );
        assert_eq!(config.contracts[1].contract_name, "MyNFT");
        assert_eq!(config.contracts[1].package, None);
        Ok(())
    }
}
