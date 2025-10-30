//! Project type definitions and detection logic for build tool selection.
//!
//! This module provides functionality to detect and handle different types of Cairo projects:
//! - Regular Scarb projects (using `scarb build`)
//! - Dojo projects (using `sozo build`)
//! - Auto-detection based on dependencies and imports

/// Project type for build tool selection
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProjectType {
    /// Regular Scarb project (uses scarb build)
    Scarb,
    /// Dojo project (uses sozo build)
    Dojo,
    /// Auto-detect project type with interactive prompt
    Auto,
}

impl ProjectType {
    /// Get the build tool name for this project type
    pub const fn build_tool(&self) -> &'static str {
        match self {
            Self::Dojo => "sozo",
            _ => "scarb",
        }
    }
}

// Implement clap::ValueEnum for CLI usage
impl clap::ValueEnum for ProjectType {
    fn value_variants<'a>() -> &'a [Self] {
        &[Self::Scarb, Self::Dojo, Self::Auto]
    }

    fn to_possible_value(&self) -> Option<clap::builder::PossibleValue> {
        Some(match self {
            Self::Scarb => clap::builder::PossibleValue::new("scarb")
                .help("Regular Scarb project (uses scarb build)"),
            Self::Dojo => {
                clap::builder::PossibleValue::new("dojo").help("Dojo project (uses sozo build)")
            }
            Self::Auto => clap::builder::PossibleValue::new("auto")
                .help("Auto-detect project type with interactive prompt"),
        })
    }
}

impl std::str::FromStr for ProjectType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "scarb" => Ok(Self::Scarb),
            "dojo" => Ok(Self::Dojo),
            "auto" => Ok(Self::Auto),
            _ => Err(format!(
                "Invalid project type: {s}. Valid options: scarb, dojo, auto"
            )),
        }
    }
}

impl std::fmt::Display for ProjectType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Scarb => write!(f, "scarb"),
            Self::Dojo => write!(f, "dojo"),
            Self::Auto => write!(f, "auto"),
        }
    }
}

use crate::args::{Project, VerifyArgs};
use crate::errors::CliError;
use dialoguer::Select;
use log::{debug, info, warn};
use std::fs;

/// Determine the project type based on arguments and auto-detection
///
/// This function resolves the project type using the following priority:
/// 1. If explicitly set to Scarb or Dojo, uses that and validates
/// 2. If set to Auto, attempts automatic detection
/// 3. Falls back to interactive prompt if detection fails
///
/// # Arguments
///
/// * `args` - Verification arguments containing the project type preference
///
/// # Returns
///
/// Returns the resolved `ProjectType` (either Scarb or Dojo, never Auto)
///
/// # Errors
///
/// Returns a `CliError` if:
/// - Dojo is specified but project doesn't have Dojo dependencies
/// - Auto-detection or interactive prompt fails
pub fn determine_project_type(args: &VerifyArgs) -> Result<ProjectType, CliError> {
    match args.project_type {
        ProjectType::Scarb => Ok(ProjectType::Scarb),
        ProjectType::Dojo => {
            // Validate that this is actually a Dojo project
            validate_dojo_project(&args.path)?;
            Ok(ProjectType::Dojo)
        }
        ProjectType::Auto => {
            // Try automatic detection first
            match args.path.detect_project_type()? {
                ProjectType::Dojo => {
                    info!("Detected Dojo project automatically");
                    Ok(ProjectType::Dojo)
                }
                ProjectType::Scarb => {
                    info!("Detected Scarb project automatically");
                    Ok(ProjectType::Scarb)
                }
                ProjectType::Auto => {
                    // Fallback to interactive prompt
                    let options = vec![
                        "Regular Scarb project (uses scarb build)",
                        "Dojo project (uses sozo build)",
                    ];

                    let selection = Select::new()
                        .with_prompt("What type of project are you verifying?")
                        .items(&options)
                        .default(0)
                        .interact()?;

                    match selection {
                        0 => Ok(ProjectType::Scarb),
                        1 => {
                            validate_dojo_project(&args.path)?;
                            Ok(ProjectType::Dojo)
                        }
                        _ => unreachable!(),
                    }
                }
            }
        }
    }
}

/// Validate that a project is actually a Dojo project
///
/// Checks if the project has Dojo dependencies in its Scarb.toml.
/// Also verifies that the `sozo` command is available (optional warning).
///
/// # Arguments
///
/// * `project` - The project configuration to validate
///
/// # Returns
///
/// Returns `Ok(())` if the project is a valid Dojo project
///
/// # Errors
///
/// Returns a `CliError` if:
/// - Project doesn't have Dojo dependencies
/// - Project type detection fails
pub fn validate_dojo_project(project: &Project) -> Result<(), CliError> {
    // Check if sozo is available (optional warning)
    if std::process::Command::new("sozo")
        .arg("--version")
        .output()
        .is_err()
    {
        warn!("sozo command not found. Dojo project verification will be handled remotely.");
    }

    // Validate project has Dojo dependencies
    if project.detect_project_type()? != ProjectType::Dojo {
        return Err(CliError::InvalidProjectType {
            specified: "dojo".to_string(),
            detected: "scarb".to_string(),
            suggestions: vec![
                "Add dojo-core dependency to Scarb.toml".to_string(),
                "Use --project-type=scarb for regular Scarb projects".to_string(),
            ],
        });
    }

    Ok(())
}

/// Extract Dojo version from Scarb.toml
///
/// Attempts to extract the Dojo version from the project's Scarb.toml file.
/// Supports three common dependency formats:
/// 1. Simple string: `dojo = "1.7.1"`
/// 2. Git tag: `dojo = { tag = "v0.7.0", git = "..." }`
/// 3. Version table: `dojo = { version = "2.0.0" }`
///
/// # Arguments
///
/// * `project_dir_path` - Absolute path to the project directory containing Scarb.toml
///
/// # Returns
///
/// Returns `Some(version_string)` if a version is found, `None` otherwise.
///
/// # Examples
///
/// ```rust,ignore
/// let version = extract_dojo_version("/path/to/project");
/// assert_eq!(version, Some("1.7.1".to_string()));
/// ```
pub fn extract_dojo_version(project_dir_path: &str) -> Option<String> {
    let scarb_toml_path = format!("{project_dir_path}/Scarb.toml");
    debug!("📁 Looking for Scarb.toml at: {scarb_toml_path}");

    // Read the Scarb.toml file
    let contents = match fs::read_to_string(&scarb_toml_path) {
        Ok(contents) => {
            debug!("📖 Successfully read Scarb.toml ({} bytes)", contents.len());
            contents
        }
        Err(e) => {
            warn!("❌ Failed to read Scarb.toml at {scarb_toml_path}: {e}");
            return None;
        }
    };

    // Parse the TOML content
    let parsed: toml::Value = match toml::from_str(&contents) {
        Ok(parsed) => {
            debug!("✅ Successfully parsed Scarb.toml as TOML");
            parsed
        }
        Err(e) => {
            warn!("❌ Failed to parse Scarb.toml: {e}");
            return None;
        }
    };

    // Navigate to dependencies.dojo and extract version
    debug!("🔎 Searching for dependencies.dojo in Scarb.toml");
    if let Some(dependencies) = parsed.get("dependencies") {
        debug!("✅ Found [dependencies] section");
        if let Some(dojo_dep) = dependencies.get("dojo") {
            debug!("✅ Found dojo dependency: {dojo_dep:?}");

            // Case 1: dojo = "1.7.1" (simple string format)
            if let Some(version_str) = dojo_dep.as_str() {
                info!("🎯 Successfully extracted Dojo version from string: {version_str}");
                return Some(version_str.to_string());
            }

            // Case 2: dojo = { tag = "v0.7.0" } (git dependency with tag)
            if let Some(tag) = dojo_dep.get("tag") {
                if let Some(tag_str) = tag.as_str() {
                    info!("🎯 Successfully extracted Dojo version from tag: {tag_str}");
                    return Some(tag_str.to_string());
                } else {
                    warn!("⚠️  Tag field exists but is not a string: {tag:?}");
                }
            }

            // Case 3: dojo = { version = "1.7.1" } (table with version field)
            if let Some(version) = dojo_dep.get("version") {
                if let Some(version_str) = version.as_str() {
                    info!(
                        "🎯 Successfully extracted Dojo version from version field: {version_str}"
                    );
                    return Some(version_str.to_string());
                } else {
                    warn!("⚠️  Version field exists but is not a string: {version:?}");
                }
            }

            warn!("⚠️  Dojo dependency found but no recognized version format (expected string, 'tag', or 'version' field)");
        } else {
            warn!("⚠️  Dependencies section found but no 'dojo' dependency");
        }
    } else {
        warn!("⚠️  No [dependencies] section found in Scarb.toml");
    }

    info!("❌ No Dojo version found in Scarb.toml");
    None
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_extract_dojo_version_simple_string() {
        let temp_dir = TempDir::new().unwrap();
        let project_path = temp_dir.path().to_str().unwrap();

        // Create Scarb.toml with simple string format: dojo = "1.7.1"
        let scarb_toml_path = format!("{project_path}/Scarb.toml");
        fs::write(
            &scarb_toml_path,
            r#"
[package]
name = "test-project"
version = "1.0.0"

[dependencies]
dojo = "1.7.1"
"#,
        )
        .unwrap();

        let result = extract_dojo_version(project_path);
        assert_eq!(result, Some("1.7.1".to_string()));
    }

    #[test]
    fn test_extract_dojo_version_git_tag() {
        let temp_dir = TempDir::new().unwrap();
        let project_path = temp_dir.path().to_str().unwrap();

        // Create Scarb.toml with git tag format: dojo = { tag = "v0.7.0" }
        let scarb_toml_path = format!("{project_path}/Scarb.toml");
        fs::write(
            &scarb_toml_path,
            r#"
[package]
name = "test-project"
version = "1.0.0"

[dependencies]
dojo = { tag = "v0.7.0", git = "https://github.com/dojoengine/dojo" }
"#,
        )
        .unwrap();

        let result = extract_dojo_version(project_path);
        assert_eq!(result, Some("v0.7.0".to_string()));
    }

    #[test]
    fn test_extract_dojo_version_table_with_version_field() {
        let temp_dir = TempDir::new().unwrap();
        let project_path = temp_dir.path().to_str().unwrap();

        // Create Scarb.toml with table format: dojo = { version = "2.0.0" }
        let scarb_toml_path = format!("{project_path}/Scarb.toml");
        fs::write(
            &scarb_toml_path,
            r#"
[package]
name = "test-project"
version = "1.0.0"

[dependencies]
dojo = { version = "2.0.0" }
"#,
        )
        .unwrap();

        let result = extract_dojo_version(project_path);
        assert_eq!(result, Some("2.0.0".to_string()));
    }

    #[test]
    fn test_extract_dojo_version_no_dojo_dependency() {
        let temp_dir = TempDir::new().unwrap();
        let project_path = temp_dir.path().to_str().unwrap();

        // Create Scarb.toml without dojo dependency
        let scarb_toml_path = format!("{project_path}/Scarb.toml");
        fs::write(
            &scarb_toml_path,
            r#"
[package]
name = "test-project"
version = "1.0.0"

[dependencies]
starknet = "2.0.0"
"#,
        )
        .unwrap();

        let result = extract_dojo_version(project_path);
        assert_eq!(result, None);
    }

    #[test]
    fn test_extract_dojo_version_missing_scarb_toml() {
        let temp_dir = TempDir::new().unwrap();
        let project_path = temp_dir.path().to_str().unwrap();

        // Don't create Scarb.toml file
        let result = extract_dojo_version(project_path);
        assert_eq!(result, None);
    }

    #[test]
    fn test_extract_dojo_version_invalid_toml() {
        let temp_dir = TempDir::new().unwrap();
        let project_path = temp_dir.path().to_str().unwrap();

        // Create invalid TOML file
        let scarb_toml_path = format!("{project_path}/Scarb.toml");
        fs::write(&scarb_toml_path, "this is not valid toml [[[").unwrap();

        let result = extract_dojo_version(project_path);
        assert_eq!(result, None);
    }

    #[test]
    fn test_extract_dojo_version_priority_string_over_tag() {
        let temp_dir = TempDir::new().unwrap();
        let project_path = temp_dir.path().to_str().unwrap();

        // This shouldn't happen in practice, but test that simple string has priority
        // Since in TOML you can't have both at same level, test with string only
        let scarb_toml_path = format!("{project_path}/Scarb.toml");
        fs::write(
            &scarb_toml_path,
            r#"
[package]
name = "test-project"

[dependencies]
dojo = "3.0.0"
"#,
        )
        .unwrap();

        let result = extract_dojo_version(project_path);
        assert_eq!(result, Some("3.0.0".to_string()));
    }
}
