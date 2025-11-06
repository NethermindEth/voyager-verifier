//! Interactive verification wizard
//!
//! Provides a guided, step-by-step verification flow for users who prefer
//! interactive prompts over CLI flags.

use super::args::{
    contract_name_value_parser, license_value_parser, Network, NetworkKind, Project, VerifyArgs,
};
use crate::core::{class_hash::ClassHash, project::ProjectType};
use crate::utils::errors::CliError;
use dialoguer::{Confirm, Input, Select};
use reqwest::Url;
use scarb_metadata::PackageMetadata;
use spdx::LicenseId;

/// Summary of verification parameters for display
#[allow(clippy::struct_excessive_bools)]
struct VerificationSummary<'a> {
    network: &'a Option<NetworkKind>,
    network_url: &'a Network,
    class_hash: &'a ClassHash,
    package: &'a Option<String>,
    contract_name: &'a str,
    license: &'a Option<LicenseId>,
    lock_file: bool,
    test_files: bool,
    watch: bool,
    verbose: bool,
}

/// Run the interactive verification wizard
///
/// Prompts the user for all required and optional verification parameters,
/// validates inputs, and returns a populated `VerifyArgs` struct.
///
/// # Arguments
///
/// * `project` - Already-loaded Scarb project
///
/// # Returns
///
/// Returns a fully populated `VerifyArgs` struct ready for verification.
///
/// # Errors
///
/// Returns a `CliError` if:
/// - User cancels the wizard
/// - Interactive prompts fail (non-TTY environment)
/// - Invalid input is provided and validation fails
pub fn run_wizard(project: Project) -> Result<VerifyArgs, CliError> {
    println!("\n🧙 Interactive Verification Wizard\n");
    println!("This wizard will guide you through verifying your contract on Voyager.\n");

    // 1. Network selection
    let (network, network_url) = prompt_network()?;

    // 2. Class hash input
    let class_hash = prompt_class_hash()?;

    // 3. Package selection (if workspace)
    let package = prompt_package(&project)?;

    // 4. Contract name
    let contract_name = prompt_contract_name()?;

    // 5. License selection
    let license = prompt_license(&project)?;

    // 6. Optional features
    let lock_file = prompt_lock_file()?;
    let test_files = prompt_test_files()?;
    let watch = prompt_watch()?;
    let verbose = prompt_verbose()?;

    // 7. Show summary
    let summary = VerificationSummary {
        network: &network,
        network_url: &network_url,
        class_hash: &class_hash,
        package: &package,
        contract_name: &contract_name,
        license: &license,
        lock_file,
        test_files,
        watch,
        verbose,
    };
    show_summary(&summary);

    // 8. Final confirmation
    if !confirm_proceed()? {
        println!("\n❌ Verification cancelled by user.");
        std::process::exit(0);
    }

    // Build VerifyArgs
    Ok(VerifyArgs {
        network,
        network_url,
        dry_run: false,
        path: project,
        class_hash: Some(class_hash),
        watch,
        license,
        contract_name: Some(contract_name),
        package,
        lock_file,
        test_files,
        project_type: ProjectType::Auto,
        #[cfg(feature = "notifications")]
        notify: false,
        verbose,
        wizard: true, // Mark as wizard mode
        fail_fast: false,
        batch_delay: None,
    })
}

/// Prompt for network selection
fn prompt_network() -> Result<(Option<NetworkKind>, Network), CliError> {
    let options = vec![
        "Mainnet (api.voyager.online)",
        "Sepolia (sepolia-api.voyager.online)",
        "Dev (dev-api.voyager.online)",
        "Custom URL",
    ];

    let selection = Select::new()
        .with_prompt("Select network")
        .items(&options)
        .default(0)
        .interact()?;

    match selection {
        0 => Ok((
            Some(NetworkKind::Mainnet),
            Network {
                // SAFETY: Hardcoded URL is guaranteed to be valid
                #[allow(clippy::unwrap_used)]
                url: Url::parse("https://api.voyager.online/beta").unwrap(),
            },
        )),
        1 => Ok((
            Some(NetworkKind::Sepolia),
            Network {
                // SAFETY: Hardcoded URL is guaranteed to be valid
                #[allow(clippy::unwrap_used)]
                url: Url::parse("https://sepolia-api.voyager.online/beta").unwrap(),
            },
        )),
        2 => Ok((
            Some(NetworkKind::Dev),
            Network {
                // SAFETY: Hardcoded URL is guaranteed to be valid
                #[allow(clippy::unwrap_used)]
                url: Url::parse("https://dev-api.voyager.online/beta").unwrap(),
            },
        )),
        3 => {
            // Custom URL input
            let url: String = Input::new()
                .with_prompt("Enter custom network URL")
                .validate_with(|input: &String| -> Result<(), &str> {
                    Url::parse(input)
                        .map(|_| ())
                        .map_err(|_| "Invalid URL format. Please enter a valid HTTP/HTTPS URL")
                })
                .interact_text()?;

            // SAFETY: URL was validated in the input above
            #[allow(clippy::unwrap_used)]
            Ok((
                None,
                Network {
                    url: Url::parse(&url).unwrap(),
                },
            ))
        }
        _ => unreachable!(),
    }
}

/// Prompt for class hash input
fn prompt_class_hash() -> Result<ClassHash, CliError> {
    let hash_str: String = Input::new()
        .with_prompt("Enter class hash")
        .validate_with(|input: &String| -> Result<(), String> {
            // Validate using the ClassHash constructor
            ClassHash::new(input).map(|_| ()).map_err(|e| e.to_string())
        })
        .interact_text()?;

    // This should never fail because we validated above, but handle it just in case
    ClassHash::new(&hash_str).map_err(|e| {
        CliError::InteractivePromptFailed(dialoguer::Error::IO(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            e.to_string(),
        )))
    })
}

/// Prompt for package selection (only for workspaces)
fn prompt_package(project: &Project) -> Result<Option<String>, CliError> {
    let metadata = project.metadata();

    // Gather packages
    let packages: Vec<&PackageMetadata> = metadata
        .packages
        .iter()
        .filter(|pkg| metadata.workspace.members.contains(&pkg.id))
        .collect();

    // Check if this is a workspace project
    let is_workspace = packages.len() > 1;

    if !is_workspace {
        // Single package project, no need to prompt
        return Ok(None);
    }

    println!(
        "\n📦 Workspace project detected with {} packages",
        packages.len()
    );

    // Create options list
    let package_names: Vec<String> = packages.iter().map(|p| p.name.clone()).collect();

    if package_names.is_empty() {
        return Err(CliError::InteractivePromptFailed(dialoguer::Error::IO(
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "No packages found in workspace",
            ),
        )));
    }

    if package_names.len() == 1 {
        // Only one package, auto-select
        println!("   Auto-selecting package: {}", package_names[0]);
        return Ok(Some(package_names[0].clone()));
    }

    let selection = Select::new()
        .with_prompt("Select package to verify")
        .items(&package_names)
        .default(0)
        .interact()?;

    Ok(Some(package_names[selection].clone()))
}

/// Prompt for contract name
fn prompt_contract_name() -> Result<String, CliError> {
    let name: String = Input::new()
        .with_prompt("Enter contract name")
        .validate_with(|input: &String| -> Result<(), String> {
            contract_name_value_parser(input).map(|_| ())
        })
        .interact_text()?;

    Ok(name)
}

/// Prompt for license selection
fn prompt_license(project: &Project) -> Result<Option<LicenseId>, CliError> {
    // Try to detect license from Scarb.toml
    let detected_license = project.get_license();

    let mut options = vec![];

    // Add detected license first if found
    if let Some(detected) = &detected_license {
        options.push(format!("{} (detected in Scarb.toml)", detected.name));
    }

    // Default to first option
    let default_idx = 0;

    // Add common licenses
    let common_licenses = vec!["MIT", "Apache-2.0", "GPL-3.0", "BSD-3-Clause", "ISC"];

    for lic in &common_licenses {
        // Skip if already added as detected
        if detected_license
            .as_ref()
            .is_some_and(|d| d.name.contains(lic) || lic.contains(d.name))
        {
            continue;
        }
        options.push((*lic).to_string());
    }

    options.push("None (no license)".to_string());
    options.push("Custom SPDX identifier...".to_string());

    let selection = Select::new()
        .with_prompt("Select license")
        .items(&options)
        .default(default_idx)
        .interact()?;

    // Handle selection
    if selection == options.len() - 2 {
        // "None" selected
        Ok(None)
    } else if selection == options.len() - 1 {
        // "Custom" selected
        let custom: String = Input::new()
            .with_prompt("Enter SPDX license identifier (e.g., MIT, Apache-2.0)")
            .validate_with(|input: &String| -> Result<(), String> {
                if input.is_empty() {
                    return Err("License identifier cannot be empty".to_string());
                }
                license_value_parser(input).map(|_| ())
            })
            .interact_text()?;

        Ok(Some(license_value_parser(&custom).map_err(|e| {
            CliError::InteractivePromptFailed(dialoguer::Error::IO(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("Invalid license identifier: {e}"),
            )))
        })?))
    } else if selection == 0 && detected_license.is_some() {
        // Detected license selected
        Ok(detected_license)
    } else {
        // One of the common licenses selected
        let selected_name = &options[selection];
        Ok(Some(license_value_parser(selected_name).map_err(|e| {
            CliError::InteractivePromptFailed(dialoguer::Error::IO(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("Invalid license identifier: {e}"),
            )))
        })?))
    }
}

/// Prompt for Scarb.lock file inclusion
fn prompt_lock_file() -> Result<bool, CliError> {
    Ok(Confirm::new()
        .with_prompt("Include Scarb.lock file? (recommended for reproducible builds)")
        .default(true)
        .interact()?)
}

/// Prompt for test files inclusion
fn prompt_test_files() -> Result<bool, CliError> {
    Ok(Confirm::new()
        .with_prompt("Include test files from src/ directory?")
        .default(false)
        .interact()?)
}

/// Prompt for watch mode
fn prompt_watch() -> Result<bool, CliError> {
    Ok(Confirm::new()
        .with_prompt("Watch for verification completion? (poll until done)")
        .default(true)
        .interact()?)
}

/// Prompt for verbose output
fn prompt_verbose() -> Result<bool, CliError> {
    Ok(Confirm::new()
        .with_prompt("Enable verbose output? (show detailed debug information)")
        .default(false)
        .interact()?)
}

/// Display verification summary
fn show_summary(summary: &VerificationSummary) {
    println!("\n📋 Verification Summary:");
    println!("   ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

    // Network
    let network_display = match summary.network {
        Some(NetworkKind::Mainnet) => "Mainnet",
        Some(NetworkKind::Sepolia) => "Sepolia",
        Some(NetworkKind::Dev) => "Dev",
        None => "Custom",
    };
    println!(
        "   Network:      {} ({})",
        network_display, summary.network_url.url
    );

    // Class hash (truncated for display)
    let hash_str = summary.class_hash.to_string();
    let hash_display = if hash_str.len() > 20 {
        format!("{}...{}", &hash_str[..10], &hash_str[hash_str.len() - 6..])
    } else {
        hash_str
    };
    println!("   Class Hash:   {hash_display}");

    // Package (if specified)
    if let Some(pkg) = summary.package {
        println!("   Package:      {pkg}");
    }

    // Contract name
    println!("   Contract:     {}", summary.contract_name);

    // License
    match summary.license {
        Some(lic) => println!("   License:      {}", lic.name),
        None => println!("   License:      None"),
    }

    // Options
    let mut options_list = vec![];
    if summary.lock_file {
        options_list.push("lock-file");
    }
    if summary.test_files {
        options_list.push("test-files");
    }
    if summary.watch {
        options_list.push("watch");
    }
    if summary.verbose {
        options_list.push("verbose");
    }

    if !options_list.is_empty() {
        println!("   Options:      {}", options_list.join(", "));
    }

    println!("   ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
}

/// Confirm proceed with verification
fn confirm_proceed() -> Result<bool, CliError> {
    Ok(Confirm::new()
        .with_prompt("Proceed with verification?")
        .default(true)
        .interact()?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_contract_name_validation() {
        // Valid names
        assert!(contract_name_value_parser("MyToken").is_ok());
        assert!(contract_name_value_parser("my_token").is_ok());
        assert!(contract_name_value_parser("my-token").is_ok());
        assert!(contract_name_value_parser("Token123").is_ok());

        // Invalid names
        assert!(contract_name_value_parser("").is_err());
        assert!(contract_name_value_parser("-token").is_err());
        assert!(contract_name_value_parser("_token").is_err());
        assert!(contract_name_value_parser("token-").is_err());
        assert!(contract_name_value_parser("token_").is_err());
        assert!(contract_name_value_parser("my token").is_err()); // space
    }

    #[test]
    fn test_license_parsing() {
        // Common licenses should work
        assert!(license_value_parser("MIT").is_ok());
        assert!(license_value_parser("Apache-2.0").is_ok());
        assert!(license_value_parser("GPL-3.0").is_ok());

        // Invalid license should fail
        assert!(license_value_parser("InvalidLicense123").is_err());
    }
}
