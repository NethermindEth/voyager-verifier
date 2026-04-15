use crate::{cli::args::Project, cli::args::VerifyArgs, errors::CliError};
use dialoguer::Select;
use log::{info, warn};
use voyager_verifier::core::project::ProjectType;

/// Determine the project type based on arguments and auto-detection.
///
/// # Errors
///
/// Returns a [`CliError`] if Dojo is specified for a non-Dojo project, or if
/// auto-detection and interactive selection fail.
pub fn determine_project_type(args: &VerifyArgs) -> Result<ProjectType, CliError> {
    match args.project_type {
        ProjectType::Scarb => Ok(ProjectType::Scarb),
        ProjectType::Dojo => {
            validate_dojo_project(&args.path)?;
            Ok(ProjectType::Dojo)
        }
        ProjectType::Auto => match args.path.detect_project_type() {
            ProjectType::Dojo => {
                info!("Detected Dojo project automatically");
                Ok(ProjectType::Dojo)
            }
            ProjectType::Scarb => {
                info!("Detected Scarb project automatically");
                Ok(ProjectType::Scarb)
            }
            ProjectType::Auto => {
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
        },
    }
}

/// Validate that a project is actually a Dojo project.
///
/// # Errors
///
/// Returns a [`CliError`] if project type detection fails or the project does
/// not contain Dojo dependencies.
pub fn validate_dojo_project(project: &Project) -> Result<(), CliError> {
    if std::process::Command::new("sozo")
        .arg("--version")
        .output()
        .is_err()
    {
        warn!("sozo command not found. Dojo project verification will be handled remotely.");
    }

    if project.detect_project_type() != ProjectType::Dojo {
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
