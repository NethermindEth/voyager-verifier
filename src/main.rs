use verifier::cli::args::{Args, Commands};

use clap::Parser;
use verifier::cli::{commands, config::Config};

fn main() -> anyhow::Result<()> {
    env_logger::init();

    // Load configuration file if it exists
    let config = Config::find_and_load().unwrap_or_else(|err| {
        eprintln!("Warning: Failed to load config file: {err}");
        None
    });

    let Args { command: cmd } = Args::parse();

    match cmd {
        Commands::Verify(args) => {
            commands::verify::handle_verify_command(args, config.as_ref())?;
        }
        Commands::Status(args) => {
            commands::status::handle_status_command(args, config.as_ref())?;
        }
        Commands::History(args) => {
            commands::history::handle_history_command(args, config.as_ref())?;
        }
        Commands::Check(args) => {
            commands::check::handle_check_command(args, config.as_ref())?;
        }
    }
    Ok(())
}
