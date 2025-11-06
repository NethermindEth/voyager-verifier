use verifier::args::{Args, Commands};

use clap::Parser;
use verifier::{config::Config, history_commands, status_commands, verify_commands};

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
            verify_commands::handle_verify_command(args, config.as_ref())?;
        }
        Commands::Status(args) => {
            status_commands::handle_status_command(args, config.as_ref())?;
        }
        Commands::History(args) => {
            history_commands::handle_history_command(args, config.as_ref())?;
        }
    }
    Ok(())
}
