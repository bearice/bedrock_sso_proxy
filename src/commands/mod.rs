pub mod job;
pub mod migrate;

use crate::Config;
use clap::Subcommand;

#[derive(Subcommand)]
pub enum Commands {
    /// Run database migrations
    Migrate {
        #[command(subcommand)]
        action: migrate::MigrateAction,
    },
    /// Run and manage background jobs
    Job {
        #[command(subcommand)]
        command: job::JobCommand,
    },
}

pub async fn handle_command(
    command: Commands,
    config: &Config,
) -> Result<(), Box<dyn std::error::Error>> {
    match command {
        Commands::Migrate { action } => migrate::handle_migrate_command(action, config).await,
        Commands::Job { command } => job::handle_job_command(command, config).await,
    }
}
