pub mod init;
pub mod job;
pub mod migrate;

use crate::Config;
use clap::Subcommand;

#[derive(Subcommand)]
pub enum Commands {
    /// Initialize database with migrations and default data
    Init {
        #[arg(
            long,
            help = "Skip default model cost data seeding",
            default_value = "false"
        )]
        skip_costs: bool,
        #[arg(
            long,
            help = "Force re-seed default data even if it exists",
            default_value = "false"
        )]
        force_seed: bool,
    },
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
        Commands::Init { skip_costs, force_seed } => {
            init::handle_init_command(
                init::InitAction::Database { skip_costs, force_seed },
                config,
            ).await
        },
        Commands::Migrate { action } => migrate::handle_migrate_command(action, config).await,
        Commands::Job { command } => job::handle_job_command(command, config).await,
    }
}
