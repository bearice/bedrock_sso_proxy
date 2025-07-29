pub mod maintenance;
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
    /// Run maintenance and background processing tasks
    Maintenance {
        #[command(subcommand)]
        task: maintenance::MaintenanceTask,
    },
}

pub async fn handle_command(
    command: Commands,
    config: &Config,
) -> Result<(), Box<dyn std::error::Error>> {
    match command {
        Commands::Migrate { action } => migrate::handle_migrate_command(action, config).await,
        Commands::Maintenance { task } => {
            maintenance::handle_maintenance_command(task, config).await
        }
    }
}
