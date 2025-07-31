use crate::Config;
use clap::Subcommand;
use tracing::info;

#[derive(Subcommand)]
pub enum MigrateAction {
    /// Run all pending migrations
    Up,
    /// Rollback the last migration
    Down {
        #[arg(
            short,
            long,
            help = "Number of migrations to rollback",
            default_value = "1"
        )]
        steps: u32,
    },
    /// Show migration status
    Status,
}

pub async fn handle_migrate_command(
    action: MigrateAction,
    config: &Config,
) -> Result<(), Box<dyn std::error::Error>> {
    use crate::cache::CacheManager;
    use crate::database::migration::Migrator;
    use crate::database::{DatabaseManager, DatabaseManagerImpl};
    use sea_orm_migration::MigratorTrait;
    use std::sync::Arc;

    let cache_manager = Arc::new(CacheManager::new_from_config(&config.cache).await?);
    let db_manager = DatabaseManagerImpl::new_from_config(config, cache_manager).await?;
    let connection = db_manager.connection();

    match action {
        MigrateAction::Up => {
            info!("Running pending migrations...");
            Migrator::up(connection, None).await?;
            info!("All migrations completed successfully");
        }
        MigrateAction::Down { steps } => {
            info!("Rolling back {} migration(s)...", steps);
            Migrator::down(connection, Some(steps)).await?;
            info!("Rollback completed successfully");
        }
        MigrateAction::Status => {
            info!("Checking migration status...");
            Migrator::status(connection).await?;
            println!("Migration status check completed (see logs for details)");
        }
    }

    Ok(())
}
