use crate::Config;
use crate::cost::CostTrackingService;
use crate::database::entities::ModelCosts;
use crate::database::DatabaseManager;
use clap::Subcommand;
use sea_orm::{EntityTrait, PaginatorTrait};
use std::sync::Arc;
use tracing::{info, warn, error};

#[derive(Subcommand)]
pub enum InitAction {
    /// Initialize database with migrations and default data
    Database {
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
}

pub async fn handle_init_command(
    action: InitAction,
    config: &Config,
) -> Result<(), Box<dyn std::error::Error>> {
    use crate::cache::CacheManager;
    use crate::database::migration::Migrator;
    use crate::database::{DatabaseManager, DatabaseManagerImpl};
    use sea_orm_migration::MigratorTrait;
    use std::sync::Arc;

    match action {
        InitAction::Database { skip_costs, force_seed } => {
            info!("Initializing database...");

            // Create dependencies
            let cache_manager = Arc::new(CacheManager::new_from_config(&config.cache).await?);
            let db_manager = DatabaseManagerImpl::new_from_config(config, cache_manager).await?;
            let connection = db_manager.connection();

            // Step 1: Run migrations (idempotent)
            info!("Running database migrations...");
            Migrator::up(connection, None).await?;
            info!("✅ Database migrations completed");

            // Step 2: Seed default data (idempotent)
            if !skip_costs {
                info!("Seeding default model cost data...");
                let db_manager_arc: Arc<dyn DatabaseManager> = Arc::new(db_manager);
                match seed_default_model_costs(db_manager_arc, force_seed).await {
                    Ok(count) => {
                        if count > 0 {
                            info!("✅ Seeded {} default model cost records", count);
                        } else {
                            info!("✅ Default model cost data already exists (use --force-seed to re-seed)");
                        }
                    }
                    Err(e) => {
                        warn!("⚠️  Failed to seed default model costs: {}", e);
                        warn!("Database initialization completed, but default costs may need manual setup");
                    }
                }
            } else {
                info!("⏭️  Skipping default model cost data seeding");
            }

            info!("🎉 Database initialization completed successfully");
        }
    }

    Ok(())
}

/// Seed default model cost data in an idempotent way using the existing cost service
async fn seed_default_model_costs(
    db_manager: Arc<dyn DatabaseManager>,
    force_seed: bool,
) -> Result<usize, Box<dyn std::error::Error>> {

    let connection = db_manager.connection();

    // Check if data already exists and whether to proceed
    if !force_seed {
        let existing_count = ModelCosts::find().count(connection).await?;
        if existing_count > 0 {
            return Ok(0); // No new records seeded
        }
    } else {
        // Clear existing data if force seeding
        info!("Force seeding enabled - clearing existing model cost data");
        ModelCosts::delete_many().exec(connection).await?;
    }

    // Use the existing cost tracking service to initialize with embedded CSV data
    let cost_service = CostTrackingService::new(db_manager);
    
    match cost_service.initialize_model_costs_from_embedded().await {
        Ok(result) => {
            info!("Successfully seeded {} model costs from embedded data", result.total_processed);
            Ok(result.total_processed)
        }
        Err(e) => {
            error!("Failed to seed model costs: {}", e);
            Err(Box::new(e))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::TestServerBuilder;

    #[tokio::test]
    async fn test_init_database_idempotent() {
        let server = TestServerBuilder::new().build().await;
        let config = &server.config;

        // First initialization
        let result = handle_init_command(
            InitAction::Database {
                skip_costs: false,
                force_seed: false,
            },
            config,
        ).await;
        assert!(result.is_ok());

        // Second initialization should also succeed (idempotent)
        let result = handle_init_command(
            InitAction::Database {
                skip_costs: false,
                force_seed: false,
            },
            config,
        ).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_init_database_skip_costs() {
        let server = TestServerBuilder::new().build().await;
        let config = &server.config;

        let result = handle_init_command(
            InitAction::Database {
                skip_costs: true,
                force_seed: false,
            },
            config,
        ).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_init_database_force_seed() {
        let server = TestServerBuilder::new().build().await;
        let config = &server.config;

        // First run with force seed
        let result = handle_init_command(
            InitAction::Database {
                skip_costs: false,
                force_seed: true,
            },
            config,
        ).await;
        assert!(result.is_ok());

        // Second run with force seed should clear and re-seed
        let result = handle_init_command(
            InitAction::Database {
                skip_costs: false,
                force_seed: true,
            },
            config,
        ).await;
        assert!(result.is_ok());
    }

    #[tokio::test] 
    async fn test_seed_default_model_costs() {
        let server = TestServerBuilder::new().build().await;
        let db_manager = server.database.clone();

        // Test initial seeding
        let count = seed_default_model_costs(db_manager.clone(), false).await.unwrap();
        assert!(count > 0);

        // Test idempotent behavior
        let count = seed_default_model_costs(db_manager.clone(), false).await.unwrap();
        assert_eq!(count, 0); // Should not seed again

        // Test force seeding
        let count = seed_default_model_costs(db_manager, true).await.unwrap();
        assert!(count > 0); // Should seed again
    }
}