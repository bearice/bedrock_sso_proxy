use bedrock_sso_proxy::{Config, Server};
use clap::{Parser, Subcommand};
use tracing::{error, info};

#[derive(Parser)]
#[command(name = "bedrock-sso-proxy")]
#[command(about = "A JWT-authenticated proxy for AWS Bedrock APIs")]
struct Cli {
    #[arg(short, long, help = "Path to configuration file")]
    config: Option<String>,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Run database migrations
    Migrate {
        #[command(subcommand)]
        action: MigrateAction,
    },
}

#[derive(Subcommand)]
enum MigrateAction {
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

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    let config = match Config::load() {
        Ok(config) => config,
        Err(e) => {
            eprintln!("Failed to load configuration: {}", e);
            std::process::exit(1);
        }
    };

    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new(&config.logging.level))
        .init();

    // Handle CLI commands
    if let Some(command) = cli.command {
        match command {
            Commands::Migrate { action } => {
                if let Err(e) = handle_migrate_command(action, &config).await {
                    error!("Migration command failed: {}", e);
                    std::process::exit(1);
                }
                return;
            }
        }
    }

    info!("Starting Bedrock SSO Proxy");
    info!("Configuration loaded successfully");

    let server = match Server::new(config).await {
        Ok(server) => server,
        Err(e) => {
            error!("Failed to initialize server: {}", e);
            std::process::exit(1);
        }
    };

    if let Err(e) = server.run().await {
        error!("Server error: {}", e);
        std::process::exit(1);
    }
}

async fn handle_migrate_command(
    action: MigrateAction,
    config: &Config,
) -> Result<(), Box<dyn std::error::Error>> {
    use bedrock_sso_proxy::cache::CacheManagerImpl;
    use bedrock_sso_proxy::database::migration::Migrator;
    use bedrock_sso_proxy::database::{DatabaseManager, DatabaseManagerImpl};
    use sea_orm_migration::MigratorTrait;
    use std::sync::Arc;

    let cache_manager = Arc::new(CacheManagerImpl::new_from_config(&config.cache).await?);
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
