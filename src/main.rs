use bedrock_sso_proxy::commands::{Commands, handle_command};
use bedrock_sso_proxy::{Config, Server};
use clap::Parser;
use tracing::{error, info};

#[derive(Parser)]
#[command(name = "bedrock-sso-proxy")]
#[command(about = "SSO proxy for AWS Bedrock APIs")]
struct Cli {
    #[arg(short, long, help = "Path to configuration file")]
    config: Option<String>,

    #[command(subcommand)]
    command: Option<Commands>,
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
        if let Err(e) = handle_command(command, &config).await {
            error!("Command failed: {}", e);
            std::process::exit(1);
        }
        return;
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
