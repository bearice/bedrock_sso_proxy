use bedrock_sso_proxy::{Config, Server};
use clap::Parser;
use tracing::{error, info};

#[derive(Parser)]
#[command(name = "bedrock-sso-proxy")]
#[command(about = "A JWT-authenticated proxy for AWS Bedrock APIs")]
struct Cli {
    #[arg(short, long, help = "Path to configuration file")]
    config: Option<String>,
}

#[tokio::main]
async fn main() {
    let _cli = Cli::parse();

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

    info!("Starting Bedrock SSO Proxy");
    info!("Configuration loaded successfully");

    let server = Server::new(config);

    if let Err(e) = server.run().await {
        error!("Server error: {}", e);
        std::process::exit(1);
    }
}
