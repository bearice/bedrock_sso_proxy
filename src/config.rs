use config::{Config as ConfigBuilder, ConfigError, Environment, File};
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
    pub jwt: JwtConfig,
    pub aws: AwsConfig,
    pub logging: LoggingConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtConfig {
    pub secret: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AwsConfig {
    pub region: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    pub level: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            server: ServerConfig {
                host: "0.0.0.0".to_string(),
                port: 3000,
            },
            jwt: JwtConfig {
                secret: "your-jwt-secret".to_string(),
            },
            aws: AwsConfig {
                region: "us-east-1".to_string(),
            },
            logging: LoggingConfig {
                level: "info".to_string(),
            },
        }
    }
}

impl Config {
    pub fn load() -> Result<Self, ConfigError> {
        let mut builder =
            ConfigBuilder::builder().add_source(config::Config::try_from(&Config::default())?);

        if Path::new("config.yaml").exists() {
            builder = builder.add_source(File::with_name("config"));
        }

        builder = builder.add_source(
            Environment::with_prefix("BEDROCK")
                .prefix_separator("_")
                .separator("__"),
        );

        builder.build()?.try_deserialize()
    }
}
