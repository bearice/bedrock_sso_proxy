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
    pub access_key_id: Option<String>,
    pub secret_access_key: Option<String>,
    pub profile: Option<String>,
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
                access_key_id: None,
                secret_access_key: None,
                profile: None,
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

    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self, ConfigError> {
        let mut builder =
            ConfigBuilder::builder().add_source(config::Config::try_from(&Config::default())?);

        if path.as_ref().exists() {
            builder = builder.add_source(File::from(path.as_ref()));
        }

        builder = builder.add_source(
            Environment::with_prefix("BEDROCK")
                .prefix_separator("_")
                .separator("__"),
        );

        builder.build()?.try_deserialize()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_config_default() {
        let config = Config::default();
        assert_eq!(config.server.host, "0.0.0.0");
        assert_eq!(config.server.port, 3000);
        assert_eq!(config.jwt.secret, "your-jwt-secret");
        assert_eq!(config.aws.region, "us-east-1");
        assert_eq!(config.logging.level, "info");
    }

    #[test]
    fn test_config_builder_with_env() {
        let env_source = Environment::with_prefix("BEDROCK")
            .prefix_separator("_")
            .separator("__");

        let builder = ConfigBuilder::builder()
            .add_source(config::Config::try_from(&Config::default()).unwrap())
            .add_source(env_source);

        let result = builder.build();
        assert!(result.is_ok());
    }

    #[test]
    fn test_config_load_from_yaml_file() {
        let yaml_content = r#"
server:
  host: "127.0.0.1"
  port: 4000
jwt:
  secret: "file-secret"
aws:
  region: "eu-west-1"
logging:
  level: "warn"
"#;

        let mut temp_file = NamedTempFile::with_suffix(".yaml").unwrap();
        temp_file.write_all(yaml_content.as_bytes()).unwrap();

        let config = Config::load_from_file(temp_file.path()).unwrap();

        assert_eq!(config.server.host, "127.0.0.1");
        assert_eq!(config.server.port, 4000);
        assert_eq!(config.jwt.secret, "file-secret");
        assert_eq!(config.aws.region, "eu-west-1");
        assert_eq!(config.logging.level, "warn");
    }

    #[test]
    fn test_config_file_loading() {
        let yaml_content = r#"
server:
  port: 4000
jwt:
  secret: "file-secret"
"#;

        let mut temp_file = NamedTempFile::with_suffix(".yaml").unwrap();
        temp_file.write_all(yaml_content.as_bytes()).unwrap();

        let builder = ConfigBuilder::builder()
            .add_source(config::Config::try_from(&Config::default()).unwrap())
            .add_source(File::from(temp_file.path()));

        let config: Config = builder.build().unwrap().try_deserialize().unwrap();

        assert_eq!(config.server.port, 4000);
        assert_eq!(config.jwt.secret, "file-secret");
    }

    #[test]
    fn test_config_load_nonexistent_file() {
        let config = Config::load_from_file("nonexistent.yaml").unwrap();

        assert_eq!(config.server.host, "0.0.0.0");
        assert_eq!(config.server.port, 3000);
    }
}
