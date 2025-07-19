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
    #[serde(default = "default_jwt_algorithm")]
    pub algorithm: String,
}

fn default_jwt_algorithm() -> String {
    "HS256".to_string()
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
                algorithm: "HS256".to_string(),
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
        assert_eq!(config.jwt.algorithm, "HS256");
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
        assert_eq!(config.jwt.algorithm, "HS256");
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
        assert_eq!(config.jwt.algorithm, "HS256");
    }

    #[test]
    fn test_config_load_nonexistent_file() {
        // Clean any environment variables that might interfere
        unsafe {
            std::env::remove_var("BEDROCK_SERVER__HOST");
            std::env::remove_var("BEDROCK_SERVER__PORT");
            std::env::remove_var("BEDROCK_JWT__SECRET");
            std::env::remove_var("BEDROCK_AWS__REGION");
            std::env::remove_var("BEDROCK_LOGGING__LEVEL");
        }

        let config = Config::load_from_file("nonexistent.yaml").unwrap();

        assert_eq!(config.server.host, "0.0.0.0");
        assert_eq!(config.server.port, 3000);
    }

    #[test]
    fn test_config_load_with_environment_variables() {
        unsafe {
            std::env::set_var("BEDROCK_SERVER__HOST", "127.0.0.1");
            std::env::set_var("BEDROCK_SERVER__PORT", "8080");
            std::env::set_var("BEDROCK_JWT__SECRET", "env-secret");
            std::env::set_var("BEDROCK_AWS__REGION", "eu-central-1");
            std::env::set_var("BEDROCK_LOGGING__LEVEL", "debug");
        }

        let config = Config::load_from_file("nonexistent.yaml").unwrap();

        assert_eq!(config.server.host, "127.0.0.1");
        assert_eq!(config.server.port, 8080);
        assert_eq!(config.jwt.secret, "env-secret");
        assert_eq!(config.aws.region, "eu-central-1");
        assert_eq!(config.logging.level, "debug");

        // Clean up environment variables
        unsafe {
            std::env::remove_var("BEDROCK_SERVER__HOST");
            std::env::remove_var("BEDROCK_SERVER__PORT");
            std::env::remove_var("BEDROCK_JWT__SECRET");
            std::env::remove_var("BEDROCK_AWS__REGION");
            std::env::remove_var("BEDROCK_LOGGING__LEVEL");
        }
    }

    #[test]
    fn test_config_load_with_invalid_yaml() {
        let invalid_yaml = "invalid: yaml: content: [";
        let mut temp_file = NamedTempFile::with_suffix(".yaml").unwrap();
        temp_file.write_all(invalid_yaml.as_bytes()).unwrap();

        let result = Config::load_from_file(temp_file.path());
        assert!(result.is_err());
    }

    #[test]
    fn test_config_load_with_partial_yaml() {
        let yaml_content = r#"
server:
  port: 5000
jwt:
  secret: "partial-secret"
"#;
        let mut temp_file = NamedTempFile::with_suffix(".yaml").unwrap();
        temp_file.write_all(yaml_content.as_bytes()).unwrap();

        let config = Config::load_from_file(temp_file.path()).unwrap();

        // Should use defaults for missing values
        assert_eq!(config.server.host, "0.0.0.0"); // Default
        assert_eq!(config.server.port, 5000); // From file
        assert_eq!(config.jwt.secret, "partial-secret"); // From file
        assert_eq!(config.aws.region, "us-east-1"); // Default
        assert_eq!(config.logging.level, "info"); // Default
    }

    #[test]
    fn test_config_with_algorithm() {
        let yaml_content = r#"
server:
  host: "0.0.0.0"
  port: 3000
jwt:
  secret: "test-secret"
  algorithm: "RS256"
aws:
  region: "us-east-1"
logging:
  level: "info"
"#;
        let mut temp_file = NamedTempFile::with_suffix(".yaml").unwrap();
        temp_file.write_all(yaml_content.as_bytes()).unwrap();

        let config = Config::load_from_file(temp_file.path()).unwrap();

        assert_eq!(config.jwt.secret, "test-secret");
        assert_eq!(config.jwt.algorithm, "RS256");
    }

    #[test]
    fn test_aws_config_with_credentials() {
        let yaml_content = r#"
server:
  host: "0.0.0.0"
  port: 3000
jwt:
  secret: "test-secret"
aws:
  region: "us-west-2"
  access_key_id: "AKIAIOSFODNN7EXAMPLE"
  secret_access_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
  profile: "test-profile"
logging:
  level: "info"
"#;
        let mut temp_file = NamedTempFile::with_suffix(".yaml").unwrap();
        temp_file.write_all(yaml_content.as_bytes()).unwrap();

        let config = Config::load_from_file(temp_file.path()).unwrap();

        assert_eq!(config.aws.region, "us-west-2");
        assert_eq!(
            config.aws.access_key_id,
            Some("AKIAIOSFODNN7EXAMPLE".to_string())
        );
        assert_eq!(
            config.aws.secret_access_key,
            Some("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".to_string())
        );
        assert_eq!(config.aws.profile, Some("test-profile".to_string()));
    }
}
