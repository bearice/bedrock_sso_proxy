use config::{Config as ConfigBuilder, ConfigError, Environment, File};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, path::Path};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
    pub jwt: JwtConfig,
    pub aws: AwsConfig,
    #[serde(default)]
    pub logging: LoggingConfig,
    #[serde(default)]
    pub oauth: OAuthConfig,
    #[serde(default)]
    pub cache: CacheConfig,
    #[serde(default)]
    pub frontend: FrontendConfig,
    #[serde(default)]
    pub admin: AdminConfig,
    #[serde(default)]
    pub storage: StorageConfig,
    #[serde(default)]
    pub metrics: MetricsConfig,
    #[serde(default)]
    pub model_mapping: ModelMappingConfig,
    #[serde(default)]
    pub usage_tracking: UsageTrackingConfig,
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
    #[serde(default = "default_access_token_ttl")]
    pub access_token_ttl: u64,
    #[serde(default = "default_refresh_token_ttl")]
    pub refresh_token_ttl: u64,
}

fn default_jwt_algorithm() -> String {
    "HS256".to_string()
}

fn default_access_token_ttl() -> u64 {
    2592000 // 30 days
}

fn default_refresh_token_ttl() -> u64 {
    7776000 // 90 days
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AwsConfig {
    pub region: String,
    pub access_key_id: Option<String>,
    pub secret_access_key: Option<String>,
    pub profile: Option<String>,
    pub bearer_token: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    #[serde(default = "default_log_level")]
    pub level: String,
    #[serde(default = "default_log_request")]
    pub log_request: bool,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: default_log_level(),
            log_request: default_log_request(),
        }
    }
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_log_request() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct OAuthConfig {
    #[serde(default)]
    pub providers: HashMap<String, OAuthProvider>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthProvider {
    pub client_id: String,
    pub client_secret: String,
    #[serde(default)]
    pub redirect_uri: Option<String>,
    #[serde(default)]
    pub scopes: Vec<String>,
    #[serde(default)]
    pub authorization_url: Option<String>,
    #[serde(default)]
    pub token_url: Option<String>,
    #[serde(default)]
    pub user_info_url: Option<String>,
    #[serde(default = "default_user_id_field")]
    pub user_id_field: String,
    #[serde(default = "default_email_field")]
    pub email_field: String,
    // For providers like Microsoft with tenant support
    #[serde(default)]
    pub tenant_id: Option<String>,
    // For providers like GitLab with instance support
    #[serde(default)]
    pub instance_url: Option<String>,
    // For providers like Auth0 with domain support
    #[serde(default)]
    pub domain: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheConfig {
    #[serde(default = "default_validation_ttl")]
    pub validation_ttl: u64,
    #[serde(default = "default_max_entries")]
    pub max_entries: usize,
    #[serde(default = "default_cleanup_interval")]
    pub cleanup_interval: u64,
}

fn default_user_id_field() -> String {
    "id".to_string()
}

fn default_email_field() -> String {
    "email".to_string()
}

fn default_validation_ttl() -> u64 {
    86400 // 24 hours
}

fn default_max_entries() -> usize {
    10000
}

fn default_cleanup_interval() -> u64 {
    3600 // 1 hour
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            validation_ttl: default_validation_ttl(),
            max_entries: default_max_entries(),
            cleanup_interval: default_cleanup_interval(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FrontendConfig {
    /// Path to serve frontend files from filesystem
    /// If not specified, uses embedded assets
    pub path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AdminConfig {
    /// List of admin email addresses
    /// Users with these emails will have admin privileges
    #[serde(default)]
    pub emails: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct StorageConfig {
    #[serde(default)]
    pub redis: RedisStorageConfig,
    #[serde(default)]
    pub database: DatabaseStorageConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedisStorageConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_redis_url")]
    pub url: String,
    #[serde(default = "default_redis_key_prefix")]
    pub key_prefix: String,
    #[serde(default = "default_redis_command_timeout")]
    pub command_timeout_seconds: u64,
    #[serde(default = "default_redis_max_connections")]
    pub max_connections: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseStorageConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_database_url")]
    pub url: String,
    #[serde(default = "default_database_max_connections")]
    pub max_connections: u32,
    #[serde(default = "default_database_migration_on_startup")]
    pub migration_on_startup: bool,
}

fn default_redis_url() -> String {
    "redis://localhost:6379".to_string()
}

fn default_redis_key_prefix() -> String {
    "bedrock_sso:".to_string()
}

fn default_redis_command_timeout() -> u64 {
    5
}

fn default_redis_max_connections() -> u32 {
    10
}

fn default_database_url() -> String {
    "sqlite://./data/bedrock_sso.db".to_string()
}

fn default_database_max_connections() -> u32 {
    5
}

fn default_database_migration_on_startup() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsConfig {
    #[serde(default = "default_metrics_enabled")]
    pub enabled: bool,
    #[serde(default = "default_metrics_port")]
    pub port: u16,
    #[serde(default = "default_metrics_endpoint")]
    pub endpoint: String,
}

fn default_metrics_enabled() -> bool {
    true
}

fn default_metrics_port() -> u16 {
    9090
}

fn default_metrics_endpoint() -> String {
    "/metrics".to_string()
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            enabled: default_metrics_enabled(),
            port: default_metrics_port(),
            endpoint: default_metrics_endpoint(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ModelMappingConfig {
    /// Custom model mappings that override default mappings
    /// Maps Anthropic API model names to AWS Bedrock model IDs
    /// Example: "claude-custom-model" -> "anthropic.claude-custom-model-v1:0"
    #[serde(default)]
    pub custom_mappings: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsageTrackingConfig {
    #[serde(default = "default_usage_tracking_enabled")]
    pub enabled: bool,
    #[serde(default = "default_batch_size")]
    pub batch_size: u32,
    #[serde(default = "default_flush_interval")]
    pub flush_interval: u64,
    #[serde(default = "default_retention_days")]
    pub retention_days: u32,
    #[serde(default = "default_detailed_logging")]
    pub enable_detailed_logging: bool,
    #[serde(default)]
    pub cost_tracking: CostTrackingConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CostTrackingConfig {
    #[serde(default = "default_cost_tracking_enabled")]
    pub enabled: bool,
    /// Default model costs (can be overridden via admin API)
    #[serde(default)]
    pub default_costs: HashMap<String, ModelCost>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelCost {
    pub input_cost_per_1k_tokens: f64,
    pub output_cost_per_1k_tokens: f64,
}

fn default_usage_tracking_enabled() -> bool {
    true
}

fn default_batch_size() -> u32 {
    100
}

fn default_flush_interval() -> u64 {
    60 // seconds
}

fn default_retention_days() -> u32 {
    365
}

fn default_detailed_logging() -> bool {
    true
}

fn default_cost_tracking_enabled() -> bool {
    true
}

impl Default for UsageTrackingConfig {
    fn default() -> Self {
        Self {
            enabled: default_usage_tracking_enabled(),
            batch_size: default_batch_size(),
            flush_interval: default_flush_interval(),
            retention_days: default_retention_days(),
            enable_detailed_logging: default_detailed_logging(),
            cost_tracking: CostTrackingConfig::default(),
        }
    }
}

impl Default for CostTrackingConfig {
    fn default() -> Self {
        Self {
            enabled: default_cost_tracking_enabled(),
            default_costs: HashMap::new(),
        }
    }
}

impl Default for RedisStorageConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            url: default_redis_url(),
            key_prefix: default_redis_key_prefix(),
            command_timeout_seconds: default_redis_command_timeout(),
            max_connections: default_redis_max_connections(),
        }
    }
}

impl Default for DatabaseStorageConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            url: default_database_url(),
            max_connections: default_database_max_connections(),
            migration_on_startup: default_database_migration_on_startup(),
        }
    }
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
                access_token_ttl: default_access_token_ttl(),
                refresh_token_ttl: default_refresh_token_ttl(),
            },
            aws: AwsConfig {
                region: "us-east-1".to_string(),
                access_key_id: None,
                secret_access_key: None,
                profile: None,
                bearer_token: None,
            },
            logging: LoggingConfig::default(),
            oauth: OAuthConfig::default(),
            cache: CacheConfig::default(),
            frontend: FrontendConfig::default(),
            admin: AdminConfig::default(),
            storage: StorageConfig::default(),
            metrics: MetricsConfig::default(),
            model_mapping: ModelMappingConfig::default(),
            usage_tracking: UsageTrackingConfig::default(),
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

    pub fn get_oauth_provider(&self, provider_name: &str) -> Option<OAuthProvider> {
        self.oauth.providers.get(provider_name).map(|provider| {
            let mut provider = provider.clone();
            // Apply predefined provider defaults if URLs are not specified
            apply_predefined_provider_defaults(provider_name, &mut provider);
            provider
        })
    }

    pub fn list_oauth_providers(&self) -> Vec<String> {
        self.oauth.providers.keys().cloned().collect()
    }

    /// Check if the given email address belongs to an admin user
    /// This performs case-insensitive matching
    pub fn is_admin(&self, email: &str) -> bool {
        let email_lower = email.to_lowercase();
        self.admin
            .emails
            .iter()
            .any(|admin_email| admin_email.to_lowercase() == email_lower)
    }

    /// Create a ModelMapper instance from the configuration
    pub fn create_model_mapper(&self) -> crate::anthropic::model_mapping::ModelMapper {
        crate::anthropic::model_mapping::ModelMapper::new(
            self.model_mapping.custom_mappings.clone(),
        )
    }
}

fn apply_predefined_provider_defaults(provider_name: &str, provider: &mut OAuthProvider) {
    match provider_name {
        "google" => apply_google_defaults(provider),
        "github" => apply_github_defaults(provider),
        "microsoft" => apply_microsoft_defaults(provider),
        "gitlab" => apply_gitlab_defaults(provider),
        "auth0" => apply_auth0_defaults(provider),
        "okta" => apply_okta_defaults(provider),
        _ => {} // Custom provider, no defaults to apply
    }
}

fn apply_google_defaults(provider: &mut OAuthProvider) {
    if provider.authorization_url.is_none() {
        provider.authorization_url =
            Some("https://accounts.google.com/o/oauth2/v2/auth".to_string());
    }
    if provider.token_url.is_none() {
        provider.token_url = Some("https://oauth2.googleapis.com/token".to_string());
    }
    if provider.user_info_url.is_none() {
        provider.user_info_url = Some("https://www.googleapis.com/oauth2/v2/userinfo".to_string());
    }
    if provider.scopes.is_empty() {
        provider.scopes = vec![
            "openid".to_string(),
            "email".to_string(),
            "profile".to_string(),
        ];
    }
    if provider.user_id_field == "id" {
        // default wasn't overridden
        provider.user_id_field = "id".to_string();
    }
    if provider.email_field == "email" {
        // default wasn't overridden
        provider.email_field = "email".to_string();
    }
}

fn apply_github_defaults(provider: &mut OAuthProvider) {
    if provider.authorization_url.is_none() {
        provider.authorization_url = Some("https://github.com/login/oauth/authorize".to_string());
    }
    if provider.token_url.is_none() {
        provider.token_url = Some("https://github.com/login/oauth/access_token".to_string());
    }
    if provider.user_info_url.is_none() {
        provider.user_info_url = Some("https://api.github.com/user".to_string());
    }
    if provider.scopes.is_empty() {
        provider.scopes = vec!["user:email".to_string()];
    }
}

fn apply_microsoft_defaults(provider: &mut OAuthProvider) {
    let tenant = provider.tenant_id.as_deref().unwrap_or("common");
    if provider.authorization_url.is_none() {
        provider.authorization_url = Some(format!(
            "https://login.microsoftonline.com/{}/oauth2/v2.0/authorize",
            tenant
        ));
    }
    if provider.token_url.is_none() {
        provider.token_url = Some(format!(
            "https://login.microsoftonline.com/{}/oauth2/v2.0/token",
            tenant
        ));
    }
    if provider.user_info_url.is_none() {
        provider.user_info_url = Some("https://graph.microsoft.com/v1.0/me".to_string());
    }
    if provider.scopes.is_empty() {
        provider.scopes = vec![
            "openid".to_string(),
            "profile".to_string(),
            "email".to_string(),
        ];
    }
    if provider.email_field == "email" {
        // default wasn't overridden
        provider.email_field = "mail".to_string();
    }
}

fn apply_gitlab_defaults(provider: &mut OAuthProvider) {
    let instance = provider
        .instance_url
        .as_deref()
        .unwrap_or("https://gitlab.com");
    if provider.authorization_url.is_none() {
        provider.authorization_url = Some(format!("{}/oauth/authorize", instance));
    }
    if provider.token_url.is_none() {
        provider.token_url = Some(format!("{}/oauth/token", instance));
    }
    if provider.user_info_url.is_none() {
        provider.user_info_url = Some(format!("{}/api/v4/user", instance));
    }
    if provider.scopes.is_empty() {
        provider.scopes = vec!["read_user".to_string()];
    }
}

fn apply_auth0_defaults(provider: &mut OAuthProvider) {
    if let Some(domain) = &provider.domain {
        if provider.authorization_url.is_none() {
            provider.authorization_url = Some(format!("https://{}/authorize", domain));
        }
        if provider.token_url.is_none() {
            provider.token_url = Some(format!("https://{}/oauth/token", domain));
        }
        if provider.user_info_url.is_none() {
            provider.user_info_url = Some(format!("https://{}/userinfo", domain));
        }
    }
    if provider.scopes.is_empty() {
        provider.scopes = vec![
            "openid".to_string(),
            "profile".to_string(),
            "email".to_string(),
        ];
    }
    if provider.user_id_field == "id" {
        // default wasn't overridden
        provider.user_id_field = "sub".to_string();
    }
}

fn apply_okta_defaults(provider: &mut OAuthProvider) {
    if let Some(domain) = &provider.domain {
        if provider.authorization_url.is_none() {
            provider.authorization_url =
                Some(format!("https://{}/oauth2/default/v1/authorize", domain));
        }
        if provider.token_url.is_none() {
            provider.token_url = Some(format!("https://{}/oauth2/default/v1/token", domain));
        }
        if provider.user_info_url.is_none() {
            provider.user_info_url = Some(format!("https://{}/oauth2/default/v1/userinfo", domain));
        }
    }
    if provider.scopes.is_empty() {
        provider.scopes = vec![
            "openid".to_string(),
            "profile".to_string(),
            "email".to_string(),
        ];
    }
    if provider.user_id_field == "id" {
        // default wasn't overridden
        provider.user_id_field = "sub".to_string();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn clean_env_vars() {
        // Remove all environment variables that start with "BEDROCK_"
        let bedrock_vars: Vec<String> = std::env::vars()
            .filter_map(|(key, _)| {
                if key.starts_with("BEDROCK_") {
                    Some(key)
                } else {
                    None
                }
            })
            .collect();

        for var in bedrock_vars {
            unsafe {
                std::env::remove_var(&var);
            }
        }
    }

    struct EnvGuard;

    impl EnvGuard {
        fn new() -> Self {
            clean_env_vars();
            EnvGuard
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            clean_env_vars();
        }
    }

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
    fn test_logging_config_default() {
        let logging_config = LoggingConfig::default();
        assert_eq!(logging_config.level, "info");
    }

    #[test]
    fn test_config_with_partial_logging() {
        let yaml_content = r#"
server:
  host: "localhost"
  port: 3000
jwt:
  secret: "test-secret"
aws:
  region: "us-east-1"
"#;
        let mut temp_file = NamedTempFile::with_suffix(".yaml").unwrap();
        temp_file.write_all(yaml_content.as_bytes()).unwrap();

        let config = Config::load_from_file(temp_file.path()).unwrap();
        // Should use default logging level when not specified
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
    #[serial]
    fn test_config_load_from_yaml_file() {
        let _guard = EnvGuard::new();

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
    #[serial]
    fn test_config_load_nonexistent_file() {
        let _guard = EnvGuard::new();

        let config = Config::load_from_file("nonexistent.yaml").unwrap();

        assert_eq!(config.server.host, "0.0.0.0");
        assert_eq!(config.server.port, 3000);
    }

    #[test]
    #[serial]
    fn test_config_load_with_environment_variables() {
        let _guard = EnvGuard::new();

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
    fn test_admin_config_is_admin() {
        let mut config = Config::default();
        config.admin.emails = vec![
            "admin@example.com".to_string(),
            "SUPERUSER@company.com".to_string(),
        ];

        // Test exact match
        assert!(config.is_admin("admin@example.com"));
        assert!(config.is_admin("SUPERUSER@company.com"));

        // Test case insensitive matching
        assert!(config.is_admin("ADMIN@example.com"));
        assert!(config.is_admin("superuser@company.com"));
        assert!(config.is_admin("Admin@Example.Com"));

        // Test non-admin
        assert!(!config.is_admin("user@example.com"));
        assert!(!config.is_admin(""));
        assert!(!config.is_admin("notadmin@company.com"));
    }

    #[test]
    fn test_admin_config_empty_list() {
        let config = Config::default();

        // No admins configured
        assert!(!config.is_admin("admin@example.com"));
        assert!(!config.is_admin("anyone@example.com"));
    }

    #[test]
    #[serial]
    fn test_config_load_with_partial_yaml() {
        let _guard = EnvGuard::new();

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
    #[serial]
    fn test_config_with_algorithm() {
        let _guard = EnvGuard::new();

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
    fn test_logging_config_default_extended() {
        let logging_config = LoggingConfig::default();
        assert_eq!(logging_config.level, "info");
        assert!(logging_config.log_request);
    }

    #[test]
    #[serial]
    fn test_config_with_custom_logging() {
        let _guard = EnvGuard::new();

        let yaml_content = r#"
logging:
  level: "debug"
  log_request: false
"#;
        let mut temp_file = NamedTempFile::with_suffix(".yaml").unwrap();
        temp_file.write_all(yaml_content.as_bytes()).unwrap();

        let config = Config::load_from_file(temp_file.path()).unwrap();

        assert_eq!(config.logging.level, "debug");
        assert!(!config.logging.log_request);
    }

    #[test]
    #[serial]
    fn test_aws_config_with_credentials() {
        let _guard = EnvGuard::new();

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

    #[test]
    #[serial]
    fn test_aws_config_with_bearer_token() {
        let _guard = EnvGuard::new();

        let yaml_content = r#"
server:
  host: "0.0.0.0"
  port: 3000
jwt:
  secret: "test-secret"
aws:
  region: "us-west-2"
  bearer_token: "ABSK-1234567890abcdef1234567890abcdef12345678"
logging:
  level: "info"
"#;
        let mut temp_file = NamedTempFile::with_suffix(".yaml").unwrap();
        temp_file.write_all(yaml_content.as_bytes()).unwrap();

        let config = Config::load_from_file(temp_file.path()).unwrap();

        assert_eq!(config.aws.region, "us-west-2");
        assert_eq!(config.aws.access_key_id, None);
        assert_eq!(config.aws.secret_access_key, None);
        assert_eq!(
            config.aws.bearer_token,
            Some("ABSK-1234567890abcdef1234567890abcdef12345678".to_string())
        );
    }
}
