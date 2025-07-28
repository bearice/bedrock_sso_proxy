use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseConfig {
    #[serde(default = "default_database_enabled")]
    pub enabled: bool,
    #[serde(default = "default_database_url")]
    pub url: String,
    #[serde(default = "default_database_max_connections")]
    pub max_connections: u32,
    #[serde(default = "default_database_migration_on_startup")]
    pub migration_on_startup: bool,
}

fn default_database_enabled() -> bool {
    true
}

fn default_database_url() -> String {
    "sqlite://./data/bedrock_sso.db?mode=rwc".to_string()
}

fn default_database_max_connections() -> u32 {
    5
}

fn default_database_migration_on_startup() -> bool {
    true
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            enabled: default_database_enabled(),
            url: default_database_url(),
            max_connections: default_database_max_connections(),
            migration_on_startup: default_database_migration_on_startup(),
        }
    }
}
