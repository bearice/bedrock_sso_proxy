// Re-export the separate database implementations
pub use super::postgres::PostgresStorage;
pub use super::sqlite::SqliteStorage;

/// Database configuration
#[derive(Debug, Clone)]
pub struct DatabaseConfig {
    pub url: String,
    pub max_connections: u32,
    pub migration_on_startup: bool,
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            url: "sqlite://./data/bedrock_sso.db".to_string(),
            max_connections: 5,
            migration_on_startup: true,
        }
    }
}