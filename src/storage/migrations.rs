use crate::storage::StorageResult;
use rust_embed::RustEmbed;
use sha2::{Digest, Sha256};
use std::collections::HashSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DatabaseType {
    Sqlite,
    Postgres,
}

impl DatabaseType {
    /// Convert from string representation
    pub fn from_database_type_str(s: &str) -> Result<Self, crate::storage::StorageError> {
        match s.to_lowercase().as_str() {
            "sqlite" => Ok(DatabaseType::Sqlite),
            "postgres" | "postgresql" => Ok(DatabaseType::Postgres),
            _ => Err(crate::storage::StorageError::InvalidData(format!(
                "Unsupported database type: {}",
                s
            ))),
        }
    }

    /// Get the folder name for this database type
    pub fn folder_name(&self) -> &'static str {
        match self {
            DatabaseType::Sqlite => "sqlite",
            DatabaseType::Postgres => "pgsql",
        }
    }

    /// Get the prefix for embedded files
    pub fn prefix(&self) -> &'static str {
        match self {
            DatabaseType::Sqlite => "sqlite/",
            DatabaseType::Postgres => "pgsql/",
        }
    }
}

#[derive(RustEmbed)]
#[folder = "migrations/sqlite"]
#[prefix = "sqlite/"]
pub struct SqliteMigrations;

#[derive(RustEmbed)]
#[folder = "migrations/pgsql"]
#[prefix = "pgsql/"]
pub struct PostgresMigrations;

/// Get migration SQL for a specific database type
pub fn get_migration_sql(
    database_type: DatabaseType,
    migration_name: &str,
) -> StorageResult<String> {
    let sql = match database_type {
        DatabaseType::Sqlite => {
            let path = format!("{}{}", database_type.prefix(), migration_name);
            SqliteMigrations::get(&path).ok_or_else(|| {
                crate::storage::StorageError::InvalidData(format!(
                    "Migration '{}' not found for SQLite",
                    migration_name
                ))
            })?
        }
        DatabaseType::Postgres => {
            let path = format!("{}{}", database_type.prefix(), migration_name);
            PostgresMigrations::get(&path).ok_or_else(|| {
                crate::storage::StorageError::InvalidData(format!(
                    "Migration '{}' not found for PostgreSQL",
                    migration_name
                ))
            })?
        }
    };

    String::from_utf8(sql.data.to_vec()).map_err(|e| {
        crate::storage::StorageError::InvalidData(format!("Invalid UTF-8 in migration file: {}", e))
    })
}

/// Parse SQL script into individual statements
pub fn parse_sql_statements(sql: &str) -> Vec<String> {
    let mut statements = Vec::new();

    // Split by semicolon
    for statement in sql.split(';') {
        let statement = statement.trim();

        // Skip empty statements
        if statement.is_empty() {
            continue;
        }

        // Remove comment lines from multi-line statements
        let cleaned_statement = statement
            .lines()
            .filter(|line| !line.trim().is_empty() && !line.trim().starts_with("--"))
            .collect::<Vec<_>>()
            .join(" ");

        let cleaned_statement = cleaned_statement.trim();

        // Only include non-empty cleaned statements
        if !cleaned_statement.is_empty() {
            // Add the semicolon back
            let final_statement = format!("{};", cleaned_statement);
            statements.push(final_statement);
        }
    }

    statements
}

/// Get all available migrations for a database type, sorted by name
pub fn get_available_migrations(database_type: DatabaseType) -> Vec<String> {
    let mut migrations = Vec::new();

    match database_type {
        DatabaseType::Sqlite => {
            for file in SqliteMigrations::iter() {
                if let Some(filename) = file.strip_prefix(database_type.prefix()) {
                    migrations.push(filename.to_string());
                }
            }
        }
        DatabaseType::Postgres => {
            for file in PostgresMigrations::iter() {
                if let Some(filename) = file.strip_prefix(database_type.prefix()) {
                    migrations.push(filename.to_string());
                }
            }
        }
    }

    migrations.sort();
    migrations
}

/// Get pending migrations that haven't been executed yet
pub fn get_pending_migrations(
    database_type: DatabaseType,
    executed_migrations: &HashSet<String>,
) -> Vec<String> {
    get_available_migrations(database_type)
        .into_iter()
        .filter(|migration| !executed_migrations.contains(migration))
        .collect()
}

/// Calculate checksum for migration content to detect changes
pub fn calculate_migration_checksum(content: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(content.as_bytes());
    format!("{:x}", hasher.finalize())
}

/// Migration execution result
#[derive(Debug, Clone)]
pub struct MigrationResult {
    pub migration_name: String,
    pub execution_time_ms: u64,
    pub checksum: String,
    pub statements_executed: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_sqlite_migration() {
        let sql = get_migration_sql(DatabaseType::Sqlite, "001_initial_schema.sql").unwrap();
        assert!(sql.contains("CREATE TABLE IF NOT EXISTS users"));
        assert!(sql.contains("INTEGER PRIMARY KEY AUTOINCREMENT"));
    }

    #[test]
    fn test_get_postgres_migration() {
        let sql = get_migration_sql(DatabaseType::Postgres, "001_initial_schema.sql").unwrap();
        assert!(sql.contains("CREATE TABLE IF NOT EXISTS users"));
        assert!(sql.contains("SERIAL PRIMARY KEY"));
    }

    #[test]
    fn test_get_available_migrations() {
        let sqlite_migrations = get_available_migrations(DatabaseType::Sqlite);
        assert!(sqlite_migrations.contains(&"001_initial_schema.sql".to_string()));

        let postgres_migrations = get_available_migrations(DatabaseType::Postgres);
        assert!(postgres_migrations.contains(&"001_initial_schema.sql".to_string()));
    }

    #[test]
    fn test_database_type_from_str() {
        assert_eq!(
            DatabaseType::from_database_type_str("sqlite").unwrap(),
            DatabaseType::Sqlite
        );
        assert_eq!(
            DatabaseType::from_database_type_str("postgres").unwrap(),
            DatabaseType::Postgres
        );
        assert_eq!(
            DatabaseType::from_database_type_str("postgresql").unwrap(),
            DatabaseType::Postgres
        );
        assert!(DatabaseType::from_database_type_str("invalid").is_err());
    }

    #[test]
    fn test_invalid_migration_name() {
        let result = get_migration_sql(DatabaseType::Sqlite, "nonexistent.sql");
        assert!(result.is_err());
    }

    #[test]
    fn test_sqlite_migration_structure() {
        let sql = get_migration_sql(DatabaseType::Sqlite, "001_initial_schema.sql").unwrap();
        let statements = super::parse_sql_statements(&sql);

        // Ensure we got the expected statements
        assert!(!statements.is_empty());
        assert!(statements.len() == 10); // 3 CREATE TABLE + 7 CREATE INDEX
        assert!(
            statements
                .iter()
                .any(|s| s.contains("CREATE TABLE IF NOT EXISTS users"))
        );
        assert!(
            statements
                .iter()
                .any(|s| s.contains("CREATE TABLE IF NOT EXISTS refresh_tokens"))
        );
        assert!(
            statements
                .iter()
                .any(|s| s.contains("CREATE TABLE IF NOT EXISTS audit_logs"))
        );
        assert!(
            statements
                .iter()
                .any(|s| s.contains("CREATE INDEX IF NOT EXISTS idx_users_email"))
        );
    }

    #[test]
    fn test_migration_tracking_table() {
        let sql = get_migration_sql(DatabaseType::Sqlite, "000_migration_tracking.sql").unwrap();
        assert!(sql.contains("CREATE TABLE IF NOT EXISTS migration_tracking"));
        assert!(sql.contains("migration_name TEXT NOT NULL UNIQUE"));
        assert!(sql.contains("executed_at"));
        assert!(sql.contains("checksum"));
    }

    #[test]
    fn test_pending_migrations() {
        use std::collections::HashSet;

        let mut executed = HashSet::new();
        executed.insert("000_migration_tracking.sql".to_string());

        let pending = get_pending_migrations(DatabaseType::Sqlite, &executed);
        assert!(pending.contains(&"001_initial_schema.sql".to_string()));
        assert!(!pending.contains(&"000_migration_tracking.sql".to_string()));
    }

    #[test]
    fn test_migration_checksum() {
        let content = "CREATE TABLE test (id INTEGER);";
        let checksum1 = calculate_migration_checksum(content);
        let checksum2 = calculate_migration_checksum(content);

        // Same content should produce same checksum
        assert_eq!(checksum1, checksum2);
        assert_eq!(checksum1.len(), 64); // SHA256 hex length

        // Different content should produce different checksum
        let different_content = "CREATE TABLE test (id TEXT);";
        let checksum3 = calculate_migration_checksum(different_content);
        assert_ne!(checksum1, checksum3);
    }

    #[test]
    fn test_comment_statements_included() {
        let sql = r#"
            CREATE TABLE users (id INTEGER);
            COMMENT ON TABLE users IS 'User data table';
            -- This is a line comment and should be filtered
            CREATE INDEX idx_users_id ON users(id);
        "#;

        let statements = parse_sql_statements(sql);

        // Should include CREATE TABLE, COMMENT, and CREATE INDEX
        assert_eq!(statements.len(), 3);
        assert!(statements.iter().any(|s| s.contains("CREATE TABLE users")));
        assert!(
            statements
                .iter()
                .any(|s| s.contains("COMMENT ON TABLE users"))
        );
        assert!(
            statements
                .iter()
                .any(|s| s.contains("CREATE INDEX idx_users_id"))
        );

        // Should not include line comments
        assert!(
            !statements
                .iter()
                .any(|s| s.contains("This is a line comment"))
        );
    }
}
