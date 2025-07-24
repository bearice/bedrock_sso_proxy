use super::{
    AuditLogEntry, DatabaseStorage, RefreshTokenData, StorageError, StorageResult, UserRecord,
};
use async_trait::async_trait;
use chrono::Utc;
use sqlx::{Pool, Postgres, Row, Sqlite, migrate::MigrateDatabase};
use std::collections::HashSet;
#[cfg(test)]
use std::collections::HashMap;

/// PostgreSQL database storage implementation
pub struct PostgresStorage {
    pool: Pool<Postgres>,
}

impl PostgresStorage {
    pub async fn new(database_url: &str) -> StorageResult<Self> {
        // Create database if it doesn't exist
        if !Postgres::database_exists(database_url)
            .await
            .unwrap_or(false)
        {
            Postgres::create_database(database_url)
                .await
                .map_err(|e| StorageError::Database(format!("Failed to create database: {}", e)))?;
        }

        let pool = Pool::<Postgres>::connect(database_url)
            .await
            .map_err(|e| StorageError::Database(format!("Failed to connect to database: {}", e)))?;

        Ok(Self { pool })
    }
}

#[async_trait]
impl DatabaseStorage for PostgresStorage {
    async fn migrate(&self) -> StorageResult<()> {
        use crate::storage::migrations::{
            get_migration_sql, get_pending_migrations,
            calculate_migration_checksum, DatabaseType
        };
        use std::time::Instant;
        
        // First, ensure migration tracking table exists
        let tracking_sql = get_migration_sql(DatabaseType::Postgres, "000_migration_tracking.sql")?;
        let tracking_statements = crate::storage::migrations::parse_sql_statements(&tracking_sql);
        for statement in tracking_statements {
            sqlx::query(&statement)
                .execute(&self.pool)
                .await
                .map_err(|e| StorageError::Database(format!("Failed to create migration tracking table: {}", e)))?;
        }
        
        // Get list of already executed migrations
        let executed_rows = sqlx::query("SELECT migration_name FROM migration_tracking ORDER BY executed_at")
            .fetch_all(&self.pool)
            .await
            .map_err(|e| StorageError::Database(format!("Failed to get executed migrations: {}", e)))?;
        
        let executed_migrations: HashSet<String> = executed_rows
            .iter()
            .map(|row| row.get::<String, _>("migration_name"))
            .collect();
        
        // Get pending migrations
        let pending_migrations = get_pending_migrations(DatabaseType::Postgres, &executed_migrations);
        
        // Execute pending migrations
        for migration_name in pending_migrations {
            let start_time = Instant::now();
            let sql = get_migration_sql(DatabaseType::Postgres, &migration_name)?;
            let checksum = calculate_migration_checksum(&sql);
            
            // Parse and execute migration statements
            let statements = crate::storage::migrations::parse_sql_statements(&sql);
            for statement in &statements {
                sqlx::query(statement)
                    .execute(&self.pool)
                    .await
                    .map_err(|e| StorageError::Database(format!("Failed to execute migration '{}' statement '{}': {}", migration_name, statement, e)))?;
            }
            
            let execution_time = start_time.elapsed().as_millis() as i32;
            
            // Record migration as executed
            sqlx::query(
                "INSERT INTO migration_tracking (migration_name, checksum, execution_time_ms) VALUES ($1, $2, $3)"
            )
            .bind(&migration_name)
            .bind(&checksum)
            .bind(execution_time)
            .execute(&self.pool)
            .await
            .map_err(|e| StorageError::Database(format!("Failed to record migration '{}': {}", migration_name, e)))?;
            
            tracing::info!(
                "Executed migration '{}' in {}ms with {} statements",
                migration_name,
                execution_time,
                statements.len()
            );
        }

        Ok(())
    }

    async fn upsert_user(&self, user: &UserRecord) -> StorageResult<i32> {
        let row = sqlx::query(
            r#"
            INSERT INTO users (provider_user_id, provider, email, display_name, created_at, updated_at, last_login)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            ON CONFLICT (provider, provider_user_id)
            DO UPDATE SET
                email = EXCLUDED.email,
                display_name = EXCLUDED.display_name,
                updated_at = EXCLUDED.updated_at,
                last_login = COALESCE(EXCLUDED.last_login, users.last_login)
            RETURNING id
            "#,
        )
        .bind(&user.provider_user_id)
        .bind(&user.provider)
        .bind(&user.email)
        .bind(&user.display_name)
        .bind(user.created_at)
        .bind(user.updated_at)
        .bind(user.last_login)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| StorageError::Database(format!("Failed to upsert user: {}", e)))?;

        Ok(row.get::<i32, _>("id"))
    }

    async fn get_user_by_provider(
        &self,
        provider: &str,
        provider_user_id: &str,
    ) -> StorageResult<Option<UserRecord>> {
        let row = sqlx::query(
            "SELECT id, provider_user_id, provider, email, display_name, created_at, updated_at, last_login FROM users WHERE provider = $1 AND provider_user_id = $2",
        )
        .bind(provider)
        .bind(provider_user_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| StorageError::Database(format!("Failed to get user by provider: {}", e)))?;

        match row {
            Some(row) => Ok(Some(UserRecord {
                id: Some(row.get("id")),
                provider_user_id: row.get("provider_user_id"),
                provider: row.get("provider"),
                email: row.get("email"),
                display_name: row.get("display_name"),
                created_at: row.get("created_at"),
                updated_at: row.get("updated_at"),
                last_login: row.get("last_login"),
            })),
            None => Ok(None),
        }
    }

    async fn get_user_by_email(&self, email: &str) -> StorageResult<Option<UserRecord>> {
        let row = sqlx::query(
            "SELECT id, provider_user_id, provider, email, display_name, created_at, updated_at, last_login FROM users WHERE email = $1",
        )
        .bind(email)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| StorageError::Database(format!("Failed to get user by email: {}", e)))?;

        match row {
            Some(row) => Ok(Some(UserRecord {
                id: Some(row.get("id")),
                provider_user_id: row.get("provider_user_id"),
                provider: row.get("provider"),
                email: row.get("email"),
                display_name: row.get("display_name"),
                created_at: row.get("created_at"),
                updated_at: row.get("updated_at"),
                last_login: row.get("last_login"),
            })),
            None => Ok(None),
        }
    }

    async fn update_last_login(&self, user_id: i32) -> StorageResult<()> {
        sqlx::query("UPDATE users SET last_login = $1, updated_at = $1 WHERE id = $2")
            .bind(Utc::now())
            .bind(user_id)
            .execute(&self.pool)
            .await
            .map_err(|e| StorageError::Database(format!("Failed to update last login: {}", e)))?;

        Ok(())
    }

    async fn store_refresh_token(&self, token: &RefreshTokenData) -> StorageResult<()> {
        sqlx::query(
            r#"
            INSERT INTO refresh_tokens (token_hash, user_id, provider, email, created_at, expires_at, rotation_count, revoked_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            ON CONFLICT (token_hash)
            DO UPDATE SET
                rotation_count = EXCLUDED.rotation_count,
                revoked_at = EXCLUDED.revoked_at
            "#,
        )
        .bind(&token.token_hash)
        .bind(&token.user_id)
        .bind(&token.provider)
        .bind(&token.email)
        .bind(token.created_at)
        .bind(token.expires_at)
        .bind(token.rotation_count as i32)
        .bind(token.revoked_at)
        .execute(&self.pool)
        .await
        .map_err(|e| StorageError::Database(format!("Failed to store refresh token: {}", e)))?;

        Ok(())
    }

    async fn get_refresh_token(&self, token_hash: &str) -> StorageResult<Option<RefreshTokenData>> {
        let row = sqlx::query(
            "SELECT token_hash, user_id, provider, email, created_at, expires_at, rotation_count, revoked_at FROM refresh_tokens WHERE token_hash = $1",
        )
        .bind(token_hash)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| StorageError::Database(format!("Failed to get refresh token: {}", e)))?;

        match row {
            Some(row) => Ok(Some(RefreshTokenData {
                token_hash: row.get("token_hash"),
                user_id: row.get("user_id"),
                provider: row.get("provider"),
                email: row.get("email"),
                created_at: row.get("created_at"),
                expires_at: row.get("expires_at"),
                rotation_count: row.get::<i32, _>("rotation_count") as u32,
                revoked_at: row.get("revoked_at"),
            })),
            None => Ok(None),
        }
    }

    async fn revoke_refresh_token(&self, token_hash: &str) -> StorageResult<()> {
        sqlx::query("UPDATE refresh_tokens SET revoked_at = $1 WHERE token_hash = $2")
            .bind(Utc::now())
            .bind(token_hash)
            .execute(&self.pool)
            .await
            .map_err(|e| {
                StorageError::Database(format!("Failed to revoke refresh token: {}", e))
            })?;

        Ok(())
    }

    async fn cleanup_expired_tokens(&self) -> StorageResult<u64> {
        let result = sqlx::query(
            "DELETE FROM refresh_tokens WHERE expires_at < $1 OR revoked_at IS NOT NULL",
        )
        .bind(Utc::now())
        .execute(&self.pool)
        .await
        .map_err(|e| StorageError::Database(format!("Failed to cleanup expired tokens: {}", e)))?;

        Ok(result.rows_affected())
    }

    async fn store_audit_log(&self, entry: &AuditLogEntry) -> StorageResult<()> {
        let metadata_json = entry
            .metadata
            .as_ref()
            .map(|m| serde_json::to_value(m).unwrap());

        sqlx::query(
            r#"
            INSERT INTO audit_logs (user_id, event_type, provider, ip_address, user_agent, success, error_message, created_at, metadata)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            "#,
        )
        .bind(entry.user_id)
        .bind(&entry.event_type)
        .bind(&entry.provider)
        .bind(entry.ip_address.as_ref())
        .bind(&entry.user_agent)
        .bind(entry.success)
        .bind(&entry.error_message)
        .bind(entry.created_at)
        .bind(metadata_json)
        .execute(&self.pool)
        .await
        .map_err(|e| StorageError::Database(format!("Failed to store audit log: {}", e)))?;

        Ok(())
    }

    async fn get_audit_logs_for_user(
        &self,
        user_id: i32,
        limit: u32,
        offset: u32,
    ) -> StorageResult<Vec<AuditLogEntry>> {
        let rows = sqlx::query(
            r#"
            SELECT id, user_id, event_type, provider, ip_address, user_agent, success, error_message, created_at, metadata
            FROM audit_logs
            WHERE user_id = $1
            ORDER BY created_at DESC
            LIMIT $2 OFFSET $3
            "#,
        )
        .bind(user_id)
        .bind(limit as i64)
        .bind(offset as i64)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| StorageError::Database(format!("Failed to get audit logs: {}", e)))?;

        let mut logs = Vec::new();
        for row in rows {
            logs.push(AuditLogEntry {
                id: Some(row.get("id")),
                user_id: row.get("user_id"),
                event_type: row.get("event_type"),
                provider: row.get("provider"),
                ip_address: row.get("ip_address"),
                user_agent: row.get("user_agent"),
                success: row.get("success"),
                error_message: row.get("error_message"),
                created_at: row.get("created_at"),
                metadata: row
                    .get::<Option<serde_json::Value>, _>("metadata")
                    .map(|v| serde_json::from_value(v).unwrap_or_default()),
            });
        }

        Ok(logs)
    }

    async fn cleanup_old_audit_logs(&self, retention_days: u32) -> StorageResult<u64> {
        let cutoff_date = Utc::now() - chrono::Duration::days(retention_days as i64);

        let result = sqlx::query("DELETE FROM audit_logs WHERE created_at < $1")
            .bind(cutoff_date)
            .execute(&self.pool)
            .await
            .map_err(|e| {
                StorageError::Database(format!("Failed to cleanup old audit logs: {}", e))
            })?;

        Ok(result.rows_affected())
    }

    async fn health_check(&self) -> StorageResult<()> {
        sqlx::query("SELECT 1")
            .execute(&self.pool)
            .await
            .map_err(|e| StorageError::Database(format!("Database health check failed: {}", e)))?;

        Ok(())
    }
}

/// SQLite database storage implementation
pub struct SqliteStorage {
    pool: Pool<Sqlite>,
}

impl SqliteStorage {
    pub async fn new(database_url: &str) -> StorageResult<Self> {
        // Create database if it doesn't exist
        if !Sqlite::database_exists(database_url).await.unwrap_or(false) {
            Sqlite::create_database(database_url)
                .await
                .map_err(|e| StorageError::Database(format!("Failed to create database: {}", e)))?;
        }

        let pool = Pool::<Sqlite>::connect(database_url)
            .await
            .map_err(|e| StorageError::Database(format!("Failed to connect to database: {}", e)))?;

        Ok(Self { pool })
    }
}

#[async_trait]
impl DatabaseStorage for SqliteStorage {
    async fn migrate(&self) -> StorageResult<()> {
        use crate::storage::migrations::{
            get_migration_sql, get_pending_migrations,
            calculate_migration_checksum, DatabaseType
        };
        use std::time::Instant;
        
        // First, ensure migration tracking table exists
        let tracking_sql = get_migration_sql(DatabaseType::Sqlite, "000_migration_tracking.sql")?;
        let tracking_statements = crate::storage::migrations::parse_sql_statements(&tracking_sql);
        for statement in tracking_statements {
            sqlx::query(&statement)
                .execute(&self.pool)
                .await
                .map_err(|e| StorageError::Database(format!("Failed to create migration tracking table: {}", e)))?;
        }
        
        // Get list of already executed migrations
        let executed_rows = sqlx::query("SELECT migration_name FROM migration_tracking ORDER BY executed_at")
            .fetch_all(&self.pool)
            .await
            .map_err(|e| StorageError::Database(format!("Failed to get executed migrations: {}", e)))?;
        
        let executed_migrations: HashSet<String> = executed_rows
            .iter()
            .map(|row| row.get::<String, _>("migration_name"))
            .collect();
        
        // Get pending migrations
        let pending_migrations = get_pending_migrations(DatabaseType::Sqlite, &executed_migrations);
        
        // Execute pending migrations
        for migration_name in pending_migrations {
            let start_time = Instant::now();
            let sql = get_migration_sql(DatabaseType::Sqlite, &migration_name)?;
            let checksum = calculate_migration_checksum(&sql);
            
            // Parse and execute migration statements
            let statements = crate::storage::migrations::parse_sql_statements(&sql);
            for statement in &statements {
                sqlx::query(statement)
                    .execute(&self.pool)
                    .await
                    .map_err(|e| StorageError::Database(format!("Failed to execute migration '{}' statement '{}': {}", migration_name, statement, e)))?;
            }
            
            let execution_time = start_time.elapsed().as_millis() as i32;
            
            // Record migration as executed
            sqlx::query(
                "INSERT INTO migration_tracking (migration_name, checksum, execution_time_ms) VALUES (?1, ?2, ?3)"
            )
            .bind(&migration_name)
            .bind(&checksum)
            .bind(execution_time)
            .execute(&self.pool)
            .await
            .map_err(|e| StorageError::Database(format!("Failed to record migration '{}': {}", migration_name, e)))?;
            
            tracing::info!(
                "Executed migration '{}' in {}ms with {} statements",
                migration_name,
                execution_time,
                statements.len()
            );
        }

        Ok(())
    }

    async fn upsert_user(&self, user: &UserRecord) -> StorageResult<i32> {
        let row = sqlx::query(
            r#"
            INSERT INTO users (provider_user_id, provider, email, display_name, created_at, updated_at, last_login)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
            ON CONFLICT (provider, provider_user_id)
            DO UPDATE SET
                email = excluded.email,
                display_name = excluded.display_name,
                updated_at = excluded.updated_at,
                last_login = COALESCE(excluded.last_login, users.last_login)
            RETURNING id
            "#,
        )
        .bind(&user.provider_user_id)
        .bind(&user.provider)
        .bind(&user.email)
        .bind(&user.display_name)
        .bind(user.created_at)
        .bind(user.updated_at)
        .bind(user.last_login)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| StorageError::Database(format!("Failed to upsert user: {}", e)))?;

        Ok(row.get::<i32, _>("id"))
    }

    async fn get_user_by_provider(
        &self,
        provider: &str,
        provider_user_id: &str,
    ) -> StorageResult<Option<UserRecord>> {
        let row = sqlx::query(
            "SELECT id, provider_user_id, provider, email, display_name, created_at, updated_at, last_login FROM users WHERE provider = ?1 AND provider_user_id = ?2",
        )
        .bind(provider)
        .bind(provider_user_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| StorageError::Database(format!("Failed to get user by provider: {}", e)))?;

        match row {
            Some(row) => Ok(Some(UserRecord {
                id: Some(row.get("id")),
                provider_user_id: row.get("provider_user_id"),
                provider: row.get("provider"),
                email: row.get("email"),
                display_name: row.get("display_name"),
                created_at: row.get("created_at"),
                updated_at: row.get("updated_at"),
                last_login: row.get("last_login"),
            })),
            None => Ok(None),
        }
    }

    async fn get_user_by_email(&self, email: &str) -> StorageResult<Option<UserRecord>> {
        let row = sqlx::query(
            "SELECT id, provider_user_id, provider, email, display_name, created_at, updated_at, last_login FROM users WHERE email = ?1",
        )
        .bind(email)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| StorageError::Database(format!("Failed to get user by email: {}", e)))?;

        match row {
            Some(row) => Ok(Some(UserRecord {
                id: Some(row.get("id")),
                provider_user_id: row.get("provider_user_id"),
                provider: row.get("provider"),
                email: row.get("email"),
                display_name: row.get("display_name"),
                created_at: row.get("created_at"),
                updated_at: row.get("updated_at"),
                last_login: row.get("last_login"),
            })),
            None => Ok(None),
        }
    }

    async fn update_last_login(&self, user_id: i32) -> StorageResult<()> {
        sqlx::query("UPDATE users SET last_login = ?1, updated_at = ?1 WHERE id = ?2")
            .bind(Utc::now())
            .bind(user_id)
            .execute(&self.pool)
            .await
            .map_err(|e| StorageError::Database(format!("Failed to update last login: {}", e)))?;

        Ok(())
    }

    async fn store_refresh_token(&self, token: &RefreshTokenData) -> StorageResult<()> {
        sqlx::query(
            r#"
            INSERT INTO refresh_tokens (token_hash, user_id, provider, email, created_at, expires_at, rotation_count, revoked_at)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
            ON CONFLICT (token_hash)
            DO UPDATE SET
                rotation_count = excluded.rotation_count,
                revoked_at = excluded.revoked_at
            "#,
        )
        .bind(&token.token_hash)
        .bind(&token.user_id)
        .bind(&token.provider)
        .bind(&token.email)
        .bind(token.created_at)
        .bind(token.expires_at)
        .bind(token.rotation_count as i32)
        .bind(token.revoked_at)
        .execute(&self.pool)
        .await
        .map_err(|e| StorageError::Database(format!("Failed to store refresh token: {}", e)))?;

        Ok(())
    }

    async fn get_refresh_token(&self, token_hash: &str) -> StorageResult<Option<RefreshTokenData>> {
        let row = sqlx::query(
            "SELECT token_hash, user_id, provider, email, created_at, expires_at, rotation_count, revoked_at FROM refresh_tokens WHERE token_hash = ?1",
        )
        .bind(token_hash)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| StorageError::Database(format!("Failed to get refresh token: {}", e)))?;

        match row {
            Some(row) => Ok(Some(RefreshTokenData {
                token_hash: row.get("token_hash"),
                user_id: row.get("user_id"),
                provider: row.get("provider"),
                email: row.get("email"),
                created_at: row.get("created_at"),
                expires_at: row.get("expires_at"),
                rotation_count: row.get::<i32, _>("rotation_count") as u32,
                revoked_at: row.get("revoked_at"),
            })),
            None => Ok(None),
        }
    }

    async fn revoke_refresh_token(&self, token_hash: &str) -> StorageResult<()> {
        sqlx::query("UPDATE refresh_tokens SET revoked_at = ?1 WHERE token_hash = ?2")
            .bind(Utc::now())
            .bind(token_hash)
            .execute(&self.pool)
            .await
            .map_err(|e| {
                StorageError::Database(format!("Failed to revoke refresh token: {}", e))
            })?;

        Ok(())
    }

    async fn cleanup_expired_tokens(&self) -> StorageResult<u64> {
        let result = sqlx::query(
            "DELETE FROM refresh_tokens WHERE expires_at < ?1 OR revoked_at IS NOT NULL",
        )
        .bind(Utc::now())
        .execute(&self.pool)
        .await
        .map_err(|e| StorageError::Database(format!("Failed to cleanup expired tokens: {}", e)))?;

        Ok(result.rows_affected())
    }

    async fn store_audit_log(&self, entry: &AuditLogEntry) -> StorageResult<()> {
        let metadata_json = entry
            .metadata
            .as_ref()
            .map(|m| serde_json::to_string(m).unwrap());

        sqlx::query(
            r#"
            INSERT INTO audit_logs (user_id, event_type, provider, ip_address, user_agent, success, error_message, created_at, metadata)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
            "#,
        )
        .bind(entry.user_id)
        .bind(&entry.event_type)
        .bind(&entry.provider)
        .bind(&entry.ip_address)
        .bind(&entry.user_agent)
        .bind(entry.success)
        .bind(&entry.error_message)
        .bind(entry.created_at)
        .bind(metadata_json)
        .execute(&self.pool)
        .await
        .map_err(|e| StorageError::Database(format!("Failed to store audit log: {}", e)))?;

        Ok(())
    }

    async fn get_audit_logs_for_user(
        &self,
        user_id: i32,
        limit: u32,
        offset: u32,
    ) -> StorageResult<Vec<AuditLogEntry>> {
        let rows = sqlx::query(
            r#"
            SELECT id, user_id, event_type, provider, ip_address, user_agent, success, error_message, created_at, metadata
            FROM audit_logs
            WHERE user_id = ?1
            ORDER BY created_at DESC
            LIMIT ?2 OFFSET ?3
            "#,
        )
        .bind(user_id)
        .bind(limit as i64)
        .bind(offset as i64)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| StorageError::Database(format!("Failed to get audit logs: {}", e)))?;

        let mut logs = Vec::new();
        for row in rows {
            logs.push(AuditLogEntry {
                id: Some(row.get("id")),
                user_id: row.get("user_id"),
                event_type: row.get("event_type"),
                provider: row.get("provider"),
                ip_address: row.get("ip_address"),
                user_agent: row.get("user_agent"),
                success: row.get("success"),
                error_message: row.get("error_message"),
                created_at: row.get("created_at"),
                metadata: row
                    .get::<Option<String>, _>("metadata")
                    .map(|s| serde_json::from_str(&s).unwrap_or_default()),
            });
        }

        Ok(logs)
    }

    async fn cleanup_old_audit_logs(&self, retention_days: u32) -> StorageResult<u64> {
        let cutoff_date = Utc::now() - chrono::Duration::days(retention_days as i64);

        let result = sqlx::query("DELETE FROM audit_logs WHERE created_at < ?1")
            .bind(cutoff_date)
            .execute(&self.pool)
            .await
            .map_err(|e| {
                StorageError::Database(format!("Failed to cleanup old audit logs: {}", e))
            })?;

        Ok(result.rows_affected())
    }

    async fn health_check(&self) -> StorageResult<()> {
        sqlx::query("SELECT 1")
            .execute(&self.pool)
            .await
            .map_err(|e| StorageError::Database(format!("Database health check failed: {}", e)))?;

        Ok(())
    }
}

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

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use tokio;

    #[tokio::test]
    async fn test_sqlite_database_storage() {
        let db = SqliteStorage::new("sqlite::memory:").await.unwrap();
        db.migrate().await.unwrap();

        let user = UserRecord {
            id: None,
            provider_user_id: "user123".to_string(),
            provider: "google".to_string(),
            email: "user@example.com".to_string(),
            display_name: Some("Test User".to_string()),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            last_login: None,
        };

        // Test user upsert
        let user_id = db.upsert_user(&user).await.unwrap();
        assert_eq!(user_id, 1);

        // Test get user by provider
        let retrieved = db.get_user_by_provider("google", "user123").await.unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().email, "user@example.com");

        // Test get user by email
        let retrieved = db.get_user_by_email("user@example.com").await.unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().provider, "google");

        // Test health check
        db.health_check().await.unwrap();
    }

    #[tokio::test]
    async fn test_refresh_token_operations() {
        let db = SqliteStorage::new("sqlite::memory:").await.unwrap();
        db.migrate().await.unwrap();

        let token = RefreshTokenData {
            token_hash: "hash123".to_string(),
            user_id: "user123".to_string(),
            provider: "google".to_string(),
            email: "user@example.com".to_string(),
            created_at: Utc::now(),
            expires_at: Utc::now() + chrono::Duration::days(90),
            rotation_count: 0,
            revoked_at: None,
        };

        // Test store refresh token
        db.store_refresh_token(&token).await.unwrap();

        // Test get refresh token
        let retrieved = db.get_refresh_token("hash123").await.unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().user_id, "user123");

        // Test revoke refresh token
        db.revoke_refresh_token("hash123").await.unwrap();
        let revoked = db.get_refresh_token("hash123").await.unwrap();
        assert!(revoked.is_some());
        assert!(revoked.unwrap().revoked_at.is_some());

        // Test cleanup expired tokens
        let cleaned = db.cleanup_expired_tokens().await.unwrap();
        assert!(cleaned > 0);
    }

    #[tokio::test]
    async fn test_audit_log_operations() {
        let db = SqliteStorage::new("sqlite::memory:").await.unwrap();
        db.migrate().await.unwrap();

        let mut metadata = HashMap::new();
        metadata.insert(
            "key".to_string(),
            serde_json::Value::String("value".to_string()),
        );

        let log_entry = AuditLogEntry {
            id: None,
            user_id: Some(1),
            event_type: "login".to_string(),
            provider: Some("google".to_string()),
            ip_address: Some("127.0.0.1".to_string()),
            user_agent: Some("Test Agent".to_string()),
            success: true,
            error_message: None,
            created_at: Utc::now(),
            metadata: Some(metadata),
        };

        // Test store audit log
        db.store_audit_log(&log_entry).await.unwrap();

        // Test get audit logs for user
        let logs = db.get_audit_logs_for_user(1, 10, 0).await.unwrap();
        assert_eq!(logs.len(), 1);
        assert_eq!(logs[0].event_type, "login");

        // Test cleanup old audit logs
        let cleaned = db.cleanup_old_audit_logs(0).await.unwrap();
        assert!(cleaned > 0);
    }

    #[tokio::test]
    async fn test_migration_tracking() {
        let db = SqliteStorage::new("sqlite::memory:").await.unwrap();
        
        // Run migrations first time
        db.migrate().await.unwrap();
        
        // Verify migration tracking table exists and has records
        let migration_count = sqlx::query("SELECT COUNT(*) as count FROM migration_tracking")
            .fetch_one(&db.pool)
            .await
            .unwrap();
        
        let count: i64 = migration_count.get("count");
        assert!(count >= 2); // Should have at least 000_migration_tracking.sql and 001_initial_schema.sql
        
        // Verify specific migrations are recorded
        let tracking_migration = sqlx::query(
            "SELECT migration_name, checksum, execution_time_ms FROM migration_tracking WHERE migration_name = ?1"
        )
        .bind("000_migration_tracking.sql")
        .fetch_one(&db.pool)
        .await
        .unwrap();
        
        assert_eq!(tracking_migration.get::<String, _>("migration_name"), "000_migration_tracking.sql");
        assert!(tracking_migration.get::<String, _>("checksum").len() == 64); // SHA256 hex length
        assert!(tracking_migration.get::<i32, _>("execution_time_ms") >= 0);
        
        // Run migrations again - should not re-run existing migrations
        let initial_count = count;
        db.migrate().await.unwrap();
        
        let migration_count_after = sqlx::query("SELECT COUNT(*) as count FROM migration_tracking")
            .fetch_one(&db.pool)
            .await
            .unwrap();
        
        let count_after: i64 = migration_count_after.get("count");
        assert_eq!(count_after, initial_count); // Should be same count, no re-runs
    }
}
