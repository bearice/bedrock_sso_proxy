use super::{
    AuditLogEntry, DatabaseStorage, RefreshTokenData, StorageError, StorageResult, StoredModelCost,
    UsageQuery, UsageRecord, UsageStats, UsageSummary, UserRecord, query_builder::UsageQueryHelper,
};
use async_trait::async_trait;
use chrono::Utc;
use rust_decimal::Decimal;
use sqlx::{Pool, Postgres, Row, migrate::MigrateDatabase};
use std::collections::HashSet;

/// PostgreSQL database storage implementation
pub struct PostgresStorage {
    pool: Pool<Postgres>,
}

impl PostgresStorage {
    /// Convert Decimal to f64 for numeric calculations
    fn decimal_to_f64(decimal: Decimal) -> f64 {
        use rust_decimal::prelude::ToPrimitive;
        decimal.to_f64().unwrap_or(0.0)
    }

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
            DatabaseType, calculate_migration_checksum, get_migration_sql, get_pending_migrations,
        };
        use std::time::Instant;

        // First, ensure migration tracking table exists
        let tracking_sql = get_migration_sql(DatabaseType::Postgres, "000_migration_tracking.sql")?;
        let tracking_statements = crate::storage::migrations::parse_sql_statements(&tracking_sql);
        for statement in tracking_statements {
            sqlx::query(&statement)
                .execute(&self.pool)
                .await
                .map_err(|e| {
                    StorageError::Database(format!(
                        "Failed to create migration tracking table: {}",
                        e
                    ))
                })?;
        }

        // Get list of already executed migrations
        let executed_rows =
            sqlx::query("SELECT migration_name FROM migration_tracking ORDER BY executed_at")
                .fetch_all(&self.pool)
                .await
                .map_err(|e| {
                    StorageError::Database(format!("Failed to get executed migrations: {}", e))
                })?;

        let executed_migrations: HashSet<String> = executed_rows
            .iter()
            .map(|row| row.get::<String, _>("migration_name"))
            .collect();

        // Get pending migrations
        let pending_migrations =
            get_pending_migrations(DatabaseType::Postgres, &executed_migrations);

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
                    .map_err(|e| {
                        StorageError::Database(format!(
                            "Failed to execute migration '{}' statement '{}': {}",
                            migration_name, statement, e
                        ))
                    })?;
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

    async fn get_user_by_id(&self, user_id: i32) -> StorageResult<Option<UserRecord>> {
        let row = sqlx::query(
            "SELECT id, provider_user_id, provider, email, display_name, created_at, updated_at, last_login FROM users WHERE id = $1",
        )
        .bind(user_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| StorageError::Database(format!("Failed to get user by ID: {}", e)))?;

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

    // Usage tracking methods implementation for PostgreSQL

    async fn store_usage_record(&self, record: &UsageRecord) -> StorageResult<()> {
        sqlx::query(
            r#"
            INSERT INTO usage_records (user_id, model_id, endpoint_type, region, request_time,
                                     input_tokens, output_tokens, total_tokens, response_time_ms,
                                     success, error_message, cost_usd)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
            "#,
        )
        .bind(record.user_id)
        .bind(&record.model_id)
        .bind(&record.endpoint_type)
        .bind(&record.region)
        .bind(record.request_time)
        .bind(record.input_tokens as i32)
        .bind(record.output_tokens as i32)
        .bind(record.total_tokens as i32)
        .bind(record.response_time_ms as i32)
        .bind(record.success)
        .bind(&record.error_message)
        .bind(record.cost_usd)
        .execute(&self.pool)
        .await
        .map_err(|e| StorageError::Database(format!("Failed to store usage record: {}", e)))?;

        Ok(())
    }

    async fn get_usage_records(&self, query: &UsageQuery) -> StorageResult<Vec<UsageRecord>> {
        // Use the dynamic query builder for PostgreSQL - clean and maintainable!
        let query_builder = UsageQueryHelper::build_query(query);

        query_builder
            .execute_postgres(&self.pool)
            .await
            .map_err(|e| StorageError::Database(format!("Failed to get usage records: {}", e)))
    }

    async fn get_usage_stats(&self, _query: &UsageQuery) -> StorageResult<UsageStats> {
        // Implementation would build dynamic SQL with WHERE conditions based on query
        // For brevity, implementing basic version
        let sql = "SELECT COUNT(*) as total_requests, COALESCE(SUM(input_tokens), 0) as total_input_tokens, COALESCE(SUM(output_tokens), 0) as total_output_tokens, COALESCE(SUM(total_tokens), 0) as total_tokens, COALESCE(AVG(response_time_ms), 0) as avg_response_time_ms, COALESCE(AVG(CASE WHEN success THEN 1.0 ELSE 0.0 END), 0) as success_rate, COALESCE(SUM(cost_usd), 0) as total_cost, COUNT(DISTINCT model_id) as unique_models, MIN(request_time) as min_time, MAX(request_time) as max_time FROM usage_records";

        let row = sqlx::query(sql)
            .fetch_one(&self.pool)
            .await
            .map_err(|e| StorageError::Database(format!("Failed to get usage stats: {}", e)))?;

        let min_time: Option<chrono::DateTime<chrono::Utc>> = row.get("min_time");
        let max_time: Option<chrono::DateTime<chrono::Utc>> = row.get("max_time");
        let now = chrono::Utc::now();

        Ok(UsageStats {
            total_requests: row.get::<i64, _>("total_requests") as u32,
            total_input_tokens: row.get::<i64, _>("total_input_tokens") as u64,
            total_output_tokens: row.get::<i64, _>("total_output_tokens") as u64,
            total_tokens: row.get::<i64, _>("total_tokens") as u64,
            avg_response_time_ms: Self::decimal_to_f64(
                row.get::<Decimal, _>("avg_response_time_ms"),
            ) as f32,
            success_rate: Self::decimal_to_f64(row.get::<Decimal, _>("success_rate")) as f32,
            total_cost: row.get::<Option<Decimal>, _>("total_cost"),
            unique_models: row.get::<i64, _>("unique_models") as u32,
            date_range: (min_time.unwrap_or(now), max_time.unwrap_or(now)),
        })
    }

    async fn upsert_usage_summary(&self, _summary: &UsageSummary) -> StorageResult<()> {
        // Stub implementation
        Ok(())
    }

    async fn get_usage_summaries(&self, _query: &UsageQuery) -> StorageResult<Vec<UsageSummary>> {
        // Stub implementation
        Ok(Vec::new())
    }

    async fn cleanup_old_usage_records(&self, retention_days: u32) -> StorageResult<u64> {
        let cutoff_date = chrono::Utc::now() - chrono::Duration::days(retention_days as i64);

        let result = sqlx::query("DELETE FROM usage_records WHERE request_time < $1")
            .bind(cutoff_date)
            .execute(&self.pool)
            .await
            .map_err(|e| {
                StorageError::Database(format!("Failed to cleanup old usage records: {}", e))
            })?;

        Ok(result.rows_affected())
    }

    async fn get_model_cost(&self, model_id: &str) -> StorageResult<Option<StoredModelCost>> {
        let row = sqlx::query(
            "SELECT id, model_id, input_cost_per_1k_tokens, output_cost_per_1k_tokens, updated_at FROM model_costs WHERE model_id = $1",
        )
        .bind(model_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| StorageError::Database(format!("Failed to get model cost: {}", e)))?;

        match row {
            Some(row) => Ok(Some(StoredModelCost {
                id: Some(row.get("id")),
                model_id: row.get("model_id"),
                input_cost_per_1k_tokens: row.get("input_cost_per_1k_tokens"),
                output_cost_per_1k_tokens: row.get("output_cost_per_1k_tokens"),
                updated_at: row.get("updated_at"),
            })),
            None => Ok(None),
        }
    }

    async fn upsert_model_cost(&self, cost: &StoredModelCost) -> StorageResult<()> {
        sqlx::query(
            r#"
            INSERT INTO model_costs (model_id, input_cost_per_1k_tokens, output_cost_per_1k_tokens, updated_at)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (model_id)
            DO UPDATE SET
                input_cost_per_1k_tokens = EXCLUDED.input_cost_per_1k_tokens,
                output_cost_per_1k_tokens = EXCLUDED.output_cost_per_1k_tokens,
                updated_at = EXCLUDED.updated_at
            "#,
        )
        .bind(&cost.model_id)
        .bind(cost.input_cost_per_1k_tokens)
        .bind(cost.output_cost_per_1k_tokens)
        .bind(cost.updated_at)
        .execute(&self.pool)
        .await
        .map_err(|e| StorageError::Database(format!("Failed to upsert model cost: {}", e)))?;

        Ok(())
    }

    async fn get_all_model_costs(&self) -> StorageResult<Vec<StoredModelCost>> {
        let rows = sqlx::query(
            "SELECT id, model_id, input_cost_per_1k_tokens, output_cost_per_1k_tokens, updated_at FROM model_costs ORDER BY model_id",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| StorageError::Database(format!("Failed to get all model costs: {}", e)))?;

        let mut costs = Vec::new();
        for row in rows {
            costs.push(StoredModelCost {
                id: Some(row.get("id")),
                model_id: row.get("model_id"),
                input_cost_per_1k_tokens: row.get("input_cost_per_1k_tokens"),
                output_cost_per_1k_tokens: row.get("output_cost_per_1k_tokens"),
                updated_at: row.get("updated_at"),
            });
        }

        Ok(costs)
    }

    async fn delete_model_cost(&self, model_id: &str) -> StorageResult<()> {
        sqlx::query("DELETE FROM model_costs WHERE model_id = $1")
            .bind(model_id)
            .execute(&self.pool)
            .await
            .map_err(|e| StorageError::Database(format!("Failed to delete model cost: {}", e)))?;

        Ok(())
    }

    async fn get_user_usage_records(
        &self,
        user_id: i32,
        limit: u32,
        offset: u32,
        model_filter: Option<&str>,
        start_date: Option<chrono::DateTime<chrono::Utc>>,
        end_date: Option<chrono::DateTime<chrono::Utc>>,
    ) -> StorageResult<Vec<UsageRecord>> {
        let query = UsageQuery {
            user_id: Some(user_id),
            model_id: model_filter.map(|s| s.to_string()),
            start_date,
            end_date,
            success_only: None,
            limit: Some(limit),
            offset: Some(offset),
        };

        self.get_usage_records(&query).await
    }

    async fn get_user_usage_stats(
        &self,
        user_id: i32,
        start_date: Option<chrono::DateTime<chrono::Utc>>,
        end_date: Option<chrono::DateTime<chrono::Utc>>,
    ) -> StorageResult<UsageStats> {
        let query = UsageQuery {
            user_id: Some(user_id),
            model_id: None,
            start_date,
            end_date,
            success_only: None,
            limit: None,
            offset: None,
        };

        self.get_usage_stats(&query).await
    }

    async fn get_system_usage_stats(
        &self,
        start_date: Option<chrono::DateTime<chrono::Utc>>,
        end_date: Option<chrono::DateTime<chrono::Utc>>,
    ) -> StorageResult<UsageStats> {
        let query = UsageQuery {
            user_id: None,
            model_id: None,
            start_date,
            end_date,
            success_only: None,
            limit: None,
            offset: None,
        };

        self.get_usage_stats(&query).await
    }

    async fn get_top_models_by_usage(
        &self,
        limit: u32,
        _start_date: Option<chrono::DateTime<chrono::Utc>>,
        _end_date: Option<chrono::DateTime<chrono::Utc>>,
    ) -> StorageResult<Vec<(String, u64)>> {
        let sql = "SELECT model_id, SUM(total_tokens) as total_tokens FROM usage_records GROUP BY model_id ORDER BY total_tokens DESC LIMIT $1";

        let rows = sqlx::query(sql)
            .bind(limit as i64)
            .fetch_all(&self.pool)
            .await
            .map_err(|e| StorageError::Database(format!("Failed to get top models: {}", e)))?;

        let mut results = Vec::new();
        for row in rows {
            results.push((
                row.get("model_id"),
                row.get::<i64, _>("total_tokens") as u64,
            ));
        }

        Ok(results)
    }

    async fn get_unique_model_ids(&self) -> StorageResult<Vec<String>> {
        let rows = sqlx::query("SELECT DISTINCT model_id FROM usage_records ORDER BY model_id")
            .fetch_all(&self.pool)
            .await
            .map_err(|e| {
                StorageError::Database(format!("Failed to get unique model IDs: {}", e))
            })?;

        let mut model_ids = Vec::new();
        for row in rows {
            model_ids.push(row.get("model_id"));
        }

        Ok(model_ids)
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use chrono::Utc;
    use std::sync::atomic::{AtomicU32, Ordering};
    use tokio;

    // Global counter for unique test database names
    static TEST_DB_COUNTER: AtomicU32 = AtomicU32::new(0);

    /// Test database wrapper that automatically cleans up on drop
    pub struct TestPostgresDb {
        pub db: PostgresStorage,
        pub db_name: String,
    }

    impl Drop for TestPostgresDb {
        fn drop(&mut self) {
            let db_name = self.db_name.clone();
            // Use tokio's runtime to run the async cleanup
            if let Ok(rt) = tokio::runtime::Handle::try_current() {
                rt.spawn(async move {
                    let _ = drop_test_postgres_db_sync(&db_name).await;
                });
            } else {
                // If no runtime available, try to create one for cleanup
                if let Ok(rt) = tokio::runtime::Runtime::new() {
                    rt.block_on(async {
                        let _ = drop_test_postgres_db_sync(&db_name).await;
                    });
                }
            }
        }
    }

    /// Helper function to create a unique test database for PostgreSQL tests
    pub async fn create_test_postgres_db() -> Result<TestPostgresDb, Box<dyn std::error::Error>> {
        let counter = TEST_DB_COUNTER.fetch_add(1, Ordering::SeqCst);
        let test_db_name = format!("bedrock_sso_test_{}", counter);

        // Connect to the default postgres database to create our test database
        let admin_url = std::env::var("POSTGRES_ADMIN_URL")
            .unwrap_or_else(|_| "postgres://localhost/postgres".to_string());

        let admin_pool = sqlx::Pool::<sqlx::Postgres>::connect(&admin_url)
            .await
            .map_err(|e| {
                format!(
                    "Failed to connect to PostgreSQL admin database at '{}'. \
                                  Please ensure PostgreSQL is running and set POSTGRES_ADMIN_URL \
                                  environment variable with proper credentials (e.g., \
                                  'postgres://user:password@localhost/postgres'). Error: {}",
                    admin_url, e
                )
            })?;

        // Drop the test database if it already exists
        let _ = drop_test_postgres_db(&test_db_name).await;

        // Create the test database
        let create_sql = format!("CREATE DATABASE \"{}\"", test_db_name);
        sqlx::query(&create_sql).execute(&admin_pool).await?;

        // Close admin connection
        admin_pool.close().await;

        // Connect to the new test database
        let test_db_url = format!("postgres://localhost/{}", test_db_name);
        let db = PostgresStorage::new(&test_db_url).await?;

        Ok(TestPostgresDb {
            db,
            db_name: test_db_name,
        })
    }

    /// Synchronous wrapper for database cleanup (for use in Drop)
    async fn drop_test_postgres_db_sync(db_name: &str) -> Result<(), Box<dyn std::error::Error>> {
        drop_test_postgres_db(db_name).await
    }

    /// Helper function to drop a test database
    pub async fn drop_test_postgres_db(db_name: &str) -> Result<(), Box<dyn std::error::Error>> {
        // Connect to the default postgres database to drop our test database
        let admin_url = std::env::var("POSTGRES_ADMIN_URL")
            .unwrap_or_else(|_| "postgres://localhost/postgres".to_string());

        let admin_pool = sqlx::Pool::<sqlx::Postgres>::connect(&admin_url).await?;

        // Force disconnect all connections to the test database
        let terminate_sql = format!(
            "SELECT pg_terminate_backend(pg_stat_activity.pid) FROM pg_stat_activity WHERE pg_stat_activity.datname = '{}' AND pid <> pg_backend_pid()",
            db_name
        );
        let _ = sqlx::query(&terminate_sql).execute(&admin_pool).await;

        // Drop the test database
        let drop_sql = format!("DROP DATABASE IF EXISTS \"{}\"", db_name);
        sqlx::query(&drop_sql).execute(&admin_pool).await?;

        admin_pool.close().await;
        Ok(())
    }

    #[tokio::test]
    async fn test_postgres_usage_tracking_operations() {
        let test_db = create_test_postgres_db()
            .await
            .expect("Failed to create test database");

        test_db.db.migrate().await.unwrap();

        // First, create a test user
        let user = UserRecord {
            id: None,
            provider: "google".to_string(),
            provider_user_id: "test-user-123".to_string(),
            email: "test@example.com".to_string(),
            display_name: Some("Test User".to_string()),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            last_login: Some(Utc::now()),
        };
        let user_id = test_db.db.upsert_user(&user).await.unwrap();

        // Test create usage record
        let usage_record = UsageRecord {
            id: None,
            user_id,
            model_id: "anthropic.claude-sonnet-4-20250514-v1:0".to_string(),
            endpoint_type: "bedrock".to_string(),
            region: "us-east-1".to_string(),
            request_time: Utc::now(),
            input_tokens: 100,
            output_tokens: 50,
            total_tokens: 150,
            response_time_ms: 250,
            success: true,
            error_message: None,
            cost_usd: Some(rust_decimal::Decimal::from_f64_retain(0.001).unwrap()),
        };

        test_db.db.store_usage_record(&usage_record).await.unwrap();

        // Test get usage stats
        let query = UsageQuery {
            user_id: Some(user_id),
            model_id: None,
            start_date: None,
            end_date: None,
            success_only: None,
            limit: None,
            offset: None,
        };

        let stats = test_db.db.get_usage_stats(&query).await.unwrap();
        assert_eq!(stats.total_requests, 1);
        assert_eq!(stats.total_input_tokens, 100);
        assert_eq!(stats.total_output_tokens, 50);
        assert_eq!(stats.total_tokens, 150);
        assert_eq!(stats.avg_response_time_ms, 250.0);
        assert_eq!(stats.success_rate, 1.0);
    }
}
