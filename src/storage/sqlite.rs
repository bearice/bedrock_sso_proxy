use super::{
    AuditLogEntry, DatabaseStorage, RefreshTokenData, StorageError, StorageResult, StoredModelCost,
    UsageQuery, UsageRecord, UsageStats, UsageSummary, UserRecord, query_builder::UsageQueryHelper,
};
use async_trait::async_trait;
use chrono::Utc;
use rust_decimal::Decimal;
use sqlx::{Pool, Row, Sqlite, migrate::MigrateDatabase};

/// SQLite database storage implementation
pub struct SqliteStorage {
    pool: Pool<Sqlite>,
}

impl SqliteStorage {
    /// Convert f64 to Decimal for SQLite compatibility
    fn f64_to_decimal(value: f64) -> Decimal {
        Decimal::from_f64_retain(value).unwrap_or_default()
    }

    /// Convert Option<f64> to Option<Decimal> for SQLite compatibility
    fn f64_to_decimal_opt(value: Option<f64>) -> Option<Decimal> {
        value.and_then(Decimal::from_f64_retain)
    }

    /// Convert Decimal to f64 for numeric calculations (SQLite version)
    fn decimal_to_f64(decimal: Decimal) -> f64 {
        use rust_decimal::prelude::ToPrimitive;
        decimal.to_f64().unwrap_or(0.0)
    }

    /// Convert Option<Decimal> to Option<f64> for SQLite compatibility
    fn decimal_to_f64_opt(value: Option<Decimal>) -> Option<f64> {
        use rust_decimal::prelude::ToPrimitive;
        value.map(|d| d.to_f64().unwrap_or(0.0))
    }

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

    pub async fn migrate(&self) -> StorageResult<()> {
        super::migrations::run_sqlite_migrations(&self.pool).await
    }
}

#[async_trait]
impl DatabaseStorage for SqliteStorage {
    async fn migrate(&self) -> StorageResult<()> {
        super::migrations::run_sqlite_migrations(&self.pool).await
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

    async fn get_user_by_id(&self, user_id: i32) -> StorageResult<Option<UserRecord>> {
        let row = sqlx::query(
            "SELECT id, provider_user_id, provider, email, display_name, created_at, updated_at, last_login FROM users WHERE id = ?1",
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
                    .and_then(|s| serde_json::from_str(&s).ok()),
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

    // Usage tracking methods implementation for SQLite

    async fn store_usage_record(&self, record: &UsageRecord) -> StorageResult<()> {
        sqlx::query(
            r#"
            INSERT INTO usage_records (user_id, model_id, endpoint_type, region, request_time,
                                     input_tokens, output_tokens, total_tokens, response_time_ms,
                                     success, error_message, cost_usd)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
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
        .bind(Self::decimal_to_f64_opt(record.cost_usd))
        .execute(&self.pool)
        .await
        .map_err(|e| StorageError::Database(format!("Failed to store usage record: {}", e)))?;

        Ok(())
    }

    async fn get_usage_records(&self, query: &UsageQuery) -> StorageResult<Vec<UsageRecord>> {
        // Use the dynamic query builder for SQLite - clean and maintainable!
        let query_builder = UsageQueryHelper::build_query(query);

        query_builder
            .execute_sqlite(&self.pool)
            .await
            .map_err(|e| StorageError::Database(format!("Failed to get usage records: {}", e)))
    }

    async fn get_usage_stats(&self, _query: &UsageQuery) -> StorageResult<UsageStats> {
        // Implementation would build dynamic SQL with WHERE conditions based on query
        // For brevity, implementing basic version
        let sql = "SELECT COUNT(*) as total_requests, COALESCE(SUM(input_tokens), 0) as total_input_tokens, COALESCE(SUM(output_tokens), 0) as total_output_tokens, COALESCE(SUM(total_tokens), 0) as total_tokens, COALESCE(AVG(CAST(response_time_ms AS REAL)), 0) as avg_response_time_ms, COALESCE(AVG(CASE WHEN success THEN 1.0 ELSE 0.0 END), 0) as success_rate, COALESCE(SUM(cost_usd), 0) as total_cost, COUNT(DISTINCT model_id) as unique_models, MIN(request_time) as min_time, MAX(request_time) as max_time FROM usage_records";

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
            avg_response_time_ms: row.get::<f64, _>("avg_response_time_ms") as f32,
            success_rate: row.get::<f64, _>("success_rate") as f32,
            total_cost: Self::f64_to_decimal_opt(row.get("total_cost")),
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

        let result = sqlx::query("DELETE FROM usage_records WHERE request_time < ?1")
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
            "SELECT id, model_id, input_cost_per_1k_tokens, output_cost_per_1k_tokens, updated_at FROM model_costs WHERE model_id = ?1",
        )
        .bind(model_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| StorageError::Database(format!("Failed to get model cost: {}", e)))?;

        match row {
            Some(row) => Ok(Some(StoredModelCost {
                id: Some(row.get("id")),
                model_id: row.get("model_id"),
                input_cost_per_1k_tokens: Self::f64_to_decimal(row.get("input_cost_per_1k_tokens")),
                output_cost_per_1k_tokens: Self::f64_to_decimal(
                    row.get("output_cost_per_1k_tokens"),
                ),
                updated_at: row.get("updated_at"),
            })),
            None => Ok(None),
        }
    }

    async fn upsert_model_cost(&self, cost: &StoredModelCost) -> StorageResult<()> {
        sqlx::query(
            r#"
            INSERT INTO model_costs (model_id, input_cost_per_1k_tokens, output_cost_per_1k_tokens, updated_at)
            VALUES (?1, ?2, ?3, ?4)
            ON CONFLICT (model_id)
            DO UPDATE SET
                input_cost_per_1k_tokens = excluded.input_cost_per_1k_tokens,
                output_cost_per_1k_tokens = excluded.output_cost_per_1k_tokens,
                updated_at = excluded.updated_at
            "#,
        )
        .bind(&cost.model_id)
        .bind(Self::decimal_to_f64(cost.input_cost_per_1k_tokens))
        .bind(Self::decimal_to_f64(cost.output_cost_per_1k_tokens))
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
                input_cost_per_1k_tokens: Self::f64_to_decimal(row.get("input_cost_per_1k_tokens")),
                output_cost_per_1k_tokens: Self::f64_to_decimal(
                    row.get("output_cost_per_1k_tokens"),
                ),
                updated_at: row.get("updated_at"),
            });
        }

        Ok(costs)
    }

    async fn delete_model_cost(&self, model_id: &str) -> StorageResult<()> {
        sqlx::query("DELETE FROM model_costs WHERE model_id = ?1")
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
        let sql = "SELECT model_id, SUM(total_tokens) as total_tokens FROM usage_records GROUP BY model_id ORDER BY total_tokens DESC LIMIT ?1";

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
