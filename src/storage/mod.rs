use async_trait::async_trait;
use chrono::{DateTime, Utc};
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, sync::Arc};
use thiserror::Error;

use crate::health::{HealthCheckResult, HealthChecker};
#[cfg(test)]
pub mod integration_tests;

pub mod blackhole;
pub mod database;
pub mod factory;
pub mod memory;
pub mod migrations;
pub mod postgres;
pub mod query_builder;
pub mod redis;
pub mod sqlite;

pub use factory::StorageFactory;

#[derive(Error, Debug)]
pub enum StorageError {
    #[error("Connection error: {0}")]
    Connection(String),
    #[error("Serialization error: {0}")]
    Serialization(String),
    #[error("Not found")]
    NotFound,
    #[error("Database error: {0}")]
    Database(String),
    #[error("Redis error: {0}")]
    Redis(String),
    #[error("Invalid data: {0}")]
    InvalidData(String),
}

pub type StorageResult<T> = Result<T, StorageError>;

/// Cache validation data structure
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CachedValidation {
    pub user_id: String,
    pub provider: String,
    pub email: String,
    pub validated_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub scopes: Vec<String>,
}

/// CSRF state tokens for OAuth security
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StateData {
    pub provider: String,
    pub redirect_uri: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

/// Refresh token data for database persistence
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RefreshTokenData {
    pub token_hash: String,
    pub user_id: String,
    pub provider: String,
    pub email: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub rotation_count: u32,
    pub revoked_at: Option<DateTime<Utc>>,
}

/// User record for database persistence
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UserRecord {
    pub id: Option<i32>,
    pub provider_user_id: String,
    pub provider: String,
    pub email: String,
    pub display_name: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub last_login: Option<DateTime<Utc>>,
}

/// Audit log entry for database persistence
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuditLogEntry {
    pub id: Option<i32>,
    pub user_id: Option<i32>,
    pub event_type: String,
    pub provider: Option<String>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub success: bool,
    pub error_message: Option<String>,
    pub created_at: DateTime<Utc>,
    pub metadata: Option<HashMap<String, serde_json::Value>>,
}

/// Usage record for database persistence - tracks individual API requests
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UsageRecord {
    pub id: Option<i32>,
    pub user_id: i32,
    pub model_id: String,
    pub endpoint_type: String, // "bedrock" or "anthropic"
    pub region: String,
    pub request_time: DateTime<Utc>,
    pub input_tokens: u32,
    pub output_tokens: u32,
    pub total_tokens: u32,
    pub response_time_ms: u32,
    pub success: bool,
    pub error_message: Option<String>,
    pub cost_usd: Option<Decimal>,
}

/// Pre-calculated usage summary for performance
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UsageSummary {
    pub id: Option<i32>,
    pub user_id: i32,
    pub model_id: String,
    pub period_type: String, // "hour", "day", "month"
    pub period_start: DateTime<Utc>,
    pub period_end: DateTime<Utc>,
    pub total_requests: u32,
    pub total_input_tokens: u64,
    pub total_output_tokens: u64,
    pub total_tokens: u64,
    pub avg_response_time_ms: f32,
    pub success_rate: f32,
    pub estimated_cost: Option<Decimal>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Model cost configuration for cost calculation
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StoredModelCost {
    pub id: Option<i32>,
    pub model_id: String,
    pub input_cost_per_1k_tokens: Decimal,
    pub output_cost_per_1k_tokens: Decimal,
    pub updated_at: DateTime<Utc>,
}

/// Query parameters for usage data retrieval
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UsageQuery {
    pub user_id: Option<i32>,
    pub model_id: Option<String>,
    pub start_date: Option<DateTime<Utc>>,
    pub end_date: Option<DateTime<Utc>>,
    pub success_only: Option<bool>,
    pub limit: Option<u32>,
    pub offset: Option<u32>,
}

/// Aggregated usage statistics
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UsageStats {
    pub total_requests: u32,
    pub total_input_tokens: u64,
    pub total_output_tokens: u64,
    pub total_tokens: u64,
    pub avg_response_time_ms: f32,
    pub success_rate: f32,
    pub total_cost: Option<Decimal>,
    pub unique_models: u32,
    pub date_range: (DateTime<Utc>, DateTime<Utc>),
}

/// Cache storage trait for TTL-based data (Redis or in-memory)
#[async_trait]
pub trait CacheStorage: Send + Sync {
    /// Store validation result with TTL
    async fn store_validation(
        &self,
        key: &str,
        validation: &CachedValidation,
        ttl_seconds: u64,
    ) -> StorageResult<()>;

    /// Get validation result
    async fn get_validation(&self, key: &str) -> StorageResult<Option<CachedValidation>>;

    /// Delete validation result
    async fn delete_validation(&self, key: &str) -> StorageResult<()>;

    /// Store CSRF state token with TTL
    async fn store_state(
        &self,
        key: &str,
        state: &StateData,
        ttl_seconds: u64,
    ) -> StorageResult<()>;

    /// Get CSRF state token
    async fn get_state(&self, key: &str) -> StorageResult<Option<StateData>>;

    /// Delete CSRF state token
    async fn delete_state(&self, key: &str) -> StorageResult<()>;

    /// Clear all cache data (useful for testing)
    async fn clear_all(&self) -> StorageResult<()>;

    /// Health check for cache storage
    async fn health_check(&self) -> StorageResult<()>;
}

/// Database storage trait for persistent data
#[async_trait]
pub trait DatabaseStorage: Send + Sync {
    /// Store or update user record
    async fn upsert_user(&self, user: &UserRecord) -> StorageResult<i32>;

    /// Get user by provider and provider_user_id
    async fn get_user_by_provider(
        &self,
        provider: &str,
        provider_user_id: &str,
    ) -> StorageResult<Option<UserRecord>>;

    /// Get user by email
    async fn get_user_by_email(&self, email: &str) -> StorageResult<Option<UserRecord>>;

    /// Update user's last login time
    async fn update_last_login(&self, user_id: i32) -> StorageResult<()>;

    /// Store refresh token
    async fn store_refresh_token(&self, token: &RefreshTokenData) -> StorageResult<()>;

    /// Get refresh token by hash
    async fn get_refresh_token(&self, token_hash: &str) -> StorageResult<Option<RefreshTokenData>>;

    /// Revoke refresh token
    async fn revoke_refresh_token(&self, token_hash: &str) -> StorageResult<()>;

    /// Clean up expired refresh tokens
    async fn cleanup_expired_tokens(&self) -> StorageResult<u64>;

    /// Store audit log entry
    async fn store_audit_log(&self, entry: &AuditLogEntry) -> StorageResult<()>;

    /// Get audit logs for user
    async fn get_audit_logs_for_user(
        &self,
        user_id: i32,
        limit: u32,
        offset: u32,
    ) -> StorageResult<Vec<AuditLogEntry>>;

    /// Clean up old audit logs
    async fn cleanup_old_audit_logs(&self, retention_days: u32) -> StorageResult<u64>;

    /// Health check for database storage
    async fn health_check(&self) -> StorageResult<()>;

    /// Run database migrations
    async fn migrate(&self) -> StorageResult<()>;

    // Usage tracking methods

    /// Store usage record
    async fn store_usage_record(&self, record: &UsageRecord) -> StorageResult<()>;

    /// Get usage records for query
    async fn get_usage_records(&self, query: &UsageQuery) -> StorageResult<Vec<UsageRecord>>;

    /// Get usage statistics for query
    async fn get_usage_stats(&self, query: &UsageQuery) -> StorageResult<UsageStats>;

    /// Store or update usage summary
    async fn upsert_usage_summary(&self, summary: &UsageSummary) -> StorageResult<()>;

    /// Get usage summaries for query
    async fn get_usage_summaries(&self, query: &UsageQuery) -> StorageResult<Vec<UsageSummary>>;

    /// Clean up old usage records
    async fn cleanup_old_usage_records(&self, retention_days: u32) -> StorageResult<u64>;

    /// Get model cost by model ID
    async fn get_model_cost(&self, model_id: &str) -> StorageResult<Option<StoredModelCost>>;

    /// Store or update model cost
    async fn upsert_model_cost(&self, cost: &StoredModelCost) -> StorageResult<()>;

    /// Get all model costs
    async fn get_all_model_costs(&self) -> StorageResult<Vec<StoredModelCost>>;

    /// Delete model cost
    async fn delete_model_cost(&self, model_id: &str) -> StorageResult<()>;

    /// Get usage records for user (paginated)
    async fn get_user_usage_records(
        &self,
        user_id: i32,
        limit: u32,
        offset: u32,
        model_filter: Option<&str>,
        start_date: Option<DateTime<Utc>>,
        end_date: Option<DateTime<Utc>>,
    ) -> StorageResult<Vec<UsageRecord>>;

    /// Get user usage statistics
    async fn get_user_usage_stats(
        &self,
        user_id: i32,
        start_date: Option<DateTime<Utc>>,
        end_date: Option<DateTime<Utc>>,
    ) -> StorageResult<UsageStats>;

    /// Get system-wide usage statistics (admin only)
    async fn get_system_usage_stats(
        &self,
        start_date: Option<DateTime<Utc>>,
        end_date: Option<DateTime<Utc>>,
    ) -> StorageResult<UsageStats>;

    /// Get top models by usage
    async fn get_top_models_by_usage(
        &self,
        limit: u32,
        start_date: Option<DateTime<Utc>>,
        end_date: Option<DateTime<Utc>>,
    ) -> StorageResult<Vec<(String, u64)>>; // (model_id, total_tokens)

    /// Get unique model IDs from usage records
    async fn get_unique_model_ids(&self) -> StorageResult<Vec<String>>;
}

/// Unified storage interface combining cache and database
pub struct Storage {
    pub cache: Box<dyn CacheStorage>,
    pub database: Box<dyn DatabaseStorage>,
}

impl Storage {
    pub fn new(cache: Box<dyn CacheStorage>, database: Box<dyn DatabaseStorage>) -> Self {
        Self { cache, database }
    }

    /// Health check for all storage systems
    pub async fn health_check(&self) -> StorageResult<()> {
        self.cache.health_check().await?;
        self.database.health_check().await?;
        Ok(())
    }

    /// Run database migrations
    pub async fn migrate(&self) -> StorageResult<()> {
        self.database.migrate().await
    }
}

/// Health checker implementation for storage
pub struct StorageHealthChecker {
    storage: Arc<Storage>,
}

impl StorageHealthChecker {
    pub fn new(storage: Arc<Storage>) -> Self {
        Self { storage }
    }
}

#[async_trait]
impl HealthChecker for StorageHealthChecker {
    async fn check(&self) -> HealthCheckResult {
        match self.storage.health_check().await {
            Ok(()) => HealthCheckResult::healthy(),
            Err(e) => HealthCheckResult::unhealthy(format!("Storage health check failed: {}", e)),
        }
    }

    fn name(&self) -> &str {
        "storage"
    }
}
