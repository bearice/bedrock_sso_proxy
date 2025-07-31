//! Database access layer with domain-specific DAOs
//!
//! This module provides direct database access without abstraction layers.
//! Each domain (users, api_keys, usage, etc.) has its own DAO for focused operations.

use std::sync::Arc;

use crate::cache::{CacheManager, TypedCacheStats};
use crate::config::Config;
use crate::health::HealthChecker;
use async_trait::async_trait;
use sea_orm::DatabaseConnection;
use thiserror::Error;

pub mod config;
pub mod dao;
pub mod entities;
pub mod migration;

pub use dao::{
    ApiKeysDao, AuditLogQueryParams, AuditLogsDao, CachedApiKeysDao, CachedModelCostsDao,
    CachedUsersDao, ModelCostsDao, RefreshTokensDao, UsageDao, UsageQuery, UsageStats, UsersDao,
};

/// Database error types
#[derive(Error, Debug)]
pub enum DatabaseError {
    #[error("Database error: {0}")]
    Database(String),
    #[error("Record not found")]
    NotFound,
    #[error("Constraint violation: {0}")]
    Constraint(String),
    #[error("Migration error: {0}")]
    Migration(String),
}

pub type DatabaseResult<T> = Result<T, DatabaseError>;

/// Database manager trait for dependency injection and testing
#[async_trait]
pub trait DatabaseManager: Send + Sync {
    /// Run database migrations
    async fn migrate(&self) -> DatabaseResult<()>;

    /// Health check for database connection
    async fn health_check(&self) -> DatabaseResult<()>;

    /// Get cache manager reference
    fn cache_manager(&self) -> Arc<CacheManager>;

    /// Get users DAO
    fn users(&self) -> CachedUsersDao;

    /// Get API keys DAO
    fn api_keys(&self) -> CachedApiKeysDao;

    /// Get usage DAO
    fn usage(&self) -> UsageDao;

    /// Get audit logs DAO
    fn audit_logs(&self) -> AuditLogsDao;

    /// Get refresh tokens DAO
    fn refresh_tokens(&self) -> RefreshTokensDao;

    /// Get model costs DAO
    fn model_costs(&self) -> CachedModelCostsDao;

    /// Get cache statistics for all cached DAOs
    fn get_cache_stats(&self) -> Option<CacheStats>;

    /// Get direct database connection (for migrations and admin operations)
    fn connection(&self) -> &DatabaseConnection;
}

/// Database connection manager implementation with optional caching
pub struct DatabaseManagerImpl {
    pub connection: DatabaseConnection,
    cache_manager: Arc<CacheManager>,
}

impl DatabaseManagerImpl {
    /// Create database manager from configuration with caching
    pub async fn new_from_config(
        config: &Config,
        cache_manager: Arc<CacheManager>,
    ) -> Result<Self, DatabaseError> {
        let connection = sea_orm::Database::connect(&config.database.url)
            .await
            .map_err(|e| DatabaseError::Database(e.to_string()))?;

        Ok(Self {
            connection,
            cache_manager,
        })
    }
}

#[async_trait]
impl DatabaseManager for DatabaseManagerImpl {
    /// Run database migrations
    async fn migrate(&self) -> DatabaseResult<()> {
        use crate::database::migration::Migrator;
        use sea_orm_migration::MigratorTrait;

        tracing::info!("Running database migrations");

        Migrator::up(&self.connection, None)
            .await
            .map_err(|e| DatabaseError::Migration(format!("Failed to run migrations: {}", e)))?;

        tracing::info!("Successfully completed all migrations");
        Ok(())
    }

    /// Health check for database connection
    async fn health_check(&self) -> DatabaseResult<()> {
        self.connection
            .ping()
            .await
            .map_err(|e| DatabaseError::Database(format!("db error: {}", e)))
    }

    /// Get cache manager reference
    fn cache_manager(&self) -> Arc<CacheManager> {
        self.cache_manager.clone()
    }

    /// Get users DAO
    fn users(&self) -> CachedUsersDao {
        CachedUsersDao::new(UsersDao::new(self.connection.clone()), &self.cache_manager)
    }

    /// Get API keys DAO
    fn api_keys(&self) -> CachedApiKeysDao {
        CachedApiKeysDao::new(
            ApiKeysDao::new(self.connection.clone()),
            &self.cache_manager,
        )
    }

    /// Get usage DAO
    fn usage(&self) -> UsageDao {
        UsageDao::new(self.connection.clone())
    }

    /// Get audit logs DAO
    fn audit_logs(&self) -> AuditLogsDao {
        AuditLogsDao::new(self.connection.clone())
    }

    /// Get refresh tokens DAO
    fn refresh_tokens(&self) -> RefreshTokensDao {
        RefreshTokensDao::new(self.connection.clone())
    }

    /// Get model costs DAO
    fn model_costs(&self) -> CachedModelCostsDao {
        CachedModelCostsDao::new(
            ModelCostsDao::new(self.connection.clone()),
            &self.cache_manager,
        )
    }

    /// Get cache statistics for all cached DAOs
    fn get_cache_stats(&self) -> Option<CacheStats> {
        // Create temporary DAOs to get stats
        let users = self.users().get_cache_stats();
        let api_keys = self.api_keys().get_cache_stats();
        let model_costs = self.model_costs().get_cache_stats();

        Some(CacheStats {
            users,
            api_keys,
            model_costs,
        })
    }

    /// Get direct database connection (for migrations and admin operations)
    fn connection(&self) -> &DatabaseConnection {
        &self.connection
    }
}

#[async_trait]
impl HealthChecker for DatabaseManagerImpl {
    fn name(&self) -> &str {
        "database"
    }
    async fn check(&self) -> crate::health::HealthCheckResult {
        match self.health_check().await {
            Ok(_) => crate::health::HealthCheckResult::healthy_with_details(serde_json::json!({
                "status": "healthy",
                "connection": "ok"
            })),
            Err(err) => crate::health::HealthCheckResult::unhealthy_with_details(
                "DB health check failed".to_string(),
                serde_json::json!({
                    "status": "unhealthy",
                    "error": err.to_string()
                }),
            ),
        }
    }
}

/// Cache statistics for all cached DAOs
#[derive(Debug, Clone)]
pub struct CacheStats {
    pub users: TypedCacheStats,
    pub api_keys: TypedCacheStats,
    pub model_costs: TypedCacheStats,
}
