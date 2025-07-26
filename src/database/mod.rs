//! Database access layer with domain-specific DAOs
//!
//! This module provides direct database access without abstraction layers.
//! Each domain (users, api_keys, usage, etc.) has its own DAO for focused operations.

use sea_orm::DatabaseConnection;
use thiserror::Error;

pub mod dao;
pub mod entities;
pub mod migration;

pub use dao::{
    ApiKeysDao, AuditLogsDao, ModelCostsDao, RefreshTokensDao, UsageDao, UsageQuery, UsageStats,
    UsersDao,
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

/// Database connection manager
pub struct DatabaseManager {
    pub connection: DatabaseConnection,
}

impl DatabaseManager {
    pub fn new(connection: DatabaseConnection) -> Self {
        Self { connection }
    }

    pub async fn new_from_config(config: &crate::config::Config) -> Result<Self, DatabaseError> {
        let connection = sea_orm::Database::connect(&config.storage.database.url)
            .await
            .map_err(|e| DatabaseError::Database(e.to_string()))?;
        Ok(Self::new(connection))
    }

    /// Run database migrations
    pub async fn migrate(&self) -> DatabaseResult<()> {
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
    pub async fn health_check(&self) -> DatabaseResult<()> {
        use crate::database::entities::users;
        use sea_orm::{EntityTrait, PaginatorTrait};

        let _count = users::Entity::find()
            .count(&self.connection)
            .await
            .map_err(|e| DatabaseError::Database(e.to_string()))?;
        Ok(())
    }

    /// Get users DAO
    pub fn users(&self) -> UsersDao {
        UsersDao::new(self.connection.clone())
    }

    /// Get API keys DAO
    pub fn api_keys(&self) -> ApiKeysDao {
        ApiKeysDao::new(self.connection.clone())
    }

    /// Get usage DAO
    pub fn usage(&self) -> UsageDao {
        UsageDao::new(self.connection.clone())
    }

    /// Get audit logs DAO
    pub fn audit_logs(&self) -> AuditLogsDao {
        AuditLogsDao::new(self.connection.clone())
    }

    /// Get refresh tokens DAO
    pub fn refresh_tokens(&self) -> RefreshTokensDao {
        RefreshTokensDao::new(self.connection.clone())
    }

    /// Get model costs DAO
    pub fn model_costs(&self) -> ModelCostsDao {
        ModelCostsDao::new(self.connection.clone())
    }
}
