use crate::database::entities::{AuditLogEntry, audit_logs};
use crate::database::{DatabaseError, DatabaseResult};
use chrono::{DateTime, Utc};
use sea_orm::{
    ActiveModelTrait, ActiveValue, ColumnTrait, DatabaseConnection, EntityTrait, PaginatorTrait,
    QueryFilter, QueryOrder, QuerySelect, Set,
};
use serde::Deserialize;
use utoipa::{IntoParams, ToSchema};

/// Query parameters for audit log filtering
#[derive(Debug, Deserialize, IntoParams, ToSchema)]
pub struct AuditLogQueryParams {
    /// Filter by user ID
    pub user_id: Option<i32>,
    /// Filter by event type (partial match)
    pub event_type: Option<String>,
    /// Filter by provider
    pub provider: Option<String>,
    /// Filter by success status
    pub success: Option<bool>,
    /// Filter by start date (ISO 8601)
    pub start_date: Option<DateTime<Utc>>,
    /// Filter by end date (ISO 8601)
    pub end_date: Option<DateTime<Utc>>,
    /// Number of records per page (default: 50, max: 1000)
    pub limit: Option<u64>,
    /// Page offset (default: 0)
    pub offset: Option<u64>,
}

/// Audit logs DAO for database operations
pub struct AuditLogsDao {
    db: DatabaseConnection,
}

impl AuditLogsDao {
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }

    /// Store audit log entry
    pub async fn store(&self, entry: &AuditLogEntry) -> DatabaseResult<()> {
        let metadata_json = entry
            .metadata
            .as_ref()
            .map(|m| serde_json::to_string(m).unwrap_or_default());

        let active_model = audit_logs::ActiveModel {
            id: ActiveValue::NotSet,
            user_id: Set(entry.user_id),
            event_type: Set(entry.event_type.clone()),
            provider: Set(entry.provider.clone()),
            ip_address: Set(entry.ip_address.clone()),
            user_agent: Set(entry.user_agent.clone()),
            success: Set(entry.success),
            error_message: Set(entry.error_message.clone()),
            created_at: Set(entry.created_at),
            metadata: Set(metadata_json),
        };

        active_model
            .insert(&self.db)
            .await
            .map_err(|e| DatabaseError::Database(e.to_string()))?;

        Ok(())
    }

    /// Get audit logs for a user
    pub async fn find_by_user(
        &self,
        user_id: i32,
        limit: u32,
        offset: u32,
    ) -> DatabaseResult<Vec<AuditLogEntry>> {
        let logs = audit_logs::Entity::find()
            .filter(audit_logs::Column::UserId.eq(user_id))
            .order_by_desc(audit_logs::Column::CreatedAt)
            .limit(Some(limit as u64))
            .offset(Some(offset as u64))
            .all(&self.db)
            .await
            .map_err(|e| DatabaseError::Database(e.to_string()))?;

        Ok(logs)
    }

    /// Find all audit logs with optional filtering (admin use)
    pub async fn find_all(
        &self,
        query_params: &AuditLogQueryParams,
    ) -> DatabaseResult<Vec<AuditLogEntry>> {
        let mut query = audit_logs::Entity::find();

        // Apply filters
        if let Some(uid) = query_params.user_id {
            query = query.filter(audit_logs::Column::UserId.eq(uid));
        }
        if let Some(ref event) = query_params.event_type {
            query = query.filter(audit_logs::Column::EventType.contains(event));
        }
        if let Some(ref prov) = query_params.provider {
            query = query.filter(audit_logs::Column::Provider.eq(prov));
        }
        if let Some(succ) = query_params.success {
            query = query.filter(audit_logs::Column::Success.eq(succ));
        }
        if let Some(start) = query_params.start_date {
            query = query.filter(audit_logs::Column::CreatedAt.gte(start));
        }
        if let Some(end) = query_params.end_date {
            query = query.filter(audit_logs::Column::CreatedAt.lte(end));
        }

        let logs = query
            .order_by_desc(audit_logs::Column::CreatedAt)
            .limit(query_params.limit)
            .offset(query_params.offset)
            .all(&self.db)
            .await
            .map_err(|e| DatabaseError::Database(e.to_string()))?;

        Ok(logs)
    }

    /// Count audit logs with optional filtering (admin use)
    pub async fn count_all(&self, query_params: &AuditLogQueryParams) -> DatabaseResult<u64> {
        let mut query = audit_logs::Entity::find();

        // Apply filters (same as find_all)
        if let Some(uid) = query_params.user_id {
            query = query.filter(audit_logs::Column::UserId.eq(uid));
        }
        if let Some(ref event) = query_params.event_type {
            query = query.filter(audit_logs::Column::EventType.contains(event));
        }
        if let Some(ref prov) = query_params.provider {
            query = query.filter(audit_logs::Column::Provider.eq(prov));
        }
        if let Some(succ) = query_params.success {
            query = query.filter(audit_logs::Column::Success.eq(succ));
        }
        if let Some(start) = query_params.start_date {
            query = query.filter(audit_logs::Column::CreatedAt.gte(start));
        }
        if let Some(end) = query_params.end_date {
            query = query.filter(audit_logs::Column::CreatedAt.lte(end));
        }

        let count = query
            .count(&self.db)
            .await
            .map_err(|e| DatabaseError::Database(e.to_string()))?;

        Ok(count)
    }

    /// Clean up old audit logs
    pub async fn cleanup_old(&self, retention_days: u32) -> DatabaseResult<u64> {
        let cutoff = Utc::now() - chrono::Duration::days(retention_days as i64);
        let result = audit_logs::Entity::delete_many()
            .filter(audit_logs::Column::CreatedAt.lt(cutoff))
            .exec(&self.db)
            .await
            .map_err(|e| DatabaseError::Database(e.to_string()))?;

        Ok(result.rows_affected)
    }
}
