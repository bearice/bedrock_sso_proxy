use crate::database::entities::{AuditLogEntry, audit_logs};
use crate::database::{DatabaseError, DatabaseResult};
use chrono::Utc;
use sea_orm::{
    ActiveModelTrait, ActiveValue, ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter,
    QueryOrder, QuerySelect, Set,
};

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

        let mut results = Vec::new();
        for log in logs {
            let metadata = log
                .metadata
                .as_ref()
                .and_then(|m| serde_json::from_str(m).ok());

            results.push(AuditLogEntry {
                id: log.id,
                user_id: log.user_id,
                event_type: log.event_type,
                provider: log.provider,
                ip_address: log.ip_address,
                user_agent: log.user_agent,
                success: log.success,
                error_message: log.error_message,
                created_at: log.created_at,
                metadata,
            });
        }

        Ok(results)
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
