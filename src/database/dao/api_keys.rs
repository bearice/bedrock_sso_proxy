use crate::database::entities::{ApiKeyRecord, api_keys};
use crate::database::{DatabaseError, DatabaseResult};
use chrono::Utc;
use sea_orm::{
    ActiveModelTrait, ActiveValue, ColumnTrait, Condition, DatabaseConnection, EntityTrait,
    QueryFilter, QueryOrder, Set,
};

/// API Keys DAO for database operations
#[derive(Clone)]
pub struct ApiKeysDao {
    db: DatabaseConnection,
}

impl ApiKeysDao {
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }

    /// Store a new API key
    pub async fn store(&self, api_key: &ApiKeyRecord) -> DatabaseResult<i32> {
        let active_model = api_keys::ActiveModel {
            id: ActiveValue::NotSet,
            key_hash: Set(api_key.key_hash.clone()),
            user_id: Set(api_key.user_id),
            name: Set(api_key.name.clone()),
            hint: Set(api_key.hint.clone()),
            created_at: Set(api_key.created_at),
            last_used: Set(api_key.last_used),
            expires_at: Set(api_key.expires_at),
            revoked_at: Set(api_key.revoked_at),
        };

        let result = active_model
            .insert(&self.db)
            .await
            .map_err(|e| DatabaseError::Database(e.to_string()))?;

        Ok(result.id)
    }

    /// Find API key by hash
    pub async fn find_by_hash(&self, key_hash: &str) -> DatabaseResult<Option<ApiKeyRecord>> {
        let key = api_keys::Entity::find()
            .filter(api_keys::Column::KeyHash.eq(key_hash))
            .one(&self.db)
            .await
            .map_err(|e| DatabaseError::Database(e.to_string()))?;

        Ok(key)
    }

    /// Find API key by ID
    pub async fn find_by_id(&self, key_id: i32) -> DatabaseResult<Option<ApiKeyRecord>> {
        let key = api_keys::Entity::find_by_id(key_id)
            .one(&self.db)
            .await
            .map_err(|e| DatabaseError::Database(e.to_string()))?;

        Ok(key)
    }

    /// Get all API keys for a user (only non-revoked ones)
    pub async fn find_by_user(&self, user_id: i32) -> DatabaseResult<Vec<ApiKeyRecord>> {
        let keys = api_keys::Entity::find()
            .filter(api_keys::Column::UserId.eq(user_id))
            .filter(api_keys::Column::RevokedAt.is_null())
            .order_by_desc(api_keys::Column::CreatedAt)
            .all(&self.db)
            .await
            .map_err(|e| DatabaseError::Database(e.to_string()))?;

        Ok(keys)
    }

    /// Update last used timestamp for an API key
    pub async fn update_last_used(&self, key: ApiKeyRecord) -> DatabaseResult<ApiKeyRecord> {
        let active_model = api_keys::ActiveModel {
            id: Set(key.id),
            last_used: Set(Some(Utc::now())),
            ..Default::default()
        };

        let updated_key = active_model
            .update(&self.db)
            .await
            .map_err(|e| DatabaseError::Database(e.to_string()))?;

        Ok(updated_key)
    }

    /// Revoke an API key
    pub async fn revoke(&self, key: ApiKeyRecord) -> DatabaseResult<ApiKeyRecord> {
        let active_model = api_keys::ActiveModel {
            id: Set(key.id),
            revoked_at: Set(Some(Utc::now())),
            ..Default::default()
        };

        let ret = active_model
            .update(&self.db)
            .await
            .map_err(|e| DatabaseError::Database(e.to_string()))?;

        Ok(ret)
    }

    /// Clean up expired or revoked API keys
    pub async fn cleanup_expired(&self) -> DatabaseResult<u64> {
        let now = Utc::now();
        let result = api_keys::Entity::delete_many()
            .filter(
                Condition::any()
                    .add(api_keys::Column::ExpiresAt.lt(now))
                    .add(api_keys::Column::RevokedAt.is_not_null()),
            )
            .exec(&self.db)
            .await
            .map_err(|e| DatabaseError::Database(e.to_string()))?;

        Ok(result.rows_affected)
    }
}
