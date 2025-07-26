use crate::database::entities::{RefreshTokenData, refresh_tokens};
use crate::database::{DatabaseError, DatabaseResult};
use chrono::Utc;
use sea_orm::{
    ActiveModelTrait, ActiveValue, ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, Set,
};

/// Refresh tokens DAO for database operations
pub struct RefreshTokensDao {
    db: DatabaseConnection,
}

impl RefreshTokensDao {
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }

    /// Store or update refresh token
    pub async fn store(&self, token: &RefreshTokenData) -> DatabaseResult<()> {
        // Try to find existing token
        let existing = refresh_tokens::Entity::find()
            .filter(refresh_tokens::Column::TokenHash.eq(&token.token_hash))
            .one(&self.db)
            .await
            .map_err(|e| DatabaseError::Database(e.to_string()))?;

        match existing {
            Some(existing_token) => {
                // Update existing token
                let mut active_model = refresh_tokens::ActiveModel::from(existing_token);
                active_model.user_id = Set(token.user_id.clone());
                active_model.provider = Set(token.provider.clone());
                active_model.email = Set(token.email.clone());
                active_model.expires_at = Set(token.expires_at);
                active_model.rotation_count = Set(token.rotation_count);
                active_model.revoked_at = Set(token.revoked_at);

                active_model
                    .update(&self.db)
                    .await
                    .map_err(|e| DatabaseError::Database(e.to_string()))?;
            }
            None => {
                // Insert new token
                let active_model = refresh_tokens::ActiveModel {
                    id: ActiveValue::NotSet,
                    token_hash: Set(token.token_hash.clone()),
                    user_id: Set(token.user_id.clone()),
                    provider: Set(token.provider.clone()),
                    email: Set(token.email.clone()),
                    created_at: Set(token.created_at),
                    expires_at: Set(token.expires_at),
                    rotation_count: Set(token.rotation_count),
                    revoked_at: Set(token.revoked_at),
                };

                active_model
                    .insert(&self.db)
                    .await
                    .map_err(|e| DatabaseError::Database(e.to_string()))?;
            }
        }

        Ok(())
    }

    /// Get refresh token by hash
    pub async fn find_by_hash(&self, token_hash: &str) -> DatabaseResult<Option<RefreshTokenData>> {
        let token = refresh_tokens::Entity::find()
            .filter(refresh_tokens::Column::TokenHash.eq(token_hash))
            .one(&self.db)
            .await
            .map_err(|e| DatabaseError::Database(e.to_string()))?;

        Ok(token)
    }

    /// Revoke refresh token
    pub async fn revoke(&self, token_hash: &str) -> DatabaseResult<()> {
        let token = refresh_tokens::Entity::find()
            .filter(refresh_tokens::Column::TokenHash.eq(token_hash))
            .one(&self.db)
            .await
            .map_err(|e| DatabaseError::Database(e.to_string()))?
            .ok_or(DatabaseError::NotFound)?;

        let mut active_model = refresh_tokens::ActiveModel::from(token);
        active_model.revoked_at = Set(Some(Utc::now()));

        active_model
            .update(&self.db)
            .await
            .map_err(|e| DatabaseError::Database(e.to_string()))?;

        Ok(())
    }

    /// Clean up expired tokens
    pub async fn cleanup_expired(&self) -> DatabaseResult<u64> {
        let now = Utc::now();
        let result = refresh_tokens::Entity::delete_many()
            .filter(refresh_tokens::Column::ExpiresAt.lt(now))
            .exec(&self.db)
            .await
            .map_err(|e| DatabaseError::Database(e.to_string()))?;

        Ok(result.rows_affected)
    }
}
