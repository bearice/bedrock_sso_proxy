use crate::database::entities::{UserRecord, UserState, users};
use crate::database::{DatabaseError, DatabaseResult};
use chrono::Utc;
use sea_orm::{
    ActiveModelTrait, ActiveValue, ColumnTrait, DatabaseConnection, EntityTrait, PaginatorTrait,
    QueryFilter, Set,
};
use sea_orm_migration::sea_query::OnConflict;

/// Users DAO for database operations
#[derive(Clone)]
pub struct UsersDao {
    db: DatabaseConnection,
}

impl UsersDao {
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }

    /// Create or update user using native upsert
    pub async fn upsert(&self, user: &UserRecord) -> DatabaseResult<i32> {
        let active_model = users::ActiveModel {
            id: ActiveValue::NotSet, // Let database auto-assign ID
            provider_user_id: Set(user.provider_user_id.clone()),
            provider: Set(user.provider.clone()),
            email: Set(user.email.clone()),
            display_name: Set(user.display_name.clone()),
            created_at: Set(user.created_at),
            updated_at: Set(user.updated_at),
            last_login: Set(user.last_login),
            state: Set(user.state),
            last_oauth_check: Set(user.last_oauth_check),
            provider_refresh_token: Set(user.provider_refresh_token.clone()),
        };

        let on_conflict =
            OnConflict::columns([users::Column::Provider, users::Column::ProviderUserId])
                .update_columns([
                    users::Column::Email,
                    users::Column::DisplayName,
                    users::Column::UpdatedAt,
                    users::Column::LastLogin,
                ])
                .to_owned();

        let result = users::Entity::insert(active_model)
            .on_conflict(on_conflict)
            .exec(&self.db)
            .await
            .map_err(|e| DatabaseError::Database(e.to_string()))?;

        tracing::info!(
            provider = %user.provider,
            provider_user_id = %user.provider_user_id,
            last_insert_id = %result.last_insert_id,
            "Database upsert result"
        );

        // Always look up the user by provider/provider_user_id after upsert
        // This ensures we get the correct existing ID regardless of SQLite's last_insert_id behavior
        tracing::info!(
            provider = %user.provider,
            provider_user_id = %user.provider_user_id,
            "Upsert: Looking up user to get correct ID"
        );
        
        let existing_user = users::Entity::find()
            .filter(users::Column::Provider.eq(&user.provider))
            .filter(users::Column::ProviderUserId.eq(&user.provider_user_id))
            .one(&self.db)
            .await
            .map_err(|e| DatabaseError::Database(e.to_string()))?
            .ok_or(DatabaseError::NotFound)?;

        tracing::info!(
            provider = %user.provider,
            provider_user_id = %user.provider_user_id,
            final_user_id = %existing_user.id,
            last_insert_id = %result.last_insert_id,
            "Upsert: Final user ID determined"
        );

        Ok(existing_user.id)
    }

    /// Find user by provider and provider user ID
    pub async fn find_by_provider(
        &self,
        provider: &str,
        provider_user_id: &str,
    ) -> DatabaseResult<Option<UserRecord>> {
        let user = users::Entity::find()
            .filter(users::Column::Provider.eq(provider))
            .filter(users::Column::ProviderUserId.eq(provider_user_id))
            .one(&self.db)
            .await
            .map_err(|e| DatabaseError::Database(e.to_string()))?;

        Ok(user)
    }

    /// Find user by ID
    pub async fn find_by_id(&self, user_id: i32) -> DatabaseResult<Option<UserRecord>> {
        let user = users::Entity::find_by_id(user_id)
            .one(&self.db)
            .await
            .map_err(|e| DatabaseError::Database(e.to_string()))?;

        Ok(user)
    }

    /// Find user by email
    pub async fn find_by_email(&self, email: &str) -> DatabaseResult<Option<UserRecord>> {
        let user = users::Entity::find()
            .filter(users::Column::Email.eq(email))
            .one(&self.db)
            .await
            .map_err(|e| DatabaseError::Database(e.to_string()))?;

        Ok(user)
    }

    /// Update last login timestamp
    pub async fn update_last_login(&self, user: UserRecord) -> DatabaseResult<UserRecord> {
        let active_model = users::ActiveModel {
            id: Set(user.id),
            last_login: Set(Some(Utc::now())),
            ..Default::default()
        };

        let updated_user = active_model
            .update(&self.db)
            .await
            .map_err(|e| DatabaseError::Database(e.to_string()))?;

        Ok(updated_user)
    }

    /// Update user state
    pub async fn update_state(&self, user_id: i32, state: UserState) -> DatabaseResult<UserRecord> {
        let active_model = users::ActiveModel {
            id: Set(user_id),
            state: Set(state),
            updated_at: Set(Utc::now()),
            ..Default::default()
        };

        let updated_user = active_model
            .update(&self.db)
            .await
            .map_err(|e| DatabaseError::Database(e.to_string()))?;

        Ok(updated_user)
    }

    /// Find users by state
    pub async fn find_by_state(&self, state: UserState) -> DatabaseResult<Vec<UserRecord>> {
        let users = users::Entity::find()
            .filter(users::Column::State.eq(state))
            .all(&self.db)
            .await
            .map_err(|e| DatabaseError::Database(e.to_string()))?;

        Ok(users)
    }

    /// Count users by state
    pub async fn count_by_state(&self, state: UserState) -> DatabaseResult<u64> {
        let count = users::Entity::find()
            .filter(users::Column::State.eq(state))
            .count(&self.db)
            .await
            .map_err(|e| DatabaseError::Database(e.to_string()))?;

        Ok(count)
    }

    /// Check if user is active (not disabled or expired)
    pub async fn is_user_active(&self, user_id: i32) -> DatabaseResult<bool> {
        let user = self.find_by_id(user_id).await?;
        Ok(user.map(|u| u.state.is_active()).unwrap_or(false))
    }

    /// Get users count by state breakdown
    pub async fn get_user_state_counts(&self) -> DatabaseResult<(u64, u64, u64)> {
        let active_count = self.count_by_state(UserState::Active).await?;
        let disabled_count = self.count_by_state(UserState::Disabled).await?;
        let expired_count = self.count_by_state(UserState::Expired).await?;

        Ok((active_count, disabled_count, expired_count))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::entities::AuditEventType;
    use chrono::Utc;
    use sea_orm::{Database, DatabaseConnection};

    async fn create_test_db() -> DatabaseConnection {
        Database::connect("sqlite::memory:").await.unwrap()
    }

    #[tokio::test]
    async fn test_upsert_id_consistency_with_interference() {
        // This test specifically checks that upsert returns consistent IDs
        // even when other INSERT operations happen in between (the original bug)
        
        let db = create_test_db().await;
        
        // Run migrations to set up tables
        use crate::database::migration::Migrator;
        use sea_orm_migration::MigratorTrait;
        Migrator::up(&db, None).await.unwrap();
        
        let dao = UsersDao::new(db.clone());
        
        // Create a user
        let user = UserRecord::new("test_provider", "test_user_id", "test@example.com")
            .with_display_name(Some("Test User".to_string()));
        
        // First upsert - should create the user
        let user_id_1 = dao.upsert(&user).await.unwrap();
        
        // Insert several audit logs to mess with last_insert_id
        // This simulates what happens in the real OAuth flow
        for i in 0..5 {
            use crate::database::entities::audit_logs;
            
            let audit_entry = audit_logs::ActiveModel {
                id: sea_orm::ActiveValue::NotSet,
                user_id: sea_orm::ActiveValue::Set(Some(user_id_1)),
                event_type: sea_orm::ActiveValue::Set(AuditEventType::OAuthLogin),
                provider: sea_orm::ActiveValue::Set(Some("test_provider".to_string())),
                ip_address: sea_orm::ActiveValue::Set(Some("127.0.0.1".to_string())),
                user_agent: sea_orm::ActiveValue::Set(Some(format!("test-agent-{}", i))),
                success: sea_orm::ActiveValue::Set(true),
                error_message: sea_orm::ActiveValue::Set(None),
                created_at: sea_orm::ActiveValue::Set(Utc::now()),
                metadata: sea_orm::ActiveValue::Set(Some("{}".to_string())),
            };
            
            audit_logs::Entity::insert(audit_entry)
                .exec(&db)
                .await
                .unwrap();
        }
        
        // Second upsert - should return the SAME user ID despite all the audit log INSERTs
        let user_id_2 = dao.upsert(&user).await.unwrap();
        
        // Third upsert after more interference
        for i in 5..10 {
            use crate::database::entities::audit_logs;
            
            let audit_entry = audit_logs::ActiveModel {
                id: sea_orm::ActiveValue::NotSet,
                user_id: sea_orm::ActiveValue::Set(Some(user_id_1)),
                event_type: sea_orm::ActiveValue::Set(AuditEventType::TokenRefresh),
                provider: sea_orm::ActiveValue::Set(Some("test_provider".to_string())),
                ip_address: sea_orm::ActiveValue::Set(Some("127.0.0.1".to_string())),
                user_agent: sea_orm::ActiveValue::Set(Some(format!("interference-agent-{}", i))),
                success: sea_orm::ActiveValue::Set(true),
                error_message: sea_orm::ActiveValue::Set(None),
                created_at: sea_orm::ActiveValue::Set(Utc::now()),
                metadata: sea_orm::ActiveValue::Set(Some("{}".to_string())),
            };
            
            audit_logs::Entity::insert(audit_entry)
                .exec(&db)
                .await
                .unwrap();
        }
        
        let user_id_3 = dao.upsert(&user).await.unwrap();
        
        // This is the critical assertion that would have caught the original bug!
        assert_eq!(user_id_1, user_id_2, "User ID should be consistent on second upsert despite audit log interference");
        assert_eq!(user_id_2, user_id_3, "User ID should be consistent on third upsert despite more interference");
        
        println!("✅ Upsert ID consistency test passed: User ID {} remained stable across multiple operations", user_id_1);
    }

    #[tokio::test] 
    async fn test_multiple_users_different_ids() {
        let db = create_test_db().await;
        
        // Run migrations
        use crate::database::migration::Migrator;
        use sea_orm_migration::MigratorTrait;
        Migrator::up(&db, None).await.unwrap();
        
        let dao = UsersDao::new(db);
        
        // Create two different users
        let user1 = UserRecord::new("provider1", "user1", "user1@example.com");
        let user2 = UserRecord::new("provider2", "user2", "user2@example.com");
        
        let user1_id = dao.upsert(&user1).await.unwrap();
        let user2_id = dao.upsert(&user2).await.unwrap();
        
        // Different users should get different IDs
        assert_ne!(user1_id, user2_id, "Different users should get different IDs");
        
        // Same users should get same IDs on repeat upserts
        let user1_id_repeat = dao.upsert(&user1).await.unwrap();
        let user2_id_repeat = dao.upsert(&user2).await.unwrap();
        
        assert_eq!(user1_id, user1_id_repeat, "User 1 should get consistent ID");
        assert_eq!(user2_id, user2_id_repeat, "User 2 should get consistent ID");
    }
}
