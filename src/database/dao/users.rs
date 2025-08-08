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

        // If last_insert_id is 0, it means the record already existed and was updated
        // We need to find the existing record to get its ID
        if result.last_insert_id == 0 {
            let existing_user = users::Entity::find()
                .filter(users::Column::Provider.eq(&user.provider))
                .filter(users::Column::ProviderUserId.eq(&user.provider_user_id))
                .one(&self.db)
                .await
                .map_err(|e| DatabaseError::Database(e.to_string()))?
                .ok_or(DatabaseError::NotFound)?;

            Ok(existing_user.id)
        } else {
            Ok(result.last_insert_id)
        }
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
