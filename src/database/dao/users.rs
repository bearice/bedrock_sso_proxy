use crate::database::entities::{UserRecord, users};
use crate::database::{DatabaseError, DatabaseResult};
use chrono::Utc;
use sea_orm::{
    ActiveModelTrait, ActiveValue, ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, Set,
};
use sea_orm_migration::sea_query::OnConflict;

/// Users DAO for database operations
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
        };

        let on_conflict = OnConflict::columns([users::Column::Provider, users::Column::ProviderUserId])
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

        Ok(result.last_insert_id)
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
    pub async fn update_last_login(&self, user_id: i32) -> DatabaseResult<()> {
        let user = users::Entity::find_by_id(user_id)
            .one(&self.db)
            .await
            .map_err(|e| DatabaseError::Database(e.to_string()))?
            .ok_or(DatabaseError::NotFound)?;

        let mut active_model = users::ActiveModel::from(user);
        active_model.last_login = Set(Some(Utc::now()));

        active_model
            .update(&self.db)
            .await
            .map_err(|e| DatabaseError::Database(e.to_string()))?;

        Ok(())
    }
}
