use async_graphql::*;
use sea_orm::*;

use crate::database::entities::*;
use crate::graphql::context::{AdminGuard, UserContext};

pub struct QueryRoot;

#[Object]
impl QueryRoot {
    /// Get current user information
    async fn me(&self, ctx: &Context<'_>) -> Result<Option<UserRecord>> {
        let user_context = ctx.data::<UserContext>()?;
        let db = ctx.data::<DatabaseConnection>()?;

        let user = Users::find_by_id(user_context.user_id)
            .one(db)
            .await
            .map_err(|e| format!("Database error: {}", e))?;

        Ok(user)
    }

    /// Get user's API keys
    async fn my_api_keys(&self, ctx: &Context<'_>) -> Result<Vec<ApiKeyRecord>> {
        let user_context = ctx.data::<UserContext>()?;
        let db = ctx.data::<DatabaseConnection>()?;

        let api_keys = ApiKeys::find()
            .filter(api_keys::Column::UserId.eq(user_context.user_id))
            .filter(api_keys::Column::RevokedAt.is_null())
            .all(db)
            .await
            .map_err(|e| format!("Database error: {}", e))?;

        Ok(api_keys)
    }

    /// Get user's usage records
    async fn my_usage_records(
        &self,
        ctx: &Context<'_>,
        #[graphql(desc = "Limit number of records")] limit: Option<u64>,
        #[graphql(desc = "Offset for pagination")] offset: Option<u64>,
    ) -> Result<Vec<UsageRecord>> {
        let user_context = ctx.data::<UserContext>()?;
        let db = ctx.data::<DatabaseConnection>()?;

        let mut query = UsageRecords::find().filter(usage_records::Column::UserId.eq(user_context.user_id));

        if let Some(limit) = limit {
            query = query.limit(limit);
        }

        if let Some(offset) = offset {
            query = query.offset(offset);
        }

        let usage_records = query
            .order_by_desc(usage_records::Column::RequestTime)
            .all(db)
            .await
            .map_err(|e| format!("Database error: {}", e))?;

        Ok(usage_records)
    }

    /// Get model costs (public information)
    async fn model_costs(
        &self,
        ctx: &Context<'_>,
        #[graphql(desc = "Filter by region")] region: Option<String>,
        #[graphql(desc = "Filter by model ID")] model_id: Option<String>,
    ) -> Result<Vec<ModelCost>> {
        let db = ctx.data::<DatabaseConnection>()?;

        let mut query = ModelCosts::find();

        if let Some(region) = region {
            query = query.filter(model_costs::Column::Region.eq(region));
        }

        if let Some(model_id) = model_id {
            query = query.filter(model_costs::Column::ModelId.eq(model_id));
        }

        let costs = query
            .all(db)
            .await
            .map_err(|e| format!("Database error: {}", e))?;

        Ok(costs)
    }

    /// Get all users (admin only)
    #[graphql(guard = "AdminGuard")]
    async fn all_users(
        &self,
        ctx: &Context<'_>,
        #[graphql(desc = "Limit number of users")] limit: Option<u64>,
        #[graphql(desc = "Offset for pagination")] offset: Option<u64>,
    ) -> Result<Vec<UserRecord>> {
        let db = ctx.data::<DatabaseConnection>()?;

        let mut query = Users::find();

        if let Some(limit) = limit {
            query = query.limit(limit);
        }

        if let Some(offset) = offset {
            query = query.offset(offset);
        }

        let users = query
            .order_by_asc(users::Column::Email)
            .all(db)
            .await
            .map_err(|e| format!("Database error: {}", e))?;

        Ok(users)
    }

    /// Get all API keys (admin only)
    #[graphql(guard = "AdminGuard")]
    async fn all_api_keys(
        &self,
        ctx: &Context<'_>,
        #[graphql(desc = "Filter by user ID")] user_id: Option<i32>,
        #[graphql(desc = "Include revoked keys")] include_revoked: Option<bool>,
    ) -> Result<Vec<ApiKeyRecord>> {
        let db = ctx.data::<DatabaseConnection>()?;

        let mut query = ApiKeys::find();

        if let Some(user_id) = user_id {
            query = query.filter(api_keys::Column::UserId.eq(user_id));
        }

        if !include_revoked.unwrap_or(false) {
            query = query.filter(api_keys::Column::RevokedAt.is_null());
        }

        let api_keys = query
            .order_by_desc(api_keys::Column::CreatedAt)
            .all(db)
            .await
            .map_err(|e| format!("Database error: {}", e))?;

        Ok(api_keys)
    }

    /// Get usage statistics (admin only)
    #[graphql(guard = "AdminGuard")]
    async fn usage_statistics(
        &self,
        ctx: &Context<'_>,
        #[graphql(desc = "Filter by user ID")] user_id: Option<i32>,
        #[graphql(desc = "Filter by model ID")] model_id: Option<String>,
        #[graphql(desc = "Limit number of records")] limit: Option<u64>,
    ) -> Result<Vec<UsageRecord>> {
        let db = ctx.data::<DatabaseConnection>()?;

        let mut query = UsageRecords::find();

        if let Some(user_id) = user_id {
            query = query.filter(usage_records::Column::UserId.eq(user_id));
        }

        if let Some(model_id) = model_id {
            query = query.filter(usage_records::Column::ModelId.eq(model_id));
        }

        if let Some(limit) = limit {
            query = query.limit(limit);
        }

        let usage_records = query
            .order_by_desc(usage_records::Column::RequestTime)
            .all(db)
            .await
            .map_err(|e| format!("Database error: {}", e))?;

        Ok(usage_records)
    }
}