use crate::cache::object::typed_cache;

use async_graphql::{ComplexObject, Context, Result as GraphQLResult, SimpleObject};
use chrono::{DateTime, Utc};
use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq, Serialize, Deserialize, SimpleObject)]
#[graphql(complex)]
#[graphql(name = "User")]
#[sea_orm(table_name = "users")]
#[typed_cache(ttl = 900)] // 15 minutes
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    pub provider_user_id: String,
    pub provider: String,
    pub email: String,
    pub display_name: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub last_login: Option<DateTime<Utc>>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

#[ComplexObject]
impl Model {
    /// Get user's email - only accessible to the user themselves or admins
    async fn secure_email(&self, ctx: &Context<'_>) -> GraphQLResult<Option<String>> {
        if let Ok(user_context) = ctx.data::<crate::graphql::UserContext>() {
            // Users can only see their own email, or admins can see all
            if user_context.user_id == self.id || user_context.is_admin {
                return Ok(Some(self.email.clone()));
            }
        }
        Ok(None)
    }

    /// Get provider user ID - only accessible to the user themselves or admins
    async fn secure_provider_user_id(&self, ctx: &Context<'_>) -> GraphQLResult<Option<String>> {
        if let Ok(user_context) = ctx.data::<crate::graphql::UserContext>() {
            if user_context.user_id == self.id || user_context.is_admin {
                return Ok(Some(self.provider_user_id.clone()));
            }
        }
        Ok(None)
    }
}
