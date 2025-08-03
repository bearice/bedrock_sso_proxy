use crate::cache::object::typed_cache;

use async_graphql::{ComplexObject, Context, Result as GraphQLResult, SimpleObject};
use chrono::{DateTime, Utc};
use rust_decimal::Decimal;
use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize, ToSchema, SimpleObject)]
#[graphql(complex)]
#[graphql(name = "UsageRecord")]
#[sea_orm(table_name = "usage_records")]
#[typed_cache(ttl = 300)] // 5 minutes
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    pub user_id: i32,
    pub model_id: String,
    pub endpoint_type: String,
    pub region: String,
    pub request_time: DateTime<Utc>,
    pub input_tokens: i32,
    pub output_tokens: i32,
    pub cache_write_tokens: Option<i32>,
    pub cache_read_tokens: Option<i32>,
    pub total_tokens: i32,
    pub response_time_ms: i32,
    pub success: bool,
    pub error_message: Option<String>,
    pub cost_usd: Option<Decimal>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

#[ComplexObject]
impl Model {
    /// Get cost information - only accessible to the record owner or admins
    async fn secure_cost_usd(&self, ctx: &Context<'_>) -> GraphQLResult<Option<Decimal>> {
        if let Ok(user_context) = ctx.data::<crate::graphql::UserContext>() {
            if user_context.user_id == self.user_id || user_context.is_admin {
                return Ok(self.cost_usd);
            }
        }
        Ok(None)
    }

    /// Get error message - only accessible to the record owner or admins
    async fn secure_error_message(&self, ctx: &Context<'_>) -> GraphQLResult<Option<String>> {
        if let Ok(user_context) = ctx.data::<crate::graphql::UserContext>() {
            if user_context.user_id == self.user_id || user_context.is_admin {
                return Ok(self.error_message.clone());
            }
        }
        Ok(None)
    }
}
