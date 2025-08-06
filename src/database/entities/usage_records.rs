use crate::cache::object::typed_cache;

use chrono::{DateTime, Utc};
use rust_decimal::Decimal;
use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize, ToSchema)]
#[sea_orm(table_name = "usage_records")]
#[typed_cache(ttl = 300)] // 5 minutes
#[schema(as = UsageRecord)]
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
    pub stop_reason: Option<String>,
    pub cost_usd: Option<Decimal>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
