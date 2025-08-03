use crate::cache::object::typed_cache;

use async_graphql::SimpleObject;
use chrono::{DateTime, Utc};
use rust_decimal::Decimal;
use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq, Serialize, Deserialize, ToSchema, SimpleObject)]
#[graphql(name = "ModelCost")]
#[typed_cache(ttl = 3600)] // Cache for 1 hour since costs change infrequently
#[sea_orm(table_name = "model_costs")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    #[sea_orm(indexed)]
    pub region: String,
    #[sea_orm(indexed)]
    pub model_id: String,
    #[sea_orm(column_name = "input_cost_per_1k_tokens")]
    pub input_cost_per_1k_tokens: Decimal,
    #[sea_orm(column_name = "output_cost_per_1k_tokens")]
    pub output_cost_per_1k_tokens: Decimal,
    #[sea_orm(column_name = "cache_write_cost_per_1k_tokens")]
    pub cache_write_cost_per_1k_tokens: Option<Decimal>,
    #[sea_orm(column_name = "cache_read_cost_per_1k_tokens")]
    pub cache_read_cost_per_1k_tokens: Option<Decimal>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
