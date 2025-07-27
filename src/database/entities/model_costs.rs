use chrono::{DateTime, Utc};
use rust_decimal::Decimal;
use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq, Serialize, Deserialize)]
#[sea_orm(table_name = "model_costs")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    #[sea_orm(unique)]
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
