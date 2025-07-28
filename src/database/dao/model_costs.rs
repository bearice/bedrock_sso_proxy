use crate::database::entities::{StoredModelCost, model_costs};
use crate::database::{DatabaseError, DatabaseResult};
use sea_orm::{ActiveValue, ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, Set};
use sea_orm_migration::sea_query::OnConflict;

/// Model costs DAO for database operations
pub struct ModelCostsDao {
    db: DatabaseConnection,
}

impl ModelCostsDao {
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }

    /// Get model cost by model ID
    pub async fn find_by_model(&self, model_id: &str) -> DatabaseResult<Option<StoredModelCost>> {
        let cost = model_costs::Entity::find()
            .filter(model_costs::Column::ModelId.eq(model_id))
            .one(&self.db)
            .await
            .map_err(|e| DatabaseError::Database(e.to_string()))?;

        Ok(cost)
    }

    /// Store or update model cost using native upsert
    pub async fn upsert_many(&self, costs: &[StoredModelCost]) -> DatabaseResult<()> {
        let active_models:Vec<_> = costs.iter().map(|cost| model_costs::ActiveModel {
            id: ActiveValue::NotSet,
            model_id: Set(cost.model_id.clone()),
            input_cost_per_1k_tokens: Set(cost.input_cost_per_1k_tokens),
            output_cost_per_1k_tokens: Set(cost.output_cost_per_1k_tokens),
            cache_write_cost_per_1k_tokens: Set(cost.cache_write_cost_per_1k_tokens),
            cache_read_cost_per_1k_tokens: Set(cost.cache_read_cost_per_1k_tokens),
            updated_at: Set(cost.updated_at),
        }).collect();

        let on_conflict = OnConflict::column(model_costs::Column::ModelId)
            .update_columns([
                model_costs::Column::InputCostPer1kTokens,
                model_costs::Column::OutputCostPer1kTokens,
                model_costs::Column::CacheWriteCostPer1kTokens,
                model_costs::Column::CacheReadCostPer1kTokens,
                model_costs::Column::UpdatedAt,
            ])
            .to_owned();

        model_costs::Entity::insert_many(active_models)
            .on_conflict(on_conflict)
            .exec(&self.db)
            .await
            .map_err(|e| DatabaseError::Database(e.to_string()))?;

        Ok(())
    }

    /// Get all model costs
    pub async fn get_all(&self) -> DatabaseResult<Vec<StoredModelCost>> {
        let costs = model_costs::Entity::find()
            .all(&self.db)
            .await
            .map_err(|e| DatabaseError::Database(e.to_string()))?;

        Ok(costs)
    }

    /// Delete model cost
    pub async fn delete(&self, model_id: &str) -> DatabaseResult<()> {
        model_costs::Entity::delete_many()
            .filter(model_costs::Column::ModelId.eq(model_id))
            .exec(&self.db)
            .await
            .map_err(|e| DatabaseError::Database(e.to_string()))?;

        Ok(())
    }
}
