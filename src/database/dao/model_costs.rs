use crate::database::entities::{ModelCost, model_costs};
use crate::database::{DatabaseError, DatabaseResult};
use sea_orm::{
    ActiveValue, ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, Set, TransactionTrait,
};
use sea_orm_migration::sea_query::OnConflict;
use tracing::{debug, trace};

/// Model costs DAO for database operations
#[derive(Clone)]
pub struct ModelCostsDao {
    db: DatabaseConnection,
}

impl ModelCostsDao {
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }

    /// Get model cost by region and model ID
    pub async fn find_by_region_and_model(
        &self,
        region: &str,
        model_id: &str,
    ) -> DatabaseResult<Option<ModelCost>> {
        let cost = model_costs::Entity::find()
            .filter(model_costs::Column::Region.eq(region))
            .filter(model_costs::Column::ModelId.eq(model_id))
            .one(&self.db)
            .await
            .map_err(|e| DatabaseError::Database(e.to_string()))?;

        Ok(cost)
    }

    /// Store or update model cost using individual upserts for SQLite compatibility
    pub async fn upsert_many(&self, costs: &[ModelCost]) -> DatabaseResult<()> {
        debug!("Upserting {} model_costs", costs.len());
        let tx = self
            .db
            .begin()
            .await
            .map_err(|e| DatabaseError::Database(e.to_string()))?;
        let active_models: Vec<_> = costs
            .iter()
            .map(|cost| model_costs::ActiveModel {
                id: ActiveValue::NotSet,
                model_id: Set(cost.model_id.clone()),
                region: Set(cost.region.clone()),
                input_cost_per_1k_tokens: Set(cost.input_cost_per_1k_tokens),
                output_cost_per_1k_tokens: Set(cost.output_cost_per_1k_tokens),
                cache_write_cost_per_1k_tokens: Set(cost.cache_write_cost_per_1k_tokens),
                cache_read_cost_per_1k_tokens: Set(cost.cache_read_cost_per_1k_tokens),
                updated_at: Set(cost.updated_at),
            })
            .collect();

        let on_conflict =
            OnConflict::columns([model_costs::Column::Region, model_costs::Column::ModelId])
                .update_columns([
                    model_costs::Column::InputCostPer1kTokens,
                    model_costs::Column::OutputCostPer1kTokens,
                    model_costs::Column::CacheWriteCostPer1kTokens,
                    model_costs::Column::CacheReadCostPer1kTokens,
                    model_costs::Column::UpdatedAt,
                ])
                .to_owned();

        for model in active_models {
            trace!("Processing {:?}", model.model_id);
            model_costs::Entity::insert(model)
                .on_conflict(on_conflict.clone())
                .exec(&tx)
                .await
                .map_err(|e| DatabaseError::Database(e.to_string()))?;
        }
        tx.commit()
            .await
            .map_err(|e| DatabaseError::Database(e.to_string()))
    }

    /// Get all model costs
    pub async fn get_all(&self) -> DatabaseResult<Vec<ModelCost>> {
        let costs = model_costs::Entity::find()
            .all(&self.db)
            .await
            .map_err(|e| DatabaseError::Database(e.to_string()))?;

        Ok(costs)
    }

    /// Delete model cost by region and model ID
    pub async fn delete_by_region_and_model(
        &self,
        region: &str,
        model_id: &str,
    ) -> DatabaseResult<()> {
        model_costs::Entity::delete_many()
            .filter(model_costs::Column::Region.eq(region))
            .filter(model_costs::Column::ModelId.eq(model_id))
            .exec(&self.db)
            .await
            .map_err(|e| DatabaseError::Database(e.to_string()))?;

        Ok(())
    }
}
