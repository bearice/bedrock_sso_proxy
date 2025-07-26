use crate::database::entities::{StoredModelCost, model_costs};
use crate::database::{DatabaseError, DatabaseResult};
use sea_orm::{
    ActiveModelTrait, ActiveValue, ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, Set,
};

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

    /// Store or update model cost
    pub async fn upsert(&self, cost: &StoredModelCost) -> DatabaseResult<()> {
        let existing = model_costs::Entity::find()
            .filter(model_costs::Column::ModelId.eq(&cost.model_id))
            .one(&self.db)
            .await
            .map_err(|e| DatabaseError::Database(e.to_string()))?;

        match existing {
            Some(existing_cost) => {
                let mut active_model = model_costs::ActiveModel::from(existing_cost);
                active_model.input_cost_per_1k_tokens = Set(cost.input_cost_per_1k_tokens);
                active_model.output_cost_per_1k_tokens = Set(cost.output_cost_per_1k_tokens);
                active_model.updated_at = Set(cost.updated_at);

                active_model
                    .update(&self.db)
                    .await
                    .map_err(|e| DatabaseError::Database(e.to_string()))?;
            }
            None => {
                let active_model = model_costs::ActiveModel {
                    id: ActiveValue::NotSet,
                    model_id: Set(cost.model_id.clone()),
                    input_cost_per_1k_tokens: Set(cost.input_cost_per_1k_tokens),
                    output_cost_per_1k_tokens: Set(cost.output_cost_per_1k_tokens),
                    updated_at: Set(cost.updated_at),
                };

                active_model
                    .insert(&self.db)
                    .await
                    .map_err(|e| DatabaseError::Database(e.to_string()))?;
            }
        }

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
