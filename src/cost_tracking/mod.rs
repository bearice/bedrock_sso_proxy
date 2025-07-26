mod aws_pricing;

pub use aws_pricing::*;

use crate::{error::AppError, storage::Storage};
use rust_decimal::{Decimal, prelude::ToPrimitive};
use std::sync::Arc;
use tracing::{info, warn};

/// Cost tracking service for AWS Bedrock models
pub struct CostTrackingService {
    storage: Arc<Storage>,
    pricing_client: PricingClient,
}

impl CostTrackingService {
    pub fn new(storage: Arc<Storage>, aws_region: String) -> Self {
        Self {
            storage,
            pricing_client: PricingClient::new(aws_region),
        }
    }

    /// Update costs for all models from AWS API (no fallback - fails if API unavailable)
    pub async fn update_all_model_costs(&self) -> Result<UpdateCostsResult, AppError> {
        info!("Starting cost update for all models from AWS API");

        let mut result = UpdateCostsResult {
            updated_models: Vec::new(),
            failed_models: Vec::new(),
            total_processed: 0,
        };

        // Get all live pricing data from AWS API (fails if API unavailable)
        let all_live_pricing = self
            .pricing_client
            .fetch_all_models_from_aws()
            .await
            .map_err(|e| {
                AppError::Internal(format!("Failed to fetch live pricing from AWS API: {}", e))
            })?;

        result.total_processed = all_live_pricing.len();
        info!(
            "Processing {} models for cost updates from AWS API",
            all_live_pricing.len()
        );

        for pricing in all_live_pricing {
            let stored_cost = crate::storage::StoredModelCost {
                id: None,
                model_id: pricing.model_id.clone(),
                input_cost_per_1k_tokens: Decimal::from_f64_retain(
                    pricing.input_cost_per_1k_tokens,
                )
                .unwrap_or_default(),
                output_cost_per_1k_tokens: Decimal::from_f64_retain(
                    pricing.output_cost_per_1k_tokens,
                )
                .unwrap_or_default(),
                updated_at: pricing.updated_at,
            };

            match self.storage.database.upsert_model_cost(&stored_cost).await {
                Ok(()) => {
                    info!(
                        "Updated cost for {} from AWS API: input=${:.4}/1k, output=${:.4}/1k",
                        pricing.model_id,
                        pricing.input_cost_per_1k_tokens,
                        pricing.output_cost_per_1k_tokens
                    );
                    result.updated_models.push(UpdatedModelCost {
                        model_id: pricing.model_id.clone(),
                        input_cost_per_1k_tokens: pricing.input_cost_per_1k_tokens,
                        output_cost_per_1k_tokens: pricing.output_cost_per_1k_tokens,
                        provider: pricing.provider.clone(),
                    });
                }
                Err(e) => {
                    warn!("Failed to store cost for {}: {}", pricing.model_id, e);
                    result.failed_models.push(FailedModelUpdate {
                        model_id: pricing.model_id.clone(),
                        error: e.to_string(),
                    });
                }
            }
        }

        info!(
            "Cost update completed: {} updated, {} failed, {} total",
            result.updated_models.len(),
            result.failed_models.len(),
            result.total_processed
        );

        Ok(result)
    }

    /// Initialize model costs from embedded data (only if database is empty)
    pub async fn initialize_model_costs_from_embedded(
        &self,
    ) -> Result<UpdateCostsResult, AppError> {
        info!("Initializing model costs from embedded pricing data");

        let mut result = UpdateCostsResult {
            updated_models: Vec::new(),
            failed_models: Vec::new(),
            total_processed: 0,
        };

        // Get all pricing data from embedded AWS pricing file
        let all_pricing = self
            .pricing_client
            .load_all_models_from_embedded()
            .await
            .map_err(|e| {
                AppError::Internal(format!("Failed to get embedded pricing data: {}", e))
            })?;

        result.total_processed = all_pricing.len();

        for pricing in all_pricing {
            let stored_cost = crate::storage::StoredModelCost {
                id: None,
                model_id: pricing.model_id.clone(),
                input_cost_per_1k_tokens: Decimal::from_f64_retain(
                    pricing.input_cost_per_1k_tokens,
                )
                .unwrap_or_default(),
                output_cost_per_1k_tokens: Decimal::from_f64_retain(
                    pricing.output_cost_per_1k_tokens,
                )
                .unwrap_or_default(),
                updated_at: chrono::Utc::now(),
            };

            // Store in database
            match self.storage.database.upsert_model_cost(&stored_cost).await {
                Ok(()) => {
                    info!(
                        "Initialized cost for {}: input=${:.4}/1k, output=${:.4}/1k",
                        pricing.model_id,
                        pricing.input_cost_per_1k_tokens,
                        pricing.output_cost_per_1k_tokens
                    );
                    result.updated_models.push(UpdatedModelCost {
                        model_id: pricing.model_id.clone(),
                        input_cost_per_1k_tokens: pricing.input_cost_per_1k_tokens,
                        output_cost_per_1k_tokens: pricing.output_cost_per_1k_tokens,
                        provider: pricing.provider.clone(),
                    });
                }
                Err(e) => {
                    warn!("Failed to initialize cost for {}: {}", pricing.model_id, e);
                    result.failed_models.push(FailedModelUpdate {
                        model_id: pricing.model_id.clone(),
                        error: e.to_string(),
                    });
                }
            }
        }

        info!(
            "Cost initialization completed: {} initialized, {} failed, {} total",
            result.updated_models.len(),
            result.failed_models.len(),
            result.total_processed
        );

        Ok(result)
    }

    /// Get cost summary for all models
    pub async fn get_cost_summary(&self) -> Result<CostSummary, AppError> {
        let all_costs = self
            .storage
            .database
            .get_all_model_costs()
            .await
            .map_err(|e| AppError::Internal(format!("Failed to get model costs: {}", e)))?;

        let mut summary = CostSummary {
            total_models: all_costs.len(),
            models: Vec::new(),
            last_updated: None,
        };

        for cost in all_costs {
            if summary.last_updated.is_none() || summary.last_updated < Some(cost.updated_at) {
                summary.last_updated = Some(cost.updated_at);
            }

            summary.models.push(ModelCostInfo {
                model_id: cost.model_id,
                input_cost_per_1k_tokens: cost.input_cost_per_1k_tokens.to_f64().unwrap_or(0.0),
                output_cost_per_1k_tokens: cost.output_cost_per_1k_tokens.to_f64().unwrap_or(0.0),
                updated_at: cost.updated_at,
            });
        }

        Ok(summary)
    }
}

/// Result of updating model costs
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct UpdateCostsResult {
    pub updated_models: Vec<UpdatedModelCost>,
    pub failed_models: Vec<FailedModelUpdate>,
    pub total_processed: usize,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct UpdatedModelCost {
    pub model_id: String,
    pub input_cost_per_1k_tokens: f64,
    pub output_cost_per_1k_tokens: f64,
    pub provider: String,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct FailedModelUpdate {
    pub model_id: String,
    pub error: String,
}

/// Cost summary for all models
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct CostSummary {
    pub total_models: usize,
    pub models: Vec<ModelCostInfo>,
    pub last_updated: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct ModelCostInfo {
    pub model_id: String,
    pub input_cost_per_1k_tokens: f64,
    pub output_cost_per_1k_tokens: f64,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}
