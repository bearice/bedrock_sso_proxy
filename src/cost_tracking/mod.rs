mod parser;

pub use parser::*;

use crate::{database::DatabaseManager, error::AppError};
use rust_decimal::{Decimal, prelude::ToPrimitive};
use std::sync::Arc;
use tracing::{info, warn};

/// Cost tracking service for AWS Bedrock models
pub struct CostTrackingService {
    database: Arc<DatabaseManager>,
    pricing_client: PricingClient,
}

impl CostTrackingService {
    pub fn new(database: Arc<DatabaseManager>, aws_region: String) -> Self {
        Self {
            database,
            pricing_client: PricingClient::new(aws_region),
        }
    }

    /// Batch update costs for all models from CSV data
    pub async fn batch_update_all_model_costs(&self) -> Result<UpdateCostsResult, AppError> {
        info!("Starting batch cost update for all models from CSV data");

        let mut result = UpdateCostsResult {
            updated_models: Vec::new(),
            failed_models: Vec::new(),
            total_processed: 0,
        };

        // Get all pricing data from CSV (all regions, all models)
        let all_pricing = PricingClient::get_batch_update_data()
            .await
            .map_err(|e| AppError::Internal(format!("Failed to get CSV pricing data: {}", e)))?;

        result.total_processed = all_pricing.len();
        info!(
            "Processing {} models for batch cost updates from CSV data",
            all_pricing.len()
        );

        for pricing in all_pricing {
            // Create unique model identifier with region
            let model_key = format!("{}:{}", pricing.region, pricing.model_id);

            let stored_cost = crate::database::entities::model_costs::Model {
                id: 0, // Will be set by database
                model_id: model_key.clone(),
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

            match self.database.model_costs().upsert(&stored_cost).await {
                Ok(()) => {
                    info!(
                        "Updated cost for {} (region: {}): input=${:.4}/1k, output=${:.4}/1k",
                        pricing.model_id,
                        pricing.region,
                        pricing.input_cost_per_1k_tokens,
                        pricing.output_cost_per_1k_tokens
                    );
                    result.updated_models.push(UpdatedModelCost {
                        model_id: model_key,
                        input_cost_per_1k_tokens: pricing.input_cost_per_1k_tokens,
                        output_cost_per_1k_tokens: pricing.output_cost_per_1k_tokens,
                        provider: pricing.provider.clone(),
                    });
                }
                Err(e) => {
                    warn!("Failed to store cost for {}: {}", model_key, e);
                    result.failed_models.push(FailedModelUpdate {
                        model_id: model_key,
                        error: e.to_string(),
                    });
                }
            }
        }

        info!(
            "Batch cost update completed: {} updated, {} failed, {} total",
            result.updated_models.len(),
            result.failed_models.len(),
            result.total_processed
        );

        Ok(result)
    }

    /// Initialize model costs from embedded CSV data (only if database is empty)
    pub async fn initialize_model_costs_from_embedded(
        &self,
    ) -> Result<UpdateCostsResult, AppError> {
        info!("Initializing model costs from embedded CSV pricing data");

        // Just use the batch update method for initialization
        self.batch_update_all_model_costs().await
    }

    /// Get cost summary for all models
    pub async fn get_cost_summary(&self) -> Result<CostSummary, AppError> {
        let all_costs = self
            .database
            .model_costs()
            .get_all()
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

    /// Get cost for a specific model in a specific region
    pub async fn get_model_cost(
        &self,
        model_id: &str,
        region: &str,
    ) -> Result<ModelPricing, AppError> {
        self.pricing_client
            .get_models_for_region(region)
            .await?
            .into_iter()
            .find(|m| m.model_id == model_id)
            .ok_or_else(|| {
                AppError::NotFound(format!("Model {} not found in region {}", model_id, region))
            })
    }

    /// Get all available regions
    pub fn get_available_regions() -> Vec<String> {
        PricingClient::get_available_regions()
    }

    /// Batch update costs from CSV content
    pub async fn batch_update_from_csv_content(&self, csv_content: &str) -> Result<UpdateCostsResult, AppError> {
        info!("Starting batch cost update from provided CSV content");

        let mut result = UpdateCostsResult {
            updated_models: Vec::new(),
            failed_models: Vec::new(),
            total_processed: 0,
        };

        // Parse CSV content
        let all_pricing = PricingClient::parse_csv_content(csv_content)?;

        result.total_processed = all_pricing.len();
        info!(
            "Processing {} models for batch cost updates from CSV content",
            all_pricing.len()
        );

        for pricing in all_pricing {
            // Create unique model identifier with region
            let model_key = format!("{}:{}", pricing.region, pricing.model_id);

            let stored_cost = crate::database::entities::model_costs::Model {
                id: 0, // Will be set by database
                model_id: model_key.clone(),
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

            match self.database.model_costs().upsert(&stored_cost).await {
                Ok(()) => {
                    info!(
                        "Updated cost for {} (region: {}): input=${:.4}/1k, output=${:.4}/1k",
                        pricing.model_id,
                        pricing.region,
                        pricing.input_cost_per_1k_tokens,
                        pricing.output_cost_per_1k_tokens
                    );
                    result.updated_models.push(UpdatedModelCost {
                        model_id: model_key,
                        input_cost_per_1k_tokens: pricing.input_cost_per_1k_tokens,
                        output_cost_per_1k_tokens: pricing.output_cost_per_1k_tokens,
                        provider: pricing.provider.clone(),
                    });
                }
                Err(e) => {
                    warn!("Failed to store cost for {}: {}", model_key, e);
                    result.failed_models.push(FailedModelUpdate {
                        model_id: model_key,
                        error: e.to_string(),
                    });
                }
            }
        }

        info!(
            "Batch cost update from CSV content completed: {} updated, {} failed, {} total",
            result.updated_models.len(),
            result.failed_models.len(),
            result.total_processed
        );

        Ok(result)
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
