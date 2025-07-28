mod parser;

use chrono::Utc;
pub use parser::*;

use crate::{database::{entities::StoredModelCost, DatabaseManager}, error::AppError};
use rust_decimal::{Decimal, prelude::ToPrimitive};
use std::sync::Arc;
use tracing::{info, debug};

/// Cached embedded pricing data parsed from CSV
pub static EMBEDDED_PRICING_CSV : &str = include_str!("../../bedrock_pricing.csv");

/// Cost tracking service for AWS Bedrock models
pub struct CostTrackingService {
    database: Arc<dyn DatabaseManager>,
}

impl CostTrackingService {
    pub fn new(database: Arc<dyn DatabaseManager>) -> Self {
        Self {
            database,
        }
    }
    /// Initialize model costs from embedded CSV data (only if database is empty)
    pub async fn initialize_model_costs_from_embedded(
        &self,
    ) -> Result<UpdateCostsResult, AppError> {
        info!("Initializing model costs from embedded CSV pricing data");

        // Just use the batch update method for initialization
        self.batch_update_from_csv_content(EMBEDDED_PRICING_CSV).await
    }

    /// Batch update costs from CSV content
    pub async fn batch_update_from_csv_content(
        &self,
        csv_content: &str,
    ) -> Result<UpdateCostsResult, AppError> {
        debug!("Starting batch cost update from provided CSV content");

        let mut result = UpdateCostsResult {
            total_processed: 0,
        };

        // Parse CSV content
        let all_pricing = parser::parse_csv_pricing_data(csv_content);

        result.total_processed = all_pricing.len();
        debug!(
            "Processing {} models for batch cost updates from CSV content",
            all_pricing.len()
        );

        let stored_cost:Vec<_> = all_pricing
            .iter()
            .map(|pricing| {
                // Create unique model identifier with region
                let model_key = format!("{}:{}", pricing.region, pricing.model_id);

                StoredModelCost {
                    id: 0, // Will be set by database
                    model_id: model_key.clone(),
                    input_cost_per_1k_tokens: Decimal::from_f64_retain(
                        pricing.input_price,
                    )
                    .unwrap_or_default(),
                    output_cost_per_1k_tokens: Decimal::from_f64_retain(
                        pricing.output_price,
                    )
                    .unwrap_or_default(),
                    cache_write_cost_per_1k_tokens: pricing
                        .cache_write_price
                        .map(|c| Decimal::from_f64_retain(c).unwrap_or_default()),
                    cache_read_cost_per_1k_tokens: pricing
                        .cache_read_price
                        .map(|c| Decimal::from_f64_retain(c).unwrap_or_default()),
                    updated_at: Utc::now(),
                }
            })
            .collect();

        self.database.model_costs().upsert_many(&stored_cost).await?;

        info!(
            "Batch cost update from CSV content completed: {} total",
            result.total_processed
        );

        Ok(result)
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

}

/// Result of updating model costs
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct UpdateCostsResult {
    pub total_processed: usize,
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
