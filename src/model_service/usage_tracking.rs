use axum::http::HeaderMap;
use chrono::Utc;
use rust_decimal::Decimal;

use crate::{
    aws::model_id_mapping::RegionalModelMapping,
    config::Config,
    database::DatabaseManager,
    error::AppError,
    model_service::types::{ModelRequest, UsageMetadata},
};
use serde::{Deserialize, Serialize};

/// Usage tracking functionality for model service
pub struct UsageTrackingService {
    config: Config,
    database: std::sync::Arc<dyn DatabaseManager>,
    model_mapping: RegionalModelMapping,
}

impl UsageTrackingService {
    pub fn new(config: Config, database: std::sync::Arc<dyn DatabaseManager>) -> Self {
        Self {
            config,
            database,
            model_mapping: RegionalModelMapping::new(),
        }
    }

    /// Extract usage metadata from AWS response body and headers
    pub fn extract_usage_metadata(
        &self,
        headers: &HeaderMap,
        response_body: &[u8],
        response_time_ms: i32,
    ) -> Result<UsageMetadata, AppError> {
        // Try to parse usage information from response body first
        let mut input_tokens = 0;
        let mut output_tokens = 0;
        let mut cache_write_tokens = None;
        let mut cache_read_tokens = None;

        // Attempt to parse JSON response body for usage information
        if let Ok(body_str) = std::str::from_utf8(response_body) {
            if let Ok(response_with_usage) = serde_json::from_str::<ResponseWithUsage>(body_str) {
                input_tokens = response_with_usage.usage.input_tokens;
                output_tokens = response_with_usage.usage.output_tokens;
                cache_write_tokens = response_with_usage.usage.cache_creation_input_tokens;
                cache_read_tokens = response_with_usage.usage.cache_read_input_tokens;
            }
        }

        // Fallback to headers if response body parsing fails
        if input_tokens == 0 && output_tokens == 0 {
            input_tokens = headers
                .get("x-amzn-bedrock-input-token-count")
                .and_then(|h| h.to_str().ok())
                .and_then(|s| s.parse::<i32>().ok())
                .unwrap_or(0);

            output_tokens = headers
                .get("x-amzn-bedrock-output-token-count")
                .and_then(|h| h.to_str().ok())
                .and_then(|s| s.parse::<i32>().ok())
                .unwrap_or(0);
        }

        // Extract region from headers or use default
        let region = headers
            .get("x-amzn-requestid")
            .and_then(|h| h.to_str().ok())
            .and_then(|s| self.extract_region_from_request_id(s))
            .unwrap_or_else(|| self.config.aws.region.clone());

        Ok(UsageMetadata {
            input_tokens,
            output_tokens,
            cache_write_tokens,
            cache_read_tokens,
            region,
            response_time_ms,
        })
    }

    /// Extract region from AWS request ID (best effort)
    fn extract_region_from_request_id(&self, _request_id: &str) -> Option<String> {
        // AWS request IDs sometimes contain region info, but this is not guaranteed
        // This is a best-effort extraction - fallback to config region
        None
    }

    /// Calculate cost for the given model and token usage
    pub async fn calculate_cost(
        &self,
        region: &str,
        model_id: &str,
        input_tokens: i32,
        output_tokens: i32,
        cache_write_tokens: Option<i32>,
        cache_read_tokens: Option<i32>,
    ) -> Option<Decimal> {
        // Strip regional prefix from model ID for cost lookup
        let normalized_model_id = self.model_mapping.strip_regional_prefix(model_id);

        match self
            .database
            .model_costs()
            .find_by_region_and_model(region, &normalized_model_id)
            .await
        {
            Ok(Some(cost_data)) => {
                let input_cost = Decimal::from(input_tokens) * cost_data.input_cost_per_1k_tokens
                    / Decimal::from(1000);
                let output_cost = Decimal::from(output_tokens)
                    * cost_data.output_cost_per_1k_tokens
                    / Decimal::from(1000);

                // Calculate cache costs if available
                let cache_write_cost = if let (Some(tokens), Some(cost_per_1k)) =
                    (cache_write_tokens, cost_data.cache_write_cost_per_1k_tokens)
                {
                    Decimal::from(tokens) * cost_per_1k / Decimal::from(1000)
                } else {
                    Decimal::from(0)
                };

                let cache_read_cost = if let (Some(tokens), Some(cost_per_1k)) =
                    (cache_read_tokens, cost_data.cache_read_cost_per_1k_tokens)
                {
                    Decimal::from(tokens) * cost_per_1k / Decimal::from(1000)
                } else {
                    Decimal::from(0)
                };

                Some(input_cost + output_cost + cache_write_cost + cache_read_cost)
            }
            Ok(None) => {
                tracing::debug!(
                    "No cost data found for model: {} (normalized: {})",
                    model_id,
                    normalized_model_id
                );
                None
            }
            Err(e) => {
                tracing::warn!("Failed to get model cost for {}: {}", model_id, e);
                None
            }
        }
    }

    /// Track usage for a model request
    pub async fn track_usage(
        &self,
        request: &ModelRequest,
        usage_metadata: &UsageMetadata,
    ) -> Result<(), AppError> {
        let user_id = request.user_id;

        // Strip regional prefix from model ID for consistent storage and cost calculation
        let normalized_model_id = self.model_mapping.strip_regional_prefix(&request.model_id);

        tracing::debug!(
            "Tracking usage for user_id={} model={} input_tokens={} output_tokens={} request_id={}",
            user_id,
            normalized_model_id,
            usage_metadata.input_tokens,
            usage_metadata.output_tokens,
            request.request_id
        );

        // Calculate cost if model pricing is available
        let cost_usd = self
            .calculate_cost(
                &usage_metadata.region,
                &request.model_id, // Use original model_id for cost calculation
                usage_metadata.input_tokens,
                usage_metadata.output_tokens,
                usage_metadata.cache_write_tokens,
                usage_metadata.cache_read_tokens,
            )
            .await
            .map(|d| d.to_string().parse::<f64>().unwrap_or(0.0));

        let usage_record = crate::database::entities::usage_records::Model {
            id: 0, // Will be set by database
            user_id,
            model_id: normalized_model_id, // Store normalized model ID
            endpoint_type: request.endpoint_type.clone(),
            region: usage_metadata.region.clone(),
            request_time: Utc::now(),
            input_tokens: usage_metadata.input_tokens,
            output_tokens: usage_metadata.output_tokens,
            cache_write_tokens: usage_metadata.cache_write_tokens,
            cache_read_tokens: usage_metadata.cache_read_tokens,
            total_tokens: usage_metadata.input_tokens
                + usage_metadata.output_tokens
                + usage_metadata.cache_write_tokens.unwrap_or(0)
                + usage_metadata.cache_read_tokens.unwrap_or(0),
            response_time_ms: usage_metadata.response_time_ms,
            success: true,
            error_message: None,
            cost_usd: cost_usd.map(|c| Decimal::from_f64_retain(c).unwrap_or_default()),
        };

        // Get usage DAO once and reuse it
        let usage_dao = self.database.usage();

        // Store usage record
        usage_dao
            .store_record(&usage_record)
            .await
            .map_err(AppError::Database)?;

        // Update hourly summary
        usage_dao
            .update_hourly_summary(&usage_record)
            .await
            .map_err(AppError::Database)?;

        Ok(())
    }
}

/// Usage information from AWS response body
#[derive(Debug, Deserialize, Serialize)]
struct ResponseUsage {
    pub input_tokens: i32,
    pub output_tokens: i32,
    pub cache_creation_input_tokens: Option<i32>,
    pub cache_read_input_tokens: Option<i32>,
}

/// Response wrapper for usage information
#[derive(Debug, Deserialize, Serialize)]
struct ResponseWithUsage {
    pub usage: ResponseUsage,
}
