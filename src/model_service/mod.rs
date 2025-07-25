pub mod aws_http;

use crate::{
    config::Config,
    cost_tracking::CostTrackingService,
    error::AppError,
    storage::{Storage, UsageRecord},
};
use rust_decimal::Decimal;
use aws_http::{AwsHttpClient, AwsResponse};
use axum::http::HeaderMap;
use async_trait::async_trait;

// Trait for AWS client operations to enable mocking
#[async_trait]
pub trait AwsClientTrait: Send + Sync {
    async fn invoke_model(
        &self,
        model_id: &str,
        content_type: Option<&str>,
        accept: Option<&str>,
        body: Vec<u8>,
    ) -> Result<AwsResponse, AppError>;

    async fn invoke_model_with_response_stream(
        &self,
        model_id: &str,
        headers: &HeaderMap,
        content_type: Option<&str>,
        accept: Option<&str>,
        body: Vec<u8>,
    ) -> Result<aws_http::AwsStreamResponse, AppError>;

    fn health_checker(&self) -> Arc<dyn crate::health::HealthChecker>;
}

// Implement the trait for the real AWS client
#[async_trait]
impl AwsClientTrait for AwsHttpClient {
    async fn invoke_model(
        &self,
        model_id: &str,
        content_type: Option<&str>,
        accept: Option<&str>,
        body: Vec<u8>,
    ) -> Result<AwsResponse, AppError> {
        self.invoke_model(model_id, content_type, accept, body).await
    }

    async fn invoke_model_with_response_stream(
        &self,
        model_id: &str,
        headers: &HeaderMap,
        content_type: Option<&str>,
        accept: Option<&str>,
        body: Vec<u8>,
    ) -> Result<aws_http::AwsStreamResponse, AppError> {
        self.invoke_model_with_response_stream(model_id, headers, content_type, accept, body).await
    }

    fn health_checker(&self) -> Arc<dyn crate::health::HealthChecker> {
        Arc::new(AwsHttpClient::health_checker(self))
    }
}

// Re-export AwsHttpClient for binaries (e2e client needs direct access)
pub use aws_http::AwsHttpClient as BinaryAwsHttpClient;
use axum::http::StatusCode;
use chrono::Utc;
use std::{sync::Arc, time::Instant};

/// Unified model service for AWS calls and usage tracking
pub struct ModelService {
    aws_client: Box<dyn AwsClientTrait>,
    storage: Arc<Storage>,
    config: Config,
}

/// Request structure for model invocation
#[derive(Debug, Clone)]
pub struct ModelRequest {
    pub model_id: String,
    pub body: Vec<u8>,
    pub headers: HeaderMap,
    pub user_id: i32,
    pub endpoint_type: String,
}

/// Response structure from model invocation
#[derive(Debug)]
pub struct ModelResponse {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: Vec<u8>,
    pub usage_metadata: Option<UsageMetadata>,
}

/// Usage metadata extracted from AWS response
#[derive(Debug, Clone)]
pub struct UsageMetadata {
    pub input_tokens: u32,
    pub output_tokens: u32,
    pub region: String,
    pub response_time_ms: u32,
}

impl ModelService {
    pub fn new(storage: Arc<Storage>, config: Config) -> Self {
        let aws_client = AwsHttpClient::new(config.aws.clone());
        Self {
            aws_client: Box::new(aws_client),
            storage,
            config,
        }
    }

    /// Create a ModelMapper from the current configuration
    pub fn create_model_mapper(&self) -> crate::anthropic::model_mapping::ModelMapper {
        self.config.create_model_mapper()
    }

    /// Initialize model costs in the background
    /// This should be called at startup to populate initial cost data
    pub async fn initialize_model_costs(&self) -> Result<(), AppError> {
        tracing::info!("Initializing model costs from fallback data");

        let cost_service =
            CostTrackingService::new(self.storage.clone(), self.config.aws.region.clone());

        // Check if we already have cost data
        let existing_costs = self
            .storage
            .database
            .get_all_model_costs()
            .await
            .map_err(|e| {
                AppError::Internal(format!("Failed to check existing model costs: {}", e))
            })?;

        if existing_costs.is_empty() {
            tracing::info!("No existing model costs found, populating with embedded fallback data");

            // Initialize with embedded data only (not AWS API during startup)
            match cost_service.initialize_model_costs_from_embedded().await {
                Ok(result) => {
                    tracing::info!(
                        "Successfully initialized {} model costs from embedded data ({} updated, {} failed)",
                        result.total_processed,
                        result.updated_models.len(),
                        result.failed_models.len()
                    );
                }
                Err(e) => {
                    tracing::warn!("Failed to initialize costs from embedded data: {}", e);
                    tracing::info!("Model costs will be populated on first usage or manual update");
                }
            }
        } else {
            tracing::info!(
                "Found {} existing model costs, skipping initialization",
                existing_costs.len()
            );
        }

        Ok(())
    }


    /// Non-streaming model invocation with automatic usage tracking
    pub async fn invoke_model(&self, request: ModelRequest) -> Result<ModelResponse, AppError> {
        let start_time = Instant::now();

        // 1. Make AWS API call
        let aws_response = self
            .aws_client
            .invoke_model(
                &request.model_id,
                request
                    .headers
                    .get("content-type")
                    .and_then(|h| h.to_str().ok()),
                request.headers.get("accept").and_then(|h| h.to_str().ok()),
                request.body.clone(),
            )
            .await?;

        let response_time_ms = start_time.elapsed().as_millis() as u32;

        // 2. Extract usage metadata from AWS response
        let usage_metadata =
            self.extract_usage_metadata(&aws_response.headers, response_time_ms)?;

        let response = ModelResponse {
            status: aws_response.status,
            headers: aws_response.headers.clone(),
            body: aws_response.body,
            usage_metadata: Some(usage_metadata.clone()),
        };

        // 3. Track usage automatically (internal call)
        if let Err(e) = self.track_usage(&request, &usage_metadata).await {
            tracing::warn!("Failed to track usage: {}", e);
        }

        Ok(response)
    }

    /// Streaming model invocation with automatic usage tracking
    pub async fn invoke_model_stream(
        &self,
        request: ModelRequest,
    ) -> Result<ModelResponse, AppError> {
        let start_time = Instant::now();

        // 1. Make AWS streaming API call
        let aws_response = self
            .aws_client
            .invoke_model_with_response_stream(
                &request.model_id,
                &request.headers,
                request
                    .headers
                    .get("content-type")
                    .and_then(|h| h.to_str().ok()),
                request.headers.get("accept").and_then(|h| h.to_str().ok()),
                request.body.clone(),
            )
            .await?;

        let response_time_ms = start_time.elapsed().as_millis() as u32;

        // 2. Extract usage metadata from AWS response headers
        let usage_metadata =
            self.extract_usage_metadata(&aws_response.headers, response_time_ms)?;

        // For streaming, we need to collect the stream into a body
        // This is a simplified implementation for usage tracking
        // In a real streaming scenario, we'd want to track usage as the stream completes
        let stream_body = Vec::new(); // Placeholder - would collect from stream

        let response = ModelResponse {
            status: aws_response.status,
            headers: aws_response.headers.clone(),
            body: stream_body,
            usage_metadata: Some(usage_metadata.clone()),
        };

        // 3. Track usage automatically (internal call)
        if let Err(e) = self.track_usage(&request, &usage_metadata).await {
            tracing::warn!("Failed to track usage in streaming call: {}", e);
        }

        Ok(response)
    }

    /// Private method - only called internally by invoke_* methods
    async fn track_usage(
        &self,
        request: &ModelRequest,
        usage_metadata: &UsageMetadata,
    ) -> Result<(), AppError> {
        let user_id = request.user_id;

        // Calculate cost if model pricing is available
        let cost_usd = self
            .calculate_cost(
                &request.model_id,
                usage_metadata.input_tokens,
                usage_metadata.output_tokens,
            )
            .await
            .map(|d| d.to_string().parse::<f64>().unwrap_or(0.0));

        let usage_record = UsageRecord {
            id: None,
            user_id,
            model_id: request.model_id.clone(),
            endpoint_type: request.endpoint_type.clone(),
            region: usage_metadata.region.clone(),
            request_time: Utc::now(),
            input_tokens: usage_metadata.input_tokens,
            output_tokens: usage_metadata.output_tokens,
            total_tokens: usage_metadata.input_tokens + usage_metadata.output_tokens,
            response_time_ms: usage_metadata.response_time_ms,
            success: true,
            error_message: None,
            cost_usd: cost_usd.map(|c| Decimal::from_f64_retain(c).unwrap_or_default()),
        };

        // Store usage record
        self.storage
            .database
            .store_usage_record(&usage_record)
            .await
            .map_err(|e| AppError::Internal(format!("Failed to store usage record: {}", e)))?;

        Ok(())
    }

    /// Extract usage metadata from AWS response headers
    fn extract_usage_metadata(
        &self,
        headers: &HeaderMap,
        response_time_ms: u32,
    ) -> Result<UsageMetadata, AppError> {
        // Try to extract token counts from AWS headers
        let input_tokens = headers
            .get("x-amzn-bedrock-input-token-count")
            .and_then(|h| h.to_str().ok())
            .and_then(|s| s.parse::<u32>().ok())
            .unwrap_or(0);

        let output_tokens = headers
            .get("x-amzn-bedrock-output-token-count")
            .and_then(|h| h.to_str().ok())
            .and_then(|s| s.parse::<u32>().ok())
            .unwrap_or(0);

        // Extract region from headers or use default
        let region = headers
            .get("x-amzn-requestid")
            .and_then(|h| h.to_str().ok())
            .and_then(|s| self.extract_region_from_request_id(s))
            .unwrap_or_else(|| self.config.aws.region.clone());

        Ok(UsageMetadata {
            input_tokens,
            output_tokens,
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
    async fn calculate_cost(
        &self,
        model_id: &str,
        input_tokens: u32,
        output_tokens: u32,
    ) -> Option<Decimal> {
        match self.storage.database.get_model_cost(model_id).await {
            Ok(Some(cost_data)) => {
                let input_cost = Decimal::from(input_tokens)
                    * cost_data.input_cost_per_1k_tokens
                    / Decimal::from(1000);
                let output_cost = Decimal::from(output_tokens)
                    * cost_data.output_cost_per_1k_tokens
                    / Decimal::from(1000);
                Some(input_cost + output_cost)
            }
            Ok(None) => {
                tracing::debug!("No cost data found for model: {}", model_id);
                None
            }
            Err(e) => {
                tracing::warn!("Failed to get model cost for {}: {}", model_id, e);
                None
            }
        }
    }

    /// Get the AWS client for direct access if needed (returns trait object)
    pub fn aws_client(&self) -> &dyn AwsClientTrait {
        self.aws_client.as_ref()
    }


    /// Get the storage layer for direct access if needed
    pub fn storage(&self) -> &Arc<Storage> {
        &self.storage
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::{AwsConfig, Config},
        storage::{Storage, database::SqliteStorage},
    };


    fn create_test_config() -> Config {
        Config {
            aws: AwsConfig {
                region: "us-east-1".to_string(),
                access_key_id: Some("test-key".to_string()),
                secret_access_key: Some("test-secret".to_string()),
                profile: None,
                bearer_token: None,
            },
            ..Default::default()
        }
    }

    async fn create_test_storage() -> Arc<Storage> {
        let sqlite_storage = SqliteStorage::new(":memory:").await.unwrap();
        sqlite_storage.migrate().await.unwrap();
        Arc::new(Storage::new(
            Box::new(crate::storage::memory::MemoryCacheStorage::new(3600)),
            Box::new(sqlite_storage),
        ))
    }

    #[tokio::test]
    async fn test_model_service_creation() {
        let config = create_test_config();
        let storage = create_test_storage().await;

        let model_service = ModelService::new(storage, config);

        // Verify service was created successfully
        assert_eq!(model_service.config.aws.region, "us-east-1");
    }

    #[tokio::test]
    async fn test_extract_usage_metadata() {
        let config = create_test_config();
        let storage = create_test_storage().await;
        let model_service = ModelService::new(storage, config);

        let mut headers = HeaderMap::new();
        headers.insert("x-amzn-bedrock-input-token-count", "100".parse().unwrap());
        headers.insert("x-amzn-bedrock-output-token-count", "50".parse().unwrap());

        let metadata = model_service.extract_usage_metadata(&headers, 250).unwrap();

        assert_eq!(metadata.input_tokens, 100);
        assert_eq!(metadata.output_tokens, 50);
        assert_eq!(metadata.response_time_ms, 250);
        assert_eq!(metadata.region, "us-east-1");
    }

    #[tokio::test]
    async fn test_calculate_cost() {
        let config = create_test_config();
        let storage = create_test_storage().await;
        let model_service = ModelService::new(storage.clone(), config);

        // Add a model cost to storage
        let model_cost = crate::storage::StoredModelCost {
            id: None,
            model_id: "test-model".to_string(),
            input_cost_per_1k_tokens: Decimal::new(3, 3), // 0.003 exactly
            output_cost_per_1k_tokens: Decimal::new(15, 3), // 0.015 exactly
            updated_at: Utc::now(),
        };
        storage
            .database
            .upsert_model_cost(&model_cost)
            .await
            .unwrap();

        // Calculate cost for 100 input tokens, 50 output tokens
        let cost = model_service.calculate_cost("test-model", 100, 50).await;

        assert!(cost.is_some());
        // Calculate expected cost: (0.003 * 100 / 1000) + (0.015 * 50 / 1000) = 0.00105
        let expected_cost = Decimal::new(105, 5); // 0.00105 exactly
        let actual_cost = cost.unwrap();
        // Use approximate comparison due to potential precision issues in calculations
        let diff = (actual_cost - expected_cost).abs();
        assert!(diff < Decimal::new(1, 7), // 0.0000001 tolerance
            "Expected cost {}, got {}, diff {}", expected_cost, actual_cost, diff);
    }

    #[tokio::test]
    async fn test_track_usage() {
        let config = create_test_config();
        let storage = create_test_storage().await;
        let model_service = ModelService::new(storage.clone(), config);

        // Create a test user first
        let user_record = crate::storage::UserRecord {
            id: None,
            provider_user_id: "test-user".to_string(),
            provider: "google".to_string(),
            email: "test@example.com".to_string(),
            display_name: Some("Test User".to_string()),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            last_login: Some(Utc::now()),
        };
        let user_id = storage.database.upsert_user(&user_record).await.unwrap();

        let request = ModelRequest {
            model_id: "test-model".to_string(),
            body: vec![],
            headers: HeaderMap::new(),
            user_id,
            endpoint_type: "bedrock".to_string(),
        };

        let usage_metadata = UsageMetadata {
            input_tokens: 100,
            output_tokens: 50,
            region: "us-east-1".to_string(),
            response_time_ms: 250,
        };

        // Track usage
        model_service
            .track_usage(&request, &usage_metadata)
            .await
            .unwrap();

        // Verify usage was recorded
        let records = storage
            .database
            .get_user_usage_records(user_id, 10, 0, None, None, None)
            .await
            .unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].input_tokens, 100);
        assert_eq!(records[0].output_tokens, 50);
        assert_eq!(records[0].model_id, "test-model");
    }
}
