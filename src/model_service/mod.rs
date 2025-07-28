use crate::aws::bedrock::{BedrockRuntime, BedrockResponse};
use crate::{
    aws::bedrock::BedrockStreamResponse, config::Config, cost_tracking::CostTrackingService,
    database::DatabaseManager, error::AppError,
};
use async_trait::async_trait;
use axum::http::HeaderMap;
use bytes::Bytes;
use futures_util::StreamExt;
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};

// Trait for AWS client operations to enable mocking
#[async_trait]
pub trait AwsClientTrait: Send + Sync {
    async fn invoke_model(
        &self,
        model_id: &str,
        content_type: Option<&str>,
        accept: Option<&str>,
        body: Vec<u8>,
    ) -> Result<BedrockResponse, AppError>;

    async fn invoke_model_with_response_stream(
        &self,
        model_id: &str,
        headers: &HeaderMap,
        content_type: Option<&str>,
        accept: Option<&str>,
        body: Vec<u8>,
    ) -> Result<BedrockStreamResponse, AppError>;

    fn health_checker(&self) -> Arc<dyn crate::health::HealthChecker>;
}

// Implement the trait for the real AWS client
#[async_trait]
impl AwsClientTrait for BedrockRuntime {
    async fn invoke_model(
        &self,
        model_id: &str,
        content_type: Option<&str>,
        accept: Option<&str>,
        body: Vec<u8>,
    ) -> Result<BedrockResponse, AppError> {
        self.invoke_model(model_id, content_type, accept, body)
            .await
    }

    async fn invoke_model_with_response_stream(
        &self,
        model_id: &str,
        headers: &HeaderMap,
        content_type: Option<&str>,
        accept: Option<&str>,
        body: Vec<u8>,
    ) -> Result<BedrockStreamResponse, AppError> {
        self.invoke_model_with_response_stream(model_id, headers, content_type, accept, body)
            .await
    }

    fn health_checker(&self) -> Arc<dyn crate::health::HealthChecker> {
        Arc::new(BedrockRuntime::health_checker(self))
    }
}

use axum::http::StatusCode;
use chrono::Utc;
use std::{sync::Arc, time::Instant};

/// Unified model service for AWS calls and usage tracking
pub struct ModelService {
    aws_client: Box<dyn AwsClientTrait>,
    database: Arc<DatabaseManager>,
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

/// Usage information from AWS response body
#[derive(Debug, Deserialize, Serialize)]
struct ResponseUsage {
    pub input_tokens: u32,
    pub output_tokens: u32,
    pub cache_creation_input_tokens: Option<u32>,
    pub cache_read_input_tokens: Option<u32>,
}

/// Response wrapper for usage information
#[derive(Debug, Deserialize, Serialize)]
struct ResponseWithUsage {
    pub usage: ResponseUsage,
}

/// AWS Bedrock invocation metrics from streaming response
#[derive(Debug, Deserialize, Serialize)]
struct BedrockInvocationMetrics {
    #[serde(rename = "inputTokenCount")]
    pub input_token_count: u32,
    #[serde(rename = "outputTokenCount")]
    pub output_token_count: u32,
    #[serde(rename = "invocationLatency")]
    pub invocation_latency: u32,
    #[serde(rename = "firstByteLatency")]
    pub first_byte_latency: u32,
}

/// Streaming event from AWS Bedrock (message_stop event)
#[derive(Debug, Deserialize, Serialize)]
struct StreamingMessageStop {
    #[serde(rename = "type")]
    pub event_type: String,
    #[serde(rename = "amazon-bedrock-invocationMetrics")]
    pub invocation_metrics: Option<BedrockInvocationMetrics>,
}

/// Usage metadata extracted from AWS response
#[derive(Debug, Clone)]
pub struct UsageMetadata {
    pub input_tokens: u32,
    pub output_tokens: u32,
    pub cache_write_tokens: Option<u32>,
    pub cache_read_tokens: Option<u32>,
    pub region: String,
    pub response_time_ms: u32,
}

impl ModelService {
    pub fn new(database: Arc<DatabaseManager>, config: Config) -> Self {
        let aws_client = BedrockRuntime::new(config.aws.clone());
        Self {
            aws_client: Box::new(aws_client),
            database,
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
            CostTrackingService::new(self.database.clone(), self.config.aws.region.clone());

        // Check if we already have cost data
        let existing_costs = self.database.model_costs().get_all().await.map_err(|e| {
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
        let usage_metadata = self.extract_usage_metadata(
            &aws_response.headers,
            &aws_response.body,
            response_time_ms,
        )?;

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

        // 2. Collect streaming events to extract token usage from final message_stop event
        let (stream_body, usage_metadata) = self
            .collect_streaming_events(aws_response.stream, response_time_ms)
            .await?;

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

    /// Collect streaming events and extract token usage from the final message_stop event
    async fn collect_streaming_events(
        &self,
        mut stream: Box<
            dyn futures_util::Stream<Item = Result<Bytes, reqwest::Error>> + Send + Unpin,
        >,
        response_time_ms: u32,
    ) -> Result<(Vec<u8>, UsageMetadata), AppError> {
        let mut all_data = Vec::new();
        let mut input_tokens = 0;
        let mut output_tokens = 0;
        let mut cache_write_tokens = None;
        let mut cache_read_tokens = None;

        // Collect all streaming chunks
        while let Some(chunk) = stream.next().await {
            match chunk {
                Ok(bytes) => {
                    all_data.extend_from_slice(&bytes);

                    // Try to parse the chunk as a streaming event
                    if let Ok(chunk_str) = std::str::from_utf8(&bytes) {
                        // Look for message_stop event with amazon-bedrock-invocationMetrics
                        if chunk_str.contains("message_stop")
                            && chunk_str.contains("amazon-bedrock-invocationMetrics")
                        {
                            // Extract the JSON from the data: line
                            for line in chunk_str.lines() {
                                if let Some(json_str) = line.strip_prefix("data: ") {
                                    // Remove "data: " prefix
                                    if let Ok(stop_event) =
                                        serde_json::from_str::<StreamingMessageStop>(json_str)
                                    {
                                        if stop_event.event_type == "message_stop" {
                                            if let Some(metrics) = stop_event.invocation_metrics {
                                                input_tokens = metrics.input_token_count;
                                                output_tokens = metrics.output_token_count;
                                                // Note: AWS Bedrock streaming doesn't currently provide cache token info
                                                // in the invocation metrics, so we leave these as None
                                                tracing::info!(
                                                    "Extracted streaming tokens: input={}, output={}, latency={}ms",
                                                    input_tokens,
                                                    output_tokens,
                                                    metrics.invocation_latency
                                                );
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        // Also look for message_start event with cache tokens in the usage field
                        else if chunk_str.contains("message_start")
                            && chunk_str.contains("cache_creation_input_tokens")
                        {
                            // Extract the JSON from the data: line
                            for line in chunk_str.lines() {
                                if let Some(json_str) = line.strip_prefix("data: ") {
                                    // Remove "data: " prefix
                                    if let Ok(start_event) =
                                        serde_json::from_str::<serde_json::Value>(json_str)
                                    {
                                        if start_event["type"] == "message_start" {
                                            if let Some(usage) =
                                                start_event["message"]["usage"].as_object()
                                            {
                                                // Extract cache tokens from message_start event
                                                if let Some(cache_creation) =
                                                    usage["cache_creation_input_tokens"].as_u64()
                                                {
                                                    cache_write_tokens =
                                                        Some(cache_creation as u32);
                                                }
                                                if let Some(cache_read) =
                                                    usage["cache_read_input_tokens"].as_u64()
                                                {
                                                    cache_read_tokens = Some(cache_read as u32);
                                                }
                                                tracing::info!(
                                                    "Extracted cache tokens from message_start: write={:?}, read={:?}",
                                                    cache_write_tokens,
                                                    cache_read_tokens
                                                );
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!("Error reading streaming chunk: {}", e);
                    // Continue processing other chunks
                }
            }
        }

        // Create usage metadata
        let usage_metadata = UsageMetadata {
            input_tokens,
            output_tokens,
            cache_write_tokens,
            cache_read_tokens,
            region: self.config.aws.region.clone(),
            response_time_ms,
        };

        Ok((all_data, usage_metadata))
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
                usage_metadata.cache_write_tokens,
                usage_metadata.cache_read_tokens,
            )
            .await
            .map(|d| d.to_string().parse::<f64>().unwrap_or(0.0));

        let usage_record = crate::database::entities::usage_records::Model {
            id: 0, // Will be set by database
            user_id,
            model_id: request.model_id.clone(),
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

        // Store usage record
        self.database
            .usage()
            .store_record(&usage_record)
            .await
            .map_err(|e| AppError::Internal(format!("Failed to store usage record: {}", e)))?;

        Ok(())
    }

    /// Extract usage metadata from AWS response body and headers
    fn extract_usage_metadata(
        &self,
        headers: &HeaderMap,
        response_body: &[u8],
        response_time_ms: u32,
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
                .and_then(|s| s.parse::<u32>().ok())
                .unwrap_or(0);

            output_tokens = headers
                .get("x-amzn-bedrock-output-token-count")
                .and_then(|h| h.to_str().ok())
                .and_then(|s| s.parse::<u32>().ok())
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
    async fn calculate_cost(
        &self,
        model_id: &str,
        input_tokens: u32,
        output_tokens: u32,
        cache_write_tokens: Option<u32>,
        cache_read_tokens: Option<u32>,
    ) -> Option<Decimal> {
        match self.database.model_costs().find_by_model(model_id).await {
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
    pub fn database(&self) -> &Arc<DatabaseManager> {
        &self.database
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        Server,
        aws::config::AwsConfig,
        config::Config,
        database::{UsageQuery, entities::*},
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

    async fn create_test_server() -> (Server, Config) {
        let mut config = create_test_config();
        config.cache.backend = "memory".to_string();
        config.database.enabled = true;
        config.database.url = "sqlite::memory:".to_string();
        config.metrics.enabled = false;

        let server = Server::new(config.clone()).await.unwrap();

        // Run migrations to create tables
        server.database.migrate().await.unwrap();

        (server, config)
    }

    #[tokio::test]
    async fn test_model_service_creation() {
        let (server, config) = create_test_server().await;
        let database = server.database.clone();
        let model_service = ModelService::new(database.clone(), config);

        // Verify service was created successfully
        assert_eq!(model_service.config.aws.region, "us-east-1");
    }

    #[tokio::test]
    async fn test_extract_usage_metadata() {
        let (server, config) = create_test_server().await;
        let database = server.database.clone();
        let model_service = ModelService::new(database.clone(), config);

        let mut headers = HeaderMap::new();
        headers.insert("x-amzn-bedrock-input-token-count", "100".parse().unwrap());
        headers.insert("x-amzn-bedrock-output-token-count", "50".parse().unwrap());

        let response_body = b"{}"; // Empty JSON response body for test
        let metadata = model_service
            .extract_usage_metadata(&headers, response_body, 250)
            .unwrap();

        assert_eq!(metadata.input_tokens, 100);
        assert_eq!(metadata.output_tokens, 50);
        assert_eq!(metadata.cache_write_tokens, None);
        assert_eq!(metadata.cache_read_tokens, None);
        assert_eq!(metadata.response_time_ms, 250);
        assert_eq!(metadata.region, "us-east-1");
    }

    #[tokio::test]
    async fn test_extract_usage_metadata_from_response_body() {
        let (server, config) = create_test_server().await;
        let database = server.database.clone();
        let model_service = ModelService::new(database.clone(), config);

        // Test with JSON response body containing cache tokens
        let response_body = br#"{"id":"msg_bdrk_01QjKY4iZgTq69BYEKRD112G","type":"message","role":"assistant","model":"claude-opus-4-20250514","content":[{"type":"text","text":"Hello! It's nice to meet you. How are you doing today?"}],"stop_reason":"end_turn","stop_sequence":null,"usage":{"input_tokens":10,"cache_creation_input_tokens":5,"cache_read_input_tokens":3,"output_tokens":18}}"#;

        let headers = HeaderMap::new();
        let metadata = model_service
            .extract_usage_metadata(&headers, response_body, 250)
            .unwrap();

        assert_eq!(metadata.input_tokens, 10);
        assert_eq!(metadata.output_tokens, 18);
        assert_eq!(metadata.cache_write_tokens, Some(5));
        assert_eq!(metadata.cache_read_tokens, Some(3));
        assert_eq!(metadata.response_time_ms, 250);
        assert_eq!(metadata.region, "us-east-1");
    }

    #[tokio::test]
    async fn test_collect_streaming_events_with_real_data() {
        let (server, config) = create_test_server().await;
        let database = server.database.clone();
        let model_service = ModelService::new(database.clone(), config);

        // Create a test stream with real AWS Bedrock streaming data
        let test_events = vec![
            // message_start event
            Bytes::from(
                "data: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_bdrk_01Cvb6nyDr4qNiwfcJMF8njo\",\"type\":\"message\",\"role\":\"assistant\",\"model\":\"claude-sonnet-4-20250514\",\"content\":[],\"stop_reason\":null,\"stop_sequence\":null,\"usage\":{\"input_tokens\":17,\"cache_creation_input_tokens\":0,\"cache_read_input_tokens\":0,\"output_tokens\":3}}}\n\n",
            ),
            // content_block_start event
            Bytes::from(
                "data: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n",
            ),
            // content_block_delta event
            Bytes::from(
                "data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"Hello! Cache tokens are useful...\"}}\n\n",
            ),
            // content_block_stop event
            Bytes::from("data: {\"type\":\"content_block_stop\",\"index\":0}\n\n"),
            // message_delta event
            Bytes::from(
                "data: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\",\"stop_sequence\":null},\"usage\":{\"output_tokens\":322}}\n\n",
            ),
            // message_stop event with amazon-bedrock-invocationMetrics
            Bytes::from(
                "data: {\"type\":\"message_stop\",\"amazon-bedrock-invocationMetrics\":{\"inputTokenCount\":17,\"outputTokenCount\":322,\"invocationLatency\":7881,\"firstByteLatency\":1145}}\n\n",
            ),
        ];

        let stream =
            futures_util::stream::iter(test_events.into_iter().map(Ok::<_, reqwest::Error>));
        let boxed_stream = Box::new(stream);

        let (collected_data, usage_metadata) = model_service
            .collect_streaming_events(boxed_stream, 250)
            .await
            .unwrap();

        // Verify token extraction from amazon-bedrock-invocationMetrics
        assert_eq!(usage_metadata.input_tokens, 17);
        assert_eq!(usage_metadata.output_tokens, 322);
        assert_eq!(usage_metadata.cache_write_tokens, Some(0)); // From message_start event
        assert_eq!(usage_metadata.cache_read_tokens, Some(0)); // From message_start event
        assert_eq!(usage_metadata.response_time_ms, 250);
        assert_eq!(usage_metadata.region, "us-east-1");

        // Verify that all streaming data was collected
        assert!(!collected_data.is_empty());
        let collected_str = String::from_utf8_lossy(&collected_data);
        assert!(collected_str.contains("message_start"));
        assert!(collected_str.contains("message_stop"));
        assert!(collected_str.contains("amazon-bedrock-invocationMetrics"));
    }

    #[tokio::test]
    async fn test_calculate_cost() {
        let (server, config) = create_test_server().await;
        let database = server.database;
        let model_service = ModelService::new(database.clone(), config);

        // Add a model cost to storage
        let model_cost = StoredModelCost {
            id: 0,
            model_id: "test-model".to_string(),
            input_cost_per_1k_tokens: Decimal::new(3, 3), // 0.003 exactly
            output_cost_per_1k_tokens: Decimal::new(15, 3), // 0.015 exactly
            cache_write_cost_per_1k_tokens: Some(Decimal::new(375, 5)), // 0.00375 exactly
            cache_read_cost_per_1k_tokens: Some(Decimal::new(3, 4)), // 0.0003 exactly
            updated_at: Utc::now(),
        };
        database.model_costs().upsert(&model_cost).await.unwrap();

        // Calculate cost for 100 input tokens, 50 output tokens, no cache tokens
        let cost = model_service
            .calculate_cost("test-model", 100, 50, None, None)
            .await;

        assert!(cost.is_some());
        // Calculate expected cost: (0.003 * 100 / 1000) + (0.015 * 50 / 1000) = 0.00105
        let expected_cost = Decimal::new(105, 5); // 0.00105 exactly
        let actual_cost = cost.unwrap();
        // Use approximate comparison due to potential precision issues in calculations
        let diff = (actual_cost - expected_cost).abs();
        assert!(
            diff < Decimal::new(1, 7), // 0.0000001 tolerance
            "Expected cost {}, got {}, diff {}",
            expected_cost,
            actual_cost,
            diff
        );
    }

    #[tokio::test]
    async fn test_track_usage() {
        let (server, config) = create_test_server().await;
        let database = server.database.clone();
        let model_service = ModelService::new(database.clone(), config);

        // Create a test user first
        let user_record = UserRecord {
            id: 0,
            provider_user_id: "test-user".to_string(),
            provider: "google".to_string(),
            email: "test@example.com".to_string(),
            display_name: Some("Test User".to_string()),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            last_login: Some(Utc::now()),
        };
        let user_id = database.users().upsert(&user_record).await.unwrap();

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
            cache_write_tokens: None,
            cache_read_tokens: None,
            region: "us-east-1".to_string(),
            response_time_ms: 250,
        };

        // Track usage
        model_service
            .track_usage(&request, &usage_metadata)
            .await
            .unwrap();

        // Verify usage was recorded
        let records = database
            .usage()
            .get_records(&UsageQuery {
                user_id: Some(user_id),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].input_tokens, 100);
        assert_eq!(records[0].output_tokens, 50);
        assert_eq!(records[0].model_id, "test-model");
    }
}
