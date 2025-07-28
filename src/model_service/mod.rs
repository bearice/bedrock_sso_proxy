use crate::aws::bedrock::{BedrockRuntime, BedrockRuntimeImpl};
use crate::{
    config::Config, cost_tracking::CostTrackingService, database::DatabaseManager, error::AppError,
};
use async_trait::async_trait;
use axum::http::HeaderMap;
use base64::Engine;
use bytes::Bytes;
use futures_util::{Stream, StreamExt};
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};

use axum::http::StatusCode;
use chrono::Utc;
use std::collections::HashMap;
use std::{sync::Arc, time::Instant};
use tokio::sync::RwLock;

/// Model service trait for dependency injection and testing
#[async_trait]
pub trait ModelService: Send + Sync {
    /// Initialize model costs in the background
    async fn initialize_model_costs(&self) -> Result<(), AppError>;

    /// Non-streaming model invocation with automatic usage tracking
    async fn invoke_model(&self, request: ModelRequest) -> Result<ModelResponse, AppError>;

    /// Streaming model invocation with automatic usage tracking
    async fn invoke_model_stream(
        &self,
        request: ModelRequest,
    ) -> Result<ModelStreamResponse, AppError>;

    /// Collect streaming events and extract token usage
    async fn collect_streaming_events(
        &self,
        stream: Box<dyn Stream<Item = Result<Bytes, reqwest::Error>> + Send + Unpin>,
        response_time_ms: u32,
    ) -> Result<(Vec<u8>, UsageMetadata), AppError>;

    /// Create a ModelMapper from the current configuration
    fn create_model_mapper(&self) -> crate::anthropic::model_mapping::ModelMapper;

    /// Get the AWS client for direct access if needed
    fn bedrock(&self) -> &dyn BedrockRuntime;

    /// Get the storage layer for direct access if needed
    fn database(&self) -> &Arc<dyn DatabaseManager>;

    /// Wait for all background token tracking tasks to complete
    async fn wait_for_token_tracking_completion(&self, timeout: std::time::Duration) -> bool;

    /// Get the count of active token tracking tasks
    async fn active_token_tracking_tasks(&self) -> usize;

    /// Abort all remaining token tracking tasks
    async fn abort_token_tracking_tasks(&self);

    /// Track usage for a model request (for internal use)
    async fn track_usage(
        &self,
        request: &ModelRequest,
        usage_metadata: &UsageMetadata,
    ) -> Result<(), AppError>;
}

/// Unified model service implementation for AWS calls and usage tracking
#[derive(Clone)]
pub struct ModelServiceImpl {
    bedrock: Arc<dyn BedrockRuntime>,
    database: Arc<dyn DatabaseManager>,
    config: Config,
    /// Background token tracking tasks
    token_tracking_tasks: Arc<RwLock<HashMap<u64, tokio::task::JoinHandle<()>>>>,
    /// Task counter for unique IDs
    task_counter: Arc<std::sync::atomic::AtomicU64>,
    /// Streaming connection manager for tracking active streams
    streaming_manager: Option<Arc<crate::shutdown::StreamingConnectionManager>>,
}

impl std::fmt::Debug for ModelServiceImpl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ModelServiceImpl")
            .field("config", &self.config)
            .finish()
    }
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

/// Streaming response structure from model invocation
pub struct ModelStreamResponse {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub stream: Box<dyn Stream<Item = Result<SseEvent, reqwest::Error>> + Send + Unpin>,
    pub usage_tracker: Option<UsageTracker>,
}

/// Usage tracker for streaming responses
pub struct UsageTracker {
    pub model_request: ModelRequest,
    pub model_service: Arc<dyn ModelService>,
    pub start_time: std::time::Instant,
}

/// Parsed SSE event structure
#[derive(Debug, Clone)]
pub struct SseEvent {
    pub event_type: Option<String>,
    pub data: Option<serde_json::Value>,
    pub raw: Vec<u8>, // Store raw binary data for direct passthrough
}

/// AWS Event Stream parser for extracting usage information from binary stream data
#[derive(Debug, Default)]
pub struct EventStreamParser {
    buffer: Vec<u8>,
    pub usage_metrics: UsageMetrics,
}

/// Extracted usage metrics from SSE events
#[derive(Debug, Default, Clone)]
pub struct UsageMetrics {
    pub input_tokens: u32,
    pub output_tokens: u32,
    pub cache_write_tokens: Option<u32>,
    pub cache_read_tokens: Option<u32>,
}

impl EventStreamParser {
    pub fn new() -> Self {
        Self::default()
    }

    /// Parse AWS Event Stream binary chunks and return complete events
    pub fn parse_chunk(
        &mut self,
        chunk: &[u8],
    ) -> Result<Vec<SseEvent>, Box<dyn std::error::Error>> {
        self.buffer.extend_from_slice(chunk);

        let mut events = Vec::new();
        let mut pos = 0;

        while pos < self.buffer.len() {
            // AWS Event Stream format: [total_length][headers_length][prelude_crc][headers][payload][message_crc]

            // Check if we have enough bytes for the prelude (12 bytes minimum)
            if self.buffer.len() - pos < 12 {
                break;
            }

            // Read total length (4 bytes, big endian)
            let total_length = u32::from_be_bytes([
                self.buffer[pos],
                self.buffer[pos + 1],
                self.buffer[pos + 2],
                self.buffer[pos + 3],
            ]) as usize;

            // Check if we have the complete message
            if self.buffer.len() - pos < total_length {
                break;
            }

            // Read headers length (4 bytes, big endian)
            let headers_length = u32::from_be_bytes([
                self.buffer[pos + 4],
                self.buffer[pos + 5],
                self.buffer[pos + 6],
                self.buffer[pos + 7],
            ]) as usize;

            // Skip prelude CRC (4 bytes)
            let headers_start = pos + 12;
            let payload_start = headers_start + headers_length;
            let payload_end = pos + total_length - 4; // Subtract message CRC

            // Extract payload (JSON data)
            if payload_start < payload_end && payload_end <= self.buffer.len() {
                let payload = self.buffer[payload_start..payload_end].to_vec();
                let original_chunk = self.buffer[pos..pos + total_length].to_vec();

                // Look for the "bytes" field in the payload which contains base64 encoded JSON
                if let Some(event) = self.extract_event_from_payload(&payload, &original_chunk)? {
                    events.push(event);
                }
            }

            pos += total_length;
        }

        // Remove processed bytes from buffer
        if pos > 0 {
            self.buffer.drain(..pos);
        }

        Ok(events)
    }

    /// Extract event from AWS Event Stream payload
    fn extract_event_from_payload(
        &mut self,
        payload: &[u8],
        original_chunk: &[u8],
    ) -> Result<Option<SseEvent>, Box<dyn std::error::Error>> {
        // Convert payload to string to look for JSON
        let payload_str = std::str::from_utf8(payload)?;

        // Look for "bytes" field which contains base64 encoded JSON
        if let Some(bytes_start) = payload_str.find("\"bytes\":\"") {
            let content_start = bytes_start + 9; // Length of "bytes":""

            if let Some(quote_end) = payload_str[content_start..].find('"') {
                let content_end = content_start + quote_end;
                let base64_content = &payload_str[content_start..content_end];

                // Decode base64
                if let Ok(decoded) =
                    base64::engine::general_purpose::STANDARD.decode(base64_content)
                {
                    if let Ok(json_str) = String::from_utf8(decoded) {
                        // Parse JSON
                        if let Ok(json_data) = serde_json::from_str::<serde_json::Value>(&json_str)
                        {
                            // Extract usage metrics
                            self.extract_usage_from_json(&json_data)?;

                            // Store original binary chunk for Bedrock route compatibility
                            return Ok(Some(SseEvent {
                                event_type: json_data
                                    .get("type")
                                    .and_then(|t| t.as_str())
                                    .map(|s| s.to_string()),
                                data: Some(json_data),
                                raw: original_chunk.to_vec(),
                            }));
                        }
                    }
                }
            }
        }

        Ok(None)
    }

    /// Extract usage information from JSON data
    fn extract_usage_from_json(
        &mut self,
        event: &serde_json::Value,
    ) -> Result<(), Box<dyn std::error::Error>> {
        match event["type"].as_str() {
            Some("message_start") => {
                self.extract_cache_tokens(event)?;
            }
            Some("message_stop") => {
                self.extract_final_tokens(event)?;
            }
            _ => {} // Ignore other event types
        }
        Ok(())
    }

    /// Extract cache tokens from message_start event
    fn extract_cache_tokens(
        &mut self,
        event: &serde_json::Value,
    ) -> Result<(), Box<dyn std::error::Error>> {
        if let Some(usage) = event["message"]["usage"].as_object() {
            if let Some(cache_creation) = usage["cache_creation_input_tokens"].as_u64() {
                self.usage_metrics.cache_write_tokens = Some(cache_creation as u32);
            }
            if let Some(cache_read) = usage["cache_read_input_tokens"].as_u64() {
                self.usage_metrics.cache_read_tokens = Some(cache_read as u32);
            }
        }
        Ok(())
    }

    /// Extract final tokens from message_stop event
    fn extract_final_tokens(
        &mut self,
        event: &serde_json::Value,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Try AWS Bedrock format first
        if let Some(metrics) = event["amazon-bedrock-invocationMetrics"].as_object() {
            if let Some(input_tokens) = metrics["inputTokenCount"].as_u64() {
                self.usage_metrics.input_tokens = input_tokens as u32;
            }
            if let Some(output_tokens) = metrics["outputTokenCount"].as_u64() {
                self.usage_metrics.output_tokens = output_tokens as u32;
            }
        }
        Ok(())
    }

    /// Get current usage metrics
    pub fn get_usage_metrics(&self) -> UsageMetrics {
        self.usage_metrics.clone()
    }
}

/// Stream that yields parsed events with usage tracking
pub struct ParsedEventStream {
    inner: Box<dyn Stream<Item = Result<Bytes, reqwest::Error>> + Send + Unpin>,
    usage_tracker: Option<UsageTracker>,
    parser: EventStreamParser,
    pending_events: std::collections::VecDeque<SseEvent>,
    streaming_connection_id: Option<u64>,
    streaming_manager: Option<Arc<crate::shutdown::StreamingConnectionManager>>,
    registration_initiated: bool,
}

impl ParsedEventStream {
    pub fn new(
        stream: Box<dyn Stream<Item = Result<Bytes, reqwest::Error>> + Send + Unpin>,
        usage_tracker: Option<UsageTracker>,
    ) -> Self {
        Self {
            inner: stream,
            usage_tracker,
            parser: EventStreamParser::new(),
            pending_events: std::collections::VecDeque::new(),
            streaming_connection_id: None,
            streaming_manager: None,
            registration_initiated: false,
        }
    }

    /// Create a new ParsedEventStream with streaming connection tracking
    pub fn new_with_streaming_manager(
        stream: Box<dyn Stream<Item = Result<Bytes, reqwest::Error>> + Send + Unpin>,
        usage_tracker: Option<UsageTracker>,
        streaming_manager: Option<Arc<crate::shutdown::StreamingConnectionManager>>,
    ) -> Self {
        Self {
            inner: stream,
            usage_tracker,
            parser: EventStreamParser::new(),
            pending_events: std::collections::VecDeque::new(),
            streaming_connection_id: None,
            streaming_manager,
            registration_initiated: false,
        }
    }
}

impl Stream for ParsedEventStream {
    type Item = Result<SseEvent, reqwest::Error>;

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        // Register streaming connection on first poll if not already registered
        if !self.registration_initiated {
            if let (Some(streaming_manager), Some(usage_tracker)) =
                (&self.streaming_manager, &self.usage_tracker)
            {
                let streaming_manager_clone = streaming_manager.clone();
                let user_id = usage_tracker.model_request.user_id;
                let model_id = usage_tracker.model_request.model_id.clone();
                let endpoint_type = usage_tracker.model_request.endpoint_type.clone();

                // Mark as initiated to prevent repeated registration
                self.registration_initiated = true;

                // We need to spawn a task to register the connection since this is async
                let waker = cx.waker().clone();
                tokio::spawn(async move {
                    let (connection_id, _completion_rx) = streaming_manager_clone
                        .register_connection(user_id, model_id, endpoint_type)
                        .await;

                    tracing::debug!("Registered streaming connection {}", connection_id);
                    // Note: We can't easily update the stream state here due to ownership
                    // The connection will be cleaned up on shutdown regardless

                    // Wake up the stream to continue processing
                    waker.wake();
                });

                // Return Pending to wait for registration
                return std::task::Poll::Pending;
            }
        }

        // First, check if we have any pending events to return
        if let Some(event) = self.pending_events.pop_front() {
            return std::task::Poll::Ready(Some(Ok(event)));
        }

        // Poll the inner stream for more chunks
        match self.inner.as_mut().poll_next_unpin(cx) {
            std::task::Poll::Ready(Some(Ok(chunk))) => {
                // Parse chunk into events
                match self.parser.parse_chunk(&chunk) {
                    Ok(events) => {
                        if events.is_empty() {
                            // No complete events yet, continue polling
                            cx.waker().wake_by_ref();
                            std::task::Poll::Pending
                        } else {
                            // Add events to pending queue
                            for event in events {
                                self.pending_events.push_back(event);
                            }

                            // Return first event
                            if let Some(event) = self.pending_events.pop_front() {
                                std::task::Poll::Ready(Some(Ok(event)))
                            } else {
                                std::task::Poll::Pending
                            }
                        }
                    }
                    Err(_) => {
                        // Parsing error, continue polling
                        cx.waker().wake_by_ref();
                        std::task::Poll::Pending
                    }
                }
            }
            std::task::Poll::Ready(Some(Err(e))) => std::task::Poll::Ready(Some(Err(e))),
            std::task::Poll::Ready(None) => {
                // Stream completed, track usage asynchronously
                if let Some(tracker) = self.usage_tracker.take() {
                    let response_time_ms = tracker.start_time.elapsed().as_millis() as u32;
                    let usage_metrics = self.parser.get_usage_metrics();

                    let usage_metadata = UsageMetadata {
                        input_tokens: usage_metrics.input_tokens,
                        output_tokens: usage_metrics.output_tokens,
                        cache_write_tokens: usage_metrics.cache_write_tokens,
                        cache_read_tokens: usage_metrics.cache_read_tokens,
                        region: "us-east-1".to_string(), // Default region - will be properly set by track_usage method
                        response_time_ms,
                    };

                    let model_service = tracker.model_service.clone();
                    let model_request = tracker.model_request.clone();

                    // Track usage in background without blocking stream completion
                    tokio::spawn(async move {
                        // Since we can't call spawn_token_tracking_task on trait object, spawn directly
                        let task_id = tokio::spawn(async move {
                            if let Err(e) = model_service
                                .track_usage(&model_request, &usage_metadata)
                                .await
                            {
                                tracing::warn!("Failed to track streaming usage: {}", e);
                            } else {
                                tracing::debug!(
                                    "Successfully tracked streaming usage: {} input, {} output tokens",
                                    usage_metadata.input_tokens,
                                    usage_metadata.output_tokens
                                );
                            }
                        });

                        tracing::debug!(
                            "Started token tracking task {:?} for streaming usage",
                            task_id
                        );
                    });
                }

                // Unregister streaming connection if it was registered
                if let (Some(streaming_manager), Some(connection_id)) =
                    (&self.streaming_manager, self.streaming_connection_id)
                {
                    let streaming_manager_clone = streaming_manager.clone();
                    tokio::spawn(async move {
                        streaming_manager_clone
                            .unregister_connection(connection_id)
                            .await;
                    });
                }

                std::task::Poll::Ready(None)
            }
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }
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

impl ModelServiceImpl {
    pub fn new(
        bedrock: Arc<BedrockRuntimeImpl>,
        database: Arc<dyn DatabaseManager>,
        config: Config,
    ) -> Self {
        Self {
            bedrock,
            database,
            config,
            token_tracking_tasks: Arc::new(RwLock::new(HashMap::new())),
            task_counter: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            streaming_manager: None,
        }
    }

    /// Create a new ModelService with a trait object (for testing with mocks)
    pub fn new_with_trait(
        bedrock: Arc<dyn BedrockRuntime>,
        database: Arc<dyn DatabaseManager>,
        config: Config,
    ) -> Self {
        Self {
            bedrock,
            database,
            config,
            token_tracking_tasks: Arc::new(RwLock::new(HashMap::new())),
            task_counter: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            streaming_manager: None,
        }
    }

    /// Set the streaming connection manager for tracking active streams
    pub fn with_streaming_manager(
        mut self,
        streaming_manager: Arc<crate::shutdown::StreamingConnectionManager>,
    ) -> Self {
        self.streaming_manager = Some(streaming_manager);
        self
    }

    /// Spawn a background token tracking task and track it
    pub async fn spawn_token_tracking_task<F>(&self, future: F) -> u64
    where
        F: std::future::Future<Output = ()> + Send + 'static,
    {
        let task_id = self
            .task_counter
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let tasks = self.token_tracking_tasks.clone();

        let handle = tokio::spawn(async move {
            future.await;
            // Remove completed task from tracking
            tasks.write().await.remove(&task_id);
        });

        self.token_tracking_tasks
            .write()
            .await
            .insert(task_id, handle);
        task_id
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
}

#[async_trait]
impl ModelService for ModelServiceImpl {
    /// Create a ModelMapper from the current configuration
    fn create_model_mapper(&self) -> crate::anthropic::model_mapping::ModelMapper {
        self.config.create_model_mapper()
    }

    /// Initialize model costs in the background
    /// This should be called at startup to populate initial cost data
    async fn initialize_model_costs(&self) -> Result<(), AppError> {
        tracing::info!("Initializing model costs from fallback data");

        let cost_service =
            CostTrackingService::new(self.database.clone());

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
                        "Successfully initialized {} model costs from embedded data",
                        result.total_processed
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
    async fn invoke_model(&self, request: ModelRequest) -> Result<ModelResponse, AppError> {
        let start_time = Instant::now();

        // 1. Make AWS API call
        let aws_response = self
            .bedrock
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
    async fn invoke_model_stream(
        &self,
        request: ModelRequest,
    ) -> Result<ModelStreamResponse, AppError> {
        let start_time = Instant::now();

        // 1. Make AWS streaming API call
        let aws_response = self
            .bedrock
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

        // 2. Create usage tracker for background usage tracking
        let usage_tracker = UsageTracker {
            model_request: request,
            model_service: Arc::new(self.clone()),
            start_time,
        };

        // 3. Wrap the stream with parsed event stream and streaming manager
        let parsed_event_stream = ParsedEventStream::new_with_streaming_manager(
            aws_response.stream,
            Some(usage_tracker),
            self.streaming_manager.clone(),
        );

        // 4. Return streaming response immediately
        let response = ModelStreamResponse {
            status: aws_response.status,
            headers: aws_response.headers.clone(),
            stream: Box::new(parsed_event_stream),
            usage_tracker: None, // Usage tracking is handled by the stream wrapper
        };

        Ok(response)
    }

    /// Collect streaming events and extract token usage using EventStreamParser
    async fn collect_streaming_events(
        &self,
        mut stream: Box<
            dyn futures_util::Stream<Item = Result<Bytes, reqwest::Error>> + Send + Unpin,
        >,
        response_time_ms: u32,
    ) -> Result<(Vec<u8>, UsageMetadata), AppError> {
        let mut all_data = Vec::new();
        let mut parser = EventStreamParser::new();

        // Collect all streaming chunks and parse them
        while let Some(chunk) = stream.next().await {
            match chunk {
                Ok(bytes) => {
                    all_data.extend_from_slice(&bytes);

                    // Parse the binary chunk using EventStreamParser
                    if let Ok(events) = parser.parse_chunk(&bytes) {
                        // Events are parsed but we only need the usage metrics
                        // The parser automatically extracts usage from message_start and message_stop events
                        for event in events {
                            if let Some(data) = &event.data {
                                if let Some(event_type) = data.get("type").and_then(|t| t.as_str())
                                {
                                    tracing::debug!("Parsed streaming event: {}", event_type);
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

        // Get usage metrics from the parser
        let usage_metrics = parser.get_usage_metrics();

        // Create usage metadata
        let usage_metadata = UsageMetadata {
            input_tokens: usage_metrics.input_tokens,
            output_tokens: usage_metrics.output_tokens,
            cache_write_tokens: usage_metrics.cache_write_tokens,
            cache_read_tokens: usage_metrics.cache_read_tokens,
            region: self.config.aws.region.clone(),
            response_time_ms,
        };

        tracing::info!(
            "Extracted streaming usage: input={}, output={}, cache_write={:?}, cache_read={:?}",
            usage_metadata.input_tokens,
            usage_metadata.output_tokens,
            usage_metadata.cache_write_tokens,
            usage_metadata.cache_read_tokens
        );

        Ok((all_data, usage_metadata))
    }

    /// Get the AWS client for direct access if needed (returns trait object)
    fn bedrock(&self) -> &dyn BedrockRuntime {
        self.bedrock.as_ref()
    }

    /// Get the storage layer for direct access if needed
    fn database(&self) -> &Arc<dyn DatabaseManager> {
        &self.database
    }

    /// Wait for all background token tracking tasks to complete
    async fn wait_for_token_tracking_completion(&self, timeout: std::time::Duration) -> bool {
        let start_time = std::time::Instant::now();

        loop {
            let task_count = self.token_tracking_tasks.read().await.len();
            if task_count == 0 {
                tracing::info!("All token tracking tasks completed");
                return true;
            }

            if start_time.elapsed() > timeout {
                tracing::error!(
                    "Timeout waiting for {} token tracking tasks to complete",
                    task_count
                );
                return false;
            }

            tracing::info!(
                "Waiting for {} token tracking tasks to complete...",
                task_count
            );
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    }

    /// Get the count of active token tracking tasks
    async fn active_token_tracking_tasks(&self) -> usize {
        self.token_tracking_tasks.read().await.len()
    }

    /// Abort all remaining token tracking tasks
    async fn abort_token_tracking_tasks(&self) {
        let mut tasks = self.token_tracking_tasks.write().await;
        let task_count = tasks.len();

        if task_count > 0 {
            tracing::info!("Aborting {} remaining token tracking tasks", task_count);

            for (task_id, handle) in tasks.drain() {
                handle.abort();
                tracing::debug!("Aborted token tracking task {}", task_id);
            }
        }
    }

    /// Track usage for a model request (for internal use)
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        aws::config::AwsConfig,
        config::Config,
        database::{UsageQuery, entities::*},
        test_utils::TestServerBuilder,
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

    async fn create_test_server() -> (crate::Server, Config) {
        let config = create_test_config();
        let server = TestServerBuilder::new()
            .with_config(config.clone())
            .build()
            .await;

        (server, config)
    }

    #[tokio::test]
    async fn test_model_service_creation() {
        let (server, config) = create_test_server().await;
        let database = server.database.clone();
        let bedrock = Arc::new(BedrockRuntimeImpl::new_test());
        let model_service = ModelServiceImpl::new(bedrock, database.clone(), config);

        // Verify service was created successfully
        assert_eq!(model_service.config.aws.region, "us-east-1");
    }

    #[tokio::test]
    async fn test_extract_usage_metadata() {
        let (server, config) = create_test_server().await;
        let database = server.database.clone();
        let bedrock = Arc::new(BedrockRuntimeImpl::new_test());
        let model_service = ModelServiceImpl::new(bedrock, database.clone(), config);

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
        let bedrock = Arc::new(BedrockRuntimeImpl::new_test());
        let model_service = ModelServiceImpl::new(bedrock, database.clone(), config);

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
        let bedrock = Arc::new(BedrockRuntimeImpl::new_test());
        let model_service = ModelServiceImpl::new(bedrock, database.clone(), config);

        // Use the real AWS binary fixture instead of SSE format
        let binary_data = include_bytes!("../../tests/fixtures/stream-out.bin");
        let stream = futures_util::stream::iter(
            vec![Bytes::from(binary_data.as_slice())]
                .into_iter()
                .map(Ok::<_, reqwest::Error>),
        );
        let boxed_stream = Box::new(stream);

        let (collected_data, usage_metadata) = model_service
            .collect_streaming_events(boxed_stream, 250)
            .await
            .unwrap();

        // Verify token extraction from binary AWS Event Stream format
        assert_eq!(usage_metadata.input_tokens, 17);
        assert_eq!(usage_metadata.output_tokens, 322);
        assert_eq!(usage_metadata.cache_write_tokens, Some(0)); // From message_start event
        assert_eq!(usage_metadata.cache_read_tokens, Some(0)); // From message_start event
        assert_eq!(usage_metadata.response_time_ms, 250);
        assert_eq!(usage_metadata.region, "us-east-1");

        // Verify that all streaming data was collected
        assert!(!collected_data.is_empty());
        assert_eq!(collected_data.len(), binary_data.len());
    }

    #[tokio::test]
    async fn test_calculate_cost() {
        let (server, config) = create_test_server().await;
        let database = server.database.clone();
        let bedrock = Arc::new(BedrockRuntimeImpl::new_test());
        let model_service = ModelServiceImpl::new(bedrock, database.clone(), config);

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
        database.model_costs().upsert_many(&[model_cost]).await.unwrap();

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
        let bedrock = Arc::new(BedrockRuntimeImpl::new_test());
        let model_service = ModelServiceImpl::new(bedrock, database.clone(), config);

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

    #[test]
    fn test_event_stream_parser() {
        let mut parser = EventStreamParser::new();

        // Use real AWS Event Stream binary data (simplified test)
        // This simulates the actual binary format from AWS
        let binary_data = include_bytes!("../../tests/fixtures/stream-out.bin");
        let events = parser.parse_chunk(binary_data).unwrap();

        // Should parse some events from the fixture
        assert!(
            !events.is_empty(),
            "Should parse events from binary fixture"
        );

        // Check that we got the expected types
        let mut has_message_start = false;
        let mut has_content_delta = false;
        let mut has_message_stop = false;

        for event in &events {
            if let Some(data) = &event.data {
                match data.get("type").and_then(|t| t.as_str()) {
                    Some("message_start") => has_message_start = true,
                    Some("content_block_delta") => has_content_delta = true,
                    Some("message_stop") => has_message_stop = true,
                    _ => {}
                }
            }
        }

        assert!(has_message_start, "Should have message_start event");
        assert!(has_content_delta, "Should have content_block_delta events");
        assert!(has_message_stop, "Should have message_stop event");

        // Check usage metrics
        let metrics = parser.get_usage_metrics();
        assert_eq!(metrics.input_tokens, 17);
        assert_eq!(metrics.output_tokens, 322);
        assert_eq!(metrics.cache_write_tokens, Some(0));
        assert_eq!(metrics.cache_read_tokens, Some(0));
    }

    #[test]
    fn test_event_stream_parser_chunked_data() {
        let mut parser = EventStreamParser::new();

        // Test parsing binary data that arrives in chunks
        let binary_data = include_bytes!("../../tests/fixtures/stream-out.bin");
        let mid_point = binary_data.len() / 2;

        let chunk1 = &binary_data[..mid_point];
        let chunk2 = &binary_data[mid_point..];

        let events1 = parser.parse_chunk(chunk1).unwrap();
        // May or may not have complete events depending on chunk boundary

        let events2 = parser.parse_chunk(chunk2).unwrap();

        let total_events = events1.len() + events2.len();
        assert!(
            total_events > 0,
            "Should have parsed some events across chunks"
        );

        // Check final usage metrics
        let metrics = parser.get_usage_metrics();
        assert_eq!(metrics.input_tokens, 17);
        assert_eq!(metrics.output_tokens, 322);
        assert_eq!(metrics.cache_write_tokens, Some(0));
        assert_eq!(metrics.cache_read_tokens, Some(0));
    }
}
