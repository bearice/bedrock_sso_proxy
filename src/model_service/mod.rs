use crate::aws::bedrock::{BedrockRuntime, BedrockRuntimeImpl};
use crate::{
    config::Config, database::DatabaseManager, error::AppError,
};
use async_trait::async_trait;
use bytes::Bytes;
use futures_util::{Stream, StreamExt};
use std::collections::HashMap;
use std::{sync::Arc, time::Instant};
use tokio::sync::RwLock;

pub mod streaming;
pub mod types;
pub mod usage;

#[cfg(test)]
mod tests;

pub use streaming::{EventStreamParser, ParsedEventStream};
pub use types::*;

/// Model service trait for dependency injection and testing
#[async_trait]
pub trait ModelService: Send + Sync {

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
        headers: &axum::http::HeaderMap,
        response_body: &[u8],
        response_time_ms: u32,
    ) -> Result<UsageMetadata, AppError> {
        let usage_tracker = usage::UsageTrackingService::new(self.config.clone(), self.database.clone());
        usage_tracker.extract_usage_metadata(headers, response_body, response_time_ms)
    }

}

#[async_trait]
impl ModelService for ModelServiceImpl {
    /// Create a ModelMapper from the current configuration
    fn create_model_mapper(&self) -> crate::anthropic::model_mapping::ModelMapper {
        self.config.create_model_mapper()
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
        let parsed_event_stream = streaming::ParsedEventStream::new_with_streaming_manager(
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
        let mut parser = streaming::EventStreamParser::new();

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
        let usage_tracker = usage::UsageTrackingService::new(self.config.clone(), self.database.clone());
        usage_tracker.track_usage(request, usage_metadata).await
    }
}
