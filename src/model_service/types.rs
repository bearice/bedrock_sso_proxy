use axum::http::{HeaderMap, StatusCode};
use futures_util::Stream;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::model_service::ModelService;

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

/// Extracted usage metrics from SSE events
#[derive(Debug, Default, Clone)]
pub struct UsageMetrics {
    pub input_tokens: u32,
    pub output_tokens: u32,
    pub cache_write_tokens: Option<u32>,
    pub cache_read_tokens: Option<u32>,
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


/// AWS Bedrock invocation metrics from streaming response
#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct BedrockInvocationMetrics {
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
pub(crate) struct StreamingMessageStop {
    #[serde(rename = "type")]
    pub event_type: String,
    #[serde(rename = "amazon-bedrock-invocationMetrics")]
    pub invocation_metrics: Option<BedrockInvocationMetrics>,
}