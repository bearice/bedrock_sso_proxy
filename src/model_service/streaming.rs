use base64::Engine;
use bytes::Bytes;
use futures_util::{Stream, StreamExt};
use std::collections::VecDeque;
use std::sync::Arc;

use crate::model_service::types::{SseEvent, UsageMetrics, UsageTracker};

/// AWS Event Stream parser for extracting usage information from binary stream data
#[derive(Debug, Default)]
pub struct EventStreamParser {
    buffer: Vec<u8>,
    pub usage_metrics: UsageMetrics,
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
    pending_events: VecDeque<SseEvent>,
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
            pending_events: VecDeque::new(),
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
            pending_events: VecDeque::new(),
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
        use crate::model_service::types::UsageMetadata;

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