use crate::aws::bedrock::{BedrockResponse, BedrockRuntime, BedrockStreamResponse};
use crate::aws::model_id_mapping::RegionalModelMapping;
use crate::error::AppError;
use crate::health::{HealthCheckResult, HealthChecker};
use async_trait::async_trait;
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use bytes::Bytes;
use futures_util::stream;
use std::sync::Arc;

/// Mock AWS Bedrock client for security testing
/// This client provides controlled responses to test proxy security logic
#[derive(Clone)]
pub struct MockBedrockRuntime {
    /// Controls the response behavior for different model IDs
    pub response_mode: MockResponseMode,
    /// Regional model mapping for testing prefix handling
    model_mapping: RegionalModelMapping,
}

#[derive(Clone, Debug)]
pub enum MockResponseMode {
    /// Always return success (200 OK) with test response
    AlwaysSuccess,
    /// Return different responses based on model ID patterns
    PatternBased,
    /// Return specific status code
    FixedStatus(StatusCode),
    /// Return error for security testing
    SecurityError,
}

impl MockBedrockRuntime {
    /// Create a new mock client with default success responses
    pub fn new() -> Self {
        Self {
            response_mode: MockResponseMode::AlwaysSuccess,
            model_mapping: RegionalModelMapping::new(),
        }
    }

    /// Create mock client that returns specific status
    pub fn with_status(status: StatusCode) -> Self {
        Self {
            response_mode: MockResponseMode::FixedStatus(status),
            model_mapping: RegionalModelMapping::new(),
        }
    }

    /// Create mock client for security testing
    pub fn for_security_tests() -> Self {
        Self {
            response_mode: MockResponseMode::PatternBased,
            model_mapping: RegionalModelMapping::new(),
        }
    }

    /// Generate mock response based on model ID and security patterns
    fn generate_response(&self, model_id: &str, body: &[u8]) -> BedrockResponse {
        let (status, response_body) = match &self.response_mode {
            MockResponseMode::AlwaysSuccess => (
                StatusCode::OK,
                br#"{"message": "Mock success response"}"#.to_vec(),
            ),
            MockResponseMode::FixedStatus(status) => {
                (*status, br#"{"error": "Mock error response"}"#.to_vec())
            }
            MockResponseMode::SecurityError => (
                StatusCode::BAD_REQUEST,
                br#"{"error": "Security validation failed"}"#.to_vec(),
            ),
            MockResponseMode::PatternBased => {
                // Analyze model ID for security patterns
                if self.is_malicious_model_id(model_id) {
                    // For security tests: malicious model IDs should be rejected by AWS
                    (
                        StatusCode::BAD_REQUEST,
                        br#"{"error": "Invalid model ID format"}"#.to_vec(),
                    )
                } else if self.is_malicious_body(body) {
                    // For security tests: malicious payloads should be rejected
                    (
                        StatusCode::BAD_REQUEST,
                        br#"{"error": "Invalid request format"}"#.to_vec(),
                    )
                } else {
                    // Normal requests succeed
                    (StatusCode::OK, br#"{"message": "Mock response", "content": [{"text": "Hello from mock AWS"}]}"#.to_vec())
                }
            }
        };

        let mut headers = HeaderMap::new();
        headers.insert("content-type", HeaderValue::from_static("application/json"));
        headers.insert(
            "x-amzn-requestid",
            HeaderValue::from_static("mock-request-id"),
        );

        BedrockResponse {
            status,
            headers,
            body: response_body,
        }
    }

    /// Check if model ID contains security attack patterns
    fn is_malicious_model_id(&self, model_id: &str) -> bool {
        let malicious_patterns = [
            "'; DROP TABLE",
            "'; SELECT",
            "1' OR '1'='1",
            "'=1",
            "';",
            "'--",
            " --",
            "../",
            "\\",
            "<script>",
            "javascript:",
            "%2e%2e%2f",
            "....//",
        ];

        for pattern in &malicious_patterns {
            if model_id.contains(pattern) {
                return true;
            }
        }
        false
    }

    /// Check if request body contains malicious patterns
    fn is_malicious_body(&self, body: &[u8]) -> bool {
        if let Ok(body_str) = std::str::from_utf8(body) {
            let malicious_patterns = [
                "<script>alert('xss')</script>",
                "javascript:alert('xss')",
                "<img src=x onerror=alert('xss')>",
            ];

            for pattern in &malicious_patterns {
                if body_str.contains(pattern) {
                    return true;
                }
            }
        }
        false
    }
}

impl Default for MockBedrockRuntime {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl BedrockRuntime for MockBedrockRuntime {
    async fn invoke_model(
        &self,
        model_id: &str,
        _content_type: Option<&str>,
        _accept: Option<&str>,
        body: Vec<u8>,
    ) -> Result<BedrockResponse, AppError> {
        // Simulate AWS processing time
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;

        Ok(self.generate_response(model_id, &body))
    }

    async fn invoke_model_with_response_stream(
        &self,
        model_id: &str,
        _headers: &HeaderMap,
        _content_type: Option<&str>,
        _accept: Option<&str>,
        body: Vec<u8>,
    ) -> Result<BedrockStreamResponse, AppError> {
        // Generate base response to determine status
        let base_response = self.generate_response(model_id, &body);

        if base_response.status != StatusCode::OK {
            // Return error response as stream
            let error_data = vec![Bytes::from(format!(
                "data: {{\"type\":\"error\",\"error\":{{\"message\":\"{}\"}}}}\n\n",
                String::from_utf8_lossy(&base_response.body)
            ))];
            let error_stream = stream::iter(error_data.into_iter().map(Ok::<_, reqwest::Error>));

            return Ok(BedrockStreamResponse {
                status: base_response.status,
                headers: base_response.headers,
                stream: Box::new(error_stream),
            });
        }

        // Success streaming response
        let mock_data = vec![
            Bytes::from("data: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_mock\"}}\n\n"),
            Bytes::from(
                "data: {\"type\":\"content_block_delta\",\"delta\":{\"text\":\"Mock AWS response\"}}\n\n",
            ),
            Bytes::from("data: {\"type\":\"message_stop\"}\n\n"),
        ];

        let mock_stream = stream::iter(mock_data.into_iter().map(Ok::<_, reqwest::Error>));
        let mut headers = HeaderMap::new();
        headers.insert(
            "content-type",
            HeaderValue::from_static("text/event-stream"),
        );

        Ok(BedrockStreamResponse {
            status: StatusCode::OK,
            headers,
            stream: Box::new(mock_stream),
        })
    }

    fn health_checker(&self) -> Arc<dyn HealthChecker> {
        Arc::new(MockHealthChecker)
    }

    fn model_mapping(&self) -> &RegionalModelMapping {
        &self.model_mapping
    }
}

/// Mock health checker for testing
pub struct MockHealthChecker;

#[async_trait]
impl HealthChecker for MockHealthChecker {
    fn name(&self) -> &str {
        "mock_aws_bedrock"
    }

    async fn check(&self) -> HealthCheckResult {
        HealthCheckResult::healthy_with_details(serde_json::json!({
            "service": "Mock AWS Bedrock",
            "region": "mock-region",
            "authentication": "mock"
        }))
    }

    fn info(&self) -> Option<serde_json::Value> {
        Some(serde_json::json!({
            "service": "Mock AWS Bedrock",
            "region": "mock-region",
            "endpoint": "mock://localhost"
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mock_client_creation() {
        let client = MockBedrockRuntime::new();
        matches!(client.response_mode, MockResponseMode::AlwaysSuccess);
    }

    #[test]
    fn test_mock_client_with_status() {
        let client = MockBedrockRuntime::with_status(StatusCode::FORBIDDEN);
        matches!(
            client.response_mode,
            MockResponseMode::FixedStatus(StatusCode::FORBIDDEN)
        );
    }

    #[test]
    fn test_malicious_model_id_detection() {
        let client = MockBedrockRuntime::for_security_tests();

        assert!(client.is_malicious_model_id("'; DROP TABLE users; --"));
        assert!(client.is_malicious_model_id("1' OR '1'='1"));
        assert!(client.is_malicious_model_id("../../../etc/passwd"));
        assert!(client.is_malicious_model_id("<script>alert('xss')</script>"));

        assert!(!client.is_malicious_model_id("anthropic.claude-v2"));
        assert!(!client.is_malicious_model_id("normal-model-id"));
    }

    #[test]
    fn test_malicious_body_detection() {
        let client = MockBedrockRuntime::for_security_tests();

        assert!(client.is_malicious_body(b"<script>alert('xss')</script>"));
        assert!(client.is_malicious_body(b"javascript:alert('xss')"));
        assert!(client.is_malicious_body(b"<img src=x onerror=alert('xss')>"));

        assert!(!client.is_malicious_body(b"{\"messages\": []}"));
        assert!(!client.is_malicious_body(b"normal request body"));
    }

    #[tokio::test]
    async fn test_mock_invoke_model_success() {
        let client = MockBedrockRuntime::new();

        let response = client
            .invoke_model(
                "anthropic.claude-v2",
                Some("application/json"),
                Some("application/json"),
                b"{\"messages\": []}".to_vec(),
            )
            .await
            .unwrap();

        assert_eq!(response.status, StatusCode::OK);
        assert!(!response.body.is_empty());
    }

    #[tokio::test]
    async fn test_mock_invoke_model_malicious_id() {
        let client = MockBedrockRuntime::for_security_tests();

        let response = client
            .invoke_model(
                "'; DROP TABLE users; --",
                Some("application/json"),
                Some("application/json"),
                b"{\"messages\": []}".to_vec(),
            )
            .await
            .unwrap();

        assert_eq!(response.status, StatusCode::BAD_REQUEST);
        assert!(String::from_utf8_lossy(&response.body).contains("Invalid model ID"));
    }

    #[tokio::test]
    async fn test_mock_invoke_model_malicious_body() {
        let client = MockBedrockRuntime::for_security_tests();

        let response = client
            .invoke_model(
                "anthropic.claude-v2",
                Some("application/json"),
                Some("application/json"),
                b"<script>alert('xss')</script>".to_vec(),
            )
            .await
            .unwrap();

        assert_eq!(response.status, StatusCode::BAD_REQUEST);
        assert!(String::from_utf8_lossy(&response.body).contains("Invalid request"));
    }

    #[tokio::test]
    async fn test_mock_streaming_success() {
        let client = MockBedrockRuntime::new();
        let headers = HeaderMap::new();

        let response = client
            .invoke_model_with_response_stream(
                "anthropic.claude-v2",
                &headers,
                Some("application/json"),
                Some("text/event-stream"),
                b"{\"messages\": []}".to_vec(),
            )
            .await
            .unwrap();

        assert_eq!(response.status, StatusCode::OK);
        assert_eq!(
            response.headers.get("content-type").unwrap(),
            "text/event-stream"
        );
    }

    #[tokio::test]
    async fn test_mock_streaming_error() {
        let client = MockBedrockRuntime::for_security_tests();
        let headers = HeaderMap::new();

        let response = client
            .invoke_model_with_response_stream(
                "'; DROP TABLE users; --",
                &headers,
                Some("application/json"),
                Some("text/event-stream"),
                b"{\"messages\": []}".to_vec(),
            )
            .await
            .unwrap();

        assert_eq!(response.status, StatusCode::BAD_REQUEST);
    }
}
