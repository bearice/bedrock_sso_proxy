use crate::aws::config::AwsConfig;
use crate::aws::model_id_mapping::RegionalModelMapping;
use crate::error::AppError;
use crate::health::{HealthCheckResult, HealthChecker};
use async_trait::async_trait;
use aws_config::SdkConfig;
use aws_credential_types::Credentials;
use aws_credential_types::provider::ProvideCredentials;
use aws_sigv4::http_request::{SignableBody, SignableRequest, SigningSettings, sign};
use aws_sigv4::sign::v4;
use aws_smithy_runtime_api::client::identity::Identity;
use axum::http::{HeaderMap, HeaderValue, Method, Request, StatusCode};
use bytes::Bytes;
use futures_util::Stream;
use reqwest::Client;
use std::sync::Arc;
use std::time::SystemTime;
use url::Url;

#[derive(Clone)]
pub struct BedrockRuntimeImpl {
    client: Client,
    config: AwsConfig,
    sdk_config: Option<SdkConfig>,
    base_url: String,
    model_mapping: RegionalModelMapping,
}

#[derive(Debug)]
pub struct BedrockRequest {
    pub method: String,
    pub url: String,
    pub headers: HeaderMap,
    pub body: Vec<u8>,
}

#[derive(Debug)]
pub struct BedrockResponse {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: Vec<u8>,
}

pub struct BedrockStreamResponse {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub stream: Box<dyn Stream<Item = Result<Bytes, reqwest::Error>> + Send + Unpin>,
}

impl BedrockRuntimeImpl {
    /// Create a new instance with AWS SDK config for credential chain support
    pub async fn new(config: AwsConfig) -> Result<Self, AppError> {
        let client = Client::new();
        let base_url = format!("https://bedrock-runtime.{}.amazonaws.com", config.region);
        let model_mapping =
            RegionalModelMapping::new_with_custom_mappings(config.get_region_prefix_mappings());

        let sdk_config = config
            .build_sdk_config()
            .await
            .map_err(|e| AppError::Internal(format!("Failed to build AWS SDK config: {}", e)))?;

        Ok(Self {
            client,
            config,
            sdk_config: Some(sdk_config),
            base_url,
            model_mapping,
        })
    }

    /// Create a test client for unit tests
    pub async fn new_test() -> Self {
        let config = AwsConfig {
            region: "us-east-1".to_string(),
            access_key_id: Some("test_key".to_string()),
            secret_access_key: Some("test_secret".to_string()),
            profile: None,
            bearer_token: None,
            region_prefix_mappings: std::collections::HashMap::new(),
        };
        Self::new(config).await.unwrap()
    }

    /// Get the regional model mapping for external access
    pub fn model_mapping(&self) -> &RegionalModelMapping {
        &self.model_mapping
    }

    /// Determine the target AWS region from the model ID
    /// If model ID has a regional prefix, use that region; otherwise use the configured region
    fn get_target_region(&self, model_id: &str) -> String {
        // Try to parse region from model ID prefix
        if let Some(region) = self.model_mapping.parse_region_from_model_id(model_id) {
            region
        } else {
            // Fall back to the configured region
            self.config.region.clone()
        }
    }

    /// Invoke a Bedrock model using direct HTTP calls
    pub async fn invoke_model(
        &self,
        model_id: &str,
        content_type: Option<&str>,
        accept: Option<&str>,
        body: Vec<u8>,
    ) -> Result<BedrockResponse, AppError> {
        tracing::trace!(
            model_id = %model_id,
            content_type = ?content_type,
            accept = ?accept,
            body_size = body.len(),
            "Starting model invocation"
        );

        // Add regional prefix to model ID if not already present
        let regionalized_model_id = self
            .model_mapping
            .add_regional_prefix(model_id, &self.config.region);

        // Determine the target region from the model ID
        let target_region = self.get_target_region(&regionalized_model_id);
        let base_url = format!("https://bedrock-runtime.{}.amazonaws.com", target_region);

        let path = format!("/model/{}/invoke", regionalized_model_id);
        let url = format!("{}{}", base_url, path);

        // Prepare headers
        let mut headers = HeaderMap::new();
        let host = format!("bedrock-runtime.{}.amazonaws.com", target_region);
        headers.insert("Host", HeaderValue::from_str(&host)?);
        headers.insert(
            "Content-Length",
            HeaderValue::from_str(&body.len().to_string())?,
        );

        if let Some(ct) = content_type {
            headers.insert("Content-Type", HeaderValue::from_str(ct)?);
        }
        if let Some(acc) = accept {
            headers.insert("Accept", HeaderValue::from_str(acc)?);
        }

        // Create AWS request structure
        let aws_request = BedrockRequest {
            method: "POST".to_string(),
            url: url.clone(),
            headers: headers.clone(),
            body: body.clone(),
        };

        let authenticated_headers = self
            .authenticate_request(&aws_request, &target_region)
            .await?;

        // Make the HTTP request
        let mut request_builder = self.client.post(&url).body(body);

        // Add all authenticated headers
        for (name, value) in authenticated_headers.iter() {
            request_builder = request_builder.header(name.as_str(), value);
        }

        let response = request_builder.send().await?;

        tracing::trace!(
            status = %response.status(),
            "Received response from AWS Bedrock"
        );

        // Check for success status codes (2xx)
        if !response.status().is_success() {
            let status_code = response.status();
            let error_body = response.text().await.unwrap_or_default();

            tracing::error!(
                status = %status_code,
                error_body = %error_body,
                "AWS Bedrock returned error response"
            );

            return Err(AppError::Aws(format!(
                "AWS Bedrock error ({}): {}",
                status_code,
                if error_body.is_empty() {
                    status_code.canonical_reason().unwrap_or("Unknown error")
                } else {
                    &error_body
                }
            )));
        }

        // Convert response
        let status = StatusCode::from_u16(response.status().as_u16())?;
        let response_headers = self.convert_reqwest_headers(response.headers());
        let response_body = response.bytes().await?.to_vec();

        tracing::trace!(
            status = %status,
            response_headers_count = response_headers.len(),
            response_body_size = response_body.len(),
            "Model invocation complete"
        );

        Ok(BedrockResponse {
            status,
            headers: response_headers,
            body: response_body,
        })
    }

    /// Invoke model with response stream (SSE)
    pub async fn invoke_model_with_response_stream(
        &self,
        model_id: &str,
        headers: &HeaderMap,
        content_type: Option<&str>,
        accept: Option<&str>,
        body: Vec<u8>,
    ) -> Result<BedrockStreamResponse, AppError> {
        // Add regional prefix to model ID if not already present
        let regionalized_model_id = self
            .model_mapping
            .add_regional_prefix(model_id, &self.config.region);

        // Determine the target region from the model ID
        let target_region = self.get_target_region(&regionalized_model_id);
        let base_url = format!("https://bedrock-runtime.{}.amazonaws.com", target_region);

        let path = format!(
            "/model/{}/invoke-with-response-stream",
            regionalized_model_id
        );
        let url = format!("{}{}", base_url, path);

        let mut processed_headers = Self::process_headers_for_aws(headers);

        // Add required headers for streaming
        if let Some(ct) = content_type {
            processed_headers.insert("content-type", HeaderValue::from_str(ct)?);
        }
        if let Some(acc) = accept {
            processed_headers.insert("accept", HeaderValue::from_str(acc)?);
        }

        // Create AWS request
        let aws_request = BedrockRequest {
            method: "POST".to_string(),
            url: url.clone(),
            headers: processed_headers.clone(),
            body: body.clone(),
        };

        // Authenticate the request (Bearer token or SigV4) with target region
        let authenticated_headers = self
            .authenticate_request(&aws_request, &target_region)
            .await?;

        // Build HTTP request
        let mut request_builder = self.client.post(&url);

        // Add all authenticated headers
        for (name, value) in authenticated_headers.iter() {
            request_builder = request_builder.header(name.as_str(), value);
        }

        // Add body
        if !body.is_empty() {
            request_builder = request_builder.body(body);
        }

        let response = request_builder.send().await?;

        // Check for success status codes (2xx) before creating stream
        if !response.status().is_success() {
            let status_code = response.status();
            let error_body = response.text().await.unwrap_or_default();

            tracing::error!(
                status = %status_code,
                error_body = %error_body,
                "AWS Bedrock streaming returned error response"
            );

            return Err(AppError::Aws(format!(
                "AWS Bedrock streaming error ({}): {}",
                status_code,
                if error_body.is_empty() {
                    status_code.canonical_reason().unwrap_or("Unknown error")
                } else {
                    &error_body
                }
            )));
        }

        // Convert response for streaming
        let status = StatusCode::from_u16(response.status().as_u16())?;
        let response_headers = self.convert_reqwest_headers(response.headers());
        let stream = Box::new(response.bytes_stream());

        Ok(BedrockStreamResponse {
            status,
            headers: response_headers,
            stream,
        })
    }

    /// Authenticate request for a specific AWS region (used for cross-region model routing)
    async fn authenticate_request(
        &self,
        request: &BedrockRequest,
        region: &str,
    ) -> Result<HeaderMap, AppError> {
        if let Some(bearer_token) = &self.config.bearer_token {
            self.add_bearer_token(request, bearer_token).await
        } else {
            self.sign_request(request, region).await
        }
    }

    /// Add Bearer token authentication to request
    async fn add_bearer_token(
        &self,
        request: &BedrockRequest,
        bearer_token: &str,
    ) -> Result<HeaderMap, AppError> {
        let mut headers = request.headers.clone();
        headers.insert(
            "Authorization",
            HeaderValue::from_str(&format!("Bearer {}", bearer_token))?,
        );
        Ok(headers)
    }

    /// Sign AWS request for a specific region using aws-sigv4 library
    async fn sign_request(
        &self,
        request: &BedrockRequest,
        region: &str,
    ) -> Result<HeaderMap, AppError> {
        let credentials = self.get_credentials().await?;

        // Parse the URL
        let url = Url::parse(&request.url)?;

        // Convert headers to the format expected by aws-sigv4
        let mut signable_headers = Vec::new();
        for (name, value) in request.headers.iter() {
            signable_headers.push((name.as_str(), value.to_str()?));
        }

        // Create signable request with proper body
        let signable_request = SignableRequest::new(
            &request.method,
            url.as_str(),
            signable_headers.iter().map(|(k, v)| (*k, *v)),
            SignableBody::Bytes(&request.body),
        )?;

        // Convert credentials to Identity
        let identity = Identity::new(credentials, None);

        // Create signing params with the specified region
        let signing_params = v4::SigningParams::builder()
            .identity(&identity)
            .region(region)
            .name("bedrock")
            .time(SystemTime::now())
            .settings(SigningSettings::default())
            .build()?
            .into();

        // Sign the request
        let signing_output = sign(signable_request, &signing_params)?;

        // Convert signed headers back to HeaderMap
        let mut signed_headers = request.headers.clone();
        let (signing_instructions, _) = signing_output.into_parts();

        // Create a mock HTTP request to apply signing instructions
        let method: Method = request
            .method
            .parse()
            .map_err(|e| AppError::BadRequest(format!("Invalid HTTP method: {}", e)))?;
        let mut http_request = Request::builder()
            .method(method)
            .uri(&request.url)
            .body(request.body.clone())
            .map_err(|e| AppError::Internal(format!("Failed to create HTTP request: {}", e)))?;

        // Apply the signing instructions
        signing_instructions.apply_to_request_http1x(&mut http_request);

        // Extract signed headers
        for (name, value) in http_request.headers() {
            signed_headers.insert(name, value.clone());
        }
        Ok(signed_headers)
    }

    /// Get credentials using explicit config or credential chain
    async fn get_credentials(&self) -> Result<Credentials, AppError> {
        // Try explicit credentials first
        if let Some(credentials) = self.config.get_explicit_credentials() {
            return Ok(credentials);
        }

        // Use credential chain via SDK config
        if let Some(sdk_config) = &self.sdk_config {
            let credential_provider = sdk_config.credentials_provider().ok_or_else(|| {
                AppError::Internal("No credential provider available".to_string())
            })?;

            let credentials = credential_provider
                .provide_credentials()
                .await
                .map_err(|e| AppError::Internal(format!("Failed to resolve credentials: {}", e)))?;

            return Ok(credentials);
        }

        Err(AppError::Internal(
            "No AWS credentials configured. Please set explicit credentials in config, environment variables (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY), AWS profile (~/.aws/credentials), or use IAM roles.".to_string()
        ))
    }

    /// Convert reqwest headers to axum HeaderMap
    fn convert_reqwest_headers(&self, headers: &reqwest::header::HeaderMap) -> HeaderMap {
        let mut header_map = HeaderMap::new();
        for (name, value) in headers.iter() {
            if let Ok(header_value) = HeaderValue::from_bytes(value.as_bytes()) {
                header_map.insert(name.clone(), header_value);
            }
        }
        header_map
    }

    /// Health check for the AWS connection
    pub async fn health_check(&self) -> Result<(), AppError> {
        // Check if we have either Bearer token or SigV4 credentials configured
        if self.config.bearer_token.is_some() {
            // Bearer token authentication is configured
            Ok(())
        } else {
            // Try to resolve credentials (explicit or credential chain)
            self.get_credentials().await.map(|_| ())
        }
    }

    /// Create a health checker for this AWS client
    pub fn health_checker(&self) -> Arc<BedrockHealthChecker> {
        Arc::new(BedrockHealthChecker {
            client: self.clone(),
        })
    }
}

/// Health checker implementation for AWS Bedrock connection
pub struct BedrockHealthChecker {
    client: BedrockRuntimeImpl,
}

#[async_trait::async_trait]
impl HealthChecker for BedrockHealthChecker {
    fn name(&self) -> &str {
        "aws_bedrock"
    }

    async fn check(&self) -> HealthCheckResult {
        match self.client.health_check().await {
            Ok(()) => {
                let auth_type = if self.client.config.bearer_token.is_some() {
                    "bearer_token"
                } else if self.client.config.access_key_id.is_some()
                    && self.client.config.secret_access_key.is_some()
                {
                    "sigv4_explicit"
                } else if self.client.sdk_config.is_some() {
                    "sigv4_credential_chain"
                } else {
                    "unknown"
                };

                HealthCheckResult::healthy_with_details(serde_json::json!({
                    "region": self.client.config.region,
                    "authentication": auth_type,
                    "endpoint": self.client.base_url
                }))
            }
            Err(err) => HealthCheckResult::unhealthy_with_details(
                "AWS authentication not configured".to_string(),
                serde_json::json!({
                    "error": err.to_string(),
                    "region": self.client.config.region,
                    "endpoint": self.client.base_url
                }),
            ),
        }
    }

    fn info(&self) -> Option<serde_json::Value> {
        Some(serde_json::json!({
            "service": "AWS Bedrock",
            "region": self.client.config.region,
            "endpoint": self.client.base_url
        }))
    }
}

// Trait for AWS client operations to enable mocking
#[async_trait]
pub trait BedrockRuntime: Send + Sync {
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

    /// Get access to the regional model mapping for prefix handling
    fn model_mapping(&self) -> &RegionalModelMapping;
}

// Implement the trait for the real AWS client
#[async_trait]
impl BedrockRuntime for BedrockRuntimeImpl {
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
        BedrockRuntimeImpl::health_checker(self)
    }

    fn model_mapping(&self) -> &RegionalModelMapping {
        BedrockRuntimeImpl::model_mapping(self)
    }
}

impl BedrockRuntimeImpl {
    /// Process headers for forwarding to AWS, removing sensitive and client-specific headers
    pub fn process_headers_for_aws(headers: &HeaderMap) -> HeaderMap {
        let mut forwarded_headers = HeaderMap::new();

        for (name, value) in headers {
            let header_name = name.as_str().to_lowercase();

            // Skip headers that shouldn't be forwarded to AWS
            match header_name.as_str() {
                // Authentication and connection headers
                "authorization" | "host" | "content-length" | "connection" => continue,

                // Browser-specific headers
                "accept-encoding" | "accept-language" | "sec-fetch-mode" | "sec-fetch-site"
                | "sec-fetch-dest" | "referer" | "origin" | "user-agent" => continue,

                // Client SDK headers (Anthropic SDK, Stainless, etc.)
                h if h.starts_with("x-stainless-") => continue,
                h if h.starts_with("anthropic-") => continue,
                h if h.starts_with("x-app") => continue,

                // Other potentially problematic headers
                "cookie" | "set-cookie" | "upgrade" | "transfer-encoding" => continue,

                _ => {
                    if let Ok(header_value) = HeaderValue::try_from(value.as_bytes()) {
                        forwarded_headers.insert(name.clone(), header_value);
                    }
                }
            }
        }

        forwarded_headers
    }

    /// Process headers from AWS response for client response
    pub fn process_headers_from_aws(headers: &HeaderMap) -> HeaderMap {
        let mut client_headers = HeaderMap::new();

        for (name, value) in headers {
            // Forward most headers but skip some AWS-specific ones
            match name.as_str().to_lowercase().as_str() {
                "x-amz-request-id" | "x-amz-id-2" | "server" | "date" => continue,
                _ => {
                    if let Ok(header_value) = HeaderValue::try_from(value.as_bytes()) {
                        client_headers.insert(name.clone(), header_value);
                    }
                }
            }
        }

        client_headers
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_aws_http_client_test_creation() {
        let client = BedrockRuntimeImpl::new_test().await;
        assert_eq!(
            client.base_url,
            "https://bedrock-runtime.us-east-1.amazonaws.com"
        );
    }

    #[test]
    fn test_process_headers_for_aws() {
        let mut headers = HeaderMap::new();
        headers.insert("authorization", HeaderValue::from_static("Bearer token"));
        headers.insert("content-type", HeaderValue::from_static("application/json"));
        headers.insert("x-custom-header", HeaderValue::from_static("custom-value"));
        headers.insert("host", HeaderValue::from_static("example.com"));

        let processed = BedrockRuntimeImpl::process_headers_for_aws(&headers);

        assert!(!processed.contains_key("authorization"));
        assert!(!processed.contains_key("host"));
        assert!(processed.contains_key("content-type"));
        assert!(processed.contains_key("x-custom-header"));
    }

    #[test]
    fn test_process_headers_for_aws_client_headers_filtered() {
        let mut headers = HeaderMap::new();

        // Headers that should be kept
        headers.insert("content-type", HeaderValue::from_static("application/json"));
        headers.insert("accept", HeaderValue::from_static("application/json"));
        headers.insert("x-custom-header", HeaderValue::from_static("custom-value"));

        // Headers that should be filtered out
        headers.insert("authorization", HeaderValue::from_static("Bearer token"));
        headers.insert("host", HeaderValue::from_static("example.com"));
        headers.insert("content-length", HeaderValue::from_static("100"));
        headers.insert("connection", HeaderValue::from_static("keep-alive"));
        headers.insert("accept-encoding", HeaderValue::from_static("gzip, deflate"));
        headers.insert(
            "accept-language",
            HeaderValue::from_static("en-US,en;q=0.9"),
        );
        headers.insert("sec-fetch-mode", HeaderValue::from_static("cors"));
        headers.insert("user-agent", HeaderValue::from_static("Mozilla/5.0"));
        headers.insert("x-stainless-lang", HeaderValue::from_static("js"));
        headers.insert(
            "x-stainless-package-version",
            HeaderValue::from_static("0.55.1"),
        );
        headers.insert("anthropic-version", HeaderValue::from_static("2023-06-01"));
        headers.insert(
            "anthropic-dangerous-direct-browser-access",
            HeaderValue::from_static("true"),
        );
        headers.insert("x-app", HeaderValue::from_static("cli"));

        let processed = BedrockRuntimeImpl::process_headers_for_aws(&headers);

        // Should be kept
        assert!(processed.contains_key("content-type"));
        assert!(processed.contains_key("accept"));
        assert!(processed.contains_key("x-custom-header"));

        // Should be filtered out
        assert!(!processed.contains_key("authorization"));
        assert!(!processed.contains_key("host"));
        assert!(!processed.contains_key("content-length"));
        assert!(!processed.contains_key("connection"));
        assert!(!processed.contains_key("accept-encoding"));
        assert!(!processed.contains_key("accept-language"));
        assert!(!processed.contains_key("sec-fetch-mode"));
        assert!(!processed.contains_key("user-agent"));
        assert!(!processed.contains_key("x-stainless-lang"));
        assert!(!processed.contains_key("x-stainless-package-version"));
        assert!(!processed.contains_key("anthropic-version"));
        assert!(!processed.contains_key("anthropic-dangerous-direct-browser-access"));
        assert!(!processed.contains_key("x-app"));

        // Only 3 headers should remain
        assert_eq!(processed.len(), 3);
    }

    #[test]
    fn test_process_headers_from_aws() {
        let mut headers = HeaderMap::new();
        headers.insert("content-type", HeaderValue::from_static("application/json"));
        headers.insert("x-amz-request-id", HeaderValue::from_static("12345"));
        headers.insert("x-custom-header", HeaderValue::from_static("custom-value"));
        headers.insert("server", HeaderValue::from_static("nginx"));

        let processed = BedrockRuntimeImpl::process_headers_from_aws(&headers);

        assert!(!processed.contains_key("x-amz-request-id"));
        assert!(!processed.contains_key("server"));
        assert!(processed.contains_key("content-type"));
        assert!(processed.contains_key("x-custom-header"));
    }

    #[tokio::test]
    async fn test_convert_reqwest_headers() {
        let client = BedrockRuntimeImpl::new_test().await;
        let mut reqwest_headers = reqwest::header::HeaderMap::new();
        reqwest_headers.insert("content-type", "application/json".parse().unwrap());
        reqwest_headers.insert("x-custom", "value".parse().unwrap());

        let converted = client.convert_reqwest_headers(&reqwest_headers);

        assert_eq!(converted.len(), 2);
        assert!(converted.contains_key("content-type"));
        assert!(converted.contains_key("x-custom"));
    }

    #[tokio::test]
    async fn test_invoke_model_with_test_client() {
        let client = BedrockRuntimeImpl::new_test().await;

        // Test that we can create the client and make a call
        // With test credentials, we expect to get an AWS error (likely 403 Forbidden)
        let result = client
            .invoke_model(
                "anthropic.claude-v2",
                Some("application/json"),
                Some("application/json"),
                b"{\"messages\": []}".to_vec(),
            )
            .await;

        // Should fail with AWS error due to invalid test credentials
        assert!(result.is_err());
        let error = result.err().unwrap();

        // Should be an AWS error containing the 403 status information
        match error {
            AppError::Aws(msg) => {
                assert!(msg.contains("403") || msg.contains("Forbidden"));
            }
            _ => panic!("Expected AWS error, got: {:?}", error),
        }
    }

    #[tokio::test]
    async fn test_invoke_model_with_response_stream_mock() {
        let client = BedrockRuntimeImpl::new_test().await;
        let headers = HeaderMap::new();

        let result = client
            .invoke_model_with_response_stream(
                "anthropic.claude-v2",
                &headers,
                Some("application/json"),
                Some("text/event-stream"),
                b"{\"messages\": []}".to_vec(),
            )
            .await;

        // Should fail with AWS error due to invalid test credentials
        assert!(result.is_err());
        let error = result.err().unwrap();

        // Should be an AWS error containing the 403 status information
        match error {
            AppError::Aws(msg) => {
                assert!(msg.contains("403") || msg.contains("Forbidden"));
            }
            _ => panic!("Expected AWS streaming error, got: {:?}", error),
        }
    }

    #[tokio::test]
    async fn test_sign_request_missing_credentials() {
        let config = AwsConfig {
            region: "us-east-1".to_string(),
            access_key_id: None,
            secret_access_key: Some("secret".to_string()),
            profile: None,
            bearer_token: None,
            region_prefix_mappings: std::collections::HashMap::new(),
        };
        let client = BedrockRuntimeImpl::new(config).await.unwrap();

        let request = BedrockRequest {
            method: "POST".to_string(),
            url: "https://bedrock-runtime.us-east-1.amazonaws.com/model/test/invoke".to_string(),
            headers: HeaderMap::new(),
            body: Vec::new(),
        };

        let result = client.sign_request(&request, "us-east-1").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_sign_request_missing_secret() {
        let config = AwsConfig {
            region: "us-east-1".to_string(),
            access_key_id: Some("access_key".to_string()),
            secret_access_key: None,
            profile: None,
            bearer_token: None,
            region_prefix_mappings: std::collections::HashMap::new(),
        };
        let client = BedrockRuntimeImpl::new(config).await.unwrap();

        let request = BedrockRequest {
            method: "POST".to_string(),
            url: "https://bedrock-runtime.us-east-1.amazonaws.com/model/test/invoke".to_string(),
            headers: HeaderMap::new(),
            body: Vec::new(),
        };

        let result = client.sign_request(&request, "us-east-1").await;
        assert!(result.is_err());
    }

    #[test]
    fn test_process_headers_for_aws_content_length() {
        let mut headers = HeaderMap::new();
        headers.insert("authorization", HeaderValue::from_static("Bearer token"));
        headers.insert("content-length", HeaderValue::from_static("100"));
        headers.insert("content-type", HeaderValue::from_static("application/json"));

        let processed = BedrockRuntimeImpl::process_headers_for_aws(&headers);

        assert!(!processed.contains_key("authorization"));
        assert!(!processed.contains_key("content-length"));
        assert!(processed.contains_key("content-type"));
    }

    #[test]
    fn test_process_headers_from_aws_date_filtering() {
        let mut headers = HeaderMap::new();
        headers.insert("content-type", HeaderValue::from_static("application/json"));
        headers.insert(
            "date",
            HeaderValue::from_static("Thu, 01 Jan 1970 00:00:00 GMT"),
        );
        headers.insert("x-amz-id-2", HeaderValue::from_static("some-id"));

        let processed = BedrockRuntimeImpl::process_headers_from_aws(&headers);

        assert!(!processed.contains_key("date"));
        assert!(!processed.contains_key("x-amz-id-2"));
        assert!(processed.contains_key("content-type"));
    }

    #[tokio::test]
    async fn test_add_bearer_token() {
        let config = AwsConfig {
            region: "us-east-1".to_string(),
            access_key_id: None,
            secret_access_key: None,
            profile: None,
            bearer_token: Some("ABSK-1234567890abcdef1234567890abcdef12345678".to_string()),
            region_prefix_mappings: std::collections::HashMap::new(),
        };
        let client = BedrockRuntimeImpl::new(config).await.unwrap();

        let mut headers = HeaderMap::new();
        headers.insert("content-type", HeaderValue::from_static("application/json"));

        let request = BedrockRequest {
            method: "POST".to_string(),
            url: "https://bedrock-runtime.us-east-1.amazonaws.com/model/test/invoke".to_string(),
            headers,
            body: Vec::new(),
        };

        let result = client
            .add_bearer_token(&request, "ABSK-1234567890abcdef1234567890abcdef12345678")
            .await;
        assert!(result.is_ok());

        let authenticated_headers = result.unwrap();
        assert!(authenticated_headers.contains_key("authorization"));
        assert_eq!(
            authenticated_headers.get("authorization").unwrap(),
            "Bearer ABSK-1234567890abcdef1234567890abcdef12345678"
        );
        assert!(authenticated_headers.contains_key("content-type"));
    }

    #[tokio::test]
    async fn test_new_with_credential_chain_explicit_credentials() {
        let config = AwsConfig {
            region: "us-east-1".to_string(),
            access_key_id: Some("test_key".to_string()),
            secret_access_key: Some("test_secret".to_string()),
            profile: None,
            bearer_token: None,
            region_prefix_mappings: std::collections::HashMap::new(),
        };

        let client = BedrockRuntimeImpl::new(config).await;
        assert!(client.is_ok());

        let client = client.unwrap();
        assert!(client.sdk_config.is_some());

        // Should be able to get credentials
        let credentials = client.get_credentials().await;
        assert!(credentials.is_ok());

        let creds = credentials.unwrap();
        assert_eq!(creds.access_key_id(), "test_key");
        assert_eq!(creds.secret_access_key(), "test_secret");
    }

    #[tokio::test]
    async fn test_get_explicit_credentials() {
        let config = AwsConfig {
            region: "us-east-1".to_string(),
            access_key_id: Some("explicit_key".to_string()),
            secret_access_key: Some("explicit_secret".to_string()),
            profile: None,
            bearer_token: None,
            region_prefix_mappings: std::collections::HashMap::new(),
        };

        let credentials = config.get_explicit_credentials();
        assert!(credentials.is_some());

        let creds = credentials.unwrap();
        assert_eq!(creds.access_key_id(), "explicit_key");
        assert_eq!(creds.secret_access_key(), "explicit_secret");
    }

    #[tokio::test]
    async fn test_get_explicit_credentials_none() {
        let config = AwsConfig {
            region: "us-east-1".to_string(),
            access_key_id: None,
            secret_access_key: None,
            profile: Some("default".to_string()),
            bearer_token: None,
            region_prefix_mappings: std::collections::HashMap::new(),
        };

        let credentials = config.get_explicit_credentials();
        assert!(credentials.is_none());
    }

    #[tokio::test]
    async fn test_health_check_with_credential_chain() {
        let config = AwsConfig {
            region: "us-east-1".to_string(),
            access_key_id: Some("test_key".to_string()),
            secret_access_key: Some("test_secret".to_string()),
            profile: None,
            bearer_token: None,
            region_prefix_mappings: std::collections::HashMap::new(),
        };

        let client = BedrockRuntimeImpl::new(config).await.unwrap();
        let health_result = client.health_check().await;
        assert!(health_result.is_ok());
    }

    #[tokio::test]
    async fn test_get_target_region_from_model_id() {
        let client = BedrockRuntimeImpl::new_test().await;

        // Test with EU prefix - should route to eu-west-1
        let target_region = client.get_target_region("eu.anthropic.claude-sonnet-4-20250514-v1:0");
        assert_eq!(target_region, "eu-west-1");

        // Test with US prefix - should route to us-east-1
        let target_region = client.get_target_region("us.anthropic.claude-sonnet-4-20250514-v1:0");
        assert_eq!(target_region, "us-east-1");

        // Test with APAC prefix - should route to ap-northeast-1
        let target_region =
            client.get_target_region("apac.anthropic.claude-sonnet-4-20250514-v1:0");
        assert_eq!(target_region, "ap-northeast-1");

        // Test without prefix - should use configured region
        let target_region = client.get_target_region("anthropic.claude-sonnet-4-20250514-v1:0");
        assert_eq!(target_region, "us-east-1");

        // Test with unknown prefix - should use configured region
        let target_region =
            client.get_target_region("unknown.anthropic.claude-sonnet-4-20250514-v1:0");
        assert_eq!(target_region, "us-east-1");
    }

    #[tokio::test]
    async fn test_region_routing_endpoint_generation() {
        let client = BedrockRuntimeImpl::new_test().await;

        // Test EU model ID generates correct endpoint
        let target_region = client.get_target_region("eu.anthropic.claude-sonnet-4-20250514-v1:0");
        let expected_url = format!("https://bedrock-runtime.{}.amazonaws.com", target_region);
        assert_eq!(
            expected_url,
            "https://bedrock-runtime.eu-west-1.amazonaws.com"
        );

        // Test APAC model ID generates correct endpoint
        let target_region =
            client.get_target_region("apac.anthropic.claude-sonnet-4-20250514-v1:0");
        let expected_url = format!("https://bedrock-runtime.{}.amazonaws.com", target_region);
        assert_eq!(
            expected_url,
            "https://bedrock-runtime.ap-northeast-1.amazonaws.com"
        );

        // Test US model ID generates correct endpoint
        let target_region = client.get_target_region("us.anthropic.claude-sonnet-4-20250514-v1:0");
        let expected_url = format!("https://bedrock-runtime.{}.amazonaws.com", target_region);
        assert_eq!(
            expected_url,
            "https://bedrock-runtime.us-east-1.amazonaws.com"
        );
    }

    #[tokio::test]
    async fn test_error_handling_for_aws_responses() {
        // This test verifies that AWS error responses are properly converted to AppError::Aws
        // We can't easily mock HTTP responses in unit tests, but we verify the error handling logic
        let client = BedrockRuntimeImpl::new_test().await;

        // Test with invalid model ID to trigger AWS error
        let result = client
            .invoke_model(
                "invalid.model.id",
                Some("application/json"),
                Some("application/json"),
                b"{}".to_vec(),
            )
            .await;

        // Should return an error (likely 400 Bad Request or 404 Not Found from AWS)
        assert!(result.is_err());
        let error = result.err().unwrap();

        // Should be an AWS error
        match error {
            AppError::Aws(msg) => {
                // Error message should contain status code information
                assert!(!msg.is_empty());
                assert!(msg.contains("AWS Bedrock error"));
            }
            _ => panic!("Expected AWS error, got: {:?}", error),
        }
    }

    #[tokio::test]
    async fn test_streaming_error_handling_for_aws_responses() {
        // This test verifies that AWS streaming error responses are properly converted to AppError::Aws
        let client = BedrockRuntimeImpl::new_test().await;
        let headers = HeaderMap::new();

        // Test with invalid model ID to trigger AWS error
        let result = client
            .invoke_model_with_response_stream(
                "invalid.model.id",
                &headers,
                Some("application/json"),
                Some("text/event-stream"),
                b"{}".to_vec(),
            )
            .await;

        // Should return an error (likely 400 Bad Request or 404 Not Found from AWS)
        assert!(result.is_err());
        let error = result.err().unwrap();

        // Should be an AWS error
        match error {
            AppError::Aws(msg) => {
                // Error message should contain status code information
                assert!(!msg.is_empty());
                assert!(msg.contains("AWS Bedrock streaming error"));
            }
            _ => panic!("Expected AWS streaming error, got: {:?}", error),
        }
    }

    #[tokio::test]
    async fn test_configurable_region_mapping_end_to_end() {
        // Test that configurable region mappings work from config through to region routing
        let mut custom_mappings = std::collections::HashMap::new();
        custom_mappings.insert("eu".to_string(), "eu-central-1".to_string());
        custom_mappings.insert("custom".to_string(), "us-west-2".to_string());

        let config = AwsConfig {
            region: "us-east-1".to_string(),
            access_key_id: Some("test_key".to_string()),
            secret_access_key: Some("test_secret".to_string()),
            profile: None,
            bearer_token: None,
            region_prefix_mappings: custom_mappings,
        };

        let client = BedrockRuntimeImpl::new(config).await.unwrap();

        // Test default US mapping (unchanged)
        let target_region = client.get_target_region("us.anthropic.claude-sonnet-4-20250514-v1:0");
        assert_eq!(target_region, "us-east-1");

        // Test custom EU mapping override
        let target_region = client.get_target_region("eu.anthropic.claude-sonnet-4-20250514-v1:0");
        assert_eq!(target_region, "eu-central-1"); // Custom override

        // Test default APAC mapping (unchanged)
        let target_region =
            client.get_target_region("apac.anthropic.claude-sonnet-4-20250514-v1:0");
        assert_eq!(target_region, "ap-northeast-1");

        // Test custom prefix mapping
        let target_region =
            client.get_target_region("custom.anthropic.claude-sonnet-4-20250514-v1:0");
        assert_eq!(target_region, "us-west-2"); // Custom mapping

        // Test no prefix - should use server's configured region
        let target_region = client.get_target_region("anthropic.claude-sonnet-4-20250514-v1:0");
        assert_eq!(target_region, "us-east-1");

        // Test unknown prefix - should use server's configured region
        let target_region =
            client.get_target_region("unknown.anthropic.claude-sonnet-4-20250514-v1:0");
        assert_eq!(target_region, "us-east-1");
    }
}
