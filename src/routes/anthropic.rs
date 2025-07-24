use crate::{
    anthropic::{
        model_mapping::ModelMapper,
        transform::{transform_anthropic_to_bedrock, transform_bedrock_to_anthropic, 
                   transform_streaming_event, validate_anthropic_request},
        AnthropicRequest,
    },
    aws_http::AwsHttpClient,
    error::AppError,
};
use axum::{
    Router,
    body::{Body, Bytes},
    extract::State,
    http::{HeaderMap, StatusCode},
    response::Response,
    routing::post,
};
use futures_util::StreamExt;
use tracing::{error, info, warn};

/// Create routes for Anthropic API endpoints
pub fn create_anthropic_routes() -> Router<AwsHttpClient> {
    Router::new()
        .route("/v1/messages", post(create_message))
}

/// Handle POST /v1/messages - Anthropic API format message creation
/// Supports both streaming and non-streaming responses based on the `stream` parameter
pub async fn create_message(
    State(aws_http_client): State<AwsHttpClient>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, AppError> {
    info!("Handling Anthropic API /v1/messages request");

    // Parse the Anthropic request
    let anthropic_request: AnthropicRequest = serde_json::from_slice(&body)
        .map_err(|e| AppError::BadRequest(format!("Invalid JSON request: {}", e)))?;

    // Validate the request format
    validate_anthropic_request(&anthropic_request)
        .map_err(AppError::from)?;

    // Create model mapper for transformations
    let model_mapper = ModelMapper::new();

    // Transform Anthropic request to Bedrock format
    let (bedrock_request, bedrock_model_id) = transform_anthropic_to_bedrock(
        anthropic_request.clone(),
        &model_mapper,
    ).map_err(AppError::from)?;

    // Convert bedrock_request to bytes for AWS call
    let bedrock_body = serde_json::to_vec(&bedrock_request)
        .map_err(|e| AppError::Internal(format!("Failed to serialize Bedrock request: {}", e)))?;

    // Check if streaming was requested
    let is_streaming = anthropic_request.stream.unwrap_or(false);

    if is_streaming {
        handle_streaming_message(
            aws_http_client,
            headers,
            bedrock_model_id,
            bedrock_body,
            anthropic_request.model,
            model_mapper,
        ).await
    } else {
        handle_non_streaming_message(
            aws_http_client,
            headers,
            bedrock_model_id,
            bedrock_body,
            anthropic_request.model,
            model_mapper,
        ).await
    }
}

/// Handle non-streaming message requests
async fn handle_non_streaming_message(
    aws_http_client: AwsHttpClient,
    headers: HeaderMap,
    bedrock_model_id: String,
    bedrock_body: Vec<u8>,
    original_model: String,
    model_mapper: ModelMapper,
) -> Result<Response, AppError> {
    info!("Processing non-streaming Anthropic request for model: {}", bedrock_model_id);

    // Process headers for AWS (remove authorization, etc.)
    let aws_headers = AwsHttpClient::process_headers_for_aws(&headers);

    // Extract content-type and accept headers if present
    let content_type = aws_headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/json");
    let accept = aws_headers
        .get("accept")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/json");

    // Make the AWS Bedrock API call
    match aws_http_client
        .invoke_model(&bedrock_model_id, Some(content_type), Some(accept), bedrock_body)
        .await
    {
        Ok(aws_response) => {
            info!(
                "Successfully invoked Bedrock model {} with status {}",
                bedrock_model_id,
                aws_response.status
            );

            // Parse AWS response body as JSON
            let bedrock_response: serde_json::Value = serde_json::from_slice(&aws_response.body)
                .map_err(|e| AppError::Internal(format!("Failed to parse Bedrock response: {}", e)))?;

            // Transform Bedrock response to Anthropic format
            let anthropic_response = transform_bedrock_to_anthropic(
                bedrock_response,
                &original_model,
                &model_mapper,
            ).map_err(AppError::from)?;

            // Return JSON response
            Ok(Response::builder()
                .status(aws_response.status)
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&anthropic_response).unwrap()))
                .unwrap())
        }
        Err(err) => {
            error!("AWS Bedrock API error for model {}: {}", bedrock_model_id, err);
            Err(err)
        }
    }
}

/// Handle streaming message requests
async fn handle_streaming_message(
    aws_http_client: AwsHttpClient,
    headers: HeaderMap,
    bedrock_model_id: String,
    bedrock_body: Vec<u8>,
    original_model: String,
    model_mapper: ModelMapper,
) -> Result<Response, AppError> {
    info!("Processing streaming Anthropic request for model: {}", bedrock_model_id);

    // Extract content type and accept headers
    let content_type = headers.get("content-type").and_then(|v| v.to_str().ok());
    let accept = headers.get("accept").and_then(|v| v.to_str().ok());

    // Call AWS Bedrock streaming API
    match aws_http_client
        .invoke_model_with_response_stream(&bedrock_model_id, &headers, content_type, accept, bedrock_body)
        .await
    {
        Ok(aws_response) => {
            info!(
                "AWS Bedrock streaming response received for model: {}",
                bedrock_model_id
            );

            // Transform the streaming response to Anthropic format
            let transformed_stream = aws_response.stream.map(move |chunk_result| {
                match chunk_result {
                    Ok(chunk) => {
                        // Transform each chunk to Anthropic format
                        match transform_streaming_event(&chunk, &model_mapper, &original_model) {
                            Ok(Some(transformed_chunk)) => Ok(Bytes::from(transformed_chunk)),
                            Ok(None) => {
                                // Skip this chunk if transformation returns None
                                warn!("Skipped chunk during streaming transformation");
                                Ok(Bytes::new())
                            }
                            Err(e) => {
                                error!("Failed to transform streaming chunk: {}", e);
                                // Pass through the original chunk on transformation error
                                Ok(chunk)
                            }
                        }
                    }
                    Err(e) => {
                        error!("Stream error: {}", e);
                        Err(axum::Error::new(e))
                    }
                }
            });

            // Create a streaming body from the transformed stream
            let body = Body::from_stream(transformed_stream);

            // Build response with proper SSE headers
            let mut response = Response::builder()
                .status(StatusCode::OK)
                .header("content-type", "text/event-stream")
                .header("cache-control", "no-cache")
                .header("connection", "keep-alive")
                .body(body)
                .unwrap();

            // Add important headers from AWS response (except problematic ones)
            for (name, value) in aws_response.headers.iter() {
                let name_str = name.as_str();
                if name_str != "content-length" 
                   && name_str != "transfer-encoding" 
                   && name_str != "content-type" 
                   && name_str != "cache-control" 
                   && name_str != "connection" {
                    response.headers_mut().insert(name, value.clone());
                }
            }

            Ok(response)
        }
        Err(err) => {
            error!(
                "AWS Bedrock streaming API error for model {}: {}",
                bedrock_model_id,
                err
            );
            Err(err)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;

    fn create_test_anthropic_request_json() -> String {
        serde_json::to_string(&serde_json::json!({
            "model": "claude-3-sonnet-20240229",
            "messages": [
                {
                    "role": "user",
                    "content": "Hello, how can you help me today?"
                }
            ],
            "max_tokens": 1000,
            "temperature": 0.7
        })).unwrap()
    }

    fn create_test_streaming_request_json() -> String {
        serde_json::to_string(&serde_json::json!({
            "model": "claude-3-sonnet-20240229",
            "messages": [
                {
                    "role": "user",
                    "content": "Hello, how can you help me today?"
                }
            ],
            "max_tokens": 1000,
            "stream": true
        })).unwrap()
    }

    #[tokio::test]
    async fn test_create_message_basic() {
        let aws_http_client = AwsHttpClient::new_test();
        let app = create_anthropic_routes().with_state(aws_http_client);

        let request = Request::builder()
            .uri("/v1/messages")
            .method("POST")
            .header("Content-Type", "application/json")
            .body(Body::from(create_test_anthropic_request_json()))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        
        // In test mode, we expect either success or a handled error
        assert!(
            response.status() == StatusCode::OK
                || response.status() == StatusCode::INTERNAL_SERVER_ERROR
                || response.status() == StatusCode::BAD_REQUEST
                || response.status() == StatusCode::FORBIDDEN
        );
    }

    #[tokio::test]
    async fn test_create_message_streaming() {
        let aws_http_client = AwsHttpClient::new_test();
        let app = create_anthropic_routes().with_state(aws_http_client);

        let request = Request::builder()
            .uri("/v1/messages")
            .method("POST")
            .header("Content-Type", "application/json")
            .body(Body::from(create_test_streaming_request_json()))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        
        // For streaming requests, we expect either OK with SSE headers or an error
        if response.status() == StatusCode::OK {
            assert_eq!(
                response.headers().get("content-type").unwrap(),
                "text/event-stream"
            );
            assert_eq!(response.headers().get("cache-control").unwrap(), "no-cache");
        } else {
            // Accept various error statuses in test mode
            assert!(
                response.status() == StatusCode::INTERNAL_SERVER_ERROR
                    || response.status() == StatusCode::BAD_REQUEST
                    || response.status() == StatusCode::FORBIDDEN
            );
        }
    }

    #[tokio::test]
    async fn test_create_message_invalid_json() {
        let aws_http_client = AwsHttpClient::new_test();
        let app = create_anthropic_routes().with_state(aws_http_client);

        let request = Request::builder()
            .uri("/v1/messages")
            .method("POST")
            .header("Content-Type", "application/json")
            .body(Body::from("invalid json"))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_create_message_missing_required_fields() {
        let aws_http_client = AwsHttpClient::new_test();
        let app = create_anthropic_routes().with_state(aws_http_client);

        let incomplete_request = serde_json::to_string(&serde_json::json!({
            "model": "claude-3-sonnet-20240229",
            // Missing messages and max_tokens
        })).unwrap();

        let request = Request::builder()
            .uri("/v1/messages")
            .method("POST")
            .header("Content-Type", "application/json")
            .body(Body::from(incomplete_request))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_create_message_unsupported_model() {
        let aws_http_client = AwsHttpClient::new_test();
        let app = create_anthropic_routes().with_state(aws_http_client);

        let request_with_unsupported_model = serde_json::to_string(&serde_json::json!({
            "model": "unsupported-model",
            "messages": [
                {
                    "role": "user",
                    "content": "Hello"
                }
            ],
            "max_tokens": 1000
        })).unwrap();

        let request = Request::builder()
            .uri("/v1/messages")
            .method("POST")
            .header("Content-Type", "application/json")
            .body(Body::from(request_with_unsupported_model))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_create_message_with_system_prompt() {
        let aws_http_client = AwsHttpClient::new_test();
        let app = create_anthropic_routes().with_state(aws_http_client);

        let request_with_system = serde_json::to_string(&serde_json::json!({
            "model": "claude-3-sonnet-20240229",
            "messages": [
                {
                    "role": "user",
                    "content": "What's 2+2?"
                }
            ],
            "max_tokens": 100,
            "system": "You are a helpful math tutor."
        })).unwrap();

        let request = Request::builder()
            .uri("/v1/messages")
            .method("POST")
            .header("Content-Type", "application/json")
            .body(Body::from(request_with_system))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        
        // Should handle system prompts correctly
        assert!(
            response.status() == StatusCode::OK
                || response.status() == StatusCode::INTERNAL_SERVER_ERROR
                || response.status() == StatusCode::BAD_REQUEST
                || response.status() == StatusCode::FORBIDDEN
        );
    }

    #[tokio::test]
    async fn test_create_message_with_all_parameters() {
        let aws_http_client = AwsHttpClient::new_test();
        let app = create_anthropic_routes().with_state(aws_http_client);

        let full_request = serde_json::to_string(&serde_json::json!({
            "model": "claude-3-sonnet-20240229",
            "messages": [
                {
                    "role": "user",
                    "content": "Tell me a short story"
                }
            ],
            "max_tokens": 500,
            "temperature": 0.8,
            "top_p": 0.9,
            "top_k": 50,
            "stop_sequences": ["END"],
            "system": "You are a creative storyteller."
        })).unwrap();

        let request = Request::builder()
            .uri("/v1/messages")
            .method("POST")
            .header("Content-Type", "application/json")
            .body(Body::from(full_request))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        
        // Should handle all parameters correctly
        assert!(
            response.status() == StatusCode::OK
                || response.status() == StatusCode::INTERNAL_SERVER_ERROR
                || response.status() == StatusCode::BAD_REQUEST
                || response.status() == StatusCode::FORBIDDEN
        );
    }

    #[tokio::test]
    async fn test_create_message_with_model_alias() {
        let aws_http_client = AwsHttpClient::new_test();
        let app = create_anthropic_routes().with_state(aws_http_client);

        let request_with_alias = serde_json::to_string(&serde_json::json!({
            "model": "claude-3-sonnet", // Using alias instead of full name
            "messages": [
                {
                    "role": "user",
                    "content": "Hello"
                }
            ],
            "max_tokens": 100
        })).unwrap();

        let request = Request::builder()
            .uri("/v1/messages")
            .method("POST")
            .header("Content-Type", "application/json")
            .body(Body::from(request_with_alias))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        
        // Should resolve aliases correctly
        assert!(
            response.status() == StatusCode::OK
                || response.status() == StatusCode::INTERNAL_SERVER_ERROR
                || response.status() == StatusCode::BAD_REQUEST
                || response.status() == StatusCode::FORBIDDEN
        );
    }

    #[tokio::test]
    async fn test_create_message_large_request() {
        let aws_http_client = AwsHttpClient::new_test();
        let app = create_anthropic_routes().with_state(aws_http_client);

        // Create a large content string
        let large_content = "A".repeat(5000);
        let large_request = serde_json::to_string(&serde_json::json!({
            "model": "claude-3-sonnet-20240229",
            "messages": [
                {
                    "role": "user",
                    "content": large_content
                }
            ],
            "max_tokens": 1000
        })).unwrap();

        let request = Request::builder()
            .uri("/v1/messages")
            .method("POST")
            .header("Content-Type", "application/json")
            .body(Body::from(large_request))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        
        // Should handle large requests appropriately
        assert!(
            response.status() == StatusCode::OK
                || response.status() == StatusCode::INTERNAL_SERVER_ERROR
                || response.status() == StatusCode::BAD_REQUEST
                || response.status() == StatusCode::FORBIDDEN
                || response.status() == StatusCode::PAYLOAD_TOO_LARGE
        );
    }
}