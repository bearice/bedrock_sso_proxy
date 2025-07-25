use crate::{
    anthropic::{
        AnthropicRequest,
        model_mapping::ModelMapper,
        transform::{
            transform_anthropic_to_bedrock, transform_bedrock_to_anthropic,
            transform_streaming_event, validate_anthropic_request,
        },
    },
    auth::jwt::ValidatedClaims,
    error::AppError,
    model_service::{ModelService, ModelRequest},
};
use axum::{
    Router,
    body::{Body, Bytes},
    extract::{Extension, State},
    http::{HeaderMap, StatusCode},
    response::Response,
    routing::post,
};
use std::sync::Arc;
use tracing::{error, info, warn};

/// Create routes for Anthropic API endpoints
pub fn create_anthropic_routes() -> Router<Arc<ModelService>> {
    Router::new().route("/v1/messages", post(create_message))
}

/// Handle POST /v1/messages - Anthropic API format message creation
/// Supports both streaming and non-streaming responses based on the `stream` parameter
pub async fn create_message(
    State(model_service): State<Arc<ModelService>>,
    Extension(claims): Extension<ValidatedClaims>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, AppError> {
    info!("Handling Anthropic API /v1/messages request");

    // Extract user_id directly from JWT claims
    let user_id = claims.user_id();

    // Parse the Anthropic request
    let anthropic_request: AnthropicRequest = serde_json::from_slice(&body)
        .map_err(|e| AppError::BadRequest(format!("Invalid JSON request: {}", e)))?;

    // Validate the request format
    validate_anthropic_request(&anthropic_request).map_err(AppError::from)?;

    // Create model mapper for transformations
    let model_mapper = ModelMapper::default();

    // Transform Anthropic request to Bedrock format
    let (bedrock_request, bedrock_model_id) =
        transform_anthropic_to_bedrock(anthropic_request.clone(), &model_mapper)
            .map_err(AppError::from)?;

    // Convert bedrock_request to bytes for AWS call
    let bedrock_body = serde_json::to_vec(&bedrock_request)
        .map_err(|e| AppError::Internal(format!("Failed to serialize Bedrock request: {}", e)))?;

    // Check if streaming was requested
    let is_streaming = anthropic_request.stream.unwrap_or(false);

    if is_streaming {
        handle_streaming_message(
            model_service,
            headers,
            bedrock_model_id,
            bedrock_body,
            anthropic_request.model,
            model_mapper,
            user_id,
        )
        .await
    } else {
        handle_non_streaming_message(
            model_service,
            headers,
            bedrock_model_id,
            bedrock_body,
            anthropic_request.model,
            model_mapper,
            user_id,
        )
        .await
    }
}

/// Handle non-streaming message requests
async fn handle_non_streaming_message(
    model_service: Arc<ModelService>,
    headers: HeaderMap,
    bedrock_model_id: String,
    bedrock_body: Vec<u8>,
    original_model: String,
    model_mapper: ModelMapper,
    user_id: i32,
) -> Result<Response, AppError> {
    info!(
        "Processing non-streaming Anthropic request for model: {}",
        bedrock_model_id
    );

    // Create ModelRequest for the service
    let model_request = ModelRequest {
        model_id: bedrock_model_id.clone(),
        body: bedrock_body,
        headers: headers.clone(),
        user_id,
        endpoint_type: "anthropic".to_string(),
    };

    // Use ModelService to invoke model (includes automatic usage tracking)
    match model_service.invoke_model(model_request).await {
        Ok(model_response) => {
            info!(
                "Successfully invoked Bedrock model {} with status {}",
                bedrock_model_id, model_response.status
            );

            // Parse AWS response body as JSON
            let bedrock_response: serde_json::Value = serde_json::from_slice(&model_response.body)
                .map_err(|e| {
                    AppError::Internal(format!("Failed to parse Bedrock response: {}", e))
                })?;

            // Transform Bedrock response to Anthropic format
            let anthropic_response =
                transform_bedrock_to_anthropic(bedrock_response, &original_model, &model_mapper)
                    .map_err(AppError::from)?;

            // Return JSON response
            Ok(Response::builder()
                .status(model_response.status)
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&anthropic_response).unwrap()))
                .unwrap())
        }
        Err(err) => {
            error!(
                "Model service error for model {}: {}",
                bedrock_model_id, err
            );
            Err(err)
        }
    }
}

/// Handle streaming message requests
async fn handle_streaming_message(
    model_service: Arc<ModelService>,
    headers: HeaderMap,
    bedrock_model_id: String,
    bedrock_body: Vec<u8>,
    original_model: String,
    model_mapper: ModelMapper,
    user_id: i32,
) -> Result<Response, AppError> {
    info!(
        "Processing streaming Anthropic request for model: {}",
        bedrock_model_id
    );

    // Create ModelRequest for the service
    let model_request = ModelRequest {
        model_id: bedrock_model_id.clone(),
        body: bedrock_body,
        headers: headers.clone(),
        user_id,
        endpoint_type: "anthropic".to_string(),
    };

    // Use ModelService to invoke streaming model (includes automatic usage tracking)
    match model_service.invoke_model_stream(model_request).await {
        Ok(model_response) => {
            info!(
                "Model service streaming response received for model: {}",
                bedrock_model_id
            );

            // For streaming, we need to transform the response body
            // Since ModelService returns the full response body, we need to process it for streaming
            let chunk = Bytes::from(model_response.body);
            let transformed_chunk = match transform_streaming_event(&chunk, &model_mapper, &original_model) {
                Ok(Some(transformed)) => Bytes::from(transformed),
                Ok(None) => {
                    warn!("Skipped chunk during streaming transformation");
                    Bytes::new()
                }
                Err(e) => {
                    error!("Failed to transform streaming chunk: {}", e);
                    chunk // Pass through the original chunk on transformation error
                }
            };

            // Create body from the transformed chunk
            let body = Body::from(transformed_chunk);

            // Build response with proper SSE headers
            let mut response = Response::builder()
                .status(StatusCode::OK)
                .header("content-type", "text/event-stream")
                .header("cache-control", "no-cache")
                .header("connection", "keep-alive")
                .body(body)
                .unwrap();

            // Add important headers from model response (except problematic ones)
            for (name, value) in model_response.headers.iter() {
                let name_str = name.as_str();
                if name_str != "content-length"
                    && name_str != "transfer-encoding"
                    && name_str != "content-type"
                    && name_str != "cache-control"
                    && name_str != "connection"
                {
                    response.headers_mut().insert(name, value.clone());
                }
            }

            Ok(response)
        }
        Err(err) => {
            error!(
                "Model service streaming error for model {}: {}",
                bedrock_model_id, err
            );
            Err(err)
        }
    }
}

// Note: user_id is now directly extracted from JWT claims via claims.user_id()
// This eliminates the need for database lookups or hash calculations on every request

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::Config,
        storage::{memory::MemoryDatabaseStorage, Storage},
    };
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use std::sync::Arc;
    use tower::ServiceExt;

    fn create_test_model_service() -> Arc<ModelService> {
        let config = Config::default();
        let storage = Arc::new(Storage::new(
            Box::new(crate::storage::memory::MemoryCacheStorage::new(3600)),
            Box::new(MemoryDatabaseStorage::new()),
        ));
        Arc::new(ModelService::new_test(storage, config))
    }

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
        }))
        .unwrap()
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
        }))
        .unwrap()
    }

    #[tokio::test]
    async fn test_create_message_basic() {
        let model_service = create_test_model_service();
        let app = create_anthropic_routes().with_state(model_service);

        let request = Request::builder()
            .uri("/v1/messages")
            .method("POST")
            .header("Content-Type", "application/json")
            .body(Body::from(create_test_anthropic_request_json()))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();

        // Without authentication, should return UNAUTHORIZED
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_create_message_streaming() {
        let model_service = create_test_model_service();
        let app = create_anthropic_routes().with_state(model_service);

        let request = Request::builder()
            .uri("/v1/messages")
            .method("POST")
            .header("Content-Type", "application/json")
            .body(Body::from(create_test_streaming_request_json()))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();

        // Without authentication, should return UNAUTHORIZED
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_create_message_invalid_json() {
        let model_service = create_test_model_service();
        let app = create_anthropic_routes().with_state(model_service);

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
        let model_service = create_test_model_service();
        let app = create_anthropic_routes().with_state(model_service);

        let incomplete_request = serde_json::to_string(&serde_json::json!({
            "model": "claude-3-sonnet-20240229",
            // Missing messages and max_tokens
        }))
        .unwrap();

        let request = Request::builder()
            .uri("/v1/messages")
            .method("POST")
            .header("Content-Type", "application/json")
            .body(Body::from(incomplete_request))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        // Without authentication, should return UNAUTHORIZED
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_create_message_unsupported_model() {
        let model_service = create_test_model_service();
        let app = create_anthropic_routes().with_state(model_service);

        let request_with_unsupported_model = serde_json::to_string(&serde_json::json!({
            "model": "unsupported-model",
            "messages": [
                {
                    "role": "user",
                    "content": "Hello"
                }
            ],
            "max_tokens": 1000
        }))
        .unwrap();

        let request = Request::builder()
            .uri("/v1/messages")
            .method("POST")
            .header("Content-Type", "application/json")
            .body(Body::from(request_with_unsupported_model))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        // Without authentication, should return UNAUTHORIZED
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_create_message_with_system_prompt() {
        let model_service = create_test_model_service();
        let app = create_anthropic_routes().with_state(model_service);

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
        }))
        .unwrap();

        let request = Request::builder()
            .uri("/v1/messages")
            .method("POST")
            .header("Content-Type", "application/json")
            .body(Body::from(request_with_system))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();

        // Without authentication, should return UNAUTHORIZED
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_create_message_with_all_parameters() {
        let model_service = create_test_model_service();
        let app = create_anthropic_routes().with_state(model_service);

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
        }))
        .unwrap();

        let request = Request::builder()
            .uri("/v1/messages")
            .method("POST")
            .header("Content-Type", "application/json")
            .body(Body::from(full_request))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();

        // Without authentication, should return UNAUTHORIZED
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_create_message_with_model_alias() {
        let model_service = create_test_model_service();
        let app = create_anthropic_routes().with_state(model_service);

        let request_with_alias = serde_json::to_string(&serde_json::json!({
            "model": "claude-3-sonnet", // Using alias instead of full name
            "messages": [
                {
                    "role": "user",
                    "content": "Hello"
                }
            ],
            "max_tokens": 100
        }))
        .unwrap();

        let request = Request::builder()
            .uri("/v1/messages")
            .method("POST")
            .header("Content-Type", "application/json")
            .body(Body::from(request_with_alias))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();

        // Without authentication, should return UNAUTHORIZED
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_create_message_large_request() {
        let model_service = create_test_model_service();
        let app = create_anthropic_routes().with_state(model_service);

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
        }))
        .unwrap();

        let request = Request::builder()
            .uri("/v1/messages")
            .method("POST")
            .header("Content-Type", "application/json")
            .body(Body::from(large_request))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();

        // Without authentication, should return UNAUTHORIZED
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}
