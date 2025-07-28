use crate::{
    anthropic::{
        AnthropicRequest,
        model_mapping::ModelMapper,
        transform::{
            transform_anthropic_to_bedrock, transform_bedrock_event_to_anthropic,
            transform_bedrock_to_anthropic, validate_anthropic_request,
        },
    },
    auth::jwt::OAuthClaims,
    error::AppError,
    model_service::{ModelRequest, ModelService},
};
use axum::{
    Router,
    body::{Body, Bytes},
    extract::{Extension, State},
    http::{HeaderMap, StatusCode},
    response::Response,
    routing::post,
};
use futures_util::StreamExt;
use serde_json::json;
use std::sync::Arc;
use tracing::{error, info};

/// Create routes for Anthropic API endpoints
pub fn create_anthropic_routes() -> Router<Arc<ModelService>> {
    Router::new().route("/v1/messages", post(create_message))
}

/// Handle POST /v1/messages - Anthropic API format message creation
/// Supports both streaming and non-streaming responses based on the `stream` parameter
pub async fn create_message(
    State(model_service): State<Arc<ModelService>>,
    Extension(claims): Extension<OAuthClaims>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, AppError> {
    info!("Handling Anthropic API /v1/messages request");

    // Extract user_id directly from JWT claims
    let user_id = claims.sub;
    tracing::trace!("User ID from JWT claims: {}", user_id);

    // Log request body details for debugging
    tracing::trace!("Request body size: {} bytes", body.len());

    // Log first 500 characters of the body for debugging (safely)
    let body_preview = if body.len() > 500 {
        format!("{}... (truncated)", String::from_utf8_lossy(&body[..500]))
    } else {
        String::from_utf8_lossy(&body).to_string()
    };
    tracing::trace!("Request body preview: {}", body_preview);

    // Parse the Anthropic request
    let anthropic_request: AnthropicRequest = serde_json::from_slice(&body).map_err(|e| {
        error!("Failed to parse JSON request body. Error: {}", e);
        tracing::trace!("Body length: {} bytes", body.len());
        if body.len() < 1000 {
            tracing::trace!("Full body content: {}", String::from_utf8_lossy(&body));
        } else {
            tracing::trace!(
                "Body too large to log completely. First 1000 chars: {}",
                String::from_utf8_lossy(&body[..1000])
            );
        }
        AppError::BadRequest(format!("Invalid JSON request: {}", e))
    })?;

    // Log successful parsing
    tracing::trace!(
        "Successfully parsed Anthropic request - Model: {}, Messages: {}, Max tokens: {}",
        anthropic_request.model,
        anthropic_request.messages.len(),
        anthropic_request.max_tokens
    );

    // Validate the request format
    validate_anthropic_request(&anthropic_request).map_err(AppError::from)?;
    tracing::trace!("Request validation passed");

    // Create model mapper for transformations from service config
    let model_mapper = model_service.create_model_mapper();

    // Transform Anthropic request to Bedrock format
    tracing::trace!(
        "Transforming Anthropic model '{}' to Bedrock format",
        anthropic_request.model
    );
    let (bedrock_request, bedrock_model_id) =
        transform_anthropic_to_bedrock(anthropic_request.clone(), &model_mapper).map_err(|e| {
            error!(
                "Failed to transform Anthropic request to Bedrock format: {}",
                e
            );
            AppError::from(e)
        })?;
    tracing::trace!(
        "Successfully transformed to Bedrock model ID: {}",
        bedrock_model_id
    );

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
                "Bedrock model {} invocation completed with status {}",
                bedrock_model_id, model_response.status
            );

            // Check for HTTP error status first
            if !model_response.status.is_success() {
                // Parse error response
                let error_response: serde_json::Value =
                    serde_json::from_slice(&model_response.body)
                        .unwrap_or_else(|_| json!({"message": "Unknown error"}));

                let error_message = error_response
                    .get("message")
                    .and_then(|m| m.as_str())
                    .unwrap_or("Unknown AWS error");

                error!(
                    "AWS Bedrock error ({}): {}",
                    model_response.status, error_message
                );

                // Return appropriate error based on status code
                return match model_response.status.as_u16() {
                    403 => Err(AppError::BadRequest(format!(
                        "Model access denied: {}. Please ensure the model is enabled in your AWS Bedrock console and your credentials have the necessary permissions.",
                        error_message
                    ))),
                    400 => Err(AppError::BadRequest(format!(
                        "Invalid request: {}",
                        error_message
                    ))),
                    401 => Err(AppError::Unauthorized(format!(
                        "Authentication failed: {}",
                        error_message
                    ))),
                    429 => Err(AppError::BadRequest(format!(
                        "Rate limit exceeded: {}",
                        error_message
                    ))),
                    _ => Err(AppError::Internal(format!(
                        "AWS Bedrock error ({}): {}",
                        model_response.status, error_message
                    ))),
                };
            }

            // Parse successful response body as JSON
            let bedrock_response: serde_json::Value = serde_json::from_slice(&model_response.body)
                .map_err(|e| {
                    error!("Failed to parse successful Bedrock response: {}", e);
                    error!(
                        "Raw Bedrock response body: {}",
                        String::from_utf8_lossy(&model_response.body)
                    );
                    AppError::Internal(format!("Failed to parse Bedrock response: {}", e))
                })?;

            // Transform Bedrock response to Anthropic format
            let anthropic_response =
                transform_bedrock_to_anthropic(bedrock_response, &original_model, &model_mapper)
                    .map_err(|e| {
                        error!("Transformation error: {}", e);
                        AppError::from(e)
                    })?;

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
    _model_mapper: ModelMapper,
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

            // For streaming, we transform each parsed event
            let transformed_stream = model_response.stream.map(move |event_result| {
                match event_result {
                    Ok(sse_event) => {
                        if let Some(data) = sse_event.data {
                            let data_clone = data.clone();
                            match transform_bedrock_event_to_anthropic(data, &original_model) {
                                Ok(transformed) => {
                                    // Format as SSE event
                                    let sse_output = format!(
                                        "data: {}\n\n",
                                        serde_json::to_string(&transformed).unwrap_or_default()
                                    );
                                    Ok(Bytes::from(sse_output))
                                }
                                Err(e) => {
                                    error!("Failed to transform streaming event: {}", e);
                                    // For transformation errors, create SSE format from original JSON
                                    let sse_output = format!(
                                        "data: {}\n\n",
                                        serde_json::to_string(&data_clone).unwrap_or_default()
                                    );
                                    Ok(Bytes::from(sse_output))
                                }
                            }
                        } else {
                            // No data to transform, create empty SSE event
                            Ok(Bytes::from("data: {}\n\n"))
                        }
                    }
                    Err(e) => Err(e),
                }
            });

            // Create body from the transformed stream
            let body = Body::from_stream(transformed_stream);

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
    use crate::{auth::middleware::jwt_auth_middleware, config::Config};
    use axum::{
        body::Body,
        http::{Request, StatusCode},
        middleware,
    };

    use tower::ServiceExt;

    async fn create_test_server() -> crate::server::Server {
        let mut config = Config::default();
        config.cache.backend = "memory".to_string();
        config.database.enabled = true;
        config.database.url = "sqlite::memory:".to_string(); // Use in-memory database
        config.metrics.enabled = false;

        let server = crate::server::Server::new(config).await.unwrap();

        // Run migrations to create tables
        server.database.migrate().await.unwrap();

        server
    }

    async fn create_test_user(server: &crate::server::Server, user_id: i32, email: &str) -> i32 {
        let user = crate::database::entities::UserRecord {
            id: 0, // Let database assign ID
            provider_user_id: format!("test_user_{}", user_id),
            provider: "test".to_string(),
            email: email.to_string(),
            display_name: Some(format!("Test User {}", user_id)),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            last_login: Some(chrono::Utc::now()),
        };
        server.database.users().upsert(&user).await.unwrap()
    }

    fn create_test_anthropic_request_json() -> String {
        serde_json::to_string(&serde_json::json!({
            "model": "claude-sonnet-4-20250514",
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
            "model": "claude-sonnet-4-20250514",
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
        let server = create_test_server().await;
        let app = create_anthropic_routes()
            .with_state(server.model_service.clone())
            .layer(middleware::from_fn_with_state(
                server.clone(),
                jwt_auth_middleware,
            ));

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
        let server = create_test_server().await;
        let app = create_anthropic_routes()
            .with_state(server.model_service.clone())
            .layer(middleware::from_fn_with_state(
                server.clone(),
                jwt_auth_middleware,
            ));

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
        let server = create_test_server().await;
        let app = create_anthropic_routes()
            .with_state(server.model_service.clone())
            .layer(middleware::from_fn_with_state(
                server.clone(),
                jwt_auth_middleware,
            ));

        // Create a valid JWT token for the test
        fn create_oauth_token(jwt_service: &crate::auth::jwt::JwtService, user_id: i32) -> String {
            let claims = crate::auth::jwt::OAuthClaims::new(user_id, 3600);
            jwt_service.create_oauth_token(&claims).unwrap()
        }

        // Create test user first
        let user_id = create_test_user(&server, 1, "test@example.com").await;
        let token = create_oauth_token(&server.jwt_service, user_id);

        let request = Request::builder()
            .uri("/v1/messages")
            .method("POST")
            .header("Content-Type", "application/json")
            .header("Authorization", format!("Bearer {}", token))
            .body(Body::from("invalid json"))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        // Invalid JSON should return 400 Bad Request
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_create_message_missing_required_fields() {
        let server = create_test_server().await;
        let app = create_anthropic_routes()
            .with_state(server.model_service.clone())
            .layer(middleware::from_fn_with_state(
                server.clone(),
                jwt_auth_middleware,
            ));

        let incomplete_request = serde_json::to_string(&serde_json::json!({
            "model": "claude-sonnet-4-20250514",
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
        let server = create_test_server().await;
        let app = create_anthropic_routes()
            .with_state(server.model_service.clone())
            .layer(middleware::from_fn_with_state(
                server.clone(),
                jwt_auth_middleware,
            ));

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
        let server = create_test_server().await;
        let app = create_anthropic_routes()
            .with_state(server.model_service.clone())
            .layer(middleware::from_fn_with_state(
                server.clone(),
                jwt_auth_middleware,
            ));

        let request_with_system = serde_json::to_string(&serde_json::json!({
            "model": "claude-sonnet-4-20250514",
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
        let server = create_test_server().await;
        let app = create_anthropic_routes()
            .with_state(server.model_service.clone())
            .layer(middleware::from_fn_with_state(
                server.clone(),
                jwt_auth_middleware,
            ));

        let full_request = serde_json::to_string(&serde_json::json!({
            "model": "claude-sonnet-4-20250514",
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
        let server = create_test_server().await;
        let app = create_anthropic_routes()
            .with_state(server.model_service.clone())
            .layer(middleware::from_fn_with_state(
                server.clone(),
                jwt_auth_middleware,
            ));

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
        let server = create_test_server().await;
        let app = create_anthropic_routes()
            .with_state(server.model_service.clone())
            .layer(middleware::from_fn_with_state(
                server.clone(),
                jwt_auth_middleware,
            ));

        // Create a large content string
        let large_content = "A".repeat(5000);
        let large_request = serde_json::to_string(&serde_json::json!({
            "model": "claude-sonnet-4-20250514",
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
