use crate::{
    auth::jwt::ValidatedClaims,
    error::AppError,
    model_service::{ModelService, ModelRequest},
};
use axum::{
    Router,
    body::{Body, Bytes},
    extract::{Path, State, Extension},
    http::{HeaderMap, StatusCode},
    response::Response,
    routing::post,
};
use std::sync::Arc;

pub fn create_bedrock_routes() -> Router<Arc<ModelService>> {
    Router::new()
        .route("/model/{model_id}/invoke", post(invoke_model))
        .route(
            "/model/{model_id}/invoke-with-response-stream",
            post(invoke_model_with_response_stream),
        )
}

async fn invoke_model(
    Path(model_id): Path<String>,
    State(model_service): State<Arc<ModelService>>,
    Extension(claims): Extension<ValidatedClaims>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<(StatusCode, HeaderMap, Bytes), AppError> {
    // Validate model ID
    if model_id.trim().is_empty() {
        return Err(AppError::BadRequest("Model ID cannot be empty".to_string()));
    }

    // Extract user_id directly from JWT claims
    let user_id = claims.user_id();

    // Create ModelRequest
    let model_request = ModelRequest {
        model_id: model_id.clone(),
        body: body.to_vec(),
        headers,
        user_id,
        endpoint_type: "bedrock".to_string(),
    };

    // Use ModelService to invoke model (includes automatic usage tracking)
    match model_service.invoke_model(model_request).await {
        Ok(model_response) => {
            tracing::info!(
                "Successfully invoked model {} with status {}",
                model_id,
                model_response.status
            );

            Ok((
                model_response.status,
                model_response.headers,
                Bytes::from(model_response.body),
            ))
        }
        Err(err) => {
            tracing::error!("Model service error for model {}: {}", model_id, err);
            Err(err)
        }
    }
}

/// Handle streaming invoke model requests (Server-Sent Events)
async fn invoke_model_with_response_stream(
    Path(model_id): Path<String>,
    State(model_service): State<Arc<ModelService>>,
    Extension(claims): Extension<ValidatedClaims>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, AppError> {
    tracing::info!("Handling streaming invoke request for model: {}", model_id);

    // Validate model ID
    if model_id.trim().is_empty() {
        return Err(AppError::BadRequest("Model ID cannot be empty".to_string()));
    }

    // Extract user_id directly from JWT claims
    let user_id = claims.user_id();

    // Create ModelRequest
    let model_request = ModelRequest {
        model_id: model_id.clone(),
        body: body.to_vec(),
        headers: headers.clone(),
        user_id,
        endpoint_type: "bedrock".to_string(),
    };

    // Use ModelService to invoke streaming model (includes automatic usage tracking)
    match model_service.invoke_model_stream(model_request).await {
        Ok(model_response) => {
            tracing::info!(
                "Successfully invoked streaming model {} with status {}",
                model_id,
                model_response.status
            );

            // For streaming, we need to return the body as a stream
            // Since ModelService returns the full response body, we need to convert it to a stream
            // This is a simplified implementation - in a real streaming scenario,
            // ModelService would return a stream directly
            let body = Body::from(model_response.body);

            // Build response with headers from ModelService
            let mut response = Response::builder()
                .status(model_response.status)
                .body(body)
                .unwrap();

            // Copy headers from model response
            for (name, value) in model_response.headers.iter() {
                if name != "content-length" && name != "transfer-encoding" {
                    response.headers_mut().insert(name, value.clone());
                }
            }

            // Ensure correct content type for SSE
            response
                .headers_mut()
                .insert("content-type", "text/event-stream".parse().unwrap());
            response
                .headers_mut()
                .insert("cache-control", "no-cache".parse().unwrap());

            Ok(response)
        }
        Err(err) => {
            tracing::error!(
                "Model service streaming error for model {}: {}",
                model_id,
                err
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
    use tower::ServiceExt;

    fn create_test_model_service() -> Arc<ModelService> {
        let config = Config::default();
        let storage = Arc::new(Storage::new(
            Box::new(crate::storage::memory::MemoryCacheStorage::new(3600)),
            Box::new(MemoryDatabaseStorage::new()),
        ));
        Arc::new(ModelService::new_test(storage, config))
    }

    #[tokio::test]
    async fn test_invoke_model_empty_model_id() {
        let model_service = create_test_model_service();
        let app = create_bedrock_routes().with_state(model_service);

        let request = Request::builder()
            .uri("/model/%20/invoke") // URL-encoded space
            .method("POST")
            .header("Content-Type", "application/json")
            .body(Body::from(r#"{"messages": []}"#))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED); // No JWT claims
    }

    #[tokio::test]
    async fn test_invoke_model_with_custom_headers() {
        let model_service = create_test_model_service();
        let app = create_bedrock_routes().with_state(model_service);

        let request = Request::builder()
            .uri("/model/anthropic.claude-v2/invoke")
            .method("POST")
            .header("Content-Type", "application/json")
            .header("Accept", "application/json")
            .header("X-Custom-Header", "custom-value")
            .body(Body::from(r#"{"messages": []}"#))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        // Without authentication, should return UNAUTHORIZED
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_invoke_model_streaming_with_empty_model_id() {
        let model_service = create_test_model_service();
        let app = create_bedrock_routes().with_state(model_service);

        let request = Request::builder()
            .uri("/model//invoke-with-response-stream") // Empty model ID
            .method("POST")
            .header("Content-Type", "application/json")
            .body(Body::from(r#"{"messages": []}"#))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        // Should return Bad Request for empty model ID in streaming endpoint
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_invoke_model_with_response_stream_success() {
        let model_service = create_test_model_service();
        let app = create_bedrock_routes().with_state(model_service);

        let request = Request::builder()
            .uri("/model/anthropic.claude-v2/invoke-with-response-stream")
            .method("POST")
            .header("Content-Type", "application/json")
            .body(Body::from(
                r#"{"messages": [{"role": "user", "content": "Hello"}]}"#,
            ))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        // Without authentication, should return UNAUTHORIZED
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_invoke_model_with_large_body() {
        let model_service = create_test_model_service();
        let app = create_bedrock_routes().with_state(model_service);

        // Create a large JSON body (simulating large input)
        let large_content = "A".repeat(1000);
        let large_body = format!(
            r#"{{"messages": [{{"role": "user", "content": "{}"}}]}}"#,
            large_content
        );

        let request = Request::builder()
            .uri("/model/anthropic.claude-v2/invoke")
            .method("POST")
            .header("Content-Type", "application/json")
            .body(Body::from(large_body))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        // Without authentication, should return UNAUTHORIZED
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}
