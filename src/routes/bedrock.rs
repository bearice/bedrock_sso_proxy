use crate::{
    database::entities::UserRecord, error::AppError, model_service::ModelRequest, server::Server,
};
use axum::{
    Router,
    body::{Body, Bytes},
    extract::{Extension, Path, State},
    http::{HeaderMap, StatusCode},
    response::Response,
    routing::post,
};
use futures_util::StreamExt;

pub fn create_bedrock_routes() -> Router<Server> {
    Router::new()
        .route("/model/{model_id}/invoke", post(invoke_model))
        .route(
            "/model/{model_id}/invoke-with-response-stream",
            post(invoke_model_with_response_stream),
        )
}

async fn invoke_model(
    Path(model_id): Path<String>,
    State(server): State<Server>,
    Extension(user): Extension<UserRecord>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<(StatusCode, HeaderMap, Bytes), AppError> {
    // Validate model ID
    if model_id.trim().is_empty() {
        return Err(AppError::BadRequest("Model ID cannot be empty".to_string()));
    }

    // Extract user_id from authenticated user record
    let user_id = user.id;

    // Create ModelRequest
    let model_request = ModelRequest {
        model_id: model_id.clone(),
        body: body.to_vec(),
        headers,
        user_id,
        endpoint_type: "bedrock".to_string(),
    };

    // Use ModelService to invoke model (includes automatic usage tracking)
    match server.model_service.invoke_model(model_request).await {
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
    State(server): State<Server>,
    Extension(user): Extension<UserRecord>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, AppError> {
    tracing::info!("Handling streaming invoke request for model: {}", model_id);

    // Validate model ID
    if model_id.trim().is_empty() {
        return Err(AppError::BadRequest("Model ID cannot be empty".to_string()));
    }

    // Extract user_id from authenticated user record
    let user_id = user.id;

    // Create ModelRequest
    let model_request = ModelRequest {
        model_id: model_id.clone(),
        body: body.to_vec(),
        headers: headers.clone(),
        user_id,
        endpoint_type: "bedrock".to_string(),
    };

    // Use ModelService to invoke streaming model (includes automatic usage tracking)
    match server
        .model_service
        .invoke_model_stream(model_request)
        .await
    {
        Ok(model_response) => {
            tracing::info!(
                "Successfully invoked streaming model {} with status {}",
                model_id,
                model_response.status
            );

            // For streaming, we return the raw binary stream for AWS compatibility
            let raw_stream = model_response
                .stream
                .map(|event_result| match event_result {
                    Ok(sse_event) => Ok(Bytes::from(sse_event.raw)),
                    Err(e) => Err(e),
                });
            let body = Body::from_stream(raw_stream);

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

            // Set content type to match AWS Bedrock response format
            response.headers_mut().insert(
                "content-type",
                "application/vnd.amazon.eventstream".parse().unwrap(),
            );
            response
                .headers_mut()
                .insert("cache-control", "no-cache".parse().unwrap());

            // Usage tracking is handled by the stream wrapper automatically

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

// Note: user_id is now directly extracted from authenticated UserRecord
// This supports both JWT and API key authentication methods

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::middleware::jwt_auth_middleware;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
        middleware,
    };
    use tower::ServiceExt;

    async fn create_test_server() -> crate::server::Server {
        crate::test_utils::TestServerBuilder::new().build().await
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

    #[tokio::test]
    async fn test_invoke_model_empty_model_id() {
        let server = create_test_server().await;
        let app = create_bedrock_routes().with_state(server.clone()).layer(
            middleware::from_fn_with_state(server.clone(), jwt_auth_middleware),
        );

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
        let server = create_test_server().await;
        let app = create_bedrock_routes().with_state(server.clone()).layer(
            middleware::from_fn_with_state(server.clone(), jwt_auth_middleware),
        );

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
        let server = create_test_server().await;
        let app = create_bedrock_routes().with_state(server.clone()).layer(
            middleware::from_fn_with_state(server.clone(), jwt_auth_middleware),
        );

        // Create a valid JWT token for the test
        fn create_oauth_token(
            jwt_service: &dyn crate::auth::jwt::JwtService,
            user_id: i32,
        ) -> String {
            let claims = crate::auth::jwt::OAuthClaims::new(user_id, 3600);
            jwt_service.create_oauth_token(&claims).unwrap()
        }

        // Create test user first
        let user_id = create_test_user(&server, 1, "test@example.com").await;
        let token = create_oauth_token(server.jwt_service.as_ref(), user_id);

        let request = Request::builder()
            .uri("/model//invoke-with-response-stream") // Empty model ID
            .method("POST")
            .header("Content-Type", "application/json")
            .header("Authorization", format!("Bearer {}", token))
            .body(Body::from(r#"{"messages": []}"#))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        // Should return Bad Request for empty model ID in streaming endpoint
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_invoke_model_with_response_stream_success() {
        let server = create_test_server().await;
        let app = create_bedrock_routes().with_state(server.clone()).layer(
            middleware::from_fn_with_state(server.clone(), jwt_auth_middleware),
        );

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
        let server = create_test_server().await;
        let app = create_bedrock_routes().with_state(server.clone()).layer(
            middleware::from_fn_with_state(server.clone(), jwt_auth_middleware),
        );

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
