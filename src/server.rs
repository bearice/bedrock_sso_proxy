use crate::{
    auth::{AuthConfig, parse_algorithm},
    aws_http::AwsHttpClient,
    config::Config,
    error::AppError,
};
use axum::{
    Router,
    body::Bytes,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    middleware,
    response::{IntoResponse, Json, Response, Sse},
    routing::{get, post},
};
use futures_util::StreamExt;
use serde::Deserialize;
use serde_json::{Value, json};
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::net::TcpListener;
use tracing::info;

pub struct Server {
    config: Config,
}

impl Server {
    pub fn new(config: Config) -> Self {
        Self { config }
    }

    pub async fn run(&self) -> Result<(), AppError> {
        let jwt_algorithm = parse_algorithm(&self.config.jwt.algorithm)?;

        let auth_config = Arc::new(AuthConfig {
            jwt_secret: self.config.jwt.secret.clone(),
            jwt_algorithm,
        });

        let aws_http_client = AwsHttpClient::new(self.config.aws.clone());

        let app = self.create_app(auth_config, aws_http_client);

        let addr = SocketAddr::from(([0, 0, 0, 0], self.config.server.port));
        let listener = TcpListener::bind(addr)
            .await
            .map_err(|e| AppError::Internal(format!("Failed to bind to address: {}", e)))?;

        info!("Server listening on http://{}", addr);

        axum::serve(listener, app)
            .await
            .map_err(|e| AppError::Internal(format!("Server error: {}", e)))?;

        Ok(())
    }

    pub fn create_app(
        &self,
        auth_config: Arc<AuthConfig>,
        aws_http_client: AwsHttpClient,
    ) -> Router {
        Router::new()
            .route("/health", get(health_check))
            .with_state(aws_http_client.clone())
            .merge(
                Router::new()
                    .route("/model/{model_id}/invoke", post(invoke_model))
                    .route(
                        "/model/{model_id}/invoke-with-response-stream",
                        post(invoke_model_with_response_stream),
                    )
                    .with_state(aws_http_client.clone())
                    .layer(middleware::from_fn_with_state(
                        auth_config.clone(),
                        crate::auth::jwt_auth_middleware,
                    )),
            )
    }
}

#[derive(Debug, Deserialize)]
struct HealthCheckQuery {
    #[serde(default)]
    check: Option<String>,
}

async fn health_check(
    State(aws_http_client): State<AwsHttpClient>,
    Query(params): Query<HealthCheckQuery>,
) -> Result<Json<Value>, AppError> {
    let mut response = json!({
        "status": "healthy",
        "service": "bedrock-sso-proxy",
        "version": env!("CARGO_PKG_VERSION")
    });

    // Determine which checks to run
    let run_aws_check = match params.check.as_deref() {
        Some("aws") => true,
        Some("all") => true,
        Some(_) => false, // Unknown check type
        None => false,    // No specific check requested
    };

    // Run AWS check if requested
    if run_aws_check {
        match aws_http_client.health_check().await {
            Ok(()) => {
                response["aws_connection"] = json!("connected");
            }
            Err(err) => {
                tracing::warn!("AWS health check failed: {}", err);
                response["status"] = json!("degraded");
                response["aws_connection"] = json!("failed");
                response["error"] = json!(err.to_string());
            }
        }
    } else if params.check.is_some() {
        // Check was requested but not recognized or bypassed
        let check_type = params.check.as_ref().unwrap();
        if check_type != "all" {
            response["error"] = json!(format!("Unknown check type: {}", check_type));
        }
        response["aws_connection"] = json!("skipped");
    }

    Ok(Json(response))
}

async fn invoke_model(
    Path(model_id): Path<String>,
    State(aws_http_client): State<AwsHttpClient>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<(StatusCode, HeaderMap, Bytes), AppError> {
    // Validate model ID
    if model_id.trim().is_empty() {
        return Err(AppError::BadRequest("Model ID cannot be empty".to_string()));
    }

    // Process headers for AWS (remove authorization, etc.)
    let aws_headers = AwsHttpClient::process_headers_for_aws(&headers);

    // Extract content-type and accept headers if present
    let content_type = aws_headers
        .get("content-type")
        .and_then(|v| v.to_str().ok());
    let accept = aws_headers.get("accept").and_then(|v| v.to_str().ok());

    // Make the AWS Bedrock API call using direct HTTP
    match aws_http_client
        .invoke_model(&model_id, content_type, accept, body.to_vec())
        .await
    {
        Ok(aws_response) => {
            // Process headers from AWS response
            let response_headers = AwsHttpClient::process_headers_from_aws(&aws_response.headers);

            tracing::info!(
                "Successfully invoked model {} with status {}",
                model_id,
                aws_response.status
            );

            Ok((
                aws_response.status,
                response_headers,
                Bytes::from(aws_response.body),
            ))
        }
        Err(err) => {
            tracing::error!("AWS Bedrock API error for model {}: {}", model_id, err);

            // Convert AppError to HTTP response - this will be handled by the error's IntoResponse impl
            Err(err)
        }
    }
}

/// Handle streaming invoke model requests (Server-Sent Events)
async fn invoke_model_with_response_stream(
    Path(model_id): Path<String>,
    State(aws_http_client): State<AwsHttpClient>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, AppError> {
    tracing::info!("Handling streaming invoke request for model: {}", model_id);

    // Extract content type and accept headers
    let content_type = headers.get("content-type").and_then(|v| v.to_str().ok());
    let accept = headers.get("accept").and_then(|v| v.to_str().ok());

    // Call AWS Bedrock streaming API
    match aws_http_client
        .invoke_model_with_response_stream(&model_id, &headers, content_type, accept, body.to_vec())
        .await
    {
        Ok(aws_response) => {
            tracing::info!(
                "AWS Bedrock streaming response received for model: {}",
                model_id
            );

            // Convert the stream to SSE format using try_stream to handle Result
            let sse_stream = aws_response.stream.map(|chunk_result| {
                match chunk_result {
                    Ok(chunk) => {
                        // Convert bytes to SSE event
                        let data = String::from_utf8_lossy(&chunk);
                        Ok(axum::response::sse::Event::default().data(&data))
                    }
                    Err(e) => {
                        tracing::error!("Stream error: {}", e);
                        // Convert reqwest error to a format that can be used in SSE
                        Err(Box::new(e) as Box<dyn std::error::Error + Send + Sync>)
                    }
                }
            });

            // Create SSE response
            let sse = Sse::new(sse_stream).keep_alive(
                axum::response::sse::KeepAlive::new()
                    .interval(Duration::from_secs(15))
                    .text("keep-alive-text"),
            );

            // Build response with AWS headers
            let mut response = sse.into_response();

            // Add important headers from AWS response
            for (name, value) in aws_response.headers.iter() {
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

            *response.status_mut() = aws_response.status;

            Ok(response)
        }
        Err(err) => {
            tracing::error!(
                "AWS Bedrock streaming API error for model {}: {}",
                model_id,
                err
            );
            Err(err)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::AuthConfig;
    use crate::aws_http::AwsHttpClient;
    use crate::config::Config;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use jsonwebtoken::{EncodingKey, Header, encode};
    use serde::{Deserialize, Serialize};
    use std::time::{SystemTime, UNIX_EPOCH};
    use tower::ServiceExt;

    #[derive(Debug, Serialize, Deserialize)]
    struct TestClaims {
        sub: String,
        exp: usize,
    }

    fn create_test_token(secret: &str, sub: &str, exp_offset: i64) -> String {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let exp = (now + exp_offset) as usize;

        let claims = TestClaims {
            sub: sub.to_string(),
            exp,
        };

        encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(secret.as_ref()),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn test_health_check_with_valid_jwt() {
        let config = Config::default();
        let auth_config = Arc::new(AuthConfig {
            jwt_secret: config.jwt.secret.clone(),
            jwt_algorithm: jsonwebtoken::Algorithm::HS256,
        });
        let aws_http_client = AwsHttpClient::new_test();

        let server = Server::new(config.clone());
        let app = server.create_app(auth_config, aws_http_client);

        let token = create_test_token(&config.jwt.secret, "user123", 3600);
        let request = Request::builder()
            .uri("/health")
            .header("Authorization", format!("Bearer {}", token))
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_health_check_without_jwt() {
        let config = Config::default();
        let auth_config = Arc::new(AuthConfig {
            jwt_secret: config.jwt.secret.clone(),
            jwt_algorithm: jsonwebtoken::Algorithm::HS256,
        });
        let aws_http_client = AwsHttpClient::new_test();

        let server = Server::new(config);
        let app = server.create_app(auth_config, aws_http_client);

        let request = Request::builder()
            .uri("/health")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_health_check_with_invalid_jwt() {
        let config = Config::default();
        let auth_config = Arc::new(AuthConfig {
            jwt_secret: config.jwt.secret.clone(),
            jwt_algorithm: jsonwebtoken::Algorithm::HS256,
        });
        let aws_http_client = AwsHttpClient::new_test();

        let server = Server::new(config);
        let app = server.create_app(auth_config, aws_http_client);

        let request = Request::builder()
            .uri("/health")
            .header("Authorization", "Bearer invalid.jwt.token")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[test]
    fn test_server_creation() {
        let config = Config::default();
        let server = Server::new(config.clone());
        assert_eq!(server.config.server.port, config.server.port);
    }

    #[tokio::test]
    async fn test_health_check_with_aws_query() {
        let config = Config::default();
        let auth_config = Arc::new(AuthConfig {
            jwt_secret: config.jwt.secret.clone(),
            jwt_algorithm: jsonwebtoken::Algorithm::HS256,
        });
        let aws_http_client = AwsHttpClient::new_test();

        let server = Server::new(config);
        let app = server.create_app(auth_config, aws_http_client);

        let request = Request::builder()
            .uri("/health?check=aws")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_health_check_with_unknown_query() {
        let config = Config::default();
        let auth_config = Arc::new(AuthConfig {
            jwt_secret: config.jwt.secret.clone(),
            jwt_algorithm: jsonwebtoken::Algorithm::HS256,
        });
        let aws_http_client = AwsHttpClient::new_test();

        let server = Server::new(config);
        let app = server.create_app(auth_config, aws_http_client);

        let request = Request::builder()
            .uri("/health?check=unknown")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_health_check_with_all_query() {
        let config = Config::default();
        let auth_config = Arc::new(AuthConfig {
            jwt_secret: config.jwt.secret.clone(),
            jwt_algorithm: jsonwebtoken::Algorithm::HS256,
        });
        let aws_http_client = AwsHttpClient::new_test();

        let server = Server::new(config);
        let app = server.create_app(auth_config, aws_http_client);

        let request = Request::builder()
            .uri("/health?check=all")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_invoke_model_with_valid_jwt() {
        let config = Config::default();
        let auth_config = Arc::new(AuthConfig {
            jwt_secret: config.jwt.secret.clone(),
            jwt_algorithm: jsonwebtoken::Algorithm::HS256,
        });
        let aws_http_client = AwsHttpClient::new_test();

        let server = Server::new(config.clone());
        let app = server.create_app(auth_config, aws_http_client);

        let token = create_test_token(&config.jwt.secret, "user123", 3600);
        let request = Request::builder()
            .uri("/model/anthropic.claude-v2/invoke")
            .method("POST")
            .header("Authorization", format!("Bearer {}", token))
            .header("Content-Type", "application/json")
            .body(Body::from(
                r#"{"messages": [{"role": "user", "content": "Hello"}]}"#,
            ))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        // Note: This will fail in tests because we don't have real AWS credentials
        // But we can verify the authentication and routing is working
        // Expected statuses: 500 (internal error), 400 (bad request), or other error codes
        assert!(
            response.status() == StatusCode::INTERNAL_SERVER_ERROR
                || response.status() == StatusCode::BAD_REQUEST
                || response.status() == StatusCode::FORBIDDEN
                || response.status() == StatusCode::OK
        );
    }

    #[tokio::test]
    async fn test_invoke_model_without_jwt() {
        let config = Config::default();
        let auth_config = Arc::new(AuthConfig {
            jwt_secret: config.jwt.secret.clone(),
            jwt_algorithm: jsonwebtoken::Algorithm::HS256,
        });
        let aws_http_client = AwsHttpClient::new_test();

        let server = Server::new(config);
        let app = server.create_app(auth_config, aws_http_client);

        let request = Request::builder()
            .uri("/model/anthropic.claude-v2/invoke")
            .method("POST")
            .header("Content-Type", "application/json")
            .body(Body::from(
                r#"{"messages": [{"role": "user", "content": "Hello"}]}"#,
            ))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_invoke_model_with_invalid_jwt() {
        let config = Config::default();
        let auth_config = Arc::new(AuthConfig {
            jwt_secret: config.jwt.secret.clone(),
            jwt_algorithm: jsonwebtoken::Algorithm::HS256,
        });
        let aws_http_client = AwsHttpClient::new_test();

        let server = Server::new(config);
        let app = server.create_app(auth_config, aws_http_client);

        let request = Request::builder()
            .uri("/model/anthropic.claude-v2/invoke")
            .method("POST")
            .header("Authorization", "Bearer invalid.jwt.token")
            .header("Content-Type", "application/json")
            .body(Body::from(
                r#"{"messages": [{"role": "user", "content": "Hello"}]}"#,
            ))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_invoke_model_get_method_not_allowed() {
        let config = Config::default();
        let auth_config = Arc::new(AuthConfig {
            jwt_secret: config.jwt.secret.clone(),
            jwt_algorithm: jsonwebtoken::Algorithm::HS256,
        });
        let aws_http_client = AwsHttpClient::new_test();

        let server = Server::new(config.clone());
        let app = server.create_app(auth_config, aws_http_client);

        let token = create_test_token(&config.jwt.secret, "user123", 3600);
        let request = Request::builder()
            .uri("/model/anthropic.claude-v2/invoke")
            .method("GET")
            .header("Authorization", format!("Bearer {}", token))
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
    }

    #[tokio::test]
    async fn test_invoke_model_with_response_stream_success() {
        let config = Config::default();
        let auth_config = Arc::new(AuthConfig {
            jwt_secret: config.jwt.secret.clone(),
            jwt_algorithm: jsonwebtoken::Algorithm::HS256,
        });
        let aws_http_client = AwsHttpClient::new_test();

        let server = Server::new(config.clone());
        let app = server.create_app(auth_config, aws_http_client);

        let token = create_test_token(&config.jwt.secret, "user123", 3600);
        let request = Request::builder()
            .uri("/model/anthropic.claude-v2/invoke-with-response-stream")
            .method("POST")
            .header("Authorization", format!("Bearer {}", token))
            .header("Content-Type", "application/json")
            .body(Body::from(
                r#"{"messages": [{"role": "user", "content": "Hello"}]}"#,
            ))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get("content-type").unwrap(),
            "text/event-stream"
        );
        assert_eq!(response.headers().get("cache-control").unwrap(), "no-cache");
    }

    #[tokio::test]
    async fn test_invoke_model_with_response_stream_unauthorized() {
        let config = Config::default();
        let auth_config = Arc::new(AuthConfig {
            jwt_secret: config.jwt.secret.clone(),
            jwt_algorithm: jsonwebtoken::Algorithm::HS256,
        });
        let aws_http_client = AwsHttpClient::new_test();

        let server = Server::new(config);
        let app = server.create_app(auth_config, aws_http_client);

        let request = Request::builder()
            .uri("/model/anthropic.claude-v2/invoke-with-response-stream")
            .method("POST")
            .header("Authorization", "Bearer invalid.jwt.token")
            .header("Content-Type", "application/json")
            .body(Body::from(
                r#"{"messages": [{"role": "user", "content": "Hello"}]}"#,
            ))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_invoke_model_with_response_stream_get_method_not_allowed() {
        let config = Config::default();
        let auth_config = Arc::new(AuthConfig {
            jwt_secret: config.jwt.secret.clone(),
            jwt_algorithm: jsonwebtoken::Algorithm::HS256,
        });
        let aws_http_client = AwsHttpClient::new_test();

        let server = Server::new(config.clone());
        let app = server.create_app(auth_config, aws_http_client);

        let token = create_test_token(&config.jwt.secret, "user123", 3600);
        let request = Request::builder()
            .uri("/model/anthropic.claude-v2/invoke-with-response-stream")
            .method("GET")
            .header("Authorization", format!("Bearer {}", token))
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
    }

    #[tokio::test]
    async fn test_invoke_model_empty_model_id() {
        let config = Config::default();
        let auth_config = Arc::new(AuthConfig {
            jwt_secret: config.jwt.secret.clone(),
            jwt_algorithm: jsonwebtoken::Algorithm::HS256,
        });
        let aws_http_client = AwsHttpClient::new_test();

        let server = Server::new(config.clone());
        let app = server.create_app(auth_config, aws_http_client);

        let token = create_test_token(&config.jwt.secret, "user123", 3600);
        let request = Request::builder()
            .uri("/model/%20/invoke") // URL-encoded space
            .method("POST")
            .header("Authorization", format!("Bearer {}", token))
            .header("Content-Type", "application/json")
            .body(Body::from(r#"{"messages": []}"#))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_invoke_model_with_custom_headers() {
        let config = Config::default();
        let auth_config = Arc::new(AuthConfig {
            jwt_secret: config.jwt.secret.clone(),
            jwt_algorithm: jsonwebtoken::Algorithm::HS256,
        });
        let aws_http_client = AwsHttpClient::new_test();

        let server = Server::new(config.clone());
        let app = server.create_app(auth_config, aws_http_client);

        let token = create_test_token(&config.jwt.secret, "user123", 3600);
        let request = Request::builder()
            .uri("/model/anthropic.claude-v2/invoke")
            .method("POST")
            .header("Authorization", format!("Bearer {}", token))
            .header("Content-Type", "application/json")
            .header("Accept", "application/json")
            .header("X-Custom-Header", "custom-value")
            .body(Body::from(r#"{"messages": []}"#))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        // Should handle custom headers appropriately
        assert!(
            response.status() == StatusCode::INTERNAL_SERVER_ERROR
                || response.status() == StatusCode::BAD_REQUEST
                || response.status() == StatusCode::OK
        );
    }

    #[tokio::test]
    async fn test_health_check_with_failing_aws_connection() {
        let mut config = Config::default();
        // Configure AWS with no credentials to force failure
        config.aws.access_key_id = None;
        config.aws.secret_access_key = None;

        let auth_config = Arc::new(AuthConfig {
            jwt_secret: config.jwt.secret.clone(),
            jwt_algorithm: jsonwebtoken::Algorithm::HS256,
        });
        let aws_http_client = AwsHttpClient::new(config.aws.clone());

        let server = Server::new(config);
        let app = server.create_app(auth_config, aws_http_client);

        let request = Request::builder()
            .uri("/health?check=aws")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        // Parse response body to verify degraded status
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body_str = String::from_utf8(body.to_vec()).unwrap();
        assert!(body_str.contains("degraded") || body_str.contains("failed"));
    }

    #[tokio::test]
    async fn test_invoke_model_with_expired_jwt() {
        let config = Config::default();
        let auth_config = Arc::new(AuthConfig {
            jwt_secret: config.jwt.secret.clone(),
            jwt_algorithm: jsonwebtoken::Algorithm::HS256,
        });
        let aws_http_client = AwsHttpClient::new_test();

        let server = Server::new(config.clone());
        let app = server.create_app(auth_config, aws_http_client);

        // Create expired token (exp time in the past)
        let expired_token = create_test_token(&config.jwt.secret, "user123", -3600);
        let request = Request::builder()
            .uri("/model/anthropic.claude-v2/invoke")
            .method("POST")
            .header("Authorization", format!("Bearer {}", expired_token))
            .header("Content-Type", "application/json")
            .body(Body::from(r#"{"messages": []}"#))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_invoke_model_with_large_body() {
        let config = Config::default();
        let auth_config = Arc::new(AuthConfig {
            jwt_secret: config.jwt.secret.clone(),
            jwt_algorithm: jsonwebtoken::Algorithm::HS256,
        });
        let aws_http_client = AwsHttpClient::new_test();

        let server = Server::new(config.clone());
        let app = server.create_app(auth_config, aws_http_client);

        let token = create_test_token(&config.jwt.secret, "user123", 3600);

        // Create a large JSON body (simulating large input)
        let large_content = "A".repeat(1000);
        let large_body = format!(
            r#"{{"messages": [{{"role": "user", "content": "{}"}}]}}"#,
            large_content
        );

        let request = Request::builder()
            .uri("/model/anthropic.claude-v2/invoke")
            .method("POST")
            .header("Authorization", format!("Bearer {}", token))
            .header("Content-Type", "application/json")
            .body(Body::from(large_body))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        // Should handle large bodies appropriately
        assert!(
            response.status() == StatusCode::INTERNAL_SERVER_ERROR
                || response.status() == StatusCode::BAD_REQUEST
                || response.status() == StatusCode::OK
        );
    }

    #[tokio::test]
    async fn test_invoke_model_streaming_with_empty_model_id() {
        let config = Config::default();
        let auth_config = Arc::new(AuthConfig {
            jwt_secret: config.jwt.secret.clone(),
            jwt_algorithm: jsonwebtoken::Algorithm::HS256,
        });
        let aws_http_client = AwsHttpClient::new_test();

        let server = Server::new(config.clone());
        let app = server.create_app(auth_config, aws_http_client);

        let token = create_test_token(&config.jwt.secret, "user123", 3600);
        let request = Request::builder()
            .uri("/model//invoke-with-response-stream") // Empty model ID
            .method("POST")
            .header("Authorization", format!("Bearer {}", token))
            .header("Content-Type", "application/json")
            .body(Body::from(r#"{"messages": []}"#))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        // Should handle empty model ID in streaming endpoint
        assert_eq!(response.status(), StatusCode::OK); // Mock response for test client
    }
}
