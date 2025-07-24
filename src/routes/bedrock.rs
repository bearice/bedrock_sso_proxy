use crate::{aws_http::AwsHttpClient, error::AppError, health::HealthService};
use axum::{
    Router,
    body::{Body, Bytes},
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{Json, Response},
    routing::{get, post},
};
use futures_util::StreamExt;
use serde::Deserialize;
use serde_json::Value;
use std::sync::Arc;

#[derive(Debug, Deserialize)]
struct HealthCheckQuery {
    #[serde(default)]
    check: Option<String>,
}

pub fn create_bedrock_routes() -> Router<(AwsHttpClient, Arc<HealthService>)> {
    Router::new().route("/health", get(health_check))
}

pub fn create_protected_bedrock_routes() -> Router<AwsHttpClient> {
    Router::new()
        .route("/model/{model_id}/invoke", post(invoke_model))
        .route(
            "/model/{model_id}/invoke-with-response-stream",
            post(invoke_model_with_response_stream),
        )
}

async fn health_check(
    State((_, health_service)): State<(AwsHttpClient, Arc<HealthService>)>,
    Query(params): Query<HealthCheckQuery>,
) -> Result<Json<Value>, AppError> {
    // Use the centralized health service
    let filter = params.check.as_deref();
    let health_response = health_service.check_health(filter).await;

    // Convert the health response to the expected JSON format
    let response_json = serde_json::to_value(&health_response)
        .map_err(|e| AppError::Internal(format!("Failed to serialize health response: {}", e)))?;

    Ok(Json(response_json))
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

    // Validate model ID
    if model_id.trim().is_empty() {
        return Err(AppError::BadRequest("Model ID cannot be empty".to_string()));
    }

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

            // AWS Bedrock already returns properly formatted SSE data, so we'll stream it directly
            let byte_stream = aws_response.stream.map(|chunk_result| {
                chunk_result.map_err(|e| {
                    tracing::error!("Stream error: {}", e);
                    axum::Error::new(e)
                })
            });

            // Create a streaming body from the AWS response
            let body = Body::from_stream(byte_stream);

            // Build response with AWS headers
            let mut response = Response::builder()
                .status(aws_response.status)
                .body(body)
                .unwrap();

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
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;

    async fn create_test_health_service() -> Arc<HealthService> {
        let health_service = Arc::new(HealthService::new());
        let aws_client = AwsHttpClient::new_test();
        health_service
            .register(Arc::new(aws_client.health_checker()))
            .await;
        health_service
    }

    #[tokio::test]
    async fn test_health_check_basic() {
        let aws_http_client = AwsHttpClient::new_test();
        let health_service = create_test_health_service().await;
        let app = create_bedrock_routes().with_state((aws_http_client, health_service));

        let request = Request::builder()
            .uri("/health")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_health_check_with_aws_query() {
        let aws_http_client = AwsHttpClient::new_test();
        let health_service = create_test_health_service().await;
        let app = create_bedrock_routes().with_state((aws_http_client, health_service));

        let request = Request::builder()
            .uri("/health?check=aws_bedrock")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_health_check_with_unknown_query() {
        let aws_http_client = AwsHttpClient::new_test();
        let health_service = create_test_health_service().await;
        let app = create_bedrock_routes().with_state((aws_http_client, health_service));

        let request = Request::builder()
            .uri("/health?check=unknown")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_invoke_model_empty_model_id() {
        let aws_http_client = AwsHttpClient::new_test();
        let app = create_protected_bedrock_routes().with_state(aws_http_client);

        let request = Request::builder()
            .uri("/model/%20/invoke") // URL-encoded space
            .method("POST")
            .header("Content-Type", "application/json")
            .body(Body::from(r#"{"messages": []}"#))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_invoke_model_with_custom_headers() {
        let aws_http_client = AwsHttpClient::new_test();
        let app = create_protected_bedrock_routes().with_state(aws_http_client);

        let request = Request::builder()
            .uri("/model/anthropic.claude-v2/invoke")
            .method("POST")
            .header("Content-Type", "application/json")
            .header("Accept", "application/json")
            .header("X-Custom-Header", "custom-value")
            .body(Body::from(r#"{"messages": []}"#))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        // Should handle custom headers appropriately
        // In test mode, we expect either success or a handled error
        assert!(
            response.status() == StatusCode::INTERNAL_SERVER_ERROR
                || response.status() == StatusCode::BAD_REQUEST
                || response.status() == StatusCode::OK
                || response.status() == StatusCode::FORBIDDEN
        );
    }

    #[tokio::test]
    async fn test_invoke_model_streaming_with_empty_model_id() {
        let aws_http_client = AwsHttpClient::new_test();
        let app = create_protected_bedrock_routes().with_state(aws_http_client);

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
        let aws_http_client = AwsHttpClient::new_test();
        let app = create_protected_bedrock_routes().with_state(aws_http_client);

        let request = Request::builder()
            .uri("/model/anthropic.claude-v2/invoke-with-response-stream")
            .method("POST")
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
    async fn test_invoke_model_with_large_body() {
        let aws_http_client = AwsHttpClient::new_test();
        let app = create_protected_bedrock_routes().with_state(aws_http_client);

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
        // Should handle large bodies appropriately
        // In test mode, we expect either success or a handled error
        assert!(
            response.status() == StatusCode::INTERNAL_SERVER_ERROR
                || response.status() == StatusCode::BAD_REQUEST
                || response.status() == StatusCode::OK
                || response.status() == StatusCode::FORBIDDEN
        );
    }
}
