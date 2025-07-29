use crate::{error::AppError, server::Server};
use axum::{
    Router,
    extract::{Query, State},
    response::Json,
    routing::get,
};
use serde::Deserialize;
use serde_json::Value;

#[derive(Debug, Deserialize)]
struct HealthCheckQuery {
    #[serde(default)]
    check: Option<String>,
}

/// Create health check routes
///
/// This module provides system-wide health check endpoints that are shared
/// across all services. The health service aggregates checks from all
/// registered components (AWS, OAuth, JWT, Storage, etc.)
pub fn create_health_routes() -> Router<Server> {
    Router::new().route("/", get(health_check))
}

async fn health_check(
    State(server): State<Server>,
    Query(params): Query<HealthCheckQuery>,
) -> Result<Json<Value>, AppError> {
    // Use the centralized health service
    let filter = params.check.as_deref();
    let health_response = server.health_service.check_health(filter).await;

    // Convert the health response to the expected JSON format
    let response_json = serde_json::to_value(&health_response)
        .map_err(|e| AppError::Internal(format!("Failed to serialize health response: {}", e)))?;

    Ok(Json(response_json))
}

#[cfg(test)]
mod tests {
    use super::*;

    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;

    #[tokio::test]
    async fn test_health_check_basic() {
        let server = crate::test_utils::TestServerBuilder::new().build().await;
        let app = create_health_routes().with_state(server);

        let request = Request::builder().uri("/").body(Body::empty()).unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_health_check_with_all_query() {
        let server = crate::test_utils::TestServerBuilder::new().build().await;
        let app = create_health_routes().with_state(server);

        let request = Request::builder()
            .uri("/?check=all")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_health_check_with_specific_query() {
        let server = crate::test_utils::TestServerBuilder::new().build().await;
        let app = create_health_routes().with_state(server);

        let request = Request::builder()
            .uri("/?check=aws")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_health_check_with_unknown_query() {
        let server = crate::test_utils::TestServerBuilder::new().build().await;
        let app = create_health_routes().with_state(server);

        let request = Request::builder()
            .uri("/?check=unknown")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }
}
