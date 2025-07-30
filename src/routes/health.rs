use crate::{error::AppError, health::HealthResponse, routes::ApiErrorResponse, server::Server};
use axum::{
    Router,
    extract::{Query, State},
    response::Json,
    routing::get,
};
use serde::Deserialize;
use utoipa::{IntoParams, ToSchema};

#[derive(Debug, Deserialize, ToSchema, IntoParams)]
pub struct HealthCheckQuery {
    #[serde(default)]
    /// Filter health checks by component name
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

#[utoipa::path(
    get,
    path = "/health",
    summary = "Health Check",
    description = "Check the health status of the proxy server and its dependencies",
    tags = ["Health"],
    params(
        HealthCheckQuery
    ),
    responses(
        (status = 200, description = "Health check results", body = HealthResponse),
        (status = 503, description = "Service unavailable", body = ApiErrorResponse)
    )
)]
pub async fn health_check(
    State(server): State<Server>,
    Query(params): Query<HealthCheckQuery>,
) -> Result<Json<HealthResponse>, AppError> {
    // Use the centralized health service
    let filter = params.check.as_deref();
    let health_response = server.health_service.check_health(filter).await;

    Ok(Json(health_response))
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
