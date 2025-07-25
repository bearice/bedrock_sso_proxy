use crate::{error::AppError, health::HealthService};
use axum::{
    Router,
    extract::{Query, State},
    response::Json,
    routing::get,
};
use serde::Deserialize;
use serde_json::Value;
use std::sync::Arc;

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
pub fn create_health_routes() -> Router<Arc<HealthService>> {
    Router::new().route("/", get(health_check))
}

async fn health_check(
    State(health_service): State<Arc<HealthService>>,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::Config,
        health::HealthService, 
        model_service::ModelService,
        storage::{memory::MemoryDatabaseStorage, Storage},
    };
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;

    async fn create_test_health_service() -> Arc<HealthService> {
        let health_service = Arc::new(HealthService::new());
        
        // Create ModelService for testing and register its AWS health checker
        let config = Config::default();
        let storage = Arc::new(Storage::new(
            Box::new(crate::storage::memory::MemoryCacheStorage::new(3600)),
            Box::new(MemoryDatabaseStorage::new()),
        ));
        let model_service = ModelService::new_test(storage, config);
        
        health_service
            .register(Arc::new(model_service.aws_client().clone().health_checker()))
            .await;
        health_service
    }

    #[tokio::test]
    async fn test_health_check_basic() {
        let health_service = create_test_health_service().await;
        let app = create_health_routes().with_state(health_service);

        let request = Request::builder().uri("/").body(Body::empty()).unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_health_check_with_all_query() {
        let health_service = create_test_health_service().await;
        let app = create_health_routes().with_state(health_service);

        let request = Request::builder()
            .uri("/?check=all")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_health_check_with_specific_query() {
        let health_service = create_test_health_service().await;
        let app = create_health_routes().with_state(health_service);

        let request = Request::builder()
            .uri("/?check=aws_bedrock")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_health_check_with_unknown_query() {
        let health_service = create_test_health_service().await;
        let app = create_health_routes().with_state(health_service);

        let request = Request::builder()
            .uri("/?check=unknown")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }
}
