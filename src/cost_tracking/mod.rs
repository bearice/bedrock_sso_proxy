mod parser;
pub mod routes;

use chrono::{DateTime, Utc};
pub use parser::{
    CsvParseError, CsvParsingError, PricingData, PricingRecord, parse_csv_pricing_data,
};

use crate::{
    database::{DatabaseManager, entities::StoredModelCost},
    error::AppError,
};
use rust_decimal::{Decimal, prelude::ToPrimitive};
use std::sync::Arc;
use tracing::{debug, info};

/// Cached embedded pricing data parsed from CSV
pub static EMBEDDED_PRICING_CSV: &str = include_str!("../../bedrock_pricing.csv");

/// Cost tracking service for AWS Bedrock models
pub struct CostTrackingService {
    database: Arc<dyn DatabaseManager>,
}

impl CostTrackingService {
    pub fn new(database: Arc<dyn DatabaseManager>) -> Self {
        Self { database }
    }
    /// Initialize model costs from embedded CSV data (only if database is empty)
    pub async fn initialize_model_costs_from_embedded(
        &self,
    ) -> Result<UpdateCostsResult, AppError> {
        info!("Initializing model costs from embedded CSV pricing data");

        // Just use the batch update method for initialization
        self.batch_update_from_csv_content(EMBEDDED_PRICING_CSV)
            .await
    }

    /// Batch update costs from CSV content
    pub async fn batch_update_from_csv_content(
        &self,
        csv_content: &str,
    ) -> Result<UpdateCostsResult, AppError> {
        debug!("Starting batch cost update from provided CSV content");

        let mut result = UpdateCostsResult { total_processed: 0 };

        // Parse CSV content
        let all_pricing = match parser::parse_csv_pricing_data(csv_content) {
            Ok(pricing) => pricing,
            Err(parse_error) => {
                // Create a detailed error message with specific line information
                let mut error_details = vec![parse_error.summary.clone()];

                if !parse_error.header_errors.is_empty() {
                    error_details.push(format!(
                        "Header errors: {}",
                        parse_error.header_errors.join("; ")
                    ));
                }

                if !parse_error.parse_errors.is_empty() {
                    error_details.push("Parse errors:".to_string());
                    for err in &parse_error.parse_errors {
                        let line_info = if let Some(ref raw_line) = err.raw_line {
                            format!(" (line content: {})", raw_line)
                        } else {
                            String::new()
                        };
                        error_details.push(format!(
                            "  - Line {}: {}{}",
                            err.line_number, err.message, line_info
                        ));
                    }
                }

                return Err(AppError::BadRequest(error_details.join("\n")));
            }
        };

        result.total_processed = all_pricing.len();
        debug!(
            "Processing {} models for batch cost updates from CSV content",
            all_pricing.len()
        );

        let stored_cost: Vec<_> = all_pricing
            .iter()
            .map(|pricing| {
                // Parse timestamp from CSV, fallback to current time if parsing fails
                let updated_at = DateTime::parse_from_rfc3339(&pricing.timestamp)
                    .map(|dt| dt.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now());

                StoredModelCost {
                    id: 0, // Will be set by database
                    region: pricing.region_id.clone(),
                    model_id: pricing.model_id.clone(),
                    input_cost_per_1k_tokens: Decimal::from_f64_retain(pricing.input_price)
                        .unwrap_or_default(),
                    output_cost_per_1k_tokens: Decimal::from_f64_retain(pricing.output_price)
                        .unwrap_or_default(),
                    cache_write_cost_per_1k_tokens: pricing
                        .cache_write_price
                        .map(|c| Decimal::from_f64_retain(c).unwrap_or_default()),
                    cache_read_cost_per_1k_tokens: pricing
                        .cache_read_price
                        .map(|c| Decimal::from_f64_retain(c).unwrap_or_default()),
                    updated_at,
                }
            })
            .collect();

        self.database
            .model_costs()
            .upsert_many(&stored_cost)
            .await?;

        info!(
            "Batch cost update from CSV content completed: {} total",
            result.total_processed
        );

        Ok(result)
    }

    /// Get cost summary for all models
    pub async fn get_cost_summary(&self) -> Result<CostSummary, AppError> {
        let all_costs = self
            .database
            .model_costs()
            .get_all()
            .await
            .map_err(|e| AppError::Internal(format!("Failed to get model costs: {}", e)))?;

        let mut summary = CostSummary {
            total_models: all_costs.len(),
            models: Vec::new(),
            last_updated: None,
        };

        for cost in all_costs {
            if summary.last_updated.is_none() || summary.last_updated < Some(cost.updated_at) {
                summary.last_updated = Some(cost.updated_at);
            }

            summary.models.push(ModelCostInfo {
                model_id: cost.model_id,
                input_cost_per_1k_tokens: cost.input_cost_per_1k_tokens.to_f64().unwrap_or(0.0),
                output_cost_per_1k_tokens: cost.output_cost_per_1k_tokens.to_f64().unwrap_or(0.0),
                updated_at: cost.updated_at,
            });
        }

        Ok(summary)
    }
}

/// Result of updating model costs
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct UpdateCostsResult {
    pub total_processed: usize,
}

/// Cost summary for all models
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct CostSummary {
    pub total_models: usize,
    pub models: Vec<ModelCostInfo>,
    pub last_updated: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct ModelCostInfo {
    pub model_id: String,
    pub input_cost_per_1k_tokens: f64,
    pub output_cost_per_1k_tokens: f64,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;

    // Integration tests moved from tests/cost_tracking_integration_tests.rs
    #[cfg(test)]
    mod integration_tests {
        use super::*;
        use axum::{
            Router,
            body::Body,
            extract::Request,
            http::{Method, StatusCode, header::AUTHORIZATION},
            middleware,
        };
        use crate::{auth::jwt::JwtService, database::entities::*};
        use chrono::Utc;
        use rust_decimal::Decimal;
        use serde_json::Value;
        use tower::ServiceExt;

        async fn create_test_server() -> crate::server::Server {
            let mut config = crate::config::Config::default();
            // Add admin email for tests
            config.admin.emails = vec!["admin@admin.example.com".to_string()];

            crate::test_utils::TestServerBuilder::new()
                .with_config(config)
                .build()
                .await
        }

        fn create_test_router(server: &crate::server::Server) -> Router {
            crate::cost_tracking::routes::create_admin_cost_routes()
                .with_state(server.clone())
                .layer(middleware::from_fn_with_state(
                    server.clone(),
                    crate::auth::middleware::admin_middleware,
                ))
                .layer(middleware::from_fn_with_state(
                    server.clone(),
                    crate::auth::middleware::jwt_auth_middleware,
                ))
        }

        fn create_test_token(
            jwt_service: &dyn JwtService,
            user_id: i32,
        ) -> String {
            let claims = crate::auth::jwt::OAuthClaims::new(user_id, 3600);
            jwt_service.create_oauth_token(&claims).unwrap()
        }

        async fn setup_test_data(database: &dyn DatabaseManager) -> i32 {
            // Create admin user
            let admin_user = UserRecord {
                id: 0,
                provider: "google".to_string(),
                provider_user_id: "admin-user".to_string(),
                email: "admin@admin.example.com".to_string(),
                display_name: Some("Admin User".to_string()),
                created_at: Utc::now(),
                updated_at: Utc::now(),
                last_login: Some(Utc::now()),
            };
            let admin_id = database.users().upsert(&admin_user).await.unwrap();

            // Create test model costs with exact decimal values
            let model_costs = vec![
                StoredModelCost {
                    id: 0,
                    region: "us-east-1".to_string(),
                    model_id: "anthropic.claude-sonnet-4-20250514-v1:0".to_string(),
                    input_cost_per_1k_tokens: Decimal::new(3, 3), // 0.003
                    output_cost_per_1k_tokens: Decimal::new(15, 3), // 0.015
                    cache_write_cost_per_1k_tokens: Some(Decimal::new(18, 4)), // 0.0018
                    cache_read_cost_per_1k_tokens: Some(Decimal::new(36, 5)), // 0.00036
                    updated_at: Utc::now(),
                },
                StoredModelCost {
                    id: 0,
                    region: "us-east-1".to_string(),
                    model_id: "anthropic.claude-3-haiku-20240307-v1:0".to_string(),
                    input_cost_per_1k_tokens: Decimal::new(25, 5), // 0.00025
                    output_cost_per_1k_tokens: Decimal::new(125, 5), // 0.00125
                    cache_write_cost_per_1k_tokens: None,
                    cache_read_cost_per_1k_tokens: None,
                    updated_at: Utc::now(),
                },
                StoredModelCost {
                    id: 0,
                    region: "us-west-2".to_string(),
                    model_id: "test-model".to_string(),
                    input_cost_per_1k_tokens: Decimal::new(1, 3), // 0.001
                    output_cost_per_1k_tokens: Decimal::new(5, 3), // 0.005
                    cache_write_cost_per_1k_tokens: None,
                    cache_read_cost_per_1k_tokens: None,
                    updated_at: Utc::now(),
                },
            ];

            database.model_costs().upsert_many(&model_costs).await.unwrap();
            admin_id
        }

        #[tokio::test]
        async fn test_get_all_model_costs() {
            let server = create_test_server().await;
            let admin_id = setup_test_data(server.database.as_ref()).await;

            let admin_token = create_test_token(server.jwt_service.as_ref(), admin_id);
            let app = create_test_router(&server);

            let request = Request::builder()
                .method(Method::GET)
                .uri("/admin/costs")
                .header(AUTHORIZATION, format!("Bearer {}", admin_token))
                .body(Body::empty())
                .unwrap();

            let response = app.oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);

            let body = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap();
            let costs: Vec<Value> = serde_json::from_slice(&body).unwrap();
            assert!(costs.len() >= 3); // Should have our test costs
        }

        #[tokio::test]
        async fn test_get_specific_model_cost() {
            let server = create_test_server().await;
            let admin_id = setup_test_data(server.database.as_ref()).await;

            let admin_token = create_test_token(server.jwt_service.as_ref(), admin_id);
            let app = create_test_router(&server);

            let request = Request::builder()
                .method(Method::GET)
                .uri("/admin/costs/us-east-1/anthropic.claude-sonnet-4-20250514-v1:0")
                .header(AUTHORIZATION, format!("Bearer {}", admin_token))
                .body(Body::empty())
                .unwrap();

            let response = app.oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);

            let body = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap();
            let cost: Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(cost["model_id"], "anthropic.claude-sonnet-4-20250514-v1:0");
            assert_eq!(cost["region"], "us-east-1");
        }

        #[tokio::test]
        async fn test_upsert_model_cost() {
            let server = create_test_server().await;
            let admin_id = setup_test_data(server.database.as_ref()).await;

            let admin_token = create_test_token(server.jwt_service.as_ref(), admin_id);
            let app = create_test_router(&server);

            let new_cost = serde_json::json!({
                "region": "us-east-1",
                "model_id": "new-test-model",
                "input_cost_per_1k_tokens": 0.002,
                "output_cost_per_1k_tokens": 0.008,
                "cache_write_cost_per_1k_tokens": 0.0012,
                "cache_read_cost_per_1k_tokens": 0.0002
            });

            let request = Request::builder()
                .method(Method::PUT)
                .uri("/admin/costs/us-east-1/new-test-model")
                .header(AUTHORIZATION, format!("Bearer {}", admin_token))
                .header("content-type", "application/json")
                .body(Body::from(new_cost.to_string()))
                .unwrap();

            let response = app.oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);

            // Verify the cost was created
            let app2 = create_test_router(&server);
            let request = Request::builder()
                .method(Method::GET)
                .uri("/admin/costs/us-east-1/new-test-model")
                .header(AUTHORIZATION, format!("Bearer {}", admin_token))
                .body(Body::empty())
                .unwrap();

            let response = app2.oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);

            let body = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap();
            let cost: Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(cost["model_id"], "new-test-model");
            assert_eq!(cost["region"], "us-east-1");
        }

        #[tokio::test]
        async fn test_upsert_model_cost_without_cache_fields() {
            let server = create_test_server().await;
            let admin_id = setup_test_data(server.database.as_ref()).await;

            let admin_token = create_test_token(server.jwt_service.as_ref(), admin_id);
            let app = create_test_router(&server);

            let new_cost = serde_json::json!({
                "region": "us-west-2",
                "model_id": "simple-test-model",
                "input_cost_per_1k_tokens": 0.001,
                "output_cost_per_1k_tokens": 0.005
                // No cache fields - should be optional
            });

            let request = Request::builder()
                .method(Method::PUT)
                .uri("/admin/costs/us-west-2/simple-test-model")
                .header(AUTHORIZATION, format!("Bearer {}", admin_token))
                .header("content-type", "application/json")
                .body(Body::from(new_cost.to_string()))
                .unwrap();

            let response = app.oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);
        }

        #[tokio::test]
        async fn test_delete_model_cost() {
            let server = create_test_server().await;
            let admin_id = setup_test_data(server.database.as_ref()).await;

            let admin_token = create_test_token(server.jwt_service.as_ref(), admin_id);
            
            // First create a cost to delete
            let app1 = create_test_router(&server);
            let new_cost = serde_json::json!({
                "region": "us-east-1",
                "model_id": "delete-test-model",
                "input_cost_per_1k_tokens": 0.001,
                "output_cost_per_1k_tokens": 0.005
            });

            let request = Request::builder()
                .method(Method::PUT)
                .uri("/admin/costs/us-east-1/delete-test-model")
                .header(AUTHORIZATION, format!("Bearer {}", admin_token))
                .header("content-type", "application/json")
                .body(Body::from(new_cost.to_string()))
                .unwrap();

            let response = app1.oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);

            // Now delete it
            let app2 = create_test_router(&server);
            let request = Request::builder()
                .method(Method::DELETE)
                .uri("/admin/costs/us-east-1/delete-test-model")
                .header(AUTHORIZATION, format!("Bearer {}", admin_token))
                .body(Body::empty())
                .unwrap();

            let response = app2.oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::NO_CONTENT);

            // Verify it's gone
            let app3 = create_test_router(&server);
            let request = Request::builder()
                .method(Method::GET)
                .uri("/admin/costs/us-east-1/delete-test-model")
                .header(AUTHORIZATION, format!("Bearer {}", admin_token))
                .body(Body::empty())
                .unwrap();

            let response = app3.oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::NOT_FOUND);
        }

        #[tokio::test]
        async fn test_bulk_update_from_csv() {
            let server = create_test_server().await;
            let admin_id = setup_test_data(server.database.as_ref()).await;

            let admin_token = create_test_token(server.jwt_service.as_ref(), admin_id);
            let app = create_test_router(&server);

            let csv_content = r#"region_id,model_id,model_name,provider,input_price,output_price,batch_input_price,batch_output_price,cache_write_price,cache_read_price,timestamp
us-east-1,test-csv-model,Test CSV Model,TestProvider,0.001,0.005,,,0.0006,0.0001,2024-01-15T10:30:00Z
us-west-2,test-csv-model-2,Test CSV Model 2,TestProvider,0.002,0.006,,,,,2024-01-15T10:30:00Z"#;

            let request = Request::builder()
                .method(Method::POST)
                .uri("/admin/costs")
                .header(AUTHORIZATION, format!("Bearer {}", admin_token))
                .header("content-type", "text/plain")
                .body(Body::from(csv_content))
                .unwrap();

            let response = app.oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);

            let body = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap();
            let result: Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(result["total_processed"], 2);
        }

        #[tokio::test]
        async fn test_bulk_update_empty_csv() {
            let server = create_test_server().await;
            let admin_id = setup_test_data(server.database.as_ref()).await;

            let admin_token = create_test_token(server.jwt_service.as_ref(), admin_id);
            let app = create_test_router(&server);

            let request = Request::builder()
                .method(Method::POST)
                .uri("/admin/costs")
                .header(AUTHORIZATION, format!("Bearer {}", admin_token))
                .header("content-type", "text/plain")
                .body(Body::from(""))
                .unwrap();

            let response = app.oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        }

        #[tokio::test]
        async fn test_get_non_existent_model_cost() {
            let server = create_test_server().await;
            let admin_id = setup_test_data(server.database.as_ref()).await;

            let admin_token = create_test_token(server.jwt_service.as_ref(), admin_id);
            let app = create_test_router(&server);

            let request = Request::builder()
                .method(Method::GET)
                .uri("/admin/costs/us-east-1/non-existent-model")
                .header(AUTHORIZATION, format!("Bearer {}", admin_token))
                .body(Body::empty())
                .unwrap();

            let response = app.oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::NOT_FOUND);
        }

        #[tokio::test]
        async fn test_unauthorized_access() {
            let server = create_test_server().await;
            setup_test_data(server.database.as_ref()).await;

            let app = create_test_router(&server);

            // Test without authorization header
            let request = Request::builder()
                .method(Method::GET)
                .uri("/admin/costs")
                .body(Body::empty())
                .unwrap();

            let response = app.oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        }

        #[tokio::test]
        async fn test_non_admin_access_forbidden() {
            let server = create_test_server().await;
            setup_test_data(server.database.as_ref()).await;

            // Create a regular user
            let user = UserRecord {
                id: 0,
                provider: "google".to_string(),
                provider_user_id: "regular-user".to_string(),
                email: "user@example.com".to_string(),
                display_name: Some("Regular User".to_string()),
                created_at: Utc::now(),
                updated_at: Utc::now(),
                last_login: Some(Utc::now()),
            };
            let user_id = server.database.users().upsert(&user).await.unwrap();

            let user_token = create_test_token(server.jwt_service.as_ref(), user_id);
            let app = create_test_router(&server);

            let request = Request::builder()
                .method(Method::GET)
                .uri("/admin/costs")
                .header(AUTHORIZATION, format!("Bearer {}", user_token))
                .body(Body::empty())
                .unwrap();

            let response = app.oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::FORBIDDEN);
        }
    }
}
