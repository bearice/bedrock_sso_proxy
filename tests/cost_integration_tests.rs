//! Integration tests for cost tracking API routes
//! These tests verify end-to-end functionality with real JWT authentication

use axum::{
    Router,
    body::Body,
    extract::Request,
    http::{Method, StatusCode, header::AUTHORIZATION},
    middleware,
};
use bedrock_sso_proxy::{auth::jwt::JwtService, database::DatabaseManager, database::entities::*};
use chrono::Utc;
use rust_decimal::Decimal;
use serde_json::Value;
use tower::ServiceExt;

mod common;
use common::PostgresTestDb;

// Macro to run the same test with both SQLite and PostgreSQL
macro_rules! database_test {
    ($test_name:ident, $test_impl:ident) => {
        pastey::paste! {
            #[tokio::test]
            async fn [<sqlite_ $test_name>]() {
                $test_impl(&create_test_server().await).await;
            }

            #[tokio::test]
            async fn [<postgres_ $test_name>]() {
                let postgres_db = match PostgresTestDb::new().await {
                    Ok(db) => db,
                    Err(_) => {
                        println!("Skipping PostgreSQL test - database not available");
                        return;
                    }
                };

                let server = create_postgres_test_server(&postgres_db).await;
                $test_impl(&server).await;

                // Clean up
                let _ = postgres_db.cleanup().await;
            }
        }
    };
}

async fn create_test_server() -> bedrock_sso_proxy::server::Server {
    let mut config = bedrock_sso_proxy::config::Config::default();
    // Add admin email for tests
    config.admin.emails = vec!["admin@admin.example.com".to_string()];

    bedrock_sso_proxy::test_utils::TestServerBuilder::new()
        .with_config(config)
        .build()
        .await
}

async fn create_postgres_test_server(
    postgres_db: &PostgresTestDb,
) -> bedrock_sso_proxy::server::Server {
    let mut config = bedrock_sso_proxy::config::Config::default();
    config.database.url = postgres_db.database_url.clone();
    config.database.enabled = true;
    // Add admin email for tests
    config.admin.emails = vec!["admin@admin.example.com".to_string()];

    bedrock_sso_proxy::test_utils::TestServerBuilder::new()
        .with_config(config)
        .build()
        .await
}

fn create_test_router(server: &bedrock_sso_proxy::server::Server) -> Router {
    bedrock_sso_proxy::routes::create_admin_cost_routes()
        .with_state(server.clone())
        .layer(middleware::from_fn_with_state(
            server.clone(),
            bedrock_sso_proxy::auth::middleware::admin_auth_middleware,
        ))
        .layer(middleware::from_fn_with_state(
            server.clone(),
            bedrock_sso_proxy::auth::middleware::jwt_only_auth_middleware,
        ))
}

fn create_test_token(jwt_service: &dyn JwtService, user_id: i32) -> String {
    let claims = bedrock_sso_proxy::auth::jwt::OAuthClaims::new(user_id, 3600);
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
        ..Default::default()
    };
    let admin_id = database.users().upsert(&admin_user).await.unwrap();

    // Create test model costs with exact decimal values
    let model_costs = vec![
        ModelCost {
            id: 0,
            region: "us-east-1".to_string(),
            model_id: "anthropic.claude-sonnet-4-20250514-v1:0".to_string(),
            input_cost_per_1k_tokens: Decimal::new(3, 3), // 0.003
            output_cost_per_1k_tokens: Decimal::new(15, 3), // 0.015
            cache_write_cost_per_1k_tokens: Some(Decimal::new(18, 4)), // 0.0018
            cache_read_cost_per_1k_tokens: Some(Decimal::new(36, 5)), // 0.00036
            updated_at: Utc::now(),
        },
        ModelCost {
            id: 0,
            region: "us-east-1".to_string(),
            model_id: "anthropic.claude-3-haiku-20240307-v1:0".to_string(),
            input_cost_per_1k_tokens: Decimal::new(25, 5), // 0.00025
            output_cost_per_1k_tokens: Decimal::new(125, 5), // 0.00125
            cache_write_cost_per_1k_tokens: None,
            cache_read_cost_per_1k_tokens: None,
            updated_at: Utc::now(),
        },
        ModelCost {
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

    database
        .model_costs()
        .upsert_many(&model_costs)
        .await
        .unwrap();
    admin_id
}

// Test implementation functions
async fn test_get_all_model_costs_impl(server: &bedrock_sso_proxy::server::Server) {
    let admin_id = setup_test_data(server.database.as_ref()).await;

    let admin_token = create_test_token(server.jwt_service.as_ref(), admin_id);
    let app = create_test_router(server);

    let request = Request::builder()
        .method(Method::GET)
        .uri("/admin/costs")
        .header(AUTHORIZATION, format!("Bearer {admin_token}"))
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

// Generate both SQLite and PostgreSQL tests
database_test!(test_get_all_model_costs, test_get_all_model_costs_impl);

async fn test_get_specific_model_cost_impl(server: &bedrock_sso_proxy::server::Server) {
    let admin_id = setup_test_data(server.database.as_ref()).await;

    let admin_token = create_test_token(server.jwt_service.as_ref(), admin_id);
    let app = create_test_router(server);

    let request = Request::builder()
        .method(Method::GET)
        .uri("/admin/costs/us-east-1/anthropic.claude-sonnet-4-20250514-v1:0")
        .header(AUTHORIZATION, format!("Bearer {admin_token}"))
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

database_test!(
    test_get_specific_model_cost,
    test_get_specific_model_cost_impl
);

async fn test_upsert_model_cost_impl(server: &bedrock_sso_proxy::server::Server) {
    let admin_id = setup_test_data(server.database.as_ref()).await;

    let admin_token = create_test_token(server.jwt_service.as_ref(), admin_id);
    let app = create_test_router(server);

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
        .header(AUTHORIZATION, format!("Bearer {admin_token}"))
        .header("content-type", "application/json")
        .body(Body::from(new_cost.to_string()))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // Verify the cost was created
    let app2 = create_test_router(server);
    let request = Request::builder()
        .method(Method::GET)
        .uri("/admin/costs/us-east-1/new-test-model")
        .header(AUTHORIZATION, format!("Bearer {admin_token}"))
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

database_test!(test_upsert_model_cost, test_upsert_model_cost_impl);

async fn test_upsert_model_cost_without_cache_fields_impl(
    server: &bedrock_sso_proxy::server::Server,
) {
    let admin_id = setup_test_data(server.database.as_ref()).await;

    let admin_token = create_test_token(server.jwt_service.as_ref(), admin_id);
    let app = create_test_router(server);

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
        .header(AUTHORIZATION, format!("Bearer {admin_token}"))
        .header("content-type", "application/json")
        .body(Body::from(new_cost.to_string()))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

database_test!(
    test_upsert_model_cost_without_cache_fields,
    test_upsert_model_cost_without_cache_fields_impl
);

async fn test_delete_model_cost_impl(server: &bedrock_sso_proxy::server::Server) {
    let admin_id = setup_test_data(server.database.as_ref()).await;

    let admin_token = create_test_token(server.jwt_service.as_ref(), admin_id);

    // First create a cost to delete
    let app1 = create_test_router(server);
    let new_cost = serde_json::json!({
        "region": "us-east-1",
        "model_id": "delete-test-model",
        "input_cost_per_1k_tokens": 0.001,
        "output_cost_per_1k_tokens": 0.005
    });

    let request = Request::builder()
        .method(Method::PUT)
        .uri("/admin/costs/us-east-1/delete-test-model")
        .header(AUTHORIZATION, format!("Bearer {admin_token}"))
        .header("content-type", "application/json")
        .body(Body::from(new_cost.to_string()))
        .unwrap();

    let response = app1.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // Now delete it
    let app2 = create_test_router(server);
    let request = Request::builder()
        .method(Method::DELETE)
        .uri("/admin/costs/us-east-1/delete-test-model")
        .header(AUTHORIZATION, format!("Bearer {admin_token}"))
        .body(Body::empty())
        .unwrap();

    let response = app2.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    // Verify it's gone
    let app3 = create_test_router(server);
    let request = Request::builder()
        .method(Method::GET)
        .uri("/admin/costs/us-east-1/delete-test-model")
        .header(AUTHORIZATION, format!("Bearer {admin_token}"))
        .body(Body::empty())
        .unwrap();

    let response = app3.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

database_test!(test_delete_model_cost, test_delete_model_cost_impl);

async fn test_bulk_update_from_csv_impl(server: &bedrock_sso_proxy::server::Server) {
    let admin_id = setup_test_data(server.database.as_ref()).await;

    let admin_token = create_test_token(server.jwt_service.as_ref(), admin_id);
    let app = create_test_router(server);

    let csv_content = r#"region_id,model_id,model_name,provider,input_price,output_price,batch_input_price,batch_output_price,cache_write_price,cache_read_price,timestamp
us-east-1,test-csv-model,Test CSV Model,TestProvider,0.001,0.005,,,0.0006,0.0001,2024-01-15T10:30:00Z
us-west-2,test-csv-model-2,Test CSV Model 2,TestProvider,0.002,0.006,,,,,2024-01-15T10:30:00Z"#;

    let request = Request::builder()
        .method(Method::POST)
        .uri("/admin/costs")
        .header(AUTHORIZATION, format!("Bearer {admin_token}"))
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

database_test!(test_bulk_update_from_csv, test_bulk_update_from_csv_impl);

async fn test_bulk_update_empty_csv_impl(server: &bedrock_sso_proxy::server::Server) {
    let admin_id = setup_test_data(server.database.as_ref()).await;

    let admin_token = create_test_token(server.jwt_service.as_ref(), admin_id);
    let app = create_test_router(server);

    let request = Request::builder()
        .method(Method::POST)
        .uri("/admin/costs")
        .header(AUTHORIZATION, format!("Bearer {admin_token}"))
        .header("content-type", "text/plain")
        .body(Body::from(""))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

database_test!(test_bulk_update_empty_csv, test_bulk_update_empty_csv_impl);

async fn test_get_non_existent_model_cost_impl(server: &bedrock_sso_proxy::server::Server) {
    let admin_id = setup_test_data(server.database.as_ref()).await;

    let admin_token = create_test_token(server.jwt_service.as_ref(), admin_id);
    let app = create_test_router(server);

    let request = Request::builder()
        .method(Method::GET)
        .uri("/admin/costs/us-east-1/non-existent-model")
        .header(AUTHORIZATION, format!("Bearer {admin_token}"))
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

database_test!(
    test_get_non_existent_model_cost,
    test_get_non_existent_model_cost_impl
);

async fn test_unauthorized_access_impl(server: &bedrock_sso_proxy::server::Server) {
    setup_test_data(server.database.as_ref()).await;

    let app = create_test_router(server);

    // Test without authorization header
    let request = Request::builder()
        .method(Method::GET)
        .uri("/admin/costs")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

database_test!(test_unauthorized_access, test_unauthorized_access_impl);

async fn test_non_admin_access_forbidden_impl(server: &bedrock_sso_proxy::server::Server) {
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
        ..Default::default()
    };
    let user_id = server.database.users().upsert(&user).await.unwrap();

    let user_token = create_test_token(server.jwt_service.as_ref(), user_id);
    let app = create_test_router(server);

    let request = Request::builder()
        .method(Method::GET)
        .uri("/admin/costs")
        .header(AUTHORIZATION, format!("Bearer {user_token}"))
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

database_test!(
    test_non_admin_access_forbidden,
    test_non_admin_access_forbidden_impl
);

// PostgreSQL variants are automatically generated by the database_test! macro for all tests
