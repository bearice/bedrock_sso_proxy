//! Integration tests for usage tracking API routes
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
        paste::paste! {
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
    // Combine user and admin routes for testing
    Router::new()
        .merge(
            bedrock_sso_proxy::routes::create_user_usage_routes()
                .with_state(server.clone())
                .layer(middleware::from_fn_with_state(
                    server.clone(),
                    bedrock_sso_proxy::auth::middleware::jwt_auth_middleware,
                )),
        )
        .merge(
            bedrock_sso_proxy::routes::create_admin_usage_routes()
                .with_state(server.clone())
                .layer(middleware::from_fn_with_state(
                    server.clone(),
                    bedrock_sso_proxy::auth::middleware::admin_middleware,
                ))
                .layer(middleware::from_fn_with_state(
                    server.clone(),
                    bedrock_sso_proxy::auth::middleware::jwt_auth_middleware,
                )),
        )
}

fn create_test_token(
    jwt_service: &dyn JwtService,
    _email: &str,
    _is_admin: bool,
    user_id: i32,
) -> String {
    let claims = bedrock_sso_proxy::auth::jwt::OAuthClaims::new(user_id, 3600);

    jwt_service.create_oauth_token(&claims).unwrap()
}

async fn setup_test_data(database: &dyn DatabaseManager) -> (i32, i32) {
    // Create test users
    let user1 = UserRecord {
        id: 0,
        provider: "google".to_string(),
        provider_user_id: "test-user-1".to_string(),
        email: "user1@example.com".to_string(),
        display_name: Some("Test User 1".to_string()),
        created_at: Utc::now(),
        updated_at: Utc::now(),
        last_login: Some(Utc::now()),
    };
    let user1_id = database.users().upsert(&user1).await.unwrap();

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

    // Create usage records for user1 with exact decimal costs
    let models = [
        (
            "anthropic.claude-sonnet-4-20250514-v1:0",
            100,
            50,
            Decimal::new(75, 4),
        ), // 0.0075
        (
            "anthropic.claude-3-haiku-20240307-v1:0",
            200,
            75,
            Decimal::new(5, 3),
        ), // 0.005
        (
            "anthropic.claude-3-opus-20240229-v1:0",
            150,
            100,
            Decimal::new(2, 2),
        ), // 0.02
    ];

    for (i, (model, input, output, cost)) in models.iter().enumerate() {
        let record = UsageRecord {
            id: 0,
            user_id: user1_id,
            model_id: model.to_string(),
            endpoint_type: if i % 2 == 0 { "bedrock" } else { "anthropic" }.to_string(),
            region: "us-east-1".to_string(),
            request_time: Utc::now() - chrono::Duration::minutes(i as i64 * 10),
            input_tokens: *input,
            output_tokens: *output,
            cache_write_tokens: None,
            cache_read_tokens: None,
            total_tokens: input + output,
            response_time_ms: 200 + (i as i32 * 50),
            success: true,
            error_message: None,
            cost_usd: Some(*cost),
        };
        database.usage().store_record(&record).await.unwrap();
    }

    // Create model costs with exact decimal values
    let model_costs = vec![
        (
            "anthropic.claude-sonnet-4-20250514-v1:0",
            Decimal::new(3, 3),
            Decimal::new(15, 3),
        ), // 0.003, 0.015
        (
            "anthropic.claude-3-haiku-20240307-v1:0",
            Decimal::new(25, 5),
            Decimal::new(125, 5),
        ), // 0.00025, 0.00125
        ("test-new-model", Decimal::new(1, 3), Decimal::new(5, 3)), // 0.001, 0.005
    ];

    let costs: Vec<_> = model_costs
        .into_iter()
        .map(|(model_id, input_cost, output_cost)| ModelCost {
            id: 0,
            region: "us-east-1".to_string(),
            model_id: model_id.to_string(),
            input_cost_per_1k_tokens: input_cost,
            output_cost_per_1k_tokens: output_cost,
            cache_write_cost_per_1k_tokens: None,
            cache_read_cost_per_1k_tokens: None,
            updated_at: Utc::now(),
        })
        .collect();
    database.model_costs().upsert_many(&costs).await.unwrap();

    (user1_id, admin_id)
}

// Test implementation functions
async fn test_get_user_usage_records_success_impl(server: &bedrock_sso_proxy::server::Server) {
    let (user_id, _) = setup_test_data(server.database.as_ref()).await;

    let token = create_test_token(
        server.jwt_service.as_ref(),
        "user1@example.com",
        false,
        user_id,
    );
    let app = create_test_router(server);

    let request = Request::builder()
        .method(Method::GET)
        .uri("/usage/records?limit=10&offset=0")
        .header(AUTHORIZATION, format!("Bearer {}", token))
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();

    assert!(json["records"].is_array());
    assert_eq!(json["records"].as_array().unwrap().len(), 3);
    assert_eq!(json["total"], 3);
    assert_eq!(json["limit"], 10);
    assert_eq!(json["offset"], 0);
}

// Generate both SQLite and PostgreSQL tests
database_test!(
    test_get_user_usage_records_success,
    test_get_user_usage_records_success_impl
);

async fn test_get_user_usage_stats_success_impl(server: &bedrock_sso_proxy::server::Server) {
    let (user_id, _) = setup_test_data(server.database.as_ref()).await;

    let token = create_test_token(
        server.jwt_service.as_ref(),
        "user1@example.com",
        false,
        user_id,
    );
    let app = create_test_router(server);

    let request = Request::builder()
        .method(Method::GET)
        .uri("/usage/stats")
        .header(AUTHORIZATION, format!("Bearer {}", token))
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(json["total_requests"], 3);
    assert_eq!(json["total_input_tokens"], 450); // 100 + 200 + 150
    assert_eq!(json["total_output_tokens"], 225); // 50 + 75 + 100
    // Use string comparison for decimal values due to floating point precision
    let total_cost: String = json["total_cost"].as_str().unwrap_or("0").to_string();
    let expected_cost = "0.0325";
    let parsed_cost: f64 = total_cost.parse().unwrap_or(0.0);
    let expected_cost_f64: f64 = expected_cost.parse().unwrap();
    assert!(
        (parsed_cost - expected_cost_f64).abs() < 0.0001,
        "Expected cost {}, got {}",
        expected_cost,
        total_cost
    );
}

database_test!(
    test_get_user_usage_stats_success,
    test_get_user_usage_stats_success_impl
);

async fn test_get_user_usage_with_filters_impl(server: &bedrock_sso_proxy::server::Server) {
    let (user_id, _) = setup_test_data(server.database.as_ref()).await;

    let token = create_test_token(
        server.jwt_service.as_ref(),
        "user1@example.com",
        false,
        user_id,
    );
    let app = create_test_router(server);

    // Test model filtering
    let request = Request::builder()
        .method(Method::GET)
        .uri("/usage/records?model=anthropic.claude-sonnet-4-20250514-v1:0")
        .header(AUTHORIZATION, format!("Bearer {}", token))
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();

    let records = json["records"].as_array().unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(
        records[0]["model_id"],
        "anthropic.claude-sonnet-4-20250514-v1:0"
    );
}

database_test!(
    test_get_user_usage_with_filters,
    test_get_user_usage_with_filters_impl
);

async fn test_admin_get_system_usage_records_impl(server: &bedrock_sso_proxy::server::Server) {
    let (_user_id, admin_id) = setup_test_data(server.database.as_ref()).await;

    let admin_token = create_test_token(
        server.jwt_service.as_ref(),
        "admin@admin.example.com",
        true,
        admin_id,
    );
    let app = create_test_router(server);

    let request = Request::builder()
        .method(Method::GET)
        .uri("/admin/usage/records")
        .header(AUTHORIZATION, format!("Bearer {}", admin_token))
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();

    assert!(json["records"].is_array());
    assert_eq!(json["records"].as_array().unwrap().len(), 3); // All system records
}

database_test!(
    test_admin_get_system_usage_records,
    test_admin_get_system_usage_records_impl
);

async fn test_admin_get_top_models_impl(server: &bedrock_sso_proxy::server::Server) {
    let (_user_id, admin_id) = setup_test_data(server.database.as_ref()).await;

    let admin_token = create_test_token(
        server.jwt_service.as_ref(),
        "admin@admin.example.com",
        true,
        admin_id,
    );
    let app = create_test_router(server);

    let request = Request::builder()
        .method(Method::GET)
        .uri("/admin/usage/top-models")
        .header(AUTHORIZATION, format!("Bearer {}", admin_token))
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();

    let models = json["models"].as_array().unwrap();
    assert_eq!(models.len(), 3);

    // Should be sorted by total tokens (descending)
    assert_eq!(
        models[0]["model_id"],
        "anthropic.claude-3-haiku-20240307-v1:0"
    );
    assert_eq!(models[0]["total_tokens"], 275); // 200 + 75
}

database_test!(test_admin_get_top_models, test_admin_get_top_models_impl);

async fn test_non_admin_access_denied_impl(server: &bedrock_sso_proxy::server::Server) {
    let (user1_id, _) = setup_test_data(server.database.as_ref()).await;

    let user_token = create_test_token(
        server.jwt_service.as_ref(),
        "user1@example.com",
        false,
        user1_id,
    );
    let app = create_test_router(server);

    // Test admin endpoint access with non-admin token
    let request = Request::builder()
        .method(Method::GET)
        .uri("/admin/usage/records")
        .header(AUTHORIZATION, format!("Bearer {}", user_token))
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

database_test!(
    test_non_admin_access_denied,
    test_non_admin_access_denied_impl
);

async fn test_unauthorized_access_impl(server: &bedrock_sso_proxy::server::Server) {
    setup_test_data(server.database.as_ref()).await;

    // Test without authorization header
    let app1 = create_test_router(server);
    let request = Request::builder()
        .method(Method::GET)
        .uri("/usage/records")
        .body(Body::empty())
        .unwrap();

    let response = app1.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    // Test with invalid token
    let app2 = create_test_router(server);
    let request = Request::builder()
        .method(Method::GET)
        .uri("/usage/records")
        .header(AUTHORIZATION, "Bearer invalid-token")
        .body(Body::empty())
        .unwrap();

    let response = app2.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

database_test!(test_unauthorized_access, test_unauthorized_access_impl);

async fn test_pagination_limits_impl(server: &bedrock_sso_proxy::server::Server) {
    let (user1_id, _) = setup_test_data(server.database.as_ref()).await;

    let token = create_test_token(
        server.jwt_service.as_ref(),
        "user1@example.com",
        false,
        user1_id,
    );
    let app = create_test_router(server);

    // Test limit enforcement (max 500)
    let request = Request::builder()
        .method(Method::GET)
        .uri("/usage/records?limit=1000")
        .header(AUTHORIZATION, format!("Bearer {}", token))
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["limit"], 500); // Should be capped at 500
}

database_test!(test_pagination_limits, test_pagination_limits_impl);

async fn test_get_stats_uses_summaries_when_available_impl(
    server: &bedrock_sso_proxy::server::Server,
) {
    let (user_id, _) = setup_test_data(server.database.as_ref()).await;

    // Create a usage summary record for the same user
    let summary = UsageSummary {
        id: 0,
        user_id,
        model_id: "anthropic.claude-sonnet-4-20250514-v1:0".to_string(),
        period_type: PeriodType::Daily,
        period_start: Utc::now() - chrono::Duration::hours(24),
        period_end: Utc::now(),
        total_requests: 10,
        successful_requests: 9,
        total_input_tokens: 1000,
        total_output_tokens: 500,
        total_tokens: 1500,
        avg_response_time_ms: 250.0,
        estimated_cost: Some(Decimal::new(150, 3)), // 0.150
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };

    // Store the summary
    server
        .database
        .usage()
        .upsert_many_summaries(&[summary])
        .await
        .unwrap();

    // Test the DAO method directly to verify it uses summaries
    use bedrock_sso_proxy::database::dao::usage::UsageQuery;

    let query = UsageQuery {
        user_id: Some(user_id),
        model_id: Some("anthropic.claude-sonnet-4-20250514-v1:0".to_string()),
        ..Default::default()
    };

    let stats = server.database.usage().get_stats(&query).await.unwrap();

    // Verify stats come from summary (not from records)
    // The summary should override the record data for this model
    assert_eq!(stats.total_requests, 10);
    assert_eq!(stats.total_input_tokens, 1000);
    assert_eq!(stats.total_output_tokens, 500);
    assert_eq!(stats.total_tokens, 1500);
    assert_eq!(stats.avg_response_time_ms, 250.0);
    assert_eq!(stats.success_rate, 0.9);

    assert!(stats.total_cost.is_some());
    let cost = stats.total_cost.unwrap();
    // Compare decimal values properly
    assert_eq!(cost, Decimal::new(150, 3)); // 0.150
}

database_test!(
    test_get_stats_uses_summaries_when_available,
    test_get_stats_uses_summaries_when_available_impl
);

// Test real-time hourly summary updates
async fn test_realtime_hourly_summary_updates_impl(server: &bedrock_sso_proxy::server::Server) {
    let database = server.database.clone();

    // Create test user
    let user = users::Model {
        id: 0, // Will be set by database
        provider_user_id: "test-user-1".to_string(),
        provider: "test".to_string(),
        email: "test@example.com".to_string(),
        display_name: Some("Test User".to_string()),
        created_at: Utc::now(),
        updated_at: Utc::now(),
        last_login: None,
    };
    let user_id = database.users().upsert(&user).await.unwrap();

    // Create first usage record
    let usage_record1 = usage_records::Model {
        id: 0,
        user_id,
        model_id: "claude-sonnet-4".to_string(),
        endpoint_type: "invoke".to_string(),
        region: "us-east-1".to_string(),
        request_time: Utc::now(),
        input_tokens: 100,
        output_tokens: 50,
        cache_write_tokens: None,
        cache_read_tokens: None,
        total_tokens: 150,
        response_time_ms: 500,
        success: true,
        error_message: None,
        cost_usd: Some(Decimal::new(25, 3)), // 0.025
    };

    // Store record and update hourly summary
    database.usage().store_record(&usage_record1).await.unwrap();
    database
        .usage()
        .update_hourly_summary(&usage_record1)
        .await
        .unwrap();

    // Verify hourly summary was created
    let summaries = database
        .usage()
        .get_summaries(&bedrock_sso_proxy::database::dao::usage::UsageQuery {
            user_id: Some(user_id),
            model_id: Some("claude-sonnet-4".to_string()),
            ..Default::default()
        })
        .await
        .unwrap();

    assert_eq!(summaries.len(), 1);
    let summary = &summaries[0];
    assert_eq!(summary.period_type, PeriodType::Hourly);
    assert_eq!(summary.total_requests, 1);
    assert_eq!(summary.total_input_tokens, 100);
    assert_eq!(summary.total_output_tokens, 50);
    assert_eq!(summary.total_tokens, 150);
    assert_eq!(summary.avg_response_time_ms, 500.0);
    assert_eq!(summary.successful_requests, 1);
    assert_eq!(summary.estimated_cost, Some(Decimal::new(25, 3)));

    // Create second usage record in the same hour
    let usage_record2 = usage_records::Model {
        id: 0,
        user_id,
        model_id: "claude-sonnet-4".to_string(),
        endpoint_type: "invoke".to_string(),
        region: "us-east-1".to_string(),
        request_time: usage_record1.request_time, // Same hour
        input_tokens: 200,
        output_tokens: 100,
        cache_write_tokens: None,
        cache_read_tokens: None,
        total_tokens: 300,
        response_time_ms: 300,
        success: false, // Failed request
        error_message: Some("Test error".to_string()),
        cost_usd: Some(Decimal::new(50, 3)), // 0.050
    };

    // Store record and update hourly summary
    database.usage().store_record(&usage_record2).await.unwrap();
    database
        .usage()
        .update_hourly_summary(&usage_record2)
        .await
        .unwrap();

    // Verify hourly summary was updated (aggregated)
    let updated_summaries = database
        .usage()
        .get_summaries(&bedrock_sso_proxy::database::dao::usage::UsageQuery {
            user_id: Some(user_id),
            model_id: Some("claude-sonnet-4".to_string()),
            ..Default::default()
        })
        .await
        .unwrap();

    assert_eq!(updated_summaries.len(), 1); // Still only 1 summary (same hour)
    let updated_summary = &updated_summaries[0];

    // Verify aggregated values
    assert_eq!(updated_summary.total_requests, 2); // 1 + 1
    assert_eq!(updated_summary.total_input_tokens, 300); // 100 + 200
    assert_eq!(updated_summary.total_output_tokens, 150); // 50 + 100
    assert_eq!(updated_summary.total_tokens, 450); // 150 + 300
    assert_eq!(updated_summary.avg_response_time_ms, 400.0); // (500 + 300) / 2
    assert_eq!(updated_summary.successful_requests, 1); // 1 success out of 2 total
    assert_eq!(updated_summary.estimated_cost, Some(Decimal::new(75, 3))); // 0.025 + 0.050

    // Create third usage record in a different hour
    let different_hour = usage_record1.request_time + chrono::Duration::hours(1);
    let usage_record3 = usage_records::Model {
        id: 0,
        user_id,
        model_id: "claude-sonnet-4".to_string(),
        endpoint_type: "invoke".to_string(),
        region: "us-east-1".to_string(),
        request_time: different_hour,
        input_tokens: 75,
        output_tokens: 25,
        cache_write_tokens: None,
        cache_read_tokens: None,
        total_tokens: 100,
        response_time_ms: 200,
        success: true,
        error_message: None,
        cost_usd: Some(Decimal::new(10, 3)), // 0.010
    };

    // Store record and update hourly summary
    database.usage().store_record(&usage_record3).await.unwrap();
    database
        .usage()
        .update_hourly_summary(&usage_record3)
        .await
        .unwrap();

    // Verify we now have 2 hourly summaries
    let all_summaries = database
        .usage()
        .get_summaries(&bedrock_sso_proxy::database::dao::usage::UsageQuery {
            user_id: Some(user_id),
            model_id: Some("claude-sonnet-4".to_string()),
            ..Default::default()
        })
        .await
        .unwrap();

    assert_eq!(all_summaries.len(), 2); // Two different hours

    // Verify the new hourly summary
    let new_hour_summary = all_summaries
        .iter()
        .find(|s| s.total_requests == 1)
        .expect("Should find the new hour summary");

    assert_eq!(new_hour_summary.total_input_tokens, 75);
    assert_eq!(new_hour_summary.total_output_tokens, 25);
    assert_eq!(new_hour_summary.total_tokens, 100);
    assert_eq!(new_hour_summary.avg_response_time_ms, 200.0);
    assert_eq!(new_hour_summary.successful_requests, 1);
    assert_eq!(new_hour_summary.estimated_cost, Some(Decimal::new(10, 3)));
}

database_test!(
    test_realtime_hourly_summary_updates,
    test_realtime_hourly_summary_updates_impl
);

// Test real-time hourly summary with different users and models
async fn test_realtime_hourly_summary_different_keys_impl(
    server: &bedrock_sso_proxy::server::Server,
) {
    let database = server.database.clone();

    // Create test users
    let user1 = users::Model {
        id: 0, // Will be set by database
        provider_user_id: "test-user-1".to_string(),
        provider: "test".to_string(),
        email: "user1@example.com".to_string(),
        display_name: Some("User 1".to_string()),
        created_at: Utc::now(),
        updated_at: Utc::now(),
        last_login: None,
    };
    let user2 = users::Model {
        id: 0, // Will be set by database
        provider_user_id: "test-user-2".to_string(),
        provider: "test".to_string(),
        email: "user2@example.com".to_string(),
        display_name: Some("User 2".to_string()),
        created_at: Utc::now(),
        updated_at: Utc::now(),
        last_login: None,
    };
    let user1_id = database.users().upsert(&user1).await.unwrap();
    let user2_id = database.users().upsert(&user2).await.unwrap();

    let now = Utc::now();

    // Create usage records for different user/model combinations in same hour
    let records = vec![
        // User 1, Model A
        usage_records::Model {
            id: 0,
            user_id: user1_id,
            model_id: "claude-sonnet-4".to_string(),
            endpoint_type: "invoke".to_string(),
            region: "us-east-1".to_string(),
            request_time: now,
            input_tokens: 100,
            output_tokens: 50,
            cache_write_tokens: None,
            cache_read_tokens: None,
            total_tokens: 150,
            response_time_ms: 300,
            success: true,
            error_message: None,
            cost_usd: Some(Decimal::new(20, 3)),
        },
        // User 1, Model B
        usage_records::Model {
            id: 0,
            user_id: user1_id,
            model_id: "claude-haiku-3".to_string(),
            endpoint_type: "invoke".to_string(),
            region: "us-east-1".to_string(),
            request_time: now,
            input_tokens: 200,
            output_tokens: 100,
            cache_write_tokens: None,
            cache_read_tokens: None,
            total_tokens: 300,
            response_time_ms: 400,
            success: true,
            error_message: None,
            cost_usd: Some(Decimal::new(15, 3)),
        },
        // User 2, Model A
        usage_records::Model {
            id: 0,
            user_id: user2_id,
            model_id: "claude-sonnet-4".to_string(),
            endpoint_type: "invoke".to_string(),
            region: "us-east-1".to_string(),
            request_time: now,
            input_tokens: 150,
            output_tokens: 75,
            cache_write_tokens: None,
            cache_read_tokens: None,
            total_tokens: 225,
            response_time_ms: 500,
            success: true,
            error_message: None,
            cost_usd: Some(Decimal::new(30, 3)),
        },
    ];

    // Store all records and update summaries
    for record in &records {
        database.usage().store_record(record).await.unwrap();
        database
            .usage()
            .update_hourly_summary(record)
            .await
            .unwrap();
    }

    // Verify we have 3 separate hourly summaries (different user/model combinations)
    let all_summaries = database
        .usage()
        .get_summaries(&bedrock_sso_proxy::database::dao::usage::UsageQuery {
            ..Default::default()
        })
        .await
        .unwrap();

    assert_eq!(all_summaries.len(), 3);

    // Check User 1, Model A summary
    let user1_model_a = all_summaries
        .iter()
        .find(|s| s.user_id == user1_id && s.model_id == "claude-sonnet-4")
        .expect("Should find User 1, Model A summary");
    assert_eq!(user1_model_a.total_requests, 1);
    assert_eq!(user1_model_a.total_tokens, 150);

    // Check User 1, Model B summary
    let user1_model_b = all_summaries
        .iter()
        .find(|s| s.user_id == user1_id && s.model_id == "claude-haiku-3")
        .expect("Should find User 1, Model B summary");
    assert_eq!(user1_model_b.total_requests, 1);
    assert_eq!(user1_model_b.total_tokens, 300);

    // Check User 2, Model A summary
    let user2_model_a = all_summaries
        .iter()
        .find(|s| s.user_id == user2_id && s.model_id == "claude-sonnet-4")
        .expect("Should find User 2, Model A summary");
    assert_eq!(user2_model_a.total_requests, 1);
    assert_eq!(user2_model_a.total_tokens, 225);
}

database_test!(
    test_realtime_hourly_summary_different_keys,
    test_realtime_hourly_summary_different_keys_impl
);
