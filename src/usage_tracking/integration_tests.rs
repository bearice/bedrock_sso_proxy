//! Integration tests for usage tracking API routes
//! These tests verify end-to-end functionality with real JWT authentication

#[cfg(test)]
mod tests {
    use crate::{auth::jwt::JwtService, database::DatabaseManager, database::entities::*};
    use axum::{
        Router,
        body::Body,
        extract::Request,
        http::{Method, StatusCode, header::AUTHORIZATION},
        middleware,
    };
    use chrono::Utc;

    use rust_decimal::Decimal;
    use serde_json::Value;

    use tower::ServiceExt;

    async fn create_test_server() -> crate::server::Server {
        let mut config = crate::config::Config::default();
        config.cache.backend = "memory".to_string();
        config.database.enabled = true;
        config.database.url = "sqlite::memory:".to_string(); // Use in-memory database
        config.metrics.enabled = false;
        // Add admin email for tests
        config.admin.emails = vec!["admin@admin.example.com".to_string()];

        let server = crate::server::Server::new(config).await.unwrap();

        // Run migrations to create tables
        server.database.migrate().await.unwrap();

        server
    }

    fn create_test_router(server: &crate::server::Server) -> Router {
        // Combine user and admin routes for testing
        Router::new()
            .merge(
                crate::usage_tracking::create_user_usage_routes()
                    .with_state(server.clone())
                    .layer(middleware::from_fn_with_state(
                        server.clone(),
                        crate::auth::middleware::jwt_auth_middleware,
                    )),
            )
            .merge(
                crate::usage_tracking::create_admin_usage_routes()
                    .with_state(server.clone())
                    .layer(middleware::from_fn_with_state(
                        server.clone(),
                        crate::auth::middleware::admin_middleware,
                    ))
                    .layer(middleware::from_fn_with_state(
                        server.clone(),
                        crate::auth::middleware::jwt_auth_middleware,
                    )),
            )
    }

    fn create_test_token(
        jwt_service: &JwtService,
        _email: &str,
        _is_admin: bool,
        user_id: i32,
    ) -> String {
        let claims = crate::auth::jwt::OAuthClaims::new(user_id, 3600);

        jwt_service.create_oauth_token(&claims).unwrap()
    }

    async fn setup_test_data(database: &DatabaseManager) -> (i32, i32) {
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
                response_time_ms: 200 + (i as u32 * 50),
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

        for (model_id, input_cost, output_cost) in model_costs {
            let cost = StoredModelCost {
                id: 0,
                model_id: model_id.to_string(),
                input_cost_per_1k_tokens: input_cost,
                output_cost_per_1k_tokens: output_cost,
                cache_write_cost_per_1k_tokens: None,
                cache_read_cost_per_1k_tokens: None,
                updated_at: Utc::now(),
            };
            database.model_costs().upsert(&cost).await.unwrap();
        }

        (user1_id, admin_id)
    }

    #[tokio::test]
    async fn test_get_user_usage_records_success() {
        let server = create_test_server().await;
        let (user_id, _) = setup_test_data(&server.database).await;

        let token = create_test_token(&server.jwt_service, "user1@example.com", false, user_id);
        let app = create_test_router(&server);

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

    #[tokio::test]
    async fn test_get_user_usage_stats_success() {
        let server = create_test_server().await;
        let (user_id, _) = setup_test_data(&server.database).await;

        let token = create_test_token(&server.jwt_service, "user1@example.com", false, user_id);
        let app = create_test_router(&server);

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

    #[tokio::test]
    async fn test_get_user_usage_with_filters() {
        let server = create_test_server().await;
        let (user_id, _) = setup_test_data(&server.database).await;

        let token = create_test_token(&server.jwt_service, "user1@example.com", false, user_id);
        let app = create_test_router(&server);

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

    #[tokio::test]
    async fn test_admin_get_system_usage_records() {
        let server = create_test_server().await;
        let (_user_id, admin_id) = setup_test_data(&server.database).await;

        let admin_token = create_test_token(
            &server.jwt_service,
            "admin@admin.example.com",
            true,
            admin_id,
        );
        let app = create_test_router(&server);

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

    #[tokio::test]
    async fn test_admin_get_top_models() {
        let server = create_test_server().await;
        let (_user_id, admin_id) = setup_test_data(&server.database).await;

        let admin_token = create_test_token(
            &server.jwt_service,
            "admin@admin.example.com",
            true,
            admin_id,
        );
        let app = create_test_router(&server);

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

    #[tokio::test]
    async fn test_admin_model_cost_management() {
        let server = create_test_server().await;
        let (_, admin_id) = setup_test_data(&server.database).await;

        let admin_token = create_test_token(
            &server.jwt_service,
            "admin@admin.example.com",
            true,
            admin_id,
        );

        // Test get all model costs
        let app1 = create_test_router(&server);
        let request = Request::builder()
            .method(Method::GET)
            .uri("/admin/model-costs")
            .header(AUTHORIZATION, format!("Bearer {}", admin_token))
            .body(Body::empty())
            .unwrap();

        let response = app1.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let costs: Vec<Value> = serde_json::from_slice(&body).unwrap();
        assert!(costs.len() >= 3); // Should have our test costs

        // Test create new model cost
        let app2 = create_test_router(&server);
        let new_cost = serde_json::json!({
            "model_id": "new-test-model",
            "input_cost_per_1k_tokens": 0.002,
            "output_cost_per_1k_tokens": 0.008
        });

        let request = Request::builder()
            .method(Method::POST)
            .uri("/admin/model-costs")
            .header(AUTHORIZATION, format!("Bearer {}", admin_token))
            .header("content-type", "application/json")
            .body(Body::from(new_cost.to_string()))
            .unwrap();

        let response = app2.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);

        // Test get specific model cost
        let app3 = create_test_router(&server);
        let request = Request::builder()
            .method(Method::GET)
            .uri("/admin/model-costs/new-test-model")
            .header(AUTHORIZATION, format!("Bearer {}", admin_token))
            .body(Body::empty())
            .unwrap();

        let response = app3.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let cost: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(cost["model_id"], "new-test-model");
        // Use string comparison for decimal values due to floating point precision
        let input_cost: String = cost["input_cost_per_1k_tokens"]
            .as_str()
            .unwrap_or("0")
            .to_string();
        let expected_cost = "0.002";
        let parsed_cost: f64 = input_cost.parse().unwrap_or(0.0);
        let expected_cost_f64: f64 = expected_cost.parse().unwrap();
        assert!(
            (parsed_cost - expected_cost_f64).abs() < 0.0001,
            "Expected cost {}, got {}",
            expected_cost,
            input_cost
        );

        // Test update model cost
        let app4 = create_test_router(&server);
        let updated_cost = serde_json::json!({
            "model_id": "new-test-model",
            "input_cost_per_1k_tokens": 0.003,
            "output_cost_per_1k_tokens": 0.010
        });

        let request = Request::builder()
            .method(Method::PUT)
            .uri("/admin/model-costs/new-test-model")
            .header(AUTHORIZATION, format!("Bearer {}", admin_token))
            .header("content-type", "application/json")
            .body(Body::from(updated_cost.to_string()))
            .unwrap();

        let response = app4.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        // Test delete model cost
        let app5 = create_test_router(&server);
        let request = Request::builder()
            .method(Method::DELETE)
            .uri("/admin/model-costs/new-test-model")
            .header(AUTHORIZATION, format!("Bearer {}", admin_token))
            .body(Body::empty())
            .unwrap();

        let response = app5.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn test_non_admin_access_denied() {
        let server = create_test_server().await;
        let (user1_id, _) = setup_test_data(&server.database).await;

        let user_token =
            create_test_token(&server.jwt_service, "user1@example.com", false, user1_id);
        let app = create_test_router(&server);

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

    #[tokio::test]
    async fn test_unauthorized_access() {
        let server = create_test_server().await;
        setup_test_data(&server.database).await;

        // Test without authorization header
        let app1 = create_test_router(&server);
        let request = Request::builder()
            .method(Method::GET)
            .uri("/usage/records")
            .body(Body::empty())
            .unwrap();

        let response = app1.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        // Test with invalid token
        let app2 = create_test_router(&server);
        let request = Request::builder()
            .method(Method::GET)
            .uri("/usage/records")
            .header(AUTHORIZATION, "Bearer invalid-token")
            .body(Body::empty())
            .unwrap();

        let response = app2.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_pagination_limits() {
        let server = create_test_server().await;
        let (user1_id, _) = setup_test_data(&server.database).await;

        let token = create_test_token(&server.jwt_service, "user1@example.com", false, user1_id);
        let app = create_test_router(&server);

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

    #[tokio::test]
    async fn test_error_handling() {
        let server = create_test_server().await;
        let (_, admin_id) = setup_test_data(&server.database).await;

        let admin_token = create_test_token(
            &server.jwt_service,
            "admin@admin.example.com",
            true,
            admin_id,
        );

        // Test invalid model cost data
        let app1 = create_test_router(&server);
        let invalid_cost = serde_json::json!({
            "model_id": "",  // Empty model ID should fail
            "input_cost_per_1k_tokens": "invalid", // Invalid type
            "output_cost_per_1k_tokens": -1 // Negative cost
        });

        let request = Request::builder()
            .method(Method::POST)
            .uri("/admin/model-costs")
            .header(AUTHORIZATION, format!("Bearer {}", admin_token))
            .header("content-type", "application/json")
            .body(Body::from(invalid_cost.to_string()))
            .unwrap();

        let response = app1.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);

        // Test accessing non-existent model cost
        let app2 = create_test_router(&server);
        let request = Request::builder()
            .method(Method::GET)
            .uri("/admin/model-costs/non-existent-model")
            .header(AUTHORIZATION, format!("Bearer {}", admin_token))
            .body(Body::empty())
            .unwrap();

        let response = app2.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}
