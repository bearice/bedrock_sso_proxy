//! Integration tests for usage tracking API routes
//! These tests verify end-to-end functionality with real JWT authentication

use axum::{
    body::Body,
    http::{Method, Request, StatusCode},
};
use bedrock_sso_proxy::database::entities::{users, *};
use chrono::Utc;
use rust_decimal::Decimal;
use serde_json::Value;

mod common;
use common::{PostgresTestDb, TestHarness};

async fn setup_test_data(harness: &TestHarness) -> (i32, i32) {
    let database = harness.server.database.as_ref();
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
        ..Default::default()
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
        ..Default::default()
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
            stop_reason: Some("end_turn".to_string()),
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
async fn test_get_user_usage_records_success_impl(harness: &TestHarness) {
    let (user_id, _) = setup_test_data(harness).await;
    let token = harness.create_integration_token(user_id);

    let request = Request::builder()
        .method(Method::GET)
        .uri("/api/usage/records?limit=10&offset=0")
        .header("Authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();

    let response = harness.make_request(request).await;
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

async fn test_get_user_usage_with_filters_impl(harness: &TestHarness) {
    let (user_id, _) = setup_test_data(harness).await;
    let token = harness.create_integration_token(user_id);

    // Test model filtering
    let request = Request::builder()
        .method(Method::GET)
        .uri("/api/usage/records?model=anthropic.claude-sonnet-4-20250514-v1:0")
        .header("Authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();

    let response = harness.make_request(request).await;
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

async fn test_admin_get_system_usage_records_impl(harness: &TestHarness) {
    let (_user_id, admin_id) = setup_test_data(harness).await;
    let admin_token = harness.create_integration_token(admin_id);

    let request = Request::builder()
        .method(Method::GET)
        .uri("/api/admin/usage/records")
        .header("Authorization", format!("Bearer {admin_token}"))
        .body(Body::empty())
        .unwrap();

    let response = harness.make_request(request).await;
    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();

    assert!(json["records"].is_array());
    assert_eq!(json["records"].as_array().unwrap().len(), 3); // All system records
}

async fn test_non_admin_access_denied_impl(harness: &TestHarness) {
    let (user1_id, _) = setup_test_data(harness).await;
    let user_token = harness.create_integration_token(user1_id);

    // Test admin endpoint access with non-admin token
    let request = Request::builder()
        .method(Method::GET)
        .uri("/api/admin/usage/records")
        .header("Authorization", format!("Bearer {user_token}"))
        .body(Body::empty())
        .unwrap();

    let response = harness.make_request(request).await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

async fn test_unauthorized_access_impl(harness: &TestHarness) {
    setup_test_data(harness).await;

    // Test without authorization header
    let request = Request::builder()
        .method(Method::GET)
        .uri("/api/usage/records")
        .body(Body::empty())
        .unwrap();

    let response = harness.make_request(request).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    // Test with invalid token
    let request = Request::builder()
        .method(Method::GET)
        .uri("/api/usage/records")
        .header("Authorization", "Bearer invalid-token")
        .body(Body::empty())
        .unwrap();

    let response = harness.make_request(request).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

async fn test_pagination_limits_impl(harness: &TestHarness) {
    let (user1_id, _) = setup_test_data(harness).await;
    let token = harness.create_integration_token(user1_id);

    // Test limit enforcement (max 500)
    let request = Request::builder()
        .method(Method::GET)
        .uri("/api/usage/records?limit=1000")
        .header("Authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();

    let response = harness.make_request(request).await;
    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["limit"], 500); // Should be capped at 500
}

async fn test_get_stats_uses_summaries_when_available_impl(harness: &TestHarness) {
    let (user_id, _) = setup_test_data(harness).await;
    let database = harness.server.database.as_ref();

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
        total_cache_write_tokens: 0,
        total_cache_read_tokens: 0,
        total_tokens: 1500,
        avg_response_time_ms: 250.0,
        estimated_cost: Some(Decimal::new(150, 3)), // 0.150
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };

    // Store the summary
    database.usage().upsert_many_summaries(&[summary]).await.unwrap();

    // Test the DAO method directly to verify it uses summaries
    use bedrock_sso_proxy::database::dao::usage::UsageQuery;

    let query = UsageQuery {
        user_id: Some(user_id),
        model_id: Some("anthropic.claude-sonnet-4-20250514-v1:0".to_string()),
        ..Default::default()
    };

    let stats = database.usage().get_stats(&query).await.unwrap();

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

async fn test_realtime_hourly_summary_updates_impl(harness: &TestHarness) {
    let database = harness.server.database.clone();

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
        ..Default::default()
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
        stop_reason: Some("end_turn".to_string()),
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
        stop_reason: None,                   // No stop_reason for failed requests
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
        stop_reason: Some("end_turn".to_string()),
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

async fn test_realtime_hourly_summary_different_keys_impl(harness: &TestHarness) {
    let database = harness.server.database.clone();

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
        ..Default::default()
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
        ..Default::default()
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
            stop_reason: Some("end_turn".to_string()),
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
            stop_reason: Some("end_turn".to_string()),
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
            stop_reason: Some("end_turn".to_string()),
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

async fn test_pagination_total_count_accuracy_impl(harness: &TestHarness) {
    let (user_id, _) = setup_test_data(harness).await;
    let database = harness.server.database.as_ref();

    // Create additional records to test pagination (setup_test_data creates 3)
    for i in 4..=20 {
        let record = UsageRecord {
            id: 0,
            user_id,
            model_id: format!("test-model-{i}"),
            endpoint_type: "bedrock".to_string(),
            region: "us-east-1".to_string(),
            request_time: Utc::now() - chrono::Duration::minutes(i as i64),
            input_tokens: 50,
            output_tokens: 25,
            cache_write_tokens: None,
            cache_read_tokens: None,
            total_tokens: 75,
            response_time_ms: 150,
            success: true,
            error_message: None,
            stop_reason: Some("end_turn".to_string()),
            cost_usd: Some(Decimal::new(10, 4)), // 0.001
        };
        database.usage().store_record(&record).await.unwrap();
    }

    let token = harness.create_integration_token(user_id);

    // Test first page (limit 5)
    let request = Request::builder()
        .method(Method::GET)
        .uri("/api/usage/records?limit=5&offset=0")
        .header("Authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();

    let response = harness.make_request(request).await;
    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();

    // Should return 5 records but total should be 20 (3 original + 17 new)
    assert_eq!(json["records"].as_array().unwrap().len(), 5);
    assert_eq!(json["total"], 20);
    assert_eq!(json["limit"], 5);
    assert_eq!(json["offset"], 0);

    // Test second page (limit 5, offset 5)
    let request2 = Request::builder()
        .method(Method::GET)
        .uri("/api/usage/records?limit=5&offset=5")
        .header("Authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();

    let response2 = harness.make_request(request2).await;
    assert_eq!(response2.status(), StatusCode::OK);

    let body2 = axum::body::to_bytes(response2.into_body(), usize::MAX)
        .await
        .unwrap();
    let json2: Value = serde_json::from_slice(&body2).unwrap();

    // Should return 5 records, same total count
    assert_eq!(json2["records"].as_array().unwrap().len(), 5);
    assert_eq!(json2["total"], 20); // Total should be consistent
    assert_eq!(json2["limit"], 5);
    assert_eq!(json2["offset"], 5);

    // Test last page (limit 5, offset 15)
    let request3 = Request::builder()
        .method(Method::GET)
        .uri("/api/usage/records?limit=5&offset=15")
        .header("Authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();

    let response3 = harness.make_request(request3).await;
    assert_eq!(response3.status(), StatusCode::OK);

    let body3 = axum::body::to_bytes(response3.into_body(), usize::MAX)
        .await
        .unwrap();
    let json3: Value = serde_json::from_slice(&body3).unwrap();

    // Should return 5 records (last page), same total count
    assert_eq!(json3["records"].as_array().unwrap().len(), 5);
    assert_eq!(json3["total"], 20); // Total should be consistent
    assert_eq!(json3["limit"], 5);
    assert_eq!(json3["offset"], 15);

    // Test beyond last page (limit 5, offset 20)
    let request4 = Request::builder()
        .method(Method::GET)
        .uri("/api/usage/records?limit=5&offset=20")
        .header("Authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();

    let response4 = harness.make_request(request4).await;
    assert_eq!(response4.status(), StatusCode::OK);

    let body4 = axum::body::to_bytes(response4.into_body(), usize::MAX)
        .await
        .unwrap();
    let json4: Value = serde_json::from_slice(&body4).unwrap();

    // Should return 0 records, but total should still be accurate
    assert_eq!(json4["records"].as_array().unwrap().len(), 0);
    assert_eq!(json4["total"], 20); // Total should be consistent even with no results
    assert_eq!(json4["limit"], 5);
    assert_eq!(json4["offset"], 20);
}

async fn test_pagination_with_filters_total_count_impl(harness: &TestHarness) {
    let (user_id, _) = setup_test_data(harness).await;
    let database = harness.server.database.as_ref();

    // Create additional records with specific model filter (5 matching records)
    for i in 1..=5 {
        let record = UsageRecord {
            id: 0,
            user_id,
            model_id: "anthropic.claude-sonnet-4-20250514-v1:0".to_string(), // Same model as one in setup
            endpoint_type: "bedrock".to_string(),
            region: "us-east-1".to_string(),
            request_time: Utc::now() - chrono::Duration::minutes(i as i64),
            input_tokens: 50,
            output_tokens: 25,
            cache_write_tokens: None,
            cache_read_tokens: None,
            total_tokens: 75,
            response_time_ms: 150,
            success: true,
            error_message: None,
            stop_reason: Some("end_turn".to_string()),
            cost_usd: Some(Decimal::new(10, 4)),
        };
        database.usage().store_record(&record).await.unwrap();
    }

    let token = harness.create_integration_token(user_id);

    // Test with model filter (should find 6 records: 1 from setup + 5 new)
    let request = Request::builder()
        .method(Method::GET)
        .uri("/api/usage/records?model=anthropic.claude-sonnet-4-20250514-v1:0&limit=3&offset=0")
        .header("Authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();

    let response = harness.make_request(request).await;
    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();

    // Should return 3 records but total should be 6 (1 original + 5 new for this model)
    assert_eq!(json["records"].as_array().unwrap().len(), 3);
    assert_eq!(json["total"], 6);
    assert_eq!(json["limit"], 3);
    assert_eq!(json["offset"], 0);

    // Verify all records are for the correct model
    let records = json["records"].as_array().unwrap();
    for record in records {
        assert_eq!(
            record["model_id"],
            "anthropic.claude-sonnet-4-20250514-v1:0"
        );
    }

    // Test second page of filtered results
    let request2 = Request::builder()
        .method(Method::GET)
        .uri("/api/usage/records?model=anthropic.claude-sonnet-4-20250514-v1:0&limit=3&offset=3")
        .header("Authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();

    let response2 = harness.make_request(request2).await;
    assert_eq!(response2.status(), StatusCode::OK);

    let body2 = axum::body::to_bytes(response2.into_body(), usize::MAX)
        .await
        .unwrap();
    let json2: Value = serde_json::from_slice(&body2).unwrap();

    // Should return 3 records (6 total - 3 offset), same total count
    assert_eq!(json2["records"].as_array().unwrap().len(), 3);
    assert_eq!(json2["total"], 6); // Total should be consistent with filter
    assert_eq!(json2["limit"], 3);
    assert_eq!(json2["offset"], 3);
}

async fn test_empty_results_pagination_impl(harness: &TestHarness) {
    let (user_id, _) = setup_test_data(harness).await;
    let token = harness.create_integration_token(user_id);

    // Test with filter that matches no records
    let request = Request::builder()
        .method(Method::GET)
        .uri("/api/usage/records?model=nonexistent-model&limit=10&offset=0")
        .header("Authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();

    let response = harness.make_request(request).await;
    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();

    // Should return 0 records and total should be 0
    assert_eq!(json["records"].as_array().unwrap().len(), 0);
    assert_eq!(json["total"], 0);
    assert_eq!(json["limit"], 10);
    assert_eq!(json["offset"], 0);
}

async fn test_get_user_usage_summaries_success_impl(harness: &TestHarness) {
    let (user_id, _) = setup_test_data(harness).await;
    let database = harness.server.database.as_ref();

    // Create usage summaries for the user
    let summaries = vec![
        UsageSummary {
            id: 0,
            user_id,
            model_id: "anthropic.claude-sonnet-4-20250514-v1:0".to_string(),
            period_type: PeriodType::Daily,
            period_start: Utc::now() - chrono::Duration::days(1),
            period_end: Utc::now(),
            total_requests: 10,
            successful_requests: 9,
            total_input_tokens: 1000,
            total_output_tokens: 500,
            total_cache_write_tokens: 0,
            total_cache_read_tokens: 0,
            total_tokens: 1500,
            avg_response_time_ms: 250.0,
            estimated_cost: Some(Decimal::new(150, 3)), // 0.150
            created_at: Utc::now(),
            updated_at: Utc::now(),
        },
        UsageSummary {
            id: 0,
            user_id,
            model_id: "anthropic.claude-3-haiku-20240307-v1:0".to_string(),
            period_type: PeriodType::Daily,
            period_start: Utc::now() - chrono::Duration::days(1),
            period_end: Utc::now(),
            total_requests: 5,
            successful_requests: 5,
            total_input_tokens: 500,
            total_output_tokens: 250,
            total_cache_write_tokens: 0,
            total_cache_read_tokens: 0,
            total_tokens: 750,
            avg_response_time_ms: 200.0,
            estimated_cost: Some(Decimal::new(75, 3)), // 0.075
            created_at: Utc::now(),
            updated_at: Utc::now(),
        },
    ];

    database.usage().upsert_many_summaries(&summaries).await.unwrap();
    let token = harness.create_integration_token(user_id);

    let request = Request::builder()
        .method(Method::GET)
        .uri("/api/usage/summaries?period_type=daily&limit=10")
        .header("Authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();

    let response = harness.make_request(request).await;
    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();

    assert!(json["summaries"].is_array());
    let summaries_array = json["summaries"].as_array().unwrap();
    assert_eq!(summaries_array.len(), 2);
    assert_eq!(json["total"], 2);
    assert_eq!(json["limit"], 10);
    assert_eq!(json["offset"], 0);

    // Verify summary data
    let summary = &summaries_array[0];
    assert_eq!(summary["user_id"], user_id);
    assert_eq!(summary["period_type"], "daily");
    assert!(summary["total_requests"].as_i64().unwrap() > 0);
    assert!(summary["estimated_cost"].is_string());
}

async fn test_get_user_usage_summaries_with_model_filter_impl(harness: &TestHarness) {
    let (user_id, _) = setup_test_data(harness).await;
    let database = harness.server.database.as_ref();

    // Create usage summaries for different models
    let summaries = vec![
        UsageSummary {
            id: 0,
            user_id,
            model_id: "anthropic.claude-sonnet-4-20250514-v1:0".to_string(),
            period_type: PeriodType::Daily,
            period_start: Utc::now() - chrono::Duration::days(1),
            period_end: Utc::now(),
            total_requests: 10,
            successful_requests: 9,
            total_input_tokens: 1000,
            total_output_tokens: 500,
            total_cache_write_tokens: 0,
            total_cache_read_tokens: 0,
            total_tokens: 1500,
            avg_response_time_ms: 250.0,
            estimated_cost: Some(Decimal::new(150, 3)),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        },
        UsageSummary {
            id: 0,
            user_id,
            model_id: "anthropic.claude-3-haiku-20240307-v1:0".to_string(),
            period_type: PeriodType::Daily,
            period_start: Utc::now() - chrono::Duration::days(1),
            period_end: Utc::now(),
            total_requests: 5,
            successful_requests: 5,
            total_input_tokens: 500,
            total_output_tokens: 250,
            total_cache_write_tokens: 0,
            total_cache_read_tokens: 0,
            total_tokens: 750,
            avg_response_time_ms: 200.0,
            estimated_cost: Some(Decimal::new(75, 3)),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        },
    ];

    database.usage().upsert_many_summaries(&summaries).await.unwrap();
    let token = harness.create_integration_token(user_id);

    // Test filtering by specific model
    let request = Request::builder()
        .method(Method::GET)
        .uri("/api/usage/summaries?model_id=anthropic.claude-sonnet-4-20250514-v1:0")
        .header("Authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();

    let response = harness.make_request(request).await;
    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();

    let summaries_array = json["summaries"].as_array().unwrap();
    assert_eq!(summaries_array.len(), 1);
    assert_eq!(json["total"], 1);

    // Verify it's the correct model
    assert_eq!(
        summaries_array[0]["model_id"],
        "anthropic.claude-sonnet-4-20250514-v1:0"
    );
}

async fn test_admin_get_usage_summaries_success_impl(harness: &TestHarness) {
    let (user1_id, admin_id) = setup_test_data(harness).await;
    let database = harness.server.database.as_ref();

    // Create another user for system-wide data
    let user2 = UserRecord {
        id: 0,
        provider: "google".to_string(),
        provider_user_id: "test-user-2".to_string(),
        email: "user2@example.com".to_string(),
        display_name: Some("Test User 2".to_string()),
        created_at: Utc::now(),
        updated_at: Utc::now(),
        last_login: Some(Utc::now()),
        ..Default::default()
    };
    let user2_id = database.users().upsert(&user2).await.unwrap();

    // Create usage summaries for multiple users
    let summaries = vec![
        UsageSummary {
            id: 0,
            user_id: user1_id,
            model_id: "anthropic.claude-sonnet-4-20250514-v1:0".to_string(),
            period_type: PeriodType::Daily,
            period_start: Utc::now() - chrono::Duration::days(1),
            period_end: Utc::now(),
            total_requests: 10,
            successful_requests: 9,
            total_input_tokens: 1000,
            total_output_tokens: 500,
            total_cache_write_tokens: 0,
            total_cache_read_tokens: 0,
            total_tokens: 1500,
            avg_response_time_ms: 250.0,
            estimated_cost: Some(Decimal::new(150, 3)),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        },
        UsageSummary {
            id: 0,
            user_id: user2_id,
            model_id: "anthropic.claude-3-haiku-20240307-v1:0".to_string(),
            period_type: PeriodType::Daily,
            period_start: Utc::now() - chrono::Duration::days(1),
            period_end: Utc::now(),
            total_requests: 5,
            successful_requests: 5,
            total_input_tokens: 500,
            total_output_tokens: 250,
            total_cache_write_tokens: 0,
            total_cache_read_tokens: 0,
            total_tokens: 750,
            avg_response_time_ms: 200.0,
            estimated_cost: Some(Decimal::new(75, 3)),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        },
    ];

    database.usage().upsert_many_summaries(&summaries).await.unwrap();
    let admin_token = harness.create_integration_token(admin_id);

    let request = Request::builder()
        .method(Method::GET)
        .uri("/api/admin/usage/summaries?period_type=daily")
        .header("Authorization", format!("Bearer {admin_token}"))
        .body(Body::empty())
        .unwrap();

    let response = harness.make_request(request).await;
    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();

    assert!(json["summaries"].is_array());
    let summaries_array = json["summaries"].as_array().unwrap();
    assert_eq!(summaries_array.len(), 2); // Both users' summaries
    assert_eq!(json["total"], 2);

    // Verify we get system-wide data (multiple users)
    let user_ids: Vec<i64> = summaries_array
        .iter()
        .map(|s| s["user_id"].as_i64().unwrap())
        .collect();
    assert!(user_ids.contains(&(user1_id as i64)));
    assert!(user_ids.contains(&(user2_id as i64)));
}

async fn test_non_admin_summaries_access_denied_impl(harness: &TestHarness) {
    let (user1_id, _) = setup_test_data(harness).await;
    let user_token = harness.create_integration_token(user1_id);

    // Test admin summaries endpoint access with non-admin token
    let request = Request::builder()
        .method(Method::GET)
        .uri("/api/admin/usage/summaries")
        .header("Authorization", format!("Bearer {user_token}"))
        .body(Body::empty())
        .unwrap();

    let response = harness.make_request(request).await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

async fn test_summaries_unauthorized_access_impl(harness: &TestHarness) {
    setup_test_data(harness).await;

    // Test without authorization header
    let request = Request::builder()
        .method(Method::GET)
        .uri("/api/usage/summaries")
        .body(Body::empty())
        .unwrap();

    let response = harness.make_request(request).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    // Test with invalid token
    let request = Request::builder()
        .method(Method::GET)
        .uri("/api/usage/summaries")
        .header("Authorization", "Bearer invalid-token")
        .body(Body::empty())
        .unwrap();

    let response = harness.make_request(request).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

async fn test_summaries_period_type_filtering_impl(harness: &TestHarness) {
    let (user_id, _) = setup_test_data(harness).await;
    let database = harness.server.database.as_ref();

    // Create summaries with different period types
    let summaries = vec![
        UsageSummary {
            id: 0,
            user_id,
            model_id: "test-model".to_string(),
            period_type: PeriodType::Hourly,
            period_start: Utc::now() - chrono::Duration::hours(1),
            period_end: Utc::now(),
            total_requests: 5,
            successful_requests: 5,
            total_input_tokens: 500,
            total_output_tokens: 250,
            total_cache_write_tokens: 0,
            total_cache_read_tokens: 0,
            total_tokens: 750,
            avg_response_time_ms: 200.0,
            estimated_cost: Some(Decimal::new(75, 3)),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        },
        UsageSummary {
            id: 0,
            user_id,
            model_id: "test-model".to_string(),
            period_type: PeriodType::Daily,
            period_start: Utc::now() - chrono::Duration::days(1),
            period_end: Utc::now(),
            total_requests: 10,
            successful_requests: 9,
            total_input_tokens: 1000,
            total_output_tokens: 500,
            total_cache_write_tokens: 0,
            total_cache_read_tokens: 0,
            total_tokens: 1500,
            avg_response_time_ms: 250.0,
            estimated_cost: Some(Decimal::new(150, 3)),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        },
        UsageSummary {
            id: 0,
            user_id,
            model_id: "test-model".to_string(),
            period_type: PeriodType::Weekly,
            period_start: Utc::now() - chrono::Duration::weeks(1),
            period_end: Utc::now(),
            total_requests: 50,
            successful_requests: 45,
            total_input_tokens: 5000,
            total_output_tokens: 2500,
            total_cache_write_tokens: 0,
            total_cache_read_tokens: 0,
            total_tokens: 7500,
            avg_response_time_ms: 275.0,
            estimated_cost: Some(Decimal::new(750, 3)),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        },
    ];

    database.usage().upsert_many_summaries(&summaries).await.unwrap();
    let token = harness.create_integration_token(user_id);

    // Test filtering by hourly period
    let request = Request::builder()
        .method(Method::GET)
        .uri("/api/usage/summaries?period_type=hourly")
        .header("Authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();

    let response = harness.make_request(request).await;
    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();

    let summaries_array = json["summaries"].as_array().unwrap();
    assert_eq!(summaries_array.len(), 1);
    assert_eq!(summaries_array[0]["period_type"], "hourly");
    assert_eq!(summaries_array[0]["total_requests"], 5);

    // Test filtering by weekly period
    let request2 = Request::builder()
        .method(Method::GET)
        .uri("/api/usage/summaries?period_type=weekly")
        .header("Authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();

    let response2 = harness.make_request(request2).await;
    assert_eq!(response2.status(), StatusCode::OK);

    let body2 = axum::body::to_bytes(response2.into_body(), usize::MAX)
        .await
        .unwrap();
    let json2: Value = serde_json::from_slice(&body2).unwrap();

    let summaries_array2 = json2["summaries"].as_array().unwrap();
    assert_eq!(summaries_array2.len(), 1);
    assert_eq!(summaries_array2[0]["period_type"], "weekly");
    assert_eq!(summaries_array2[0]["total_requests"], 50);

    // Test invalid period type (should default to daily)
    let request3 = Request::builder()
        .method(Method::GET)
        .uri("/api/usage/summaries?period_type=invalid")
        .header("Authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();

    let response3 = harness.make_request(request3).await;
    assert_eq!(response3.status(), StatusCode::OK);

    let body3 = axum::body::to_bytes(response3.into_body(), usize::MAX)
        .await
        .unwrap();
    let json3: Value = serde_json::from_slice(&body3).unwrap();

    // Should default to daily and return daily summary
    let summaries_array3 = json3["summaries"].as_array().unwrap();
    assert_eq!(summaries_array3.len(), 1);
    assert_eq!(summaries_array3[0]["period_type"], "daily");
}

async fn test_empty_summaries_results_impl(harness: &TestHarness) {
    let (user_id, _) = setup_test_data(harness).await;
    let token = harness.create_integration_token(user_id);

    // Test with filter that matches no summaries
    let request = Request::builder()
        .method(Method::GET)
        .uri("/api/usage/summaries?model_id=nonexistent-model")
        .header("Authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();

    let response = harness.make_request(request).await;
    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();

    // Should return 0 summaries and total should be 0
    assert_eq!(json["summaries"].as_array().unwrap().len(), 0);
    assert_eq!(json["total"], 0);
    assert_eq!(json["limit"], 1000); // Default limit
    assert_eq!(json["offset"], 0);
}

// Macro to generate tests for both SQLite and PostgreSQL
macro_rules! generate_db_tests {
    ($test_name:ident, $test_impl:ident) => {
        pastey::paste! {
            #[tokio::test]
            async fn [<sqlite_ $test_name>]() {
                let harness = TestHarness::new().await;
                $test_impl(&harness).await;
            }

            #[tokio::test]
            async fn [<postgres_ $test_name>]() {
                let postgres = match PostgresTestDb::new().await {
                    Ok(db) => db,
                    Err(_) => {
                        println!("Skipping PostgreSQL test: TEST_POSTGRES_URL not set or connection failed.");
                        return;
                    }
                };
                let harness = TestHarness::with_postgres(&postgres).await;
                $test_impl(&harness).await;
                postgres.cleanup().await.unwrap();
            }
        }
    };
}

generate_db_tests!(
    test_get_user_usage_records_success,
    test_get_user_usage_records_success_impl
);
generate_db_tests!(
    test_get_user_usage_with_filters,
    test_get_user_usage_with_filters_impl
);
generate_db_tests!(
    test_admin_get_system_usage_records,
    test_admin_get_system_usage_records_impl
);
generate_db_tests!(
    test_non_admin_access_denied,
    test_non_admin_access_denied_impl
);
generate_db_tests!(test_unauthorized_access, test_unauthorized_access_impl);
generate_db_tests!(test_pagination_limits, test_pagination_limits_impl);
generate_db_tests!(
    test_get_stats_uses_summaries_when_available,
    test_get_stats_uses_summaries_when_available_impl
);
generate_db_tests!(
    test_realtime_hourly_summary_updates,
    test_realtime_hourly_summary_updates_impl
);
generate_db_tests!(
    test_realtime_hourly_summary_different_keys,
    test_realtime_hourly_summary_different_keys_impl
);
generate_db_tests!(
    test_pagination_total_count_accuracy,
    test_pagination_total_count_accuracy_impl
);
generate_db_tests!(
    test_pagination_with_filters_total_count,
    test_pagination_with_filters_total_count_impl
);
generate_db_tests!(
    test_empty_results_pagination,
    test_empty_results_pagination_impl
);
generate_db_tests!(
    test_get_user_usage_summaries_success,
    test_get_user_usage_summaries_success_impl
);
generate_db_tests!(
    test_get_user_usage_summaries_with_model_filter,
    test_get_user_usage_summaries_with_model_filter_impl
);
generate_db_tests!(
    test_admin_get_usage_summaries_success,
    test_admin_get_usage_summaries_success_impl
);
generate_db_tests!(
    test_non_admin_summaries_access_denied,
    test_non_admin_summaries_access_denied_impl
);
generate_db_tests!(
    test_summaries_unauthorized_access,
    test_summaries_unauthorized_access_impl
);
generate_db_tests!(
    test_summaries_period_type_filtering,
    test_summaries_period_type_filtering_impl
);
generate_db_tests!(
    test_empty_summaries_results,
    test_empty_summaries_results_impl
);

async fn test_get_user_usage_with_date_filters_impl(harness: &TestHarness) {
    let (user_id, _) = setup_test_data(harness).await;
    let token = harness.create_integration_token(user_id);
    let now = Utc::now();

    // Test 1: start_date and end_date to find one record (created 10 mins ago)
    let start_date = now - chrono::Duration::minutes(15);
    let end_date = now - chrono::Duration::minutes(5);
    let uri = format!(
        "/api/usage/records?start_date={}&end_date={}",
        start_date.to_rfc3339(),
        end_date.to_rfc3339()
    );

    let request = Request::builder()
        .method(Method::GET)
        .uri(uri)
        .header("Authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();

    let response = harness.make_request(request).await;
    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        json["records"].as_array().unwrap().len(),
        1,
        "Failed start_date and end_date test"
    );
    assert_eq!(json["total"], 1);

    // Test 2: Only start_date, should find two records (at T-0m and T-10m)
    let start_date = now - chrono::Duration::minutes(15);
    let uri = format!("/api/usage/records?start_date={}", start_date.to_rfc3339());
    let request = Request::builder()
        .method(Method::GET)
        .uri(uri)
        .header("Authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();

    let response = harness.make_request(request).await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        json["records"].as_array().unwrap().len(),
        2,
        "Failed start_date only test"
    );
    assert_eq!(json["total"], 2);

    // Test 3: Only end_date, should find one record (at T-20m)
    let end_date = now - chrono::Duration::minutes(15);
    let uri = format!("/api/usage/records?end_date={}", end_date.to_rfc3339());
    let request = Request::builder()
        .method(Method::GET)
        .uri(uri)
        .header("Authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    let response = harness.make_request(request).await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        json["records"].as_array().unwrap().len(),
        1,
        "Failed end_date only test"
    );
    assert_eq!(json["total"], 1);
}

generate_db_tests!(
    test_get_user_usage_with_date_filters,
    test_get_user_usage_with_date_filters_impl
);

async fn test_invalid_query_parameters_are_handled_gracefully_impl(harness: &TestHarness) {
    let (user_id, _) = setup_test_data(harness).await;
    let token = harness.create_integration_token(user_id);

    // Test 1: Invalid 'limit' parameter (non-numeric)
    let uri = "/api/usage/records?limit=not-a-number";
    let request = Request::builder()
        .method(Method::GET)
        .uri(uri)
        .header("Authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();

    let response = harness.make_request(request).await;
    // Axum's Query extractor should return a 400-level error for deserialization failure.
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    // Test 2: Invalid 'offset' parameter (negative number)
    let uri = "/api/usage/records?offset=-10";
    let request = Request::builder()
        .method(Method::GET)
        .uri(uri)
        .header("Authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();

    let response = harness.make_request(request).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

generate_db_tests!(
    test_invalid_query_parameters_are_handled_gracefully,
    test_invalid_query_parameters_are_handled_gracefully_impl
);
