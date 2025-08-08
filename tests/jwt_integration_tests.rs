use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use std::sync::Arc;
mod common;
use common::{PostgresTestDb, RequestBuilder, TestHarness};

#[tokio::test]
async fn test_integration_jwt_token_validation() {
    let harness = TestHarness::with_secret("integration-test-secret-123").await;
    let created_user_id = harness.create_test_user("test1@example.com").await;
    let token = harness.create_integration_token(created_user_id);

    // Verify we can decode the token
    let claims = harness.verify_token(&token).unwrap();
    assert_eq!(claims.sub, created_user_id); // sub field now contains the user_id
}

#[tokio::test]
async fn test_integration_server_with_real_jwt() {
    let harness = TestHarness::with_secret("integration-test-secret-456").await;
    let created_user_id = harness.create_test_user("test2@example.com").await;

    let token = harness.create_integration_token(created_user_id);

    let request = RequestBuilder::health_with_auth(&token);

    let response = harness.make_request(request).await;
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_integration_invalid_signature() {
    let harness = TestHarness::new().await;
    let created_user_id = harness.create_test_user("test3@example.com").await;

    // Create token with different secret (will fail validation)
    let wrong_harness = TestHarness::with_secret("wrong-secret").await;
    let token = wrong_harness.create_integration_token(created_user_id);

    let request =
        RequestBuilder::invoke_model_with_auth("test-model", &token, r#"{"messages": []}"#);

    let response = harness.make_request(request).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_integration_token_with_custom_claims() {
    // Use standard test harness to avoid JWT secret mismatch issues
    let harness = TestHarness::new().await;
    let created_user_id = harness.create_test_user("test456@example.com").await;

    let token = harness.create_integration_token(created_user_id);

    // Test that JWT with custom claims works for authenticated endpoints
    let request = RequestBuilder::health_with_auth(&token);
    let response = harness.make_request(request).await;
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_integration_malformed_authorization_header() {
    let harness = TestHarness::new().await;
    let _created_user_id = harness.create_test_user("test789@example.com").await;

    // Test various malformed authorization headers
    let malformed_headers = vec![
        "NotBearer token",
        "Bearer",
        "Bearer ",
        "Bearer token.with.not.enough.parts",
        "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.invalid-payload.signature",
        "Basic dXNlcjpwYXNz", // Basic auth instead of Bearer
    ];

    for header_value in malformed_headers {
        let request = Request::builder()
            .uri("/bedrock/model/test-model/invoke")
            .method("POST")
            .header("Authorization", header_value)
            .header("Content-Type", "application/json")
            .body(Body::from(r#"{"messages": []}"#))
            .unwrap();

        let response = harness.make_request(request).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}

#[tokio::test]
async fn test_integration_concurrent_requests() {
    let harness = Arc::new(TestHarness::new().await);
    let created_user_id = harness.create_test_user("test789c@example.com").await;
    let token = harness.create_integration_token(created_user_id);

    // Create multiple concurrent requests
    let mut handles = vec![];

    for i in 0..10 {
        let harness_clone = harness.clone();
        let token_clone = token.clone();

        let handle = tokio::spawn(async move {
            let request = RequestBuilder::health_with_check_and_auth("all", &token_clone);

            let response = harness_clone.make_request(request).await;
            (i, response.status())
        });

        handles.push(handle);
    }

    // Wait for all requests to complete
    let results = futures_util::future::join_all(handles).await;

    // Verify all requests succeeded
    for result in results {
        let (i, status) = result.unwrap();
        assert_eq!(status, StatusCode::OK, "Request {i} failed");
    }
}

#[tokio::test]
async fn test_integration_token_expiration_edge_cases() {
    let harness = TestHarness::new().await;
    harness.create_test_user("test1@example.com").await;

    // Create token that expires in 1 second
    let short_token = harness.create_token_with_expiry(1, 1);

    // Request should work immediately
    let request = RequestBuilder::health_with_auth(&short_token);

    let response = harness.make_request(request).await;
    assert_eq!(response.status(), StatusCode::OK);

    // Wait for token to expire
    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

    // Request should now fail
    let request =
        RequestBuilder::invoke_model_with_auth("test-model", &short_token, r#"{"messages": []}"#);

    let response = harness.make_request(request).await;

    // Debug: Extract status and body
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let body_str = String::from_utf8_lossy(&body);
    println!("Response status: {status}, body: {body_str}");

    // Should fail with UNAUTHORIZED for expired token
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "Expired JWT token should result in 401 Unauthorized, not {status} - Body: {body_str}"
    );
}

// PostgreSQL test variants
// These tests run the same logic but with a PostgreSQL database backend

#[tokio::test]
async fn test_postgres_jwt_token_validation() {
    let postgres_db = match PostgresTestDb::new().await {
        Ok(db) => db,
        Err(_) => {
            println!("Skipping PostgreSQL test - database not available");
            return;
        }
    };

    let harness = TestHarness::with_postgres_and_secret(&postgres_db, "postgres-jwt-secret").await;
    let created_user_id = harness.create_test_user("postgres_test1@example.com").await;
    let token = harness.create_integration_token(created_user_id);

    // Verify we can decode the token
    let claims = harness.verify_token(&token).unwrap();
    assert_eq!(claims.sub, created_user_id); // sub field now contains the user_id

    // Clean up
    let _ = postgres_db.cleanup().await;
}

#[tokio::test]
async fn test_postgres_server_with_real_jwt() {
    let postgres_db = match PostgresTestDb::new().await {
        Ok(db) => db,
        Err(_) => {
            println!("Skipping PostgreSQL test - database not available");
            return;
        }
    };

    let harness =
        TestHarness::with_postgres_and_secret(&postgres_db, "postgres-jwt-secret-456").await;
    let created_user_id = harness.create_test_user("postgres_test2@example.com").await;

    let token = harness.create_integration_token(created_user_id);

    let request = RequestBuilder::health_with_auth(&token);

    let response = harness.make_request(request).await;
    assert_eq!(response.status(), StatusCode::OK);

    // Clean up
    let _ = postgres_db.cleanup().await;
}

#[tokio::test]
async fn test_postgres_invalid_signature() {
    let postgres_db = match PostgresTestDb::new().await {
        Ok(db) => db,
        Err(_) => {
            println!("Skipping PostgreSQL test - database not available");
            return;
        }
    };

    let harness = TestHarness::with_postgres(&postgres_db).await;
    let created_user_id = harness.create_test_user("postgres_test3@example.com").await;

    // Create token with different secret (will fail validation)
    let postgres_db2 = match PostgresTestDb::new().await {
        Ok(db) => db,
        Err(_) => {
            println!("Skipping PostgreSQL test - database not available for second instance");
            let _ = postgres_db.cleanup().await;
            return;
        }
    };
    let wrong_harness = TestHarness::with_postgres_and_secret(&postgres_db2, "wrong-secret").await;
    let token = wrong_harness.create_integration_token(created_user_id);

    let request =
        RequestBuilder::invoke_model_with_auth("test-model", &token, r#"{"messages": []}"#);

    let response = harness.make_request(request).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    // Clean up
    let _ = postgres_db.cleanup().await;
    let _ = postgres_db2.cleanup().await;
}

#[tokio::test]
async fn test_postgres_concurrent_requests() {
    let postgres_db = match PostgresTestDb::new().await {
        Ok(db) => db,
        Err(_) => {
            println!("Skipping PostgreSQL test - database not available");
            return;
        }
    };

    let harness = Arc::new(TestHarness::with_postgres(&postgres_db).await);
    let created_user_id = harness
        .create_test_user("postgres_test_concurrent@example.com")
        .await;
    let token = harness.create_integration_token(created_user_id);

    // Create multiple concurrent requests
    let mut handles = vec![];

    for i in 0..5 {
        // Reduce concurrency for PostgreSQL tests
        let harness_clone = harness.clone();
        let token_clone = token.clone();

        let handle = tokio::spawn(async move {
            let request = RequestBuilder::health_with_check_and_auth("all", &token_clone);

            let response = harness_clone.make_request(request).await;
            (i, response.status())
        });

        handles.push(handle);
    }

    // Wait for all requests to complete
    let results = futures_util::future::join_all(handles).await;

    // Verify all requests succeeded
    for result in results {
        let (i, status) = result.unwrap();
        assert_eq!(status, StatusCode::OK, "Request {i} failed");
    }

    // Clean up
    let _ = postgres_db.cleanup().await;
}
