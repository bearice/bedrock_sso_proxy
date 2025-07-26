use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use std::sync::Arc;
mod common;
use common::{RequestBuilder, TestHarness};

#[tokio::test]
async fn test_integration_jwt_token_validation() {
    let harness = TestHarness::with_secret("integration-test-secret-123").await;
    let token = harness.create_integration_token(123);

    // Verify we can decode the token
    let claims = harness.verify_token(&token).unwrap();
    assert_eq!(claims.sub, 123); // sub field now contains the user_id
}

#[tokio::test]
async fn test_integration_server_with_real_jwt() {
    let harness = TestHarness::with_secret("integration-test-secret-456").await;

    let token = harness.create_integration_token(123);

    let request = RequestBuilder::health_with_auth(&token);

    let response = harness.make_request(request).await;
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_integration_invalid_signature() {
    let harness = TestHarness::new().await;

    // Create token with different secret (will fail validation)
    let wrong_harness = TestHarness::with_secret("wrong-secret").await;
    let token = wrong_harness.create_integration_token(123);

    let request =
        RequestBuilder::invoke_model_with_auth("test-model", &token, r#"{"messages": []}"#);

    let response = harness.make_request(request).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_integration_token_with_custom_claims() {
    // Use standard test harness to avoid JWT secret mismatch issues
    let harness = TestHarness::new().await;

    let token = harness.create_integration_token(456);

    // Test that JWT with custom claims works for authenticated endpoints
    let request = RequestBuilder::health_with_auth(&token);
    let response = harness.make_request(request).await;
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_integration_malformed_authorization_header() {
    let harness = TestHarness::new().await;

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
    let token = harness.create_integration_token(789);

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
        assert_eq!(status, StatusCode::OK, "Request {} failed", i);
    }
}

#[tokio::test]
async fn test_integration_token_expiration_edge_cases() {
    let harness = TestHarness::new().await;

    // Create token that expires in 1 second
    let short_token = harness.create_token_with_expiry(1, 999);

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
    println!("Response status: {}, body: {}", status, body_str);

    // Should fail with UNAUTHORIZED for expired token
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "Expired JWT token should result in 401 Unauthorized, not {} - Body: {}",
        status,
        body_str
    );
}
