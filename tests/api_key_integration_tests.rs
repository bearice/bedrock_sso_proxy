use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use bedrock_sso_proxy::auth::api_key::{CreateApiKeyRequest, CreateApiKeyResponse};

mod common;
use common::{RequestBuilder, TestHarness};

/// Helper function to create an API key for a given user
async fn create_api_key(
    harness: &TestHarness,
    user_email: &str,
    key_name: &str,
    expires_in_days: Option<u32>,
) -> (String, String) {
    let user_id = harness.create_test_user(user_email).await;
    let jwt_token = harness.create_integration_token(user_id);

    let create_request = CreateApiKeyRequest {
        name: key_name.to_string(),
        expires_in_days,
    };

    let request = Request::builder()
        .uri("/api/keys")
        .method("POST")
        .header("Authorization", format!("Bearer {}", jwt_token))
        .header("Content-Type", "application/json")
        .body(Body::from(serde_json::to_string(&create_request).unwrap()))
        .unwrap();

    let response = harness.make_request(request).await;
    assert_eq!(response.status(), StatusCode::OK, "Failed to create API key");

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let create_response: CreateApiKeyResponse = serde_json::from_slice(&body).unwrap();

    (create_response.key, jwt_token)
}

#[tokio::test]
async fn test_api_key_authentication_with_authorization_header() {
    let harness = TestHarness::new_for_security_tests().await;
    let (api_key, _) = create_api_key(
        &harness,
        "test1@example.com",
        "Test API Key",
        Some(30),
    )
    .await;
    assert!(api_key.starts_with("SSOK_"));

    // Now test using the API key to access Bedrock API
    let bedrock_request = RequestBuilder::invoke_model_with_api_key_bearer(
        "anthropic.claude-sonnet-4-20250514-v1:0",
        &api_key,
        r#"{"anthropic_version": "bedrock-2023-05-31", "max_tokens": 100, "messages": [{"role": "user", "content": "Hello"}]}"#,
    );

    let response = harness.make_request(bedrock_request).await;
    // With mock AWS, we should get a 200 OK
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_api_key_authentication_with_x_api_key_header() {
    let harness = TestHarness::new_for_security_tests().await;
    let (api_key, _) = create_api_key(
        &harness,
        "test2@example.com",
        "Test X-API-Key",
        Some(30),
    )
    .await;

    // Test using X-API-Key header instead of Authorization header
    let anthropic_request = RequestBuilder::invoke_model_with_api_key_header(
        "anthropic.claude-sonnet-4-20250514-v1:0",
        &api_key,
        r#"{"anthropic_version": "bedrock-2023-05-31", "max_tokens": 100, "messages": [{"role": "user", "content": "Hello"}]}"#,
    );

    let response = harness.make_request(anthropic_request).await;
    // With mock AWS, we should get a 200 OK
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_invalid_api_key_authentication() {
    let harness = TestHarness::new_for_security_tests().await;

    // Test with invalid API key
    let request = RequestBuilder::invoke_model_with_api_key_bearer(
        "anthropic.claude-sonnet-4-20250514-v1:0",
        "SSOK_invalid_key_12345678",
        r#"{"anthropic_version": "bedrock-2023-05-31", "max_tokens": 100, "messages": [{"role": "user", "content": "Hello"}]}"#,
    );

    let response = harness.make_request(request).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_api_key_disabled() {
    // The default harness (`new()`) has API keys disabled.
    let harness = TestHarness::new().await;

    // Test with API key when disabled
    let request = RequestBuilder::invoke_model_with_api_key_bearer(
        "anthropic.claude-sonnet-4-20250514-v1:0",
        "SSOK_some_key_12345678",
        r#"{"anthropic_version": "bedrock-2023-05-31", "max_tokens": 100, "messages": [{"role": "user", "content": "Hello"}]}"#,
    );

    let response = harness.make_request(request).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_revoked_api_key_authentication() {
    let harness = TestHarness::new_for_security_tests().await;

    // Create an API key
    let (api_key, jwt_token) =
        create_api_key(&harness, "test3@example.com", "Test Revoke Key", Some(30)).await;

    // Hash the API key for revocation (endpoint expects key hash, not raw key)
    let key_hash = bedrock_sso_proxy::database::entities::api_keys::hash_api_key(&api_key);

    // Revoke the API key
    let revoke_request = Request::builder()
        .uri(format!("/api/keys/{key_hash}"))
        .method("DELETE")
        .header("Authorization", format!("Bearer {jwt_token}"))
        .body(Body::empty())
        .unwrap();

    let response = harness.make_request(revoke_request).await;
    assert_eq!(response.status(), StatusCode::OK);

    // Try to use the revoked API key
    let test_request = RequestBuilder::invoke_model_with_api_key_bearer(
        "anthropic.claude-sonnet-4-20250514-v1:0",
        &api_key,
        r#"{"anthropic_version": "bedrock-2023-05-31", "max_tokens": 100, "messages": [{"role": "user", "content": "Hello"}]}"#,
    );

    let response = harness.make_request(test_request).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_dual_authentication_support() {
    let harness = TestHarness::new_for_security_tests().await;
    let user_id = harness.create_test_user("test4@example.com").await;
    let jwt_token = harness.create_integration_token(user_id);

    // Test JWT authentication still works
    let jwt_request = RequestBuilder::invoke_model_with_auth(
        "anthropic.claude-sonnet-4-20250514-v1:0",
        &jwt_token,
        r#"{"anthropic_version": "bedrock-2023-05-31", "max_tokens": 100, "messages": [{"role": "user", "content": "Hello"}]}"#,
    );

    let response = harness.make_request(jwt_request).await;
    assert_eq!(response.status(), StatusCode::OK);

    // Create and test API key authentication
    let (api_key, _) =
        create_api_key(&harness, "test4@example.com", "Dual Auth Test", Some(30)).await;

    // Test API key authentication
    let api_key_request = RequestBuilder::invoke_model_with_api_key_bearer(
        "anthropic.claude-sonnet-4-20250514-v1:0",
        &api_key,
        r#"{"anthropic_version": "bedrock-2023-05-31", "max_tokens": 100, "messages": [{"role": "user", "content": "Hello"}]}"#,
    );

    let response = harness.make_request(api_key_request).await;
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_expired_api_key_is_rejected() {
    let harness = TestHarness::new_for_security_tests().await;

    // Create an API key that expires immediately by passing Some(0).
    let (api_key, _) = create_api_key(
        &harness,
        "expired@example.com",
        "Expired Key",
        Some(0),
    )
    .await;

    // Now, try to use the expired key.
    let bedrock_request = RequestBuilder::invoke_model_with_api_key_bearer(
        "anthropic.claude-sonnet-4-20250514-v1:0",
        &api_key,
        r#"{"anthropic_version": "bedrock-2023-05-31", "max_tokens": 100, "messages": [{"role": "user", "content": "Hello"}]}"#,
    );

    let response = harness.make_request(bedrock_request).await;
    // Should be unauthorized because the key is expired.
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}
