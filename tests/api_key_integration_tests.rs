use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use bedrock_sso_proxy::{
    auth::api_key::CreateApiKeyRequest,
    server::Server,
    test_utils::{TestServerBuilder, create_test_jwt, create_test_user_with_data},
};
use tower::ServiceExt;

async fn create_test_server() -> Server {
    let mut config = bedrock_sso_proxy::config::Config::default();
    config.api_keys.enabled = true;

    TestServerBuilder::new().with_config(config).build().await
}

#[tokio::test]
async fn test_api_key_authentication_with_authorization_header() {
    let server = create_test_server().await;
    let user_id =
        create_test_user_with_data(&server.database, "test_user_1", "test", "test1@example.com")
            .await;
    let app = server.create_app();

    // First, create an API key via JWT authentication
    let jwt_token = create_test_jwt(&server.jwt_service, user_id);
    let create_request = CreateApiKeyRequest {
        name: "Test API Key".to_string(),
        expires_in_days: Some(30),
    };

    let request = Request::builder()
        .uri("/api/keys")
        .method("POST")
        .header("Authorization", format!("Bearer {}", jwt_token))
        .header("Content-Type", "application/json")
        .body(Body::from(serde_json::to_string(&create_request).unwrap()))
        .unwrap();

    let response = app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let create_response: bedrock_sso_proxy::auth::api_key::CreateApiKeyResponse =
        serde_json::from_slice(&body).unwrap();

    let api_key = create_response.key;
    assert!(api_key.starts_with("SSOK_"));

    // Now test using the API key to access Bedrock API
    let bedrock_request = Request::builder()
        .uri("/bedrock/model/anthropic.claude-sonnet-4-20250514-v1:0/invoke")
        .method("POST")
        .header("Authorization", format!("Bearer {}", api_key))
        .header("Content-Type", "application/json")
        .body(Body::from(r#"{"anthropic_version": "bedrock-2023-05-31", "max_tokens": 100, "messages": [{"role": "user", "content": "Hello"}]}"#))
        .unwrap();

    let response = app.oneshot(bedrock_request).await.unwrap();
    // Should not be unauthorized (would get 401 if API key auth failed)
    // Note: Will get 500 or other error due to AWS not being configured, but not 401
    assert_ne!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_api_key_authentication_with_x_api_key_header() {
    let server = create_test_server().await;
    let user_id =
        create_test_user_with_data(&server.database, "test_user_2", "test", "test2@example.com")
            .await;
    let app = server.create_app();

    // First, create an API key via JWT authentication
    let jwt_token = create_test_jwt(&server.jwt_service, user_id);
    let create_request = CreateApiKeyRequest {
        name: "Test X-API-Key".to_string(),
        expires_in_days: Some(30),
    };

    let request = Request::builder()
        .uri("/api/keys")
        .method("POST")
        .header("Authorization", format!("Bearer {}", jwt_token))
        .header("Content-Type", "application/json")
        .body(Body::from(serde_json::to_string(&create_request).unwrap()))
        .unwrap();

    let response = app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let create_response: bedrock_sso_proxy::auth::api_key::CreateApiKeyResponse =
        serde_json::from_slice(&body).unwrap();

    let api_key = create_response.key;

    // Test using X-API-Key header instead of Authorization header
    let anthropic_request = Request::builder()
        .uri("/anthropic/v1/messages")
        .method("POST")
        .header("X-API-Key", &api_key)
        .header("Content-Type", "application/json")
        .body(Body::from(r#"{"model": "claude-sonnet-4-20250514", "max_tokens": 100, "messages": [{"role": "user", "content": "Hello"}]}"#))
        .unwrap();

    let response = app.oneshot(anthropic_request).await.unwrap();
    // Should not be unauthorized (would get 401 if API key auth failed)
    assert_ne!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_invalid_api_key_authentication() {
    let server = create_test_server().await;
    let app = server.create_app();

    // Test with invalid API key
    let request = Request::builder()
        .uri("/bedrock/model/anthropic.claude-sonnet-4-20250514-v1:0/invoke")
        .method("POST")
        .header("Authorization", "Bearer SSOK_invalid_key_12345678")
        .header("Content-Type", "application/json")
        .body(Body::from(r#"{"anthropic_version": "bedrock-2023-05-31", "max_tokens": 100, "messages": [{"role": "user", "content": "Hello"}]}"#))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_api_key_disabled() {
    let mut config = bedrock_sso_proxy::config::Config::default();
    config.api_keys.enabled = false; // Disable API keys

    let server = TestServerBuilder::new().with_config(config).build().await;

    let app = server.create_app();

    // Test with API key when disabled
    let request = Request::builder()
        .uri("/bedrock/model/anthropic.claude-sonnet-4-20250514-v1:0/invoke")
        .method("POST")
        .header("Authorization", "Bearer SSOK_some_key_12345678")
        .header("Content-Type", "application/json")
        .body(Body::from(r#"{"anthropic_version": "bedrock-2023-05-31", "max_tokens": 100, "messages": [{"role": "user", "content": "Hello"}]}"#))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_revoked_api_key_authentication() {
    let server = create_test_server().await;
    let user_id =
        create_test_user_with_data(&server.database, "test_user_3", "test", "test3@example.com")
            .await;
    let app = server.create_app();

    // Create an API key
    let jwt_token = create_test_jwt(&server.jwt_service, user_id);
    let create_request = CreateApiKeyRequest {
        name: "Test Revoke Key".to_string(),
        expires_in_days: Some(30),
    };

    let request = Request::builder()
        .uri("/api/keys")
        .method("POST")
        .header("Authorization", format!("Bearer {}", jwt_token))
        .header("Content-Type", "application/json")
        .body(Body::from(serde_json::to_string(&create_request).unwrap()))
        .unwrap();

    let response = app.clone().oneshot(request).await.unwrap();
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let create_response: bedrock_sso_proxy::auth::api_key::CreateApiKeyResponse =
        serde_json::from_slice(&body).unwrap();

    let api_key = create_response.key;

    // Revoke the API key
    let revoke_request = Request::builder()
        .uri(format!("/api/keys/{}", api_key))
        .method("DELETE")
        .header("Authorization", format!("Bearer {}", jwt_token))
        .body(Body::empty())
        .unwrap();

    let response = app.clone().oneshot(revoke_request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // Try to use the revoked API key
    let test_request = Request::builder()
        .uri("/bedrock/model/anthropic.claude-sonnet-4-20250514-v1:0/invoke")
        .method("POST")
        .header("Authorization", format!("Bearer {}", api_key))
        .header("Content-Type", "application/json")
        .body(Body::from(r#"{"anthropic_version": "bedrock-2023-05-31", "max_tokens": 100, "messages": [{"role": "user", "content": "Hello"}]}"#))
        .unwrap();

    let response = app.oneshot(test_request).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_dual_authentication_support() {
    let server = create_test_server().await;
    let user_id =
        create_test_user_with_data(&server.database, "test_user_4", "test", "test4@example.com")
            .await;
    let app = server.create_app();

    // Test JWT authentication still works
    let jwt_token = create_test_jwt(&server.jwt_service, user_id);
    let jwt_request = Request::builder()
        .uri("/bedrock/model/anthropic.claude-sonnet-4-20250514-v1:0/invoke")
        .method("POST")
        .header("Authorization", format!("Bearer {}", jwt_token))
        .header("Content-Type", "application/json")
        .body(Body::from(r#"{"anthropic_version": "bedrock-2023-05-31", "max_tokens": 100, "messages": [{"role": "user", "content": "Hello"}]}"#))
        .unwrap();

    let response = app.clone().oneshot(jwt_request).await.unwrap();
    // Should not be unauthorized (would get 401 if JWT auth failed)
    assert_ne!(response.status(), StatusCode::UNAUTHORIZED);

    // Create and test API key authentication
    let create_request = CreateApiKeyRequest {
        name: "Dual Auth Test".to_string(),
        expires_in_days: Some(30),
    };

    let request = Request::builder()
        .uri("/api/keys")
        .method("POST")
        .header("Authorization", format!("Bearer {}", jwt_token))
        .header("Content-Type", "application/json")
        .body(Body::from(serde_json::to_string(&create_request).unwrap()))
        .unwrap();

    let response = app.clone().oneshot(request).await.unwrap();
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let create_response: bedrock_sso_proxy::auth::api_key::CreateApiKeyResponse =
        serde_json::from_slice(&body).unwrap();

    let api_key = create_response.key;

    // Test API key authentication
    let api_key_request = Request::builder()
        .uri("/anthropic/v1/messages")
        .method("POST")
        .header("Authorization", format!("Bearer {}", api_key))
        .header("Content-Type", "application/json")
        .body(Body::from(r#"{"model": "claude-sonnet-4-20250514", "max_tokens": 100, "messages": [{"role": "user", "content": "Hello"}]}"#))
        .unwrap();

    let response = app.oneshot(api_key_request).await.unwrap();
    // Should not be unauthorized (would get 401 if API key auth failed)
    assert_ne!(response.status(), StatusCode::UNAUTHORIZED);
}
