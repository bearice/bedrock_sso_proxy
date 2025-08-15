//! OAuth integration tests that verify the complete authentication flow
//!
//! These tests simulate the real OAuth process to catch bugs that only occur
//! in the full end-to-end flow, such as ID consistency issues.

mod common;
use common::TestHarness;
use bedrock_sso_proxy::auth::oauth::TokenRequest;
use bedrock_sso_proxy::utils::request_context::RequestContext;
use wiremock::{
    matchers::{method, path},
    Mock, MockServer, ResponseTemplate,
};

#[tokio::test]
async fn test_oauth_end_to_end_user_id_consistency() {
    let harness = TestHarness::new().await;
    
    // Start a mock OAuth server to simulate Google's responses
    let mock_server = MockServer::start().await;
    
    // Mock the token exchange endpoint
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "mock_access_token_123",
            "token_type": "Bearer",
            "expires_in": 3600,
            "refresh_token": "mock_refresh_token_456",
            "scope": "openid email profile"
        })))
        .mount(&mock_server)
        .await;
    
    // Mock the user info endpoint
    Mock::given(method("GET"))
        .and(path("/userinfo"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "sub": "google_user_12345",
            "email": "testuser@example.com", 
            "name": "Test User",
            "email_verified": true
        })))
        .mount(&mock_server)
        .await;
    
    // Create a custom OAuth configuration that uses our mock server
    let mut config = harness.server.config.as_ref().clone();
    
    // Create a Google provider configuration for testing
    use bedrock_sso_proxy::auth::config::OAuthProvider;
    
    let google_provider = OAuthProvider {
        client_id: "test_client_id".to_string(),
        client_secret: "test_client_secret".to_string(),
        redirect_uri: Some("http://localhost:3000/auth/callback/google".to_string()),
        scopes: vec!["openid".to_string(), "email".to_string(), "profile".to_string()],
        authorization_url: Some(format!("{}/auth", mock_server.uri())),
        token_url: Some(format!("{}/token", mock_server.uri())),
        user_info_url: Some(format!("{}/userinfo", mock_server.uri())),
        user_id_field: "sub".to_string(),
        email_field: "email".to_string(),
        ..Default::default()
    };
    
    config.oauth.providers.insert("google".to_string(), google_provider);
    
    // Create OAuth service with mock configuration
    let oauth_service = bedrock_sso_proxy::auth::oauth::service::OAuthService::new(
        config.clone(),
        harness.server.jwt_service.clone(),
        harness.server.database.clone(),
        harness.server.cache.clone(),
    ).unwrap();
    
    let context = RequestContext {
        ip_address: Some("127.0.0.1".to_string()),
        user_agent: Some("test-agent".to_string()),
    };
    
    // First OAuth login - simulate the complete flow with real state
    let auth_response_1 = oauth_service
        .get_authorization_url("google", "http://localhost:3000/auth/callback/google")
        .await
        .unwrap();
    
    let token_request_1 = TokenRequest {
        provider: "google".to_string(),
        authorization_code: "mock_auth_code_1".to_string(),
        redirect_uri: "http://localhost:3000/auth/callback/google".to_string(),
        state: auth_response_1.state,
    };
    
    let token_response_1 = oauth_service.exchange_code_for_token(token_request_1, context.clone()).await.unwrap();
    let user_id_from_jwt_1 = decode_user_id_from_jwt(&token_response_1.access_token);
    
    // Second OAuth login - same user, should get same ID
    let auth_response_2 = oauth_service
        .get_authorization_url("google", "http://localhost:3000/auth/callback/google")
        .await
        .unwrap();
    
    let token_request_2 = TokenRequest {
        provider: "google".to_string(),
        authorization_code: "mock_auth_code_2".to_string(), 
        redirect_uri: "http://localhost:3000/auth/callback/google".to_string(),
        state: auth_response_2.state,
    };
    
    let token_response_2 = oauth_service.exchange_code_for_token(token_request_2, context.clone()).await.unwrap();
    let user_id_from_jwt_2 = decode_user_id_from_jwt(&token_response_2.access_token);
    
    // Third OAuth login - should still get the same ID
    let auth_response_3 = oauth_service
        .get_authorization_url("google", "http://localhost:3000/auth/callback/google")
        .await
        .unwrap();
    
    let token_request_3 = TokenRequest {
        provider: "google".to_string(),
        authorization_code: "mock_auth_code_3".to_string(),
        redirect_uri: "http://localhost:3000/auth/callback/google".to_string(), 
        state: auth_response_3.state,
    };
    
    let token_response_3 = oauth_service.exchange_code_for_token(token_request_3, context).await.unwrap();
    let user_id_from_jwt_3 = decode_user_id_from_jwt(&token_response_3.access_token);
    
    // This is the critical assertion that would have caught the original bug!
    assert_eq!(user_id_from_jwt_1, user_id_from_jwt_2, 
        "Same user should get consistent ID across OAuth logins (first vs second)");
    assert_eq!(user_id_from_jwt_2, user_id_from_jwt_3, 
        "Same user should get consistent ID across OAuth logins (second vs third)");
    
    println!("✅ End-to-end OAuth user ID consistency test passed: User ID {} remained consistent across 3 logins", user_id_from_jwt_1);
}


// Helper function to decode user ID from JWT token
fn decode_user_id_from_jwt(jwt_token: &str) -> i32 {
    use base64::{engine::general_purpose, Engine as _};
    
    let parts: Vec<&str> = jwt_token.split('.').collect();
    assert_eq!(parts.len(), 3, "JWT should have 3 parts");
    
    let payload = general_purpose::STANDARD_NO_PAD
        .decode(parts[1])
        .expect("Failed to decode JWT payload");
    
    let claims: serde_json::Value = serde_json::from_slice(&payload)
        .expect("Failed to parse JWT claims");
    
    claims["sub"].as_i64().expect("JWT should have 'sub' claim") as i32
}

#[tokio::test]
async fn test_oauth_different_users_get_different_ids() {
    let harness = TestHarness::new().await;
    
    // Start a mock OAuth server
    let mock_server = MockServer::start().await;
    
    // Mock token endpoint for both users
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "mock_access_token",
            "token_type": "Bearer", 
            "expires_in": 3600,
            "refresh_token": "mock_refresh_token",
            "scope": "openid email profile"
        })))
        .mount(&mock_server)
        .await;
    
    // Mock user info endpoint for User 1
    Mock::given(method("GET"))
        .and(path("/userinfo"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "sub": "google_user_111",
            "email": "user1@example.com",
            "name": "User One",
            "email_verified": true
        })))
        .expect(1)  // Only expect this once
        .mount(&mock_server)
        .await;
    
    // Mock user info endpoint for User 2 (different response)
    Mock::given(method("GET"))
        .and(path("/userinfo"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "sub": "google_user_222", 
            "email": "user2@example.com",
            "name": "User Two",
            "email_verified": true
        })))
        .mount(&mock_server)
        .await;
    
    // Create OAuth service with mock configuration
    let mut config = harness.server.config.as_ref().clone();
    
    // Create a Google provider configuration for testing
    use bedrock_sso_proxy::auth::config::OAuthProvider;
    
    let google_provider = OAuthProvider {
        client_id: "test_client_id".to_string(),
        client_secret: "test_client_secret".to_string(),
        redirect_uri: Some("http://localhost:3000/auth/callback/google".to_string()),
        scopes: vec!["openid".to_string(), "email".to_string(), "profile".to_string()],
        authorization_url: Some(format!("{}/auth", mock_server.uri())),
        token_url: Some(format!("{}/token", mock_server.uri())),
        user_info_url: Some(format!("{}/userinfo", mock_server.uri())),
        user_id_field: "sub".to_string(),
        email_field: "email".to_string(),
        ..Default::default()
    };
    
    config.oauth.providers.insert("google".to_string(), google_provider);
    
    let oauth_service = bedrock_sso_proxy::auth::oauth::service::OAuthService::new(
        config.clone(),
        harness.server.jwt_service.clone(),
        harness.server.database.clone(),
        harness.server.cache.clone(),
    ).unwrap();
    
    let context = RequestContext {
        ip_address: Some("127.0.0.1".to_string()),
        user_agent: Some("test-agent".to_string()),
    };
    
    // First user login
    let auth_response_user1 = oauth_service
        .get_authorization_url("google", "http://localhost:3000/auth/callback/google")
        .await
        .unwrap();
    
    let token_request_user1 = TokenRequest {
        provider: "google".to_string(),
        authorization_code: "auth_code_user1".to_string(),
        redirect_uri: "http://localhost:3000/auth/callback/google".to_string(),
        state: auth_response_user1.state,
    };
    
    let token_response_user1 = oauth_service.exchange_code_for_token(token_request_user1, context.clone()).await.unwrap();
    let user1_id = decode_user_id_from_jwt(&token_response_user1.access_token);
    
    // Update mock for second user
    mock_server.reset().await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "mock_access_token_2",
            "token_type": "Bearer",
            "expires_in": 3600,
            "refresh_token": "mock_refresh_token_2", 
            "scope": "openid email profile"
        })))
        .mount(&mock_server)
        .await;
        
    Mock::given(method("GET"))
        .and(path("/userinfo"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "sub": "google_user_222",
            "email": "user2@example.com", 
            "name": "User Two",
            "email_verified": true
        })))
        .mount(&mock_server)
        .await;
    
    // Second user login  
    let auth_response_user2 = oauth_service
        .get_authorization_url("google", "http://localhost:3000/auth/callback/google")
        .await
        .unwrap();
    
    let token_request_user2 = TokenRequest {
        provider: "google".to_string(),
        authorization_code: "auth_code_user2".to_string(),
        redirect_uri: "http://localhost:3000/auth/callback/google".to_string(),
        state: auth_response_user2.state,
    };
    
    let token_response_user2 = oauth_service.exchange_code_for_token(token_request_user2, context.clone()).await.unwrap();
    let user2_id = decode_user_id_from_jwt(&token_response_user2.access_token);
    
    // Verify different users get different IDs
    assert_ne!(user1_id, user2_id, "Different users should get different IDs");
    
    println!("✅ Multiple users OAuth test passed: User 1 ID: {}, User 2 ID: {}", user1_id, user2_id);
}

#[tokio::test]
async fn test_oauth_with_real_state_management() {
    let harness = TestHarness::new().await;
    
    // Start a mock OAuth server
    let mock_server = MockServer::start().await;
    
    // Mock the OAuth endpoints
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "mock_access_token",
            "token_type": "Bearer",
            "expires_in": 3600,
            "refresh_token": "mock_refresh_token",
            "scope": "openid email profile"
        })))
        .mount(&mock_server)
        .await;
    
    Mock::given(method("GET"))
        .and(path("/userinfo"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "sub": "test_user_789",
            "email": "statetest@example.com",
            "name": "State Test User",
            "email_verified": true
        })))
        .mount(&mock_server)
        .await;
    
    // Create OAuth service with mock configuration
    let mut config = harness.server.config.as_ref().clone();
    
    // Create a Google provider configuration for testing
    use bedrock_sso_proxy::auth::config::OAuthProvider;
    
    let google_provider = OAuthProvider {
        client_id: "test_client_id".to_string(),
        client_secret: "test_client_secret".to_string(),
        redirect_uri: Some("http://localhost:3000/auth/callback/google".to_string()),
        scopes: vec!["openid".to_string(), "email".to_string(), "profile".to_string()],
        authorization_url: Some(format!("{}/auth", mock_server.uri())),
        token_url: Some(format!("{}/token", mock_server.uri())),
        user_info_url: Some(format!("{}/userinfo", mock_server.uri())),
        user_id_field: "sub".to_string(),
        email_field: "email".to_string(),
        ..Default::default()
    };
    
    config.oauth.providers.insert("google".to_string(), google_provider);
    
    let oauth_service = bedrock_sso_proxy::auth::oauth::service::OAuthService::new(
        config.clone(),
        harness.server.jwt_service.clone(),
        harness.server.database.clone(),
        harness.server.cache.clone(),
    ).unwrap();
    
    // First, generate a real authorization URL to get a valid state
    let auth_response = oauth_service
        .get_authorization_url("google", "http://localhost:3000/auth/callback/google")
        .await
        .unwrap();
    
    let context = RequestContext {
        ip_address: Some("127.0.0.1".to_string()),
        user_agent: Some("test-agent".to_string()),
    };
    
    // Use the real state from the authorization URL
    let token_request = TokenRequest {
        provider: "google".to_string(),
        authorization_code: "valid_auth_code".to_string(),
        redirect_uri: "http://localhost:3000/auth/callback/google".to_string(),
        state: auth_response.state,
    };
    
    // This should work with proper state validation
    let token_response = oauth_service.exchange_code_for_token(token_request, context).await.unwrap();
    let user_id = decode_user_id_from_jwt(&token_response.access_token);
    
    println!("✅ OAuth with real state management test passed: User ID {}", user_id);
}