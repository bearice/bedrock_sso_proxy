use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use bedrock_sso_proxy::{Config, Server, auth::AuthConfig, aws_http::AwsHttpClient};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};
use std::{
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use tower::ServiceExt;

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    exp: usize,
    iat: usize,
    user_id: Option<String>,
    role: Option<String>,
    permissions: Option<Vec<String>>,
}

fn create_real_jwt_token(
    secret: &str,
    sub: &str,
    user_id: Option<&str>,
    permissions: Option<Vec<&str>>,
) -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as usize;

    let claims = Claims {
        sub: sub.to_string(),
        exp: now + 3600, // 1 hour from now
        iat: now,
        user_id: user_id.map(|s| s.to_string()),
        role: Some("user".to_string()),
        permissions: permissions.map(|p| p.iter().map(|s| s.to_string()).collect()),
    };

    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_ref()),
    )
    .unwrap()
}

fn verify_jwt_token(token: &str, secret: &str) -> Result<Claims, jsonwebtoken::errors::Error> {
    let mut validation = Validation::new(Algorithm::HS256);
    validation.validate_exp = true;

    let token_data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret.as_ref()),
        &validation,
    )?;

    Ok(token_data.claims)
}

#[tokio::test]
async fn test_integration_jwt_token_validation() {
    let secret = "integration-test-secret-123";
    let token = create_real_jwt_token(
        secret,
        "test_user",
        Some("user123"),
        Some(vec!["read", "write"]),
    );

    // Verify we can decode the token
    let claims = verify_jwt_token(&token, secret).unwrap();
    assert_eq!(claims.sub, "test_user");
    assert_eq!(claims.user_id, Some("user123".to_string()));
    assert_eq!(
        claims.permissions,
        Some(vec!["read".to_string(), "write".to_string()])
    );
}

#[tokio::test]
async fn test_integration_server_with_real_jwt() {
    let mut config = Config::default();
    config.jwt.secret = "integration-test-secret-456".to_string();

    let auth_config = Arc::new(AuthConfig {
        jwt_secret: config.jwt.secret.clone(),
    });
    let aws_http_client = AwsHttpClient::new_test();

    let server = Server::new(config.clone());
    let app = server.create_app(auth_config, aws_http_client);

    // Test with a real JWT token containing detailed claims
    let token = create_real_jwt_token(
        &config.jwt.secret,
        "integration_user",
        Some("int_123"),
        Some(vec!["bedrock:invoke", "bedrock:stream"]),
    );

    let request = Request::builder()
        .uri("/health")
        .header("Authorization", format!("Bearer {}", token))
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_integration_invalid_signature() {
    let config = Config::default();
    let auth_config = Arc::new(AuthConfig {
        jwt_secret: config.jwt.secret.clone(),
    });
    let aws_http_client = AwsHttpClient::new_test();

    let server = Server::new(config.clone());
    let app = server.create_app(auth_config, aws_http_client);

    // Create token with different secret
    let token = create_real_jwt_token("wrong-secret", "test_user", Some("user123"), None);

    let request = Request::builder()
        .uri("/model/test-model/invoke")
        .method("POST")
        .header("Authorization", format!("Bearer {}", token))
        .header("Content-Type", "application/json")
        .body(Body::from(r#"{"messages": []}"#))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_integration_token_with_custom_claims() {
    let mut config = Config::default();
    config.jwt.secret = "custom-claims-secret".to_string();

    let auth_config = Arc::new(AuthConfig {
        jwt_secret: config.jwt.secret.clone(),
    });
    let aws_http_client = AwsHttpClient::new_test();

    let server = Server::new(config.clone());
    let app = server.create_app(auth_config, aws_http_client);

    // Create token with custom claims
    let token = create_real_jwt_token(
        &config.jwt.secret,
        "admin_user",
        Some("admin_456"),
        Some(vec!["bedrock:*", "admin:*"]),
    );

    let request = Request::builder()
        .uri("/model/anthropic.claude-v2/invoke-with-response-stream")
        .method("POST")
        .header("Authorization", format!("Bearer {}", token))
        .header("Content-Type", "application/json")
        .body(Body::from(
            r#"{"messages": [{"role": "user", "content": "Test"}]}"#,
        ))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get("content-type").unwrap(),
        "text/event-stream"
    );
}

#[tokio::test]
async fn test_integration_malformed_authorization_header() {
    let config = Config::default();
    let auth_config = Arc::new(AuthConfig {
        jwt_secret: config.jwt.secret.clone(),
    });
    let aws_http_client = AwsHttpClient::new_test();

    let server = Server::new(config);
    let app = server.create_app(auth_config, aws_http_client);

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
            .uri("/model/test-model/invoke")
            .method("POST")
            .header("Authorization", header_value)
            .header("Content-Type", "application/json")
            .body(Body::from(r#"{"messages": []}"#))
            .unwrap();

        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}

#[tokio::test]
async fn test_integration_concurrent_requests() {
    let config = Config::default();
    let auth_config = Arc::new(AuthConfig {
        jwt_secret: config.jwt.secret.clone(),
    });
    let aws_http_client = AwsHttpClient::new_test();

    let server = Server::new(config.clone());
    let app = Arc::new(server.create_app(auth_config, aws_http_client));

    let token = create_real_jwt_token(
        &config.jwt.secret,
        "concurrent_user",
        Some("conc_123"),
        None,
    );

    // Create multiple concurrent requests
    let mut handles = vec![];

    for i in 0..10 {
        let app_clone = app.clone();
        let token_clone = token.clone();

        let handle = tokio::spawn(async move {
            let request = Request::builder()
                .uri("/health?check=all")
                .header("Authorization", format!("Bearer {}", token_clone))
                .body(Body::empty())
                .unwrap();

            let response = (*app_clone).clone().oneshot(request).await.unwrap();
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
    let config = Config::default();
    let auth_config = Arc::new(AuthConfig {
        jwt_secret: config.jwt.secret.clone(),
    });
    let aws_http_client = AwsHttpClient::new_test();

    let server = Server::new(config.clone());
    let app = server.create_app(auth_config, aws_http_client);

    // Test token that expires in 1 second
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as usize;

    let short_lived_claims = Claims {
        sub: "short_lived_user".to_string(),
        exp: now + 1, // 1 second from now
        iat: now,
        user_id: Some("short_123".to_string()),
        role: Some("user".to_string()),
        permissions: None,
    };

    let short_token = encode(
        &Header::default(),
        &short_lived_claims,
        &EncodingKey::from_secret(config.jwt.secret.as_ref()),
    )
    .unwrap();

    // Request should work immediately
    let request = Request::builder()
        .uri("/health")
        .header("Authorization", format!("Bearer {}", short_token))
        .body(Body::empty())
        .unwrap();

    let response = app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // Wait for token to expire
    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

    // Request should now fail
    let request = Request::builder()
        .uri("/model/test-model/invoke")
        .method("POST")
        .header("Authorization", format!("Bearer {}", short_token))
        .header("Content-Type", "application/json")
        .body(Body::from(r#"{"messages": []}"#))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    
    // Debug: Extract status and body
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let body_str = String::from_utf8_lossy(&body);
    println!("Response status: {}, body: {}", status, body_str);
    
    // Should fail with UNAUTHORIZED for expired token
    assert_eq!(status, StatusCode::UNAUTHORIZED, "Expired JWT token should result in 401 Unauthorized, not {} - Body: {}", status, body_str);
}
