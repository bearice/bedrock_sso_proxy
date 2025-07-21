use axum::{
    body::Body,
    http::{Request, StatusCode},
    Router,
};
use bedrock_sso_proxy::{Config, Server, auth::{AuthConfig, jwt::{JwtService, parse_algorithm}}, aws_http::AwsHttpClient};
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

// Test setup helpers
struct TestSetup {
    #[allow(dead_code)]
    config: Config,
    app: Router,
    jwt_secret: String,
}

impl TestSetup {
    async fn new() -> Self {
        Self::with_secret("test-secret-123").await
    }

    async fn with_secret(secret: &str) -> Self {
        let mut config = Config::default();
        config.jwt.secret = secret.to_string();

        let jwt_service = JwtService::new(config.jwt.secret.clone(), parse_algorithm(&config.jwt.algorithm).unwrap());
        let auth_config = Arc::new(AuthConfig::new(jwt_service));
        let aws_http_client = AwsHttpClient::new_test();

        let server = Server::new(config.clone());
        let app = server.create_app(auth_config, aws_http_client).await;

        Self {
            jwt_secret: config.jwt.secret.clone(),
            config,
            app,
        }
    }

    fn create_token(&self, sub: &str, user_id: Option<&str>, permissions: Option<Vec<&str>>) -> String {
        create_real_jwt_token(&self.jwt_secret, sub, user_id, permissions)
    }

    fn create_token_with_expiry(&self, sub: &str, exp_offset: i64) -> String {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as usize;

        let claims = Claims {
            sub: sub.to_string(),
            exp: (now as i64 + exp_offset) as usize,
            iat: now,
            user_id: Some("test_user".to_string()),
            role: Some("user".to_string()),
            permissions: None,
        };

        encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(self.jwt_secret.as_ref()),
        )
        .unwrap()
    }

    async fn make_request(&self, request: Request<Body>) -> axum::response::Response {
        self.app.clone().oneshot(request).await.unwrap()
    }
}

// Request builders
struct RequestBuilder;

impl RequestBuilder {
    #[allow(dead_code)]
    fn health() -> Request<Body> {
        Request::builder()
            .uri("/health")
            .body(Body::empty())
            .unwrap()
    }

    fn health_with_auth(token: &str) -> Request<Body> {
        Request::builder()
            .uri("/health")
            .header("Authorization", format!("Bearer {}", token))
            .body(Body::empty())
            .unwrap()
    }

    fn health_with_check_and_auth(check_type: &str, token: &str) -> Request<Body> {
        Request::builder()
            .uri(&format!("/health?check={}", check_type))
            .header("Authorization", format!("Bearer {}", token))
            .body(Body::empty())
            .unwrap()
    }

    fn invoke_model_with_auth(model_id: &str, token: &str, body: &str) -> Request<Body> {
        Request::builder()
            .uri(&format!("/model/{}/invoke", model_id))
            .method("POST")
            .header("Authorization", format!("Bearer {}", token))
            .header("Content-Type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap()
    }

    fn invoke_streaming_with_auth(model_id: &str, token: &str, body: &str) -> Request<Body> {
        Request::builder()
            .uri(&format!("/model/{}/invoke-with-response-stream", model_id))
            .method("POST")
            .header("Authorization", format!("Bearer {}", token))
            .header("Content-Type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap()
    }

    #[allow(dead_code)]
    fn custom_auth_header(uri: &str, method: &str, auth_header: &str, body: &str) -> Request<Body> {
        Request::builder()
            .uri(uri)
            .method(method)
            .header("Authorization", auth_header)
            .header("Content-Type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap()
    }
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
    let setup = TestSetup::with_secret("integration-test-secret-456").await;
    
    let token = setup.create_token(
        "integration_user",
        Some("int_123"),
        Some(vec!["bedrock:invoke", "bedrock:stream"]),
    );

    let request = RequestBuilder::health_with_auth(&token);

    let response = setup.make_request(request).await;
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_integration_invalid_signature() {
    let setup = TestSetup::new().await;

    // Create token with different secret (will fail validation)
    let token = create_real_jwt_token("wrong-secret", "test_user", Some("user123"), None);

    let request = RequestBuilder::invoke_model_with_auth("test-model", &token, r#"{"messages": []}"#);

    let response = setup.make_request(request).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_integration_token_with_custom_claims() {
    let setup = TestSetup::with_secret("custom-claims-secret").await;

    let token = setup.create_token(
        "admin_user",
        Some("admin_456"),
        Some(vec!["bedrock:*", "admin:*"]),
    );

    let request = RequestBuilder::invoke_streaming_with_auth("anthropic.claude-v2", &token, r#"{"messages": [{"role": "user", "content": "Test"}]}"#);

    let response = setup.make_request(request).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get("content-type").unwrap(),
        "text/event-stream"
    );
}

#[tokio::test]
async fn test_integration_malformed_authorization_header() {
    let setup = TestSetup::new().await;

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

        let response = setup.make_request(request).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}

#[tokio::test]
async fn test_integration_concurrent_requests() {
    let setup = Arc::new(TestSetup::new().await);
    let token = setup.create_token("concurrent_user", Some("conc_123"), None);

    // Create multiple concurrent requests
    let mut handles = vec![];

    for i in 0..10 {
        let setup_clone = setup.clone();
        let token_clone = token.clone();

        let handle = tokio::spawn(async move {
            let request = RequestBuilder::health_with_check_and_auth("all", &token_clone);

            let response = setup_clone.make_request(request).await;
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
    let setup = TestSetup::new().await;

    // Create token that expires in 1 second
    let short_token = setup.create_token_with_expiry("short_lived_user", 1);

    // Request should work immediately
    let request = RequestBuilder::health_with_auth(&short_token);

    let response = setup.make_request(request).await;
    assert_eq!(response.status(), StatusCode::OK);

    // Wait for token to expire
    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

    // Request should now fail
    let request = RequestBuilder::invoke_model_with_auth("test-model", &short_token, r#"{"messages": []}"#);

    let response = setup.make_request(request).await;

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
