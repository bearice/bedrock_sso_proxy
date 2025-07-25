use axum::{
    Router,
    body::Body,
    http::{Method, Request, StatusCode},
};
use bedrock_sso_proxy::{
    Config, Server,
    auth::jwt::Claims,
};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use std::time::{SystemTime, UNIX_EPOCH};
use tower::ServiceExt;


/// Unified test harness that handles app setup and token management
pub struct TestHarness {
    #[allow(dead_code)]
    pub config: Config,
    pub app: Router,
    pub jwt_secret: String,
}


impl TestHarness {
    /// Create test harness with default secret
    pub async fn new() -> Self {
        Self::with_secret("test-secret-123").await
    }

    /// Create test harness with custom secret
    pub async fn with_secret(secret: &str) -> Self {
        let mut config = Config::default();
        config.jwt.secret = secret.to_string();
        config.storage.redis.enabled = false;
        config.storage.database.enabled = false;
        config.metrics.enabled = false;
        
        // Add test AWS credentials for integration tests
        config.aws.access_key_id = Some("test-access-key".to_string());
        config.aws.secret_access_key = Some("test-secret-key".to_string());

        let server = Server::new(config.clone()).await.unwrap();
        let app = server.create_app();

        Self {
            jwt_secret: config.jwt.secret.clone(),
            config,
            app,
        }
    }


    /// Create JWT token from claims
    pub fn create_token(&self, claims: &Claims) -> String {
        encode(
            &Header::default(),
            claims,
            &EncodingKey::from_secret(self.jwt_secret.as_ref()),
        )
        .unwrap()
    }

    /// Create JWT token for integration tests
    #[allow(dead_code)]
    pub fn create_integration_token(
        &self,
        sub: &str,
        user_id: i32,
    ) -> String {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as usize;

        let claims = Claims {
            sub: sub.to_string(),
            exp: now + 3600, // 1 hour expiry
            user_id,
        };
        self.create_token(&claims)
    }

    /// Create JWT token for security tests
    #[allow(dead_code)]
    pub fn create_security_token(&self, sub: &str, exp_offset: i64) -> String {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let exp = (now + exp_offset) as usize;

        let claims = Claims {
            sub: sub.to_string(),
            exp,
            user_id: 456, // Test user ID for security tests
        };
        self.create_token(&claims)
    }

    /// Create JWT token with custom expiry
    #[allow(dead_code)]
    pub fn create_token_with_expiry(
        &self,
        sub: &str,
        exp_offset: i64,
        user_id: i32,
    ) -> String {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let exp = (now + exp_offset) as usize;

        let claims = Claims {
            sub: sub.to_string(),
            exp,
            user_id,
        };
        self.create_token(&claims)
    }

    /// Make request using the test app
    pub async fn make_request(&self, request: Request<Body>) -> axum::response::Response {
        self.app.clone().oneshot(request).await.unwrap()
    }

    /// Verify JWT token
    #[allow(dead_code)]
    pub fn verify_token(&self, token: &str) -> Result<Claims, jsonwebtoken::errors::Error> {
        let mut validation = Validation::new(Algorithm::HS256);
        validation.validate_exp = true;

        let token_data = decode::<Claims>(
            token,
            &DecodingKey::from_secret(self.jwt_secret.as_ref()),
            &validation,
        )?;

        Ok(token_data.claims)
    }
}

/// Unified request builder for both test suites
pub struct RequestBuilder;

impl RequestBuilder {
    /// Health check with auth
    pub fn health_with_auth(token: &str) -> Request<Body> {
        Request::builder()
            .uri("/health")
            .header("Authorization", format!("Bearer {}", token))
            .body(Body::empty())
            .unwrap()
    }

    /// Health check with query parameter and auth
    #[allow(dead_code)]
    pub fn health_with_check_and_auth(check_type: &str, token: &str) -> Request<Body> {
        Request::builder()
            .uri(format!("/health?check={}", check_type))
            .header("Authorization", format!("Bearer {}", token))
            .body(Body::empty())
            .unwrap()
    }

    /// Model invoke with auth
    pub fn invoke_model_with_auth(model_id: &str, token: &str, body: &str) -> Request<Body> {
        Request::builder()
            .uri(format!("/bedrock/model/{}/invoke", model_id))
            .method("POST")
            .header("Authorization", format!("Bearer {}", token))
            .header("Content-Type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap()
    }

    /// Model invoke streaming with auth
    #[allow(dead_code)]
    pub fn invoke_streaming_with_auth(model_id: &str, token: &str, body: &str) -> Request<Body> {
        Request::builder()
            .uri(format!(
                "/bedrock/model/{}/invoke-with-response-stream",
                model_id
            ))
            .method("POST")
            .header("Authorization", format!("Bearer {}", token))
            .header("Content-Type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap()
    }

    /// Custom request with method, headers, and body
    #[allow(dead_code)]
    pub fn custom_request(
        uri: &str,
        method: Method,
        token: &str,
        headers: &[(&str, &str)],
        body: &str,
    ) -> Request<Body> {
        let mut builder = Request::builder()
            .uri(uri)
            .method(method)
            .header("Authorization", format!("Bearer {}", token))
            .header("Content-Type", "application/json");

        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }

        builder.body(Body::from(body.to_string())).unwrap()
    }

    /// Request with custom content type
    #[allow(dead_code)]
    pub fn with_content_type(
        uri: &str,
        method: Method,
        token: &str,
        content_type: &str,
        body: &str,
    ) -> Result<Request<Body>, Box<dyn std::error::Error>> {
        Ok(Request::builder()
            .uri(uri)
            .method(method)
            .header("Authorization", format!("Bearer {}", token))
            .header("Content-Type", content_type)
            .body(Body::from(body.to_string()))?)
    }
}

/// Helper functions for common test patterns
pub mod helpers {
    use super::*;

    /// Assert response status with context
    #[allow(dead_code)]
    pub fn assert_status_with_context(
        response: &axum::response::Response,
        expected: StatusCode,
        context: &str,
    ) {
        assert_eq!(
            response.status(),
            expected,
            "Expected {} for {}, got {}",
            expected,
            context,
            response.status()
        );
    }

    /// Assert response status is one of several acceptable values
    #[allow(dead_code)]
    pub fn assert_status_in(
        response: &axum::response::Response,
        acceptable: &[StatusCode],
        context: &str,
    ) {
        assert!(
            acceptable.contains(&response.status()),
            "Expected one of {:?} for {}, got {}",
            acceptable,
            context,
            response.status()
        );
    }
}
