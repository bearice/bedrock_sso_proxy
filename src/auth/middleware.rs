use crate::auth::{ValidatedClaims, jwt::JwtService};
use crate::error::AppError;
use axum::{
    extract::{Request, State},
    http::header::AUTHORIZATION,
    middleware::Next,
    response::Response,
};
use std::sync::Arc;

#[derive(Clone)]
pub struct AuthConfig {
    pub jwt_service: JwtService,
}

impl AuthConfig {
    pub fn new(jwt_service: JwtService) -> Self {
        Self { jwt_service }
    }
}

pub async fn jwt_auth_middleware(
    State(auth_config): State<Arc<AuthConfig>>,
    mut request: Request,
    next: Next,
) -> Result<Response, AppError> {
    let auth_header = request
        .headers()
        .get(AUTHORIZATION)
        .and_then(|header| header.to_str().ok())
        .ok_or_else(|| AppError::Unauthorized("Missing Authorization header".to_string()))?;

    if !auth_header.starts_with("Bearer ") {
        return Err(AppError::Unauthorized(
            "Invalid Authorization format".to_string(),
        ));
    }

    let token = &auth_header[7..];

    // Validate token (supports both OAuth and legacy tokens)
    let _claims = auth_config.jwt_service.validate_token(token)?;

    // Remove Authorization header before forwarding to AWS
    request.headers_mut().remove(AUTHORIZATION);

    Ok(next.run(request).await)
}

// Enhanced middleware that provides claims to the request
pub async fn jwt_auth_middleware_with_claims(
    State(auth_config): State<Arc<AuthConfig>>,
    mut request: Request,
    next: Next,
) -> Result<Response, AppError> {
    let auth_header = request
        .headers()
        .get(AUTHORIZATION)
        .and_then(|header| header.to_str().ok())
        .ok_or_else(|| AppError::Unauthorized("Missing Authorization header".to_string()))?;

    if !auth_header.starts_with("Bearer ") {
        return Err(AppError::Unauthorized(
            "Invalid Authorization format".to_string(),
        ));
    }

    let token = &auth_header[7..];

    // Validate token and get claims
    let claims = auth_config.jwt_service.validate_token(token)?;

    // Add claims to request extensions for downstream handlers
    request.extensions_mut().insert(claims);

    // Remove Authorization header before forwarding to AWS
    request.headers_mut().remove(AUTHORIZATION);

    Ok(next.run(request).await)
}

// Utility function to extract claims from request extensions
pub fn extract_claims(request: &Request) -> Option<&ValidatedClaims> {
    request.extensions().get::<ValidatedClaims>()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{
        ValidatedClaims,
        jwt::{JwtService, OAuthClaims},
    };
    use axum::{
        Router,
        body::Body,
        extract::Request as ExtractRequest,
        http::{Request, StatusCode},
        middleware,
        routing::get,
    };
    use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
    use std::time::{SystemTime, UNIX_EPOCH};
    use tower::ServiceExt;

    // Legacy claims for testing
    use crate::auth::jwt::Claims;

    async fn test_handler() -> &'static str {
        "success"
    }

    async fn test_claims_handler(request: ExtractRequest) -> &'static str {
        let claims = extract_claims(&request);
        match claims {
            Some(ValidatedClaims::OAuth(_)) => "oauth_success",
            Some(ValidatedClaims::Legacy(_)) => "legacy_success",
            None => "no_claims",
        }
    }

    fn create_legacy_token(secret: &str, sub: &str, exp_offset: i64) -> String {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let exp = (now + exp_offset) as usize;

        let claims = Claims {
            sub: sub.to_string(),
            exp,
        };

        encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(secret.as_ref()),
        )
        .unwrap()
    }

    fn create_oauth_token(jwt_service: &JwtService) -> String {
        let claims = OAuthClaims::new(
            "google:123".to_string(),
            "google".to_string(),
            "test@example.com".to_string(),
            3600,
            None,
        );

        jwt_service.create_oauth_token(&claims).unwrap()
    }

    #[tokio::test]
    async fn test_jwt_auth_middleware_legacy_token() {
        let jwt_service = JwtService::new("test-secret".to_string(), Algorithm::HS256);
        let auth_config = Arc::new(AuthConfig::new(jwt_service));

        let app =
            Router::new()
                .route("/test", get(test_handler))
                .layer(middleware::from_fn_with_state(
                    auth_config.clone(),
                    jwt_auth_middleware,
                ));

        let token = create_legacy_token("test-secret", "user123", 3600);
        let request = Request::builder()
            .uri("/test")
            .header("Authorization", format!("Bearer {}", token))
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_jwt_auth_middleware_oauth_token() {
        let jwt_service = JwtService::new("test-secret".to_string(), Algorithm::HS256);
        let oauth_token = create_oauth_token(&jwt_service);
        let auth_config = Arc::new(AuthConfig::new(jwt_service));

        let app =
            Router::new()
                .route("/test", get(test_handler))
                .layer(middleware::from_fn_with_state(
                    auth_config.clone(),
                    jwt_auth_middleware,
                ));

        let request = Request::builder()
            .uri("/test")
            .header("Authorization", format!("Bearer {}", oauth_token))
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_jwt_auth_middleware_with_claims_oauth() {
        let jwt_service = JwtService::new("test-secret".to_string(), Algorithm::HS256);
        let oauth_token = create_oauth_token(&jwt_service);
        let auth_config = Arc::new(AuthConfig::new(jwt_service));

        let app = Router::new()
            .route("/test", get(test_claims_handler))
            .layer(middleware::from_fn_with_state(
                auth_config.clone(),
                jwt_auth_middleware_with_claims,
            ));

        let request = Request::builder()
            .uri("/test")
            .header("Authorization", format!("Bearer {}", oauth_token))
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body_str = String::from_utf8(body.to_vec()).unwrap();
        assert_eq!(body_str, "oauth_success");
    }

    #[tokio::test]
    async fn test_jwt_auth_middleware_with_claims_legacy() {
        let jwt_service = JwtService::new("test-secret".to_string(), Algorithm::HS256);
        let auth_config = Arc::new(AuthConfig::new(jwt_service));

        let app = Router::new()
            .route("/test", get(test_claims_handler))
            .layer(middleware::from_fn_with_state(
                auth_config.clone(),
                jwt_auth_middleware_with_claims,
            ));

        let token = create_legacy_token("test-secret", "user123", 3600);
        let request = Request::builder()
            .uri("/test")
            .header("Authorization", format!("Bearer {}", token))
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body_str = String::from_utf8(body.to_vec()).unwrap();
        assert_eq!(body_str, "legacy_success");
    }

    #[tokio::test]
    async fn test_jwt_auth_middleware_missing_header() {
        let jwt_service = JwtService::new("test-secret".to_string(), Algorithm::HS256);
        let auth_config = Arc::new(AuthConfig::new(jwt_service));

        let app =
            Router::new()
                .route("/test", get(test_handler))
                .layer(middleware::from_fn_with_state(
                    auth_config.clone(),
                    jwt_auth_middleware,
                ));

        let request = Request::builder().uri("/test").body(Body::empty()).unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_jwt_auth_middleware_invalid_format() {
        let jwt_service = JwtService::new("test-secret".to_string(), Algorithm::HS256);
        let auth_config = Arc::new(AuthConfig::new(jwt_service));

        let app =
            Router::new()
                .route("/test", get(test_handler))
                .layer(middleware::from_fn_with_state(
                    auth_config.clone(),
                    jwt_auth_middleware,
                ));

        let request = Request::builder()
            .uri("/test")
            .header("Authorization", "Invalid token")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_jwt_auth_middleware_invalid_token() {
        let jwt_service = JwtService::new("test-secret".to_string(), Algorithm::HS256);
        let auth_config = Arc::new(AuthConfig::new(jwt_service));

        let app =
            Router::new()
                .route("/test", get(test_handler))
                .layer(middleware::from_fn_with_state(
                    auth_config.clone(),
                    jwt_auth_middleware,
                ));

        let request = Request::builder()
            .uri("/test")
            .header("Authorization", "Bearer invalid.jwt.token")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_jwt_auth_middleware_expired_token() {
        let jwt_service = JwtService::new("test-secret".to_string(), Algorithm::HS256);
        let auth_config = Arc::new(AuthConfig::new(jwt_service));

        let app =
            Router::new()
                .route("/test", get(test_handler))
                .layer(middleware::from_fn_with_state(
                    auth_config.clone(),
                    jwt_auth_middleware,
                ));

        let token = create_legacy_token("test-secret", "user123", -3600);
        let request = Request::builder()
            .uri("/test")
            .header("Authorization", format!("Bearer {}", token))
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_authorization_header_removed() {
        let jwt_service = JwtService::new("test-secret".to_string(), Algorithm::HS256);
        let auth_config = Arc::new(AuthConfig::new(jwt_service));

        async fn header_check_handler(request: ExtractRequest) -> String {
            match request.headers().get(AUTHORIZATION) {
                Some(_) => "header_present".to_string(),
                None => "header_removed".to_string(),
            }
        }

        let app = Router::new()
            .route("/test", get(header_check_handler))
            .layer(middleware::from_fn_with_state(
                auth_config.clone(),
                jwt_auth_middleware,
            ));

        let token = create_legacy_token("test-secret", "user123", 3600);
        let request = Request::builder()
            .uri("/test")
            .header("Authorization", format!("Bearer {}", token))
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body_str = String::from_utf8(body.to_vec()).unwrap();
        assert_eq!(body_str, "header_removed");
    }
}
