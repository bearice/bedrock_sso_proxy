use crate::error::AppError;
use axum::{
    extract::{Request, State},
    http::header::AUTHORIZATION,
    middleware::Next,
    response::Response,
};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub exp: usize,
}

#[derive(Clone)]
pub struct AuthConfig {
    pub jwt_secret: String,
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

    let mut validation = Validation::new(Algorithm::HS256);
    validation.validate_exp = true; // Ensure expiration validation is enabled
    validation.leeway = 0; // No leeway for expiration - expired tokens should be rejected immediately

    let _claims = decode::<Claims>(
        token,
        &DecodingKey::from_secret(auth_config.jwt_secret.as_ref()),
        &validation,
    )?;

    request.headers_mut().remove(AUTHORIZATION);

    Ok(next.run(request).await)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        Router,
        body::Body,
        http::{Request, StatusCode},
        middleware,
        routing::get,
    };
    use jsonwebtoken::{EncodingKey, Header, encode};
    use std::time::{SystemTime, UNIX_EPOCH};
    use tower::ServiceExt;

    async fn test_handler() -> &'static str {
        "success"
    }

    fn create_test_token(secret: &str, sub: &str, exp_offset: i64) -> String {
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

    #[tokio::test]
    async fn test_jwt_auth_middleware_valid_token() {
        let auth_config = Arc::new(AuthConfig {
            jwt_secret: "test-secret".to_string(),
        });

        let app =
            Router::new()
                .route("/test", get(test_handler))
                .layer(middleware::from_fn_with_state(
                    auth_config.clone(),
                    jwt_auth_middleware,
                ));

        let token = create_test_token("test-secret", "user123", 3600);
        let request = Request::builder()
            .uri("/test")
            .header("Authorization", format!("Bearer {}", token))
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_jwt_auth_middleware_missing_header() {
        let auth_config = Arc::new(AuthConfig {
            jwt_secret: "test-secret".to_string(),
        });

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
        let auth_config = Arc::new(AuthConfig {
            jwt_secret: "test-secret".to_string(),
        });

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
        let auth_config = Arc::new(AuthConfig {
            jwt_secret: "test-secret".to_string(),
        });

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
        let auth_config = Arc::new(AuthConfig {
            jwt_secret: "test-secret".to_string(),
        });

        let app =
            Router::new()
                .route("/test", get(test_handler))
                .layer(middleware::from_fn_with_state(
                    auth_config.clone(),
                    jwt_auth_middleware,
                ));

        let token = create_test_token("test-secret", "user123", -3600);
        let request = Request::builder()
            .uri("/test")
            .header("Authorization", format!("Bearer {}", token))
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_jwt_auth_middleware_wrong_secret() {
        let auth_config = Arc::new(AuthConfig {
            jwt_secret: "correct-secret".to_string(),
        });

        let app =
            Router::new()
                .route("/test", get(test_handler))
                .layer(middleware::from_fn_with_state(
                    auth_config.clone(),
                    jwt_auth_middleware,
                ));

        let token = create_test_token("wrong-secret", "user123", 3600);
        let request = Request::builder()
            .uri("/test")
            .header("Authorization", format!("Bearer {}", token))
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}
