use crate::error::AppError;
use axum::{
    extract::{Request, State},
    http::header::AUTHORIZATION,
    middleware::Next,
    response::Response,
};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, jwk::Jwk};
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use std::sync::Arc;

pub fn parse_algorithm(alg: &str) -> Result<Algorithm, AppError> {
    Algorithm::from_str(alg)
        .map_err(|_| AppError::BadRequest(format!("Unsupported JWT algorithm: {}", alg)))
}

fn create_decoding_key(key_data: &str, algorithm: Algorithm) -> Result<DecodingKey, AppError> {
    // First, try to parse as JWK (JSON format)
    if key_data.trim_start().starts_with('{') {
        let jwk: Jwk = serde_json::from_str(key_data)
            .map_err(|_| AppError::Unauthorized("Invalid JWK format".to_string()))?;

        return DecodingKey::from_jwk(&jwk)
            .map_err(|_| AppError::Unauthorized("Invalid JWK key".to_string()));
    }

    // Otherwise, handle as PEM or raw secret based on algorithm
    match algorithm {
        Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512 => {
            Ok(DecodingKey::from_secret(key_data.as_ref()))
        }
        Algorithm::RS256
        | Algorithm::RS384
        | Algorithm::RS512
        | Algorithm::PS256
        | Algorithm::PS384
        | Algorithm::PS512 => DecodingKey::from_rsa_pem(key_data.as_bytes())
            .map_err(|_| AppError::Unauthorized("Invalid RSA key format".to_string())),
        Algorithm::ES256 | Algorithm::ES384 => DecodingKey::from_ec_pem(key_data.as_bytes())
            .map_err(|_| AppError::Unauthorized("Invalid EC key format".to_string())),
        Algorithm::EdDSA => DecodingKey::from_ed_pem(key_data.as_bytes())
            .map_err(|_| AppError::Unauthorized("Invalid EdDSA key format".to_string())),
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub exp: usize,
}

#[derive(Clone)]
pub struct AuthConfig {
    pub jwt_secret: String,
    pub jwt_algorithm: Algorithm,
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

    let mut validation = Validation::new(auth_config.jwt_algorithm);
    validation.validate_exp = true; // Ensure expiration validation is enabled
    validation.leeway = 0; // No leeway for expiration - expired tokens should be rejected immediately

    let decoding_key = create_decoding_key(&auth_config.jwt_secret, auth_config.jwt_algorithm)?;

    let _claims = decode::<Claims>(token, &decoding_key, &validation)?;

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
            jwt_algorithm: Algorithm::HS256,
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
            jwt_algorithm: Algorithm::HS256,
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
            jwt_algorithm: Algorithm::HS256,
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
            jwt_algorithm: Algorithm::HS256,
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
            jwt_algorithm: Algorithm::HS256,
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

    #[test]
    fn test_parse_algorithm_valid() {
        assert!(parse_algorithm("HS256").is_ok());
        assert!(parse_algorithm("HS384").is_ok());
        assert!(parse_algorithm("HS512").is_ok());
        assert!(parse_algorithm("RS256").is_ok());
        assert!(parse_algorithm("RS384").is_ok());
        assert!(parse_algorithm("RS512").is_ok());
        assert!(parse_algorithm("PS256").is_ok());
        assert!(parse_algorithm("PS384").is_ok());
        assert!(parse_algorithm("PS512").is_ok());
        assert!(parse_algorithm("ES256").is_ok());
        assert!(parse_algorithm("ES384").is_ok());
        assert!(parse_algorithm("EdDSA").is_ok());
    }

    #[test]
    fn test_parse_algorithm_case_sensitive() {
        // Algorithms are case sensitive per JWT spec
        assert!(parse_algorithm("hs256").is_err());
        assert!(parse_algorithm("rs256").is_err());
        assert!(parse_algorithm("eddsa").is_err());
    }

    #[test]
    fn test_parse_algorithm_invalid() {
        assert!(parse_algorithm("INVALID").is_err());
        assert!(parse_algorithm("HS999").is_err());
        assert!(parse_algorithm("").is_err());
    }

    #[test]
    fn test_create_decoding_key_hmac_secret() {
        let key = create_decoding_key("test-secret", Algorithm::HS256);
        assert!(key.is_ok());
    }

    #[test]
    fn test_create_decoding_key_jwk_format() {
        let jwk_json = r#"{
            "kty": "oct",
            "alg": "HS256",
            "k": "dGVzdC1zZWNyZXQ"
        }"#;
        let key = create_decoding_key(jwk_json, Algorithm::HS256);
        assert!(key.is_ok());
    }

    #[test]
    fn test_create_decoding_key_invalid_jwk() {
        let invalid_jwk = r#"{"invalid": "jwk"}"#;
        let key = create_decoding_key(invalid_jwk, Algorithm::HS256);
        assert!(key.is_err());
    }

    #[tokio::test]
    async fn test_jwt_auth_middleware_wrong_secret() {
        let auth_config = Arc::new(AuthConfig {
            jwt_secret: "correct-secret".to_string(),
            jwt_algorithm: Algorithm::HS256,
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
