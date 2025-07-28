use crate::error::AppError;
use crate::health::{HealthCheckResult, HealthChecker};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use jsonwebtoken::{
    Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode, jwk::Jwk,
};
use std::str::FromStr;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

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

fn create_encoding_key(key_data: &str, algorithm: Algorithm) -> Result<EncodingKey, AppError> {
    match algorithm {
        Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512 => {
            Ok(EncodingKey::from_secret(key_data.as_ref()))
        }
        Algorithm::RS256
        | Algorithm::RS384
        | Algorithm::RS512
        | Algorithm::PS256
        | Algorithm::PS384
        | Algorithm::PS512 => EncodingKey::from_rsa_pem(key_data.as_bytes())
            .map_err(|_| AppError::Unauthorized("Invalid RSA key format".to_string())),
        Algorithm::ES256 | Algorithm::ES384 => EncodingKey::from_ec_pem(key_data.as_bytes())
            .map_err(|_| AppError::Unauthorized("Invalid EC key format".to_string())),
        Algorithm::EdDSA => EncodingKey::from_ed_pem(key_data.as_bytes())
            .map_err(|_| AppError::Unauthorized("Invalid EdDSA key format".to_string())),
    }
}

// OAuth-issued JWT claims structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthClaims {
    pub sub: i32, // Database user ID
    pub iat: usize,
    pub exp: usize,
}

impl OAuthClaims {
    pub fn new(user_id: i32, expires_in_seconds: u64) -> Self {
        let now = Utc::now().timestamp() as usize;
        Self {
            sub: user_id,
            iat: now,
            exp: now + expires_in_seconds as usize,
        }
    }

    pub fn is_expired(&self) -> bool {
        let now = Utc::now().timestamp() as usize;
        self.exp <= now
    }

    pub fn expires_at(&self) -> DateTime<Utc> {
        DateTime::from_timestamp(self.exp as i64, 0).unwrap_or_else(Utc::now)
    }
}

/// JWT service trait for dependency injection and testing
#[async_trait]
pub trait JwtService: Send + Sync {
    /// Create OAuth token from claims
    fn create_oauth_token(&self, claims: &OAuthClaims) -> Result<String, AppError>;

    /// Validate OAuth token and return claims
    fn validate_oauth_token(&self, token: &str) -> Result<OAuthClaims, AppError>;

    /// Validate token (alias for validate_oauth_token)
    fn validate_token(&self, token: &str) -> Result<OAuthClaims, AppError>;

    /// Get algorithm used by this service
    fn algorithm(&self) -> Algorithm;

    /// Get secret used by this service
    fn secret(&self) -> &str;
}

#[derive(Clone)]
pub struct JwtServiceImpl {
    pub secret: String,
    pub algorithm: Algorithm,
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
}

impl JwtServiceImpl {
    pub fn new(secret: String, algorithm: Algorithm) -> Result<Self, AppError> {
        let encoding_key = create_encoding_key(&secret, algorithm)?;
        let decoding_key = create_decoding_key(&secret, algorithm)?;

        Ok(Self {
            secret,
            algorithm,
            encoding_key,
            decoding_key,
        })
    }

    /// Create a health checker for this JWT service
    pub fn health_checker(&self) -> Arc<JwtHealthChecker> {
        Arc::new(JwtHealthChecker {
            service: self.clone(),
        })
    }
}

#[async_trait]
impl JwtService for JwtServiceImpl {
    fn create_oauth_token(&self, claims: &OAuthClaims) -> Result<String, AppError> {
        let header = Header::new(self.algorithm);
        encode(&header, claims, &self.encoding_key)
            .map_err(|e| AppError::Internal(format!("Failed to create token: {}", e)))
    }

    fn validate_oauth_token(&self, token: &str) -> Result<OAuthClaims, AppError> {
        let mut validation = Validation::new(self.algorithm);
        validation.validate_exp = true;
        validation.leeway = 0;

        let token_data = decode::<OAuthClaims>(token, &self.decoding_key, &validation)
            .map_err(|_| AppError::Unauthorized("Invalid or expired token".to_string()))?;

        Ok(token_data.claims)
    }

    fn validate_token(&self, token: &str) -> Result<OAuthClaims, AppError> {
        self.validate_oauth_token(token)
    }

    fn algorithm(&self) -> Algorithm {
        self.algorithm
    }

    fn secret(&self) -> &str {
        &self.secret
    }
}

/// Health checker implementation for JWT service
pub struct JwtHealthChecker {
    service: JwtServiceImpl,
}

#[async_trait::async_trait]
impl HealthChecker for JwtHealthChecker {
    fn name(&self) -> &str {
        "jwt"
    }

    async fn check(&self) -> HealthCheckResult {
        // Test the JWT service by creating and validating a test token
        let test_claims = OAuthClaims::new(
            1,  // user_id
            60, // 1 minute expiry
        );

        match self.service.create_oauth_token(&test_claims) {
            Ok(token) => {
                // Try to validate the token we just created
                match self.service.validate_oauth_token(&token) {
                    Ok(validated_claims) => {
                        if validated_claims.sub == test_claims.sub {
                            HealthCheckResult::healthy_with_details(serde_json::json!({
                                "algorithm": format!("{:?}", self.service.algorithm),
                                "token_creation": "success",
                                "token_validation": "success"
                            }))
                        } else {
                            HealthCheckResult::unhealthy_with_details(
                                "Token validation returned incorrect claims".to_string(),
                                serde_json::json!({
                                    "algorithm": format!("{:?}", self.service.algorithm),
                                    "token_creation": "success",
                                    "token_validation": "failed",
                                    "error": "claims mismatch"
                                }),
                            )
                        }
                    }
                    Err(err) => HealthCheckResult::unhealthy_with_details(
                        "Failed to validate test JWT token".to_string(),
                        serde_json::json!({
                            "algorithm": format!("{:?}", self.service.algorithm),
                            "token_creation": "success",
                            "token_validation": "failed",
                            "error": err.to_string()
                        }),
                    ),
                }
            }
            Err(err) => HealthCheckResult::unhealthy_with_details(
                "Failed to create test JWT token".to_string(),
                serde_json::json!({
                    "algorithm": format!("{:?}", self.service.algorithm),
                    "token_creation": "failed",
                    "error": err.to_string()
                }),
            ),
        }
    }

    fn info(&self) -> Option<serde_json::Value> {
        Some(serde_json::json!({
            "service": "JWT Token Service",
            "algorithm": format!("{:?}", self.service.algorithm),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn test_oauth_claims_creation() {
        let claims = OAuthClaims::new(1, 3600);

        assert_eq!(claims.sub, 1);
        assert!(!claims.is_expired());
    }

    #[test]
    fn test_jwt_service_oauth_token() {
        let service = JwtServiceImpl::new("test-secret".to_string(), Algorithm::HS256).unwrap();

        let claims = OAuthClaims::new(1, 3600);

        let token = service.create_oauth_token(&claims).unwrap();
        assert!(!token.is_empty());

        let validated = service.validate_oauth_token(&token).unwrap();
        assert_eq!(validated.sub, 1);
    }

    #[test]
    fn test_oauth_claims_expiration() {
        let mut claims = OAuthClaims::new(1, 3600);

        assert!(!claims.is_expired());

        // Manually set expiration to past
        claims.exp = (Utc::now().timestamp() - 3600) as usize;
        assert!(claims.is_expired());
    }
}
