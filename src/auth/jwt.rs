use crate::error::AppError;
use crate::health::{HealthCheckResult, HealthChecker};
use chrono::{DateTime, Utc};
use jsonwebtoken::{
    Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode, jwk::Jwk,
};
use std::str::FromStr;

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

// Legacy Claims structure for backward compatibility
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub exp: usize,
}

// Enhanced Claims structure for OAuth-issued tokens
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthClaims {
    pub sub: String,
    pub iat: usize,
    pub exp: usize,
    pub provider: String,
    pub email: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token_id: Option<String>,
}

impl OAuthClaims {
    pub fn new(
        user_id: String,
        provider: String,
        email: String,
        expires_in_seconds: u64,
        refresh_token_id: Option<String>,
    ) -> Self {
        let now = Utc::now().timestamp() as usize;
        Self {
            sub: user_id,
            iat: now,
            exp: now + expires_in_seconds as usize,
            provider,
            email,
            refresh_token_id,
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

#[derive(Clone)]
pub struct JwtService {
    pub secret: String,
    pub algorithm: Algorithm,
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
}

impl JwtService {
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

    pub fn create_oauth_token(&self, claims: &OAuthClaims) -> Result<String, AppError> {
        let header = Header::new(self.algorithm);
        encode(&header, claims, &self.encoding_key)
            .map_err(|e| AppError::Internal(format!("Failed to create token: {}", e)))
    }

    pub fn validate_oauth_token(&self, token: &str) -> Result<OAuthClaims, AppError> {
        let mut validation = Validation::new(self.algorithm);
        validation.validate_exp = true;
        validation.leeway = 0;

        let token_data = decode::<OAuthClaims>(token, &self.decoding_key, &validation)
            .map_err(|_| AppError::Unauthorized("Invalid or expired token".to_string()))?;

        Ok(token_data.claims)
    }

    pub fn validate_legacy_token(&self, token: &str) -> Result<Claims, AppError> {
        let mut validation = Validation::new(self.algorithm);
        validation.validate_exp = true;
        validation.leeway = 0;

        let token_data = decode::<Claims>(token, &self.decoding_key, &validation)
            .map_err(|_| AppError::Unauthorized("Invalid or expired token".to_string()))?;

        Ok(token_data.claims)
    }

    // Try to decode as OAuth token first, then fall back to legacy
    pub fn validate_token(&self, token: &str) -> Result<ValidatedClaims, AppError> {
        // First try OAuth token format
        if let Ok(oauth_claims) = self.validate_oauth_token(token) {
            return Ok(ValidatedClaims::OAuth(oauth_claims));
        }

        // Fall back to legacy token format
        match self.validate_legacy_token(token) {
            Ok(legacy_claims) => Ok(ValidatedClaims::Legacy(legacy_claims)),
            Err(_) => Err(AppError::Unauthorized(
                "Invalid or expired token".to_string(),
            )),
        }
    }

    /// Create a health checker for this JWT service
    pub fn health_checker(&self) -> JwtHealthChecker {
        JwtHealthChecker {
            service: self.clone(),
        }
    }
}

/// Health checker implementation for JWT service
pub struct JwtHealthChecker {
    service: JwtService,
}

#[async_trait::async_trait]
impl HealthChecker for JwtHealthChecker {
    fn name(&self) -> &str {
        "jwt"
    }

    async fn check(&self) -> HealthCheckResult {
        // Test the JWT service by creating and validating a test token
        let test_claims = OAuthClaims::new(
            "health_check_user".to_string(),
            "health_check".to_string(),
            "health@example.com".to_string(),
            60, // 1 minute expiry
            None,
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
            "supported_claims": ["OAuth", "Legacy"]
        }))
    }
}

#[derive(Debug, Clone)]
pub enum ValidatedClaims {
    OAuth(OAuthClaims),
    Legacy(Claims),
}

impl ValidatedClaims {
    pub fn subject(&self) -> &str {
        match self {
            ValidatedClaims::OAuth(claims) => &claims.sub,
            ValidatedClaims::Legacy(claims) => &claims.sub,
        }
    }

    pub fn provider(&self) -> Option<&str> {
        match self {
            ValidatedClaims::OAuth(claims) => Some(&claims.provider),
            ValidatedClaims::Legacy(_) => None,
        }
    }

    pub fn email(&self) -> Option<&str> {
        match self {
            ValidatedClaims::OAuth(claims) => Some(&claims.email),
            ValidatedClaims::Legacy(_) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

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
        let claims = OAuthClaims::new(
            "google:123".to_string(),
            "google".to_string(),
            "test@example.com".to_string(),
            3600,
            Some("refresh_123".to_string()),
        );

        assert_eq!(claims.sub, "google:123");
        assert_eq!(claims.provider, "google");
        assert_eq!(claims.email, "test@example.com");
        assert_eq!(claims.refresh_token_id, Some("refresh_123".to_string()));
        assert!(!claims.is_expired());
    }

    #[test]
    fn test_jwt_service_oauth_token() {
        let service = JwtService::new("test-secret".to_string(), Algorithm::HS256).unwrap();

        let claims = OAuthClaims::new(
            "google:123".to_string(),
            "google".to_string(),
            "test@example.com".to_string(),
            3600,
            None,
        );

        let token = service.create_oauth_token(&claims).unwrap();
        assert!(!token.is_empty());

        let validated = service.validate_oauth_token(&token).unwrap();
        assert_eq!(validated.sub, "google:123");
        assert_eq!(validated.provider, "google");
        assert_eq!(validated.email, "test@example.com");
    }

    #[test]
    fn test_jwt_service_legacy_token() {
        let service = JwtService::new("test-secret".to_string(), Algorithm::HS256).unwrap();
        let token = create_test_token("test-secret", "user123", 3600);

        let validated = service.validate_legacy_token(&token).unwrap();
        assert_eq!(validated.sub, "user123");
    }

    #[test]
    fn test_jwt_service_mixed_validation() {
        let service = JwtService::new("test-secret".to_string(), Algorithm::HS256).unwrap();

        // Test OAuth token
        let oauth_claims = OAuthClaims::new(
            "google:123".to_string(),
            "google".to_string(),
            "test@example.com".to_string(),
            3600,
            None,
        );
        let oauth_token = service.create_oauth_token(&oauth_claims).unwrap();

        match service.validate_token(&oauth_token).unwrap() {
            ValidatedClaims::OAuth(claims) => {
                assert_eq!(claims.sub, "google:123");
                assert_eq!(claims.provider, "google");
            }
            ValidatedClaims::Legacy(_) => panic!("Expected OAuth claims"),
        }

        // Test legacy token
        let legacy_token = create_test_token("test-secret", "user123", 3600);

        match service.validate_token(&legacy_token).unwrap() {
            ValidatedClaims::Legacy(claims) => {
                assert_eq!(claims.sub, "user123");
            }
            ValidatedClaims::OAuth(_) => panic!("Expected legacy claims"),
        }
    }

    #[test]
    fn test_validated_claims_accessors() {
        let oauth_claims = OAuthClaims::new(
            "google:123".to_string(),
            "google".to_string(),
            "test@example.com".to_string(),
            3600,
            None,
        );

        let oauth_validated = ValidatedClaims::OAuth(oauth_claims);
        assert_eq!(oauth_validated.subject(), "google:123");
        assert_eq!(oauth_validated.provider(), Some("google"));
        assert_eq!(oauth_validated.email(), Some("test@example.com"));

        let legacy_claims = Claims {
            sub: "user123".to_string(),
            exp: 1234567890,
        };

        let legacy_validated = ValidatedClaims::Legacy(legacy_claims);
        assert_eq!(legacy_validated.subject(), "user123");
        assert_eq!(legacy_validated.provider(), None);
        assert_eq!(legacy_validated.email(), None);
    }

    #[test]
    fn test_oauth_claims_expiration() {
        let mut claims = OAuthClaims::new(
            "google:123".to_string(),
            "google".to_string(),
            "test@example.com".to_string(),
            3600,
            None,
        );

        assert!(!claims.is_expired());

        // Manually set expiration to past
        claims.exp = (Utc::now().timestamp() - 3600) as usize;
        assert!(claims.is_expired());
    }
}
