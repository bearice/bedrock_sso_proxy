// Re-export API key structures and functions from database entities
pub use crate::database::entities::api_keys::{
    Model as ApiKey, hash_api_key, validate_api_key_format,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Request to create a new API key
#[derive(Debug, Serialize, Deserialize)]
pub struct CreateApiKeyRequest {
    pub name: String,
    pub expires_in_days: Option<u32>,
}

/// Response containing the new API key
#[derive(Debug, Serialize, Deserialize)]
pub struct CreateApiKeyResponse {
    pub id: i32,
    pub name: String,
    pub key: String, // Only returned once
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_api_key() {
        let key = "SSOK_test12345";
        let hash1 = hash_api_key(key);
        let hash2 = hash_api_key(key);

        // Same input should produce same hash
        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 64); // SHA-256 hex string

        // Different input should produce different hash
        let hash3 = hash_api_key("SSOK_different");
        assert_ne!(hash1, hash3);
    }

    #[test]
    fn test_validate_api_key_format() {
        // Valid keys (32 chars after prefix)
        assert!(validate_api_key_format("SSOK_abcdef1234567890abcdef1234567890", "SSOK_").is_ok());
        assert!(validate_api_key_format("SSOK_ABC123DEF456789AABC123DEF456789A", "SSOK_").is_ok());

        // Invalid prefix
        assert!(
            validate_api_key_format("INVALID_abcdef1234567890abcdef1234567890", "SSOK_").is_err()
        );

        // Too short
        assert!(validate_api_key_format("SSOK_short", "SSOK_").is_err());

        // Too long
        assert!(
            validate_api_key_format("SSOK_abcdef1234567890abcdef1234567890extra", "SSOK_").is_err()
        );

        // Invalid characters
        assert!(validate_api_key_format("SSOK_abcdef1234567890abcdef123456789!", "SSOK_").is_err());
    }

    #[test]
    fn test_api_key_validity() {
        let (mut api_key, _) = ApiKey::new(1, "test".to_string(), None);

        // Should be valid initially
        assert!(api_key.is_valid());

        // Should be invalid after revoking
        api_key.revoked_at = Some(Utc::now());
        assert!(!api_key.is_valid());

        // Create expired key
        let past_date = Utc::now() - chrono::Duration::hours(1);
        let (expired_key, _) = ApiKey::new(1, "expired".to_string(), Some(past_date));
        assert!(!expired_key.is_valid());

        // Create future expiry key
        let future_date = Utc::now() + chrono::Duration::hours(1);
        let (future_key, _) = ApiKey::new(1, "future".to_string(), Some(future_date));
        assert!(future_key.is_valid());
    }

}
