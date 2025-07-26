use crate::error::AppError;
use chrono::{DateTime, Utc};
use rand::{distributions::Alphanumeric, Rng};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// API Key data structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKey {
    pub id: Option<i32>,
    pub key_hash: String,
    pub user_id: i32,
    pub name: String,
    pub created_at: DateTime<Utc>,
    pub last_used: Option<DateTime<Utc>>,
    pub expires_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
}

impl ApiKey {
    /// Create a new API key
    pub fn new(user_id: i32, name: String, expires_at: Option<DateTime<Utc>>) -> (Self, String) {
        let raw_key = generate_api_key("SSOK_", 32);
        let key_hash = hash_api_key(&raw_key);
        
        let api_key = Self {
            id: None,
            key_hash,
            user_id,
            name,
            created_at: Utc::now(),
            last_used: None,
            expires_at,
            revoked_at: None,
        };
        
        (api_key, raw_key)
    }

    /// Check if the API key is valid (not expired and not revoked)
    pub fn is_valid(&self) -> bool {
        // Check if revoked
        if self.revoked_at.is_some() {
            return false;
        }

        // Check if expired
        if let Some(expires_at) = self.expires_at {
            if expires_at <= Utc::now() {
                return false;
            }
        }

        true
    }

    /// Mark as revoked
    pub fn revoke(&mut self) {
        self.revoked_at = Some(Utc::now());
    }

    /// Update last used timestamp
    pub fn update_last_used(&mut self) {
        self.last_used = Some(Utc::now());
    }
}

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

/// API key info without the actual key
#[derive(Debug, Serialize, Deserialize)]
pub struct ApiKeyInfo {
    pub id: i32,
    pub name: String,
    pub created_at: DateTime<Utc>,
    pub last_used: Option<DateTime<Utc>>,
    pub expires_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
}

impl From<ApiKey> for ApiKeyInfo {
    fn from(key: ApiKey) -> Self {
        Self {
            id: key.id.unwrap_or(0),
            name: key.name,
            created_at: key.created_at,
            last_used: key.last_used,
            expires_at: key.expires_at,
            revoked_at: key.revoked_at,
        }
    }
}

/// Generate a new API key with the given prefix and length
pub fn generate_api_key(prefix: &str, length: usize) -> String {
    let random_part: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(length)
        .map(char::from)
        .collect();
    
    format!("{}{}", prefix, random_part)
}

/// Hash an API key for storage
pub fn hash_api_key(key: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(key.as_bytes());
    hex::encode(hasher.finalize())
}

/// Extract user ID from API key (validates format)
pub fn validate_api_key_format(key: &str, prefix: &str) -> Result<(), AppError> {
    if !key.starts_with(prefix) {
        return Err(AppError::Unauthorized(
            "Invalid API key format".to_string()
        ));
    }

    let key_part = &key[prefix.len()..];
    if key_part.len() < 16 || key_part.len() > 64 {
        return Err(AppError::Unauthorized(
            "Invalid API key length".to_string()
        ));
    }

    // Check if key contains only alphanumeric characters
    if !key_part.chars().all(|c| c.is_alphanumeric()) {
        return Err(AppError::Unauthorized(
            "Invalid API key characters".to_string()
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_api_key() {
        let key = generate_api_key("SSOK_", 32);
        assert!(key.starts_with("SSOK_"));
        assert_eq!(key.len(), 37); // "SSOK_" + 32 chars
        
        // Generate another key to ensure uniqueness
        let key2 = generate_api_key("SSOK_", 32);
        assert_ne!(key, key2);
    }

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
        // Valid keys
        assert!(validate_api_key_format("SSOK_abcdef1234567890", "SSOK_").is_ok());
        assert!(validate_api_key_format("SSOK_ABC123DEF456789A", "SSOK_").is_ok());  // Fixed to be 16 chars
        
        // Invalid prefix
        assert!(validate_api_key_format("INVALID_abcdef1234567890", "SSOK_").is_err());
        
        // Too short
        assert!(validate_api_key_format("SSOK_short", "SSOK_").is_err());
        
        // Invalid characters
        assert!(validate_api_key_format("SSOK_invalid-chars!", "SSOK_").is_err());
    }

    #[test]
    fn test_api_key_validity() {
        let (mut api_key, _) = ApiKey::new(1, "test".to_string(), None);
        
        // Should be valid initially
        assert!(api_key.is_valid());
        
        // Should be invalid after revoking
        api_key.revoke();
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

    #[test]
    fn test_api_key_info_conversion() {
        let (api_key, _) = ApiKey::new(1, "test".to_string(), None);
        let info: ApiKeyInfo = api_key.into();
        
        assert_eq!(info.name, "test");
        assert!(info.revoked_at.is_none());
    }
}