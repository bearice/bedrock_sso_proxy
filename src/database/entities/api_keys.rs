use crate::cache::typed::typed_cache;
use chrono::{DateTime, Utc};
use rand::{Rng, distr::Alphanumeric};
use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq, Serialize, Deserialize)]
#[sea_orm(table_name = "api_keys")]
#[typed_cache(ttl = 300)] // 5 minutes
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    #[sea_orm(unique)]
    pub key_hash: String,
    pub user_id: i32,
    pub name: String,
    pub created_at: DateTime<Utc>,
    pub last_used: Option<DateTime<Utc>>,
    pub expires_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

/// API key info without the actual key or hash
#[derive(Debug, Serialize, Deserialize)]
pub struct ApiKeyInfo {
    pub id: i32,
    pub name: String,
    pub created_at: DateTime<Utc>,
    pub last_used: Option<DateTime<Utc>>,
    pub expires_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
}

impl From<Model> for ApiKeyInfo {
    fn from(key: Model) -> Self {
        Self {
            id: key.id,
            name: key.name,
            created_at: key.created_at,
            last_used: key.last_used,
            expires_at: key.expires_at,
            revoked_at: key.revoked_at,
        }
    }
}

impl Model {
    /// Create a new API key
    pub fn new(user_id: i32, name: String, expires_at: Option<DateTime<Utc>>) -> (Self, String) {
        let raw_key = generate_api_key("SSOK_", 32);
        let key_hash = hash_api_key(&raw_key);
        eprintln!("key_hash={}",key_hash);
        let api_key = Self {
            id: 0, // Will be set by database
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

    /// Check if API key is valid (not expired and not revoked)
    pub fn is_valid(&self) -> bool {
        // Check if revoked
        if self.revoked_at.is_some() {
            return false;
        }

        // Check if expired
        if let Some(expires_at) = self.expires_at {
            if expires_at < Utc::now() {
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

/// Generate a random API key with the given prefix and length
fn generate_api_key(prefix: &str, length: usize) -> String {
    let random_part: String = rand::rng()
        .sample_iter(&Alphanumeric)
        .take(length)
        .map(char::from)
        .collect();

    format!("{}{}", prefix, random_part)
}

/// Hash an API key using SHA-256
pub fn hash_api_key(api_key: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(api_key.as_bytes());
    format!("{:x}", hasher.finalize())
}

/// Validate API key format
pub fn validate_api_key_format(
    api_key: &str,
    expected_prefix: &str,
) -> Result<(), crate::error::AppError> {
    if !api_key.starts_with(expected_prefix) {
        return Err(crate::error::AppError::Unauthorized(
            "Invalid API key format".to_string(),
        ));
    }

    // Check minimum length (prefix + at least 16 characters)
    if api_key.len() < expected_prefix.len() + 16 {
        return Err(crate::error::AppError::Unauthorized(
            "Invalid API key format".to_string(),
        ));
    }

    // Check that it contains only alphanumeric characters after prefix
    let key_part = &api_key[expected_prefix.len()..];
    if !key_part.chars().all(|c| c.is_alphanumeric()) {
        return Err(crate::error::AppError::Unauthorized(
            "Invalid API key format".to_string(),
        ));
    }

    Ok(())
}
