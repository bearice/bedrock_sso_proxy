use crate::cache::object::typed_cache;

use async_graphql::{ComplexObject, Context, Result as GraphQLResult, SimpleObject};
use chrono::{DateTime, Utc};
use rand::{distr::Alphanumeric, Rng};
use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use utoipa::ToSchema;

/// API key prefix for all generated keys
pub const API_KEY_PREFIX: &str = "SSOK_";

/// API key length after prefix (32 alphanumeric characters)
pub const API_KEY_LENGTH: usize = 32;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq, Serialize, Deserialize, ToSchema, SimpleObject)]
#[graphql(complex)]
#[graphql(name = "ApiKey")]
#[sea_orm(table_name = "api_keys")]
#[typed_cache(ttl = 300)] // 5 minutes
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    #[sea_orm(unique)]
    pub key_hash: String,
    pub user_id: i32,
    pub name: String,
    pub hint: String,
    pub created_at: DateTime<Utc>,
    pub last_used: Option<DateTime<Utc>>,
    pub expires_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

impl Model {
    /// Create a new API key
    pub fn new(user_id: i32, name: String, expires_at: Option<DateTime<Utc>>) -> (Self, String) {
        let raw_key = generate_api_key(API_KEY_PREFIX, API_KEY_LENGTH);
        let key_hash = hash_api_key(&raw_key);
        let hint = create_key_hint(&raw_key);
        let api_key = Self {
            id: 0, // Will be set by database
            key_hash,
            user_id,
            name,
            hint,
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
}

/// Generate a random API key with the given prefix and length
fn generate_api_key(prefix: &str, length: usize) -> String {
    let random_part: String = rand::rng()
        .sample_iter(&Alphanumeric)
        .take(length)
        .map(char::from)
        .collect();

    format!("{prefix}{random_part}")
}

/// Hash an API key using SHA-256
pub fn hash_api_key(api_key: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(api_key.as_bytes());
    format!("{:x}", hasher.finalize())
}

/// Create a hint for an API key showing first 4 and last 4 characters (excluding prefix)
pub fn create_key_hint(api_key: &str) -> String {
    if api_key.starts_with(API_KEY_PREFIX) && api_key.len() == API_KEY_PREFIX.len() + API_KEY_LENGTH
    {
        let key_part = &api_key[API_KEY_PREFIX.len()..];
        format!(
            "{}{}****{}",
            API_KEY_PREFIX,
            &key_part[..4],                  // First 4 chars after prefix
            &key_part[API_KEY_LENGTH - 4..]  // Last 4 chars
        )
    } else {
        // Fallback for invalid format
        format!("{API_KEY_PREFIX}****")
    }
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

    // Check exact length (prefix + exactly API_KEY_LENGTH characters)
    let expected_total_length = expected_prefix.len() + API_KEY_LENGTH;
    if api_key.len() != expected_total_length {
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

#[ComplexObject]
impl Model {
    /// Get key hash - only accessible to the key owner or admins
    async fn secure_key_hash(&self, ctx: &Context<'_>) -> GraphQLResult<Option<String>> {
        if let Ok(user_context) = ctx.data::<crate::graphql::UserContext>() {
            if user_context.user_id == self.user_id || user_context.is_admin {
                return Ok(Some(self.key_hash.clone()));
            }
        }
        Ok(None)
    }

    /// Check if this key is valid (not expired, not revoked)
    async fn is_key_valid(&self) -> bool {
        self.is_valid()
    }

    /// Get user who owns this key - only accessible to the key owner or admins
    async fn owner(&self, ctx: &Context<'_>) -> GraphQLResult<Option<crate::database::entities::UserRecord>> {
        if let Ok(user_context) = ctx.data::<crate::graphql::UserContext>() {
            if user_context.user_id == self.user_id || user_context.is_admin {
                // In a real implementation, you'd fetch the user from database
                // For now, we'll return None to avoid circular dependencies
                return Ok(None);
            }
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_key_hint() {
        // Test with valid key (SSOK_ + 32 chars)
        let key = "SSOK_abcd1234efgh5678ijkl9012mnop3456";
        let hint = create_key_hint(key);
        assert_eq!(hint, "SSOK_abcd****3456");

        // Test with another valid key
        let key = "SSOK_1234567890abcdefghijklmnop123456";
        let hint = create_key_hint(key);
        assert_eq!(hint, "SSOK_1234****3456");

        // Test with invalid length (too short)
        let key = "SSOK_12345678";
        let hint = create_key_hint(key);
        assert_eq!(hint, "SSOK_****");

        // Test with invalid prefix
        let key = "INVALID_abcd1234efgh5678ijkl9012mnop3456";
        let hint = create_key_hint(key);
        assert_eq!(hint, "SSOK_****");

        // Test with wrong total length
        let key = "SSOK_abcd1234efgh5678ijkl9012mnop3456extra";
        let hint = create_key_hint(key);
        assert_eq!(hint, "SSOK_****");
    }
}
