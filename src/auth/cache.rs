use chrono::{DateTime, Utc};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tokio::time::{self, Duration};
use uuid::Uuid;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CachedValidation {
    pub claims: crate::auth::jwt::OAuthClaims,
    pub validated_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StateData {
    pub provider: String,
    pub redirect_uri: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RefreshTokenData {
    pub user_id: String,
    pub provider: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub rotation_count: u32,
}

#[derive(Clone)]
pub struct OAuthCache {
    validation_cache: Arc<DashMap<String, CachedValidation>>,
    state_cache: Arc<DashMap<String, StateData>>,
    refresh_token_cache: Arc<DashMap<String, RefreshTokenData>>,
    #[allow(dead_code)]
    validation_ttl: Duration,
    state_ttl: Duration,
    refresh_token_ttl: Duration,
    max_entries: usize,
}

impl OAuthCache {
    pub fn new(
        validation_ttl_seconds: u64,
        state_ttl_seconds: u64,
        refresh_token_ttl_seconds: u64,
        max_entries: usize,
    ) -> Self {
        let cache = Self {
            validation_cache: Arc::new(DashMap::new()),
            state_cache: Arc::new(DashMap::new()),
            refresh_token_cache: Arc::new(DashMap::new()),
            validation_ttl: Duration::from_secs(validation_ttl_seconds),
            state_ttl: Duration::from_secs(state_ttl_seconds),
            refresh_token_ttl: Duration::from_secs(refresh_token_ttl_seconds),
            max_entries,
        };

        // Only start cleanup task if we're in a tokio runtime
        if tokio::runtime::Handle::try_current().is_ok() {
            cache.start_cleanup_task();
        }
        cache
    }

    // Validation cache methods with internal hashing
    pub fn get_validation(&self, token: &str) -> Option<CachedValidation> {
        let token_hash = hash_token(token);
        self.validation_cache.get(&token_hash).and_then(|entry| {
            if !entry.claims.is_expired() {
                Some(entry.clone())
            } else {
                // Entry expired, remove it
                drop(entry);
                self.validation_cache.remove(&token_hash);
                None
            }
        })
    }

    pub fn set_validation(&self, token: &str, claims: crate::auth::jwt::OAuthClaims) {
        if self.validation_cache.len() >= self.max_entries {
            self.cleanup_expired_validations();
        }
        
        let token_hash = hash_token(token);
        let validation = CachedValidation {
            claims,
            validated_at: Utc::now(),
        };
        
        self.validation_cache.insert(token_hash, validation);
    }

    pub fn remove_validation(&self, token: &str) {
        let token_hash = hash_token(token);
        self.validation_cache.remove(&token_hash);
    }

    // State cache methods
    pub fn create_state(&self, provider: String, redirect_uri: String) -> String {
        let state = Uuid::new_v4().to_string();
        let now = Utc::now();
        let state_data = StateData {
            provider,
            redirect_uri,
            created_at: now,
            expires_at: now + chrono::Duration::seconds(self.state_ttl.as_secs() as i64),
        };
        self.state_cache.insert(state.clone(), state_data);
        state
    }

    pub fn get_state_data(&self, state: &str) -> Option<StateData> {
        self.state_cache.get(state).and_then(|state_data| {
            if state_data.expires_at > Utc::now() {
                Some(state_data.clone())
            } else {
                None
            }
        })
    }

    pub fn get_and_remove_state(&self, state: &str) -> Option<StateData> {
        self.state_cache.remove(state).and_then(|(_, state_data)| {
            if state_data.expires_at > Utc::now() {
                Some(state_data)
            } else {
                None
            }
        })
    }

    // Refresh token methods
    pub fn create_refresh_token(&self, user_id: String, provider: String) -> String {
        let token = Uuid::new_v4().to_string();
        let token_hash = hash_token(&token);
        let now = Utc::now();
        let token_data = RefreshTokenData {
            user_id,
            provider,
            created_at: now,
            expires_at: now + chrono::Duration::seconds(self.refresh_token_ttl.as_secs() as i64),
            rotation_count: 0,
        };
        self.refresh_token_cache.insert(token_hash, token_data);
        token
    }

    pub fn get_refresh_token_data(&self, token: &str) -> Option<RefreshTokenData> {
        let token_hash = hash_token(token);
        self.refresh_token_cache.get(&token_hash).and_then(|entry| {
            if entry.expires_at > Utc::now() {
                Some(entry.clone())
            } else {
                // Entry expired, remove it
                drop(entry);
                self.refresh_token_cache.remove(&token_hash);
                None
            }
        })
    }

    pub fn rotate_refresh_token(&self, old_token: &str, user_id: String, provider: String) -> Option<String> {
        let old_token_hash = hash_token(old_token);
        
        // Remove old token and get its data
        if let Some((_, old_data)) = self.refresh_token_cache.remove(&old_token_hash) {
            if old_data.expires_at > Utc::now() {
                // Create new token with incremented rotation count
                let new_token = Uuid::new_v4().to_string();
                let new_token_hash = hash_token(&new_token);
                let now = Utc::now();
                let new_token_data = RefreshTokenData {
                    user_id,
                    provider,
                    created_at: now,
                    expires_at: now + chrono::Duration::seconds(self.refresh_token_ttl.as_secs() as i64),
                    rotation_count: old_data.rotation_count + 1,
                };
                self.refresh_token_cache.insert(new_token_hash, new_token_data);
                Some(new_token)
            } else {
                None
            }
        } else {
            None
        }
    }

    pub fn revoke_refresh_token(&self, token: &str) {
        let token_hash = hash_token(token);
        self.refresh_token_cache.remove(&token_hash);
    }

    // Cleanup methods
    fn cleanup_expired_validations(&self) {
        self.validation_cache.retain(|_, validation| !validation.claims.is_expired());
    }

    #[allow(dead_code)]
    fn cleanup_expired_states(&self) {
        let now = Utc::now();
        self.state_cache.retain(|_, state| state.expires_at > now);
    }

    #[allow(dead_code)]
    fn cleanup_expired_refresh_tokens(&self) {
        let now = Utc::now();
        self.refresh_token_cache.retain(|_, token_data| token_data.expires_at > now);
    }

    fn start_cleanup_task(&self) {
        let validation_cache = self.validation_cache.clone();
        let state_cache = self.state_cache.clone();
        let refresh_token_cache = self.refresh_token_cache.clone();
        
        tokio::spawn(async move {
            let mut interval = time::interval(Duration::from_secs(3600)); // Clean up every hour
            loop {
                interval.tick().await;
                
                let now = Utc::now();
                validation_cache.retain(|_, validation| !validation.claims.is_expired());
                state_cache.retain(|_, state| state.expires_at > now);
                refresh_token_cache.retain(|_, token_data| token_data.expires_at > now);
            }
        });
    }

    // Statistics methods for monitoring
    pub fn stats(&self) -> CacheStats {
        CacheStats {
            validation_entries: self.validation_cache.len(),
            state_entries: self.state_cache.len(),
            refresh_token_entries: self.refresh_token_cache.len(),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct CacheStats {
    pub validation_entries: usize,
    pub state_entries: usize,
    pub refresh_token_entries: usize,
}

fn hash_token(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    format!("{:x}", hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_validation_cache() {
        let cache = OAuthCache::new(3600, 600, 86400, 1000);
        let token = "test_token";
        
        let claims = crate::auth::jwt::OAuthClaims::new(
            "google:123".to_string(),
            "google".to_string(),
            "test@example.com".to_string(),
            vec!["email".to_string()],
            3600, // 1 hour
            None,
        );

        // Test set and get
        cache.set_validation(token, claims.clone());
        let retrieved = cache.get_validation(token);
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().claims.sub, "google:123");

        // Test remove
        cache.remove_validation(token);
        assert!(cache.get_validation(token).is_none());
    }

    #[tokio::test]
    async fn test_state_cache() {
        let cache = OAuthCache::new(3600, 600, 86400, 1000);
        
        let state = cache.create_state("google".to_string(), "http://localhost/callback".to_string());
        assert!(!state.is_empty());

        let state_data = cache.get_and_remove_state(&state);
        assert!(state_data.is_some());
        let data = state_data.unwrap();
        assert_eq!(data.provider, "google");
        assert_eq!(data.redirect_uri, "http://localhost/callback");

        // Should be removed after get_and_remove
        assert!(cache.get_and_remove_state(&state).is_none());
    }

    #[tokio::test]
    async fn test_refresh_token_cache() {
        let cache = OAuthCache::new(3600, 600, 86400, 1000);
        
        let token = cache.create_refresh_token("google:123".to_string(), "google".to_string());
        assert!(!token.is_empty());

        let token_data = cache.get_refresh_token_data(&token);
        assert!(token_data.is_some());
        let data = token_data.unwrap();
        assert_eq!(data.user_id, "google:123");
        assert_eq!(data.provider, "google");
        assert_eq!(data.rotation_count, 0);

        // Test rotation
        let new_token = cache.rotate_refresh_token(&token, "google:123".to_string(), "google".to_string());
        assert!(new_token.is_some());
        let new_token = new_token.unwrap();
        assert_ne!(token, new_token);

        // Old token should be invalid
        assert!(cache.get_refresh_token_data(&token).is_none());
        
        // New token should be valid with incremented rotation count
        let new_data = cache.get_refresh_token_data(&new_token);
        assert!(new_data.is_some());
        assert_eq!(new_data.unwrap().rotation_count, 1);
    }

    #[test]
    fn test_hash_token() {
        let token = "test_token_123";
        let hash1 = hash_token(token);
        let hash2 = hash_token(token);
        
        // Same token should produce same hash
        assert_eq!(hash1, hash2);
        
        // Different tokens should produce different hashes
        let different_hash = hash_token("different_token");
        assert_ne!(hash1, different_hash);
        
        // Hash should be hex string of expected length (SHA256 = 64 hex chars)
        assert_eq!(hash1.len(), 64);
    }

    #[tokio::test]
    async fn test_expired_validation_cleanup() {
        let cache = OAuthCache::new(1, 600, 86400, 1000); // 1 second TTL
        let token = "test_token";
        
        let claims = crate::auth::jwt::OAuthClaims::new(
            "google:123".to_string(),
            "google".to_string(),
            "test@example.com".to_string(),
            vec!["email".to_string()],
            1, // 1 second expiration
            None,
        );

        cache.set_validation(token, claims);
        
        // Should be available immediately
        assert!(cache.get_validation(token).is_some());
        
        // Wait for expiration
        tokio::time::sleep(Duration::from_secs(2)).await;
        
        // Should be removed due to expiration
        assert!(cache.get_validation(token).is_none());
    }
}