//! Cached API Keys DAO with transparent caching for API key operations
//!
//! This module provides a cached wrapper around ApiKeysDao that implements
//! transparent caching for API key lookups with automatic invalidation.
//! This is particularly important for authentication performance.

use super::api_keys::ApiKeysDao;
use super::cached::{CacheKeyBuilder, CachedDao};
use crate::cache::CacheManagerImpl;
use crate::database::DatabaseResult;
use crate::database::entities::ApiKeyRecord;

/// Cached API Keys DAO providing transparent caching for API key operations
pub struct CachedApiKeysDao {
    cached_dao: CachedDao<ApiKeysDao, ApiKeyRecord>,
    key_builder: CacheKeyBuilder,
}

impl CachedApiKeysDao {
    /// Create a new cached API keys DAO
    pub fn new(api_keys_dao: ApiKeysDao, cache: &CacheManagerImpl) -> Self {
        Self {
            cached_dao: CachedDao::new(api_keys_dao, cache),
            key_builder: CacheKeyBuilder::new("api_key"),
        }
    }

    /// Get the inner ApiKeysDao reference
    pub fn inner(&self) -> &ApiKeysDao {
        self.cached_dao.inner()
    }

    /// Find API key by hash with caching (critical for auth performance)
    pub async fn find_by_hash(&self, key_hash: &str) -> DatabaseResult<Option<ApiKeyRecord>> {
        let cache_key = self.key_builder.hash_key(key_hash);

        self.cached_dao
            .get_or_compute(&cache_key, || async {
                self.cached_dao.inner().find_by_hash(key_hash).await
            })
            .await
    }

    /// Get all API keys for a user with caching
    pub async fn find_by_user(&self, user_id: i32) -> DatabaseResult<Vec<ApiKeyRecord>> {
        // For list operations, we'll bypass cache for list operations and only cache individual lookups
        self.cached_dao.inner().find_by_user(user_id).await
    }

    /// Store a new API key with cache invalidation
    pub async fn store(&self, api_key: &ApiKeyRecord) -> DatabaseResult<i32> {
        // Generate cache keys that might be affected by this operation
        let cache_keys = vec![self.key_builder.hash_key(&api_key.key_hash)];

        self.cached_dao
            .update_and_invalidate(
                || async { self.cached_dao.inner().store(api_key).await },
                &cache_keys,
            )
            .await
    }

    /// Update last used timestamp with cache invalidation
    pub async fn update_last_used(&self, key: ApiKeyRecord) -> DatabaseResult<ApiKeyRecord> {
        // Generate cache keys that might be affected
        let cache_keys = vec![self.key_builder.hash_key(&key.key_hash)];

        self.cached_dao
            .update_and_invalidate(
                || async { self.cached_dao.inner().update_last_used(key).await },
                &cache_keys,
            )
            .await
    }

    /// Revoke an API key with cache invalidation
    pub async fn revoke(&self, key: ApiKeyRecord) -> DatabaseResult<ApiKeyRecord> {
        // Generate cache keys that need to be invalidated
        let cache_keys = vec![self.key_builder.hash_key(&key.key_hash)];

        // Perform the revocation with proper cache invalidation
        self.cached_dao
            .update_and_invalidate(
                || async { self.cached_dao.inner().revoke(key).await },
                &cache_keys,
            )
            .await
    }

    /// Clean up expired or revoked API keys
    pub async fn cleanup_expired(&self) -> DatabaseResult<u64> {
        // Cleanup operations affect multiple keys, so we'll just call the inner DAO
        // and let TTL handle cache cleanup
        self.cached_dao.inner().cleanup_expired().await
    }

    /// Invalidate cache entry by key hash
    pub async fn invalidate_by_hash(&self, key_hash: &str) -> DatabaseResult<()> {
        let cache_keys = vec![self.key_builder.hash_key(key_hash)];
        self.cached_dao.invalidate_keys(&cache_keys).await
    }

    /// Get cache statistics
    pub fn get_cache_stats(&self) -> crate::cache::typed::TypedCacheStats {
        self.cached_dao.get_cache_stats()
    }
}
