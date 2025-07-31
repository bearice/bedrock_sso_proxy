//! Cached DAO layer providing transparent caching for database operations
//!
//! This module provides a transparent cache layer for DAOs using the typed cache system.
//! It offers automatic cache invalidation, type safety, and performance optimization
//! for read-heavy database operations.

use crate::cache::CacheManager;
use crate::cache::object::{CachedObject, TypedCache};
use crate::database::DatabaseResult;
use async_trait::async_trait;
use std::fmt::Debug;
use std::time::Duration;

/// Trait for DAOs that support caching operations
#[async_trait]
pub trait CacheableDao<T: CachedObject> {
    /// Get entity from cache or database
    async fn get_cached(&self, cache_key: &str) -> DatabaseResult<Option<T>>;

    /// Store entity and update cache
    async fn store_and_cache(&self, entity: &T, cache_key: &str) -> DatabaseResult<T>;

    /// Update entity and invalidate related cache entries
    async fn update_and_invalidate(&self, entity: &T, cache_keys: &[String]) -> DatabaseResult<()>;

    /// Delete entity and invalidate cache
    async fn delete_and_invalidate(&self, cache_keys: &[String]) -> DatabaseResult<()>;

    /// Invalidate specific cache keys
    async fn invalidate_keys(&self, cache_keys: &[String]) -> DatabaseResult<()>;
}

/// Generic cached DAO wrapper that provides transparent caching
#[derive(Clone)]
pub struct CachedDao<D, T>
where
    T: CachedObject + Debug + Clone,
    D: Send + Sync + Clone,
{
    /// Inner DAO implementation
    inner: D,
    /// Typed cache for this entity type
    cache: TypedCache<T>,
}

impl<D, T> CachedDao<D, T>
where
    T: CachedObject + Debug + Clone,
    D: Send + Sync + Clone,
{
    /// Create a new cached DAO wrapper
    pub fn new(inner: D, cache: &CacheManager) -> Self {
        Self {
            inner,
            cache: cache.cache(),
        }
    }

    /// Get the inner DAO reference
    pub fn inner(&self) -> &D {
        &self.inner
    }

    /// Get the typed cache reference
    pub fn cache(&self) -> &TypedCache<T> {
        &self.cache
    }

    /// Get entity from cache first, fallback to provided compute function
    pub async fn get_or_compute<F, Fut>(
        &self,
        cache_key: &str,
        compute: F,
    ) -> DatabaseResult<Option<T>>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = DatabaseResult<Option<T>>>,
    {
        // Try cache first
        match self.cache.get(cache_key).await {
            Ok(Some(cached_value)) => {
                tracing::debug!("Cache hit for key: {}", cache_key);
                return Ok(Some(cached_value));
            }
            Ok(None) => {
                tracing::debug!("Cache miss for key: {}", cache_key);
            }
            Err(cache_error) => {
                tracing::warn!("Cache error for key {}: {}", cache_key, cache_error);
                // Continue to database on cache error
            }
        }

        // Cache miss or error - compute value
        let value = compute().await?;

        // Cache the result (both Some and None values)
        // We create a wrapper to handle Option<T> caching properly
        if let Some(ref entity) = value {
            if let Err(cache_error) = self.cache.set(cache_key, entity).await {
                tracing::warn!(
                    "Failed to cache entity for key {}: {}",
                    cache_key,
                    cache_error
                );
                // Don't fail the operation due to cache errors
            } else {
                tracing::debug!("Cached entity for key: {}", cache_key);
            }
        }
        // Note: For now, we don't cache None values to avoid cache pollution
        // In production, you might want to cache None values with shorter TTL

        Ok(value)
    }

    /// Store entity in database and cache
    pub async fn store_and_cache<F, Fut>(
        &self,
        entity: &T,
        cache_key: &str,
        store_fn: F,
    ) -> DatabaseResult<T>
    where
        F: FnOnce(&T) -> Fut,
        Fut: std::future::Future<Output = DatabaseResult<T>>,
    {
        // Store in database first
        let stored_entity = store_fn(entity).await?;

        // Cache the stored entity
        if let Err(cache_error) = self.cache.set(cache_key, &stored_entity).await {
            tracing::warn!("Failed to cache stored entity: {}", cache_error);
            // Don't fail the operation due to cache errors
        }

        Ok(stored_entity)
    }

    /// Update entity and invalidate cache entries
    pub async fn update_and_invalidate<F, R, Fut>(
        &self,
        update_fn: F,
        cache_keys: &[String],
    ) -> DatabaseResult<R>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = DatabaseResult<R>>,
    {
        // Perform the update operation
        let ret = update_fn().await?;

        // Invalidate cache entries
        self.invalidate_keys(cache_keys).await?;

        Ok(ret)
    }

    /// Delete entity and invalidate cache
    pub async fn delete_and_invalidate<F, Fut>(
        &self,
        delete_fn: F,
        cache_keys: &[String],
    ) -> DatabaseResult<()>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = DatabaseResult<()>>,
    {
        // Perform the delete operation
        delete_fn().await?;

        // Invalidate cache entries
        self.invalidate_keys(cache_keys).await?;

        Ok(())
    }

    /// Invalidate specific cache keys
    pub async fn invalidate_keys(&self, cache_keys: &[String]) -> DatabaseResult<()> {
        for key in cache_keys {
            if let Err(cache_error) = self.cache.delete(key).await {
                tracing::warn!("Failed to invalidate cache key {}: {}", key, cache_error);
                // Continue with other keys on error
            } else {
                tracing::trace!("Flushed cache key: {}", key);
            }
        }
        Ok(())
    }

    /// Get cache statistics
    pub fn get_cache_stats(&self) -> crate::cache::object::TypedCacheStats {
        self.cache.get_stats()
    }
}

/// Cache key builder helper for consistent key generation
#[derive(Clone)]
pub struct CacheKeyBuilder {
    prefix: String,
}

impl CacheKeyBuilder {
    /// Create a new cache key builder with the given prefix
    pub fn new(prefix: &str) -> Self {
        Self {
            prefix: prefix.to_string(),
        }
    }

    /// Build a cache key with the given components
    pub fn build(&self, components: &[&str]) -> String {
        let mut key = self.prefix.clone();
        for component in components {
            key.push(':');
            key.push_str(component);
        }
        key
    }

    /// Build cache key for ID-based lookup
    pub fn id_key(&self, id: impl std::fmt::Display) -> String {
        self.build(&["id", &id.to_string()])
    }

    /// Build cache key for hash-based lookup
    pub fn hash_key(&self, hash: &str) -> String {
        self.build(&["hash", hash])
    }

    /// Build cache key for user-based lookup
    pub fn user_key(&self, user_id: impl std::fmt::Display) -> String {
        self.build(&["user", &user_id.to_string()])
    }

    /// Build cache key for provider-based lookup
    pub fn provider_key(&self, provider: &str, provider_user_id: &str) -> String {
        self.build(&["provider", provider, provider_user_id])
    }

    /// Build cache key for email-based lookup
    pub fn email_key(&self, email: &str) -> String {
        self.build(&["email", email])
    }

    /// Build cache key for model-based lookup
    pub fn model_key(&self, model_id: &str) -> String {
        self.build(&["model", model_id])
    }
}

/// Configuration for DAO caching behavior
#[derive(Debug, Clone)]
pub struct DaoCacheConfig {
    /// Default TTL for cache entries
    pub default_ttl: Option<Duration>,
    /// Whether to enable cache-aside pattern for reads
    pub enable_read_cache: bool,
    /// Whether to enable write-through caching
    pub enable_write_cache: bool,
    /// Whether to enable automatic invalidation
    pub enable_invalidation: bool,
}

impl Default for DaoCacheConfig {
    fn default() -> Self {
        Self {
            default_ttl: None, // Use entity-specific TTL
            enable_read_cache: true,
            enable_write_cache: true,
            enable_invalidation: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::entities::UserRecord;
    use chrono::Utc;

    #[tokio::test]
    async fn test_cache_key_builder() {
        let builder = CacheKeyBuilder::new("user");

        assert_eq!(builder.id_key(123), "user:id:123");
        assert_eq!(
            builder.email_key("test@example.com"),
            "user:email:test@example.com"
        );
        assert_eq!(
            builder.provider_key("google", "12345"),
            "user:provider:google:12345"
        );
        assert_eq!(builder.build(&["custom", "key"]), "user:custom:key");
    }

    #[tokio::test]
    async fn test_cached_dao_basic_operations() {
        let backend = CacheManager::new_memory();
        let cached_dao = CachedDao::<(), UserRecord>::new((), &backend);

        let user = UserRecord {
            id: 1,
            provider_user_id: "test123".to_string(),
            provider: "google".to_string(),
            email: "test@example.com".to_string(),
            display_name: Some("Test User".to_string()),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            last_login: None,
        };

        // Test cache miss and compute
        let result = cached_dao
            .get_or_compute("test_key", || async { Ok(Some(user.clone())) })
            .await
            .unwrap();

        assert_eq!(result, Some(user.clone()));

        // Test cache hit
        let cached_result = cached_dao
            .get_or_compute("test_key", || async {
                // This should not be called due to cache hit
                panic!("Should not compute when cache hit");
            })
            .await
            .unwrap();

        assert_eq!(cached_result, Some(user));
    }

    #[tokio::test]
    async fn test_cache_invalidation() {
        let backend = CacheManager::new_memory();
        let cached_dao = CachedDao::<(), UserRecord>::new((), &backend);

        // Cache an entry
        let _ = cached_dao
            .cache
            .set(
                "test_key",
                &UserRecord {
                    id: 1,
                    provider_user_id: "test123".to_string(),
                    provider: "google".to_string(),
                    email: "test@example.com".to_string(),
                    display_name: Some("Test User".to_string()),
                    created_at: Utc::now(),
                    updated_at: Utc::now(),
                    last_login: None,
                },
            )
            .await;

        // Verify it's cached
        assert!(cached_dao.cache.exists("test_key").await.unwrap());

        // Invalidate
        cached_dao
            .invalidate_keys(&["test_key".to_string()])
            .await
            .unwrap();

        // Verify it's removed
        assert!(!cached_dao.cache.exists("test_key").await.unwrap());
    }
}
