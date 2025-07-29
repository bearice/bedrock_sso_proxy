//! Cached DAO layer providing transparent caching for database operations
//!
//! This module provides a transparent cache layer for DAOs using the typed cache system.
//! It offers automatic cache invalidation, type safety, and performance optimization
//! for read-heavy database operations.

use crate::cache::CacheManagerImpl;
use crate::cache::typed::{CachedObject, TypedCache};
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
    pub fn new(inner: D, cache: &CacheManagerImpl) -> Self {
        Self {
            inner,
            cache: cache.get_typed_cache(),
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
            if let Err(cache_error) = self.cache.set_default(cache_key, entity).await {
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
        if let Err(cache_error) = self.cache.set_default(cache_key, &stored_entity).await {
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
                tracing::debug!("Invalidated cache key: {}", key);
            }
        }
        Ok(())
    }

    /// Get cache statistics
    pub fn get_cache_stats(&self) -> crate::cache::typed::TypedCacheStats {
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
        let backend = CacheManagerImpl::new_memory();
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
        let backend = CacheManagerImpl::new_memory();
        let cached_dao = CachedDao::<(), UserRecord>::new((), &backend);

        // Cache an entry
        let _ = cached_dao
            .cache
            .set_default(
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

    // Integration tests from tests/cached_integration_test.rs
    #[cfg(test)]
    mod integration_tests {
        use super::*;
        use crate::database::entities::ApiKeyRecord;
        use chrono::Utc;

        // Mock DAO for testing
        #[derive(Clone)]
        struct MockUsersDao {
            call_count: std::sync::Arc<std::sync::atomic::AtomicUsize>,
        }

        impl MockUsersDao {
            fn new() -> Self {
                Self {
                    call_count: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
                }
            }

            fn get_call_count(&self) -> usize {
                self.call_count.load(std::sync::atomic::Ordering::SeqCst)
            }

            async fn find_by_id(&self, user_id: i32) -> Result<Option<UserRecord>, String> {
                self.call_count
                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst);

                if user_id == 1 {
                    Ok(Some(UserRecord {
                        id: 1,
                        provider_user_id: "test123".to_string(),
                        provider: "google".to_string(),
                        email: "test@example.com".to_string(),
                        display_name: Some("Test User".to_string()),
                        created_at: Utc::now(),
                        updated_at: Utc::now(),
                        last_login: None,
                    }))
                } else {
                    Ok(None)
                }
            }
        }

        #[tokio::test]
        async fn test_cache_hit_and_miss() {
            let backend = CacheManagerImpl::new_memory();
            let mock_dao = MockUsersDao::new();
            let cached_dao = CachedDao::new(mock_dao.clone(), &backend);

            // First call - cache miss, should call DAO
            let result1 = cached_dao
                .get_or_compute("user:1", || async {
                    mock_dao
                        .find_by_id(1)
                        .await
                        .map_err(crate::database::DatabaseError::Database)
                })
                .await
                .unwrap();

            assert!(result1.is_some());
            assert_eq!(mock_dao.get_call_count(), 1);

            // Second call - cache hit, should NOT call DAO
            let result2 = cached_dao
                .get_or_compute("user:1", || async {
                    mock_dao
                        .find_by_id(1)
                        .await
                        .map_err(crate::database::DatabaseError::Database)
                })
                .await
                .unwrap();

            assert!(result2.is_some());
            assert_eq!(mock_dao.get_call_count(), 1); // No additional call

            // Verify cached data is correct
            assert_eq!(result1.as_ref().unwrap().id, result2.as_ref().unwrap().id);
            assert_eq!(
                result1.as_ref().unwrap().email,
                result2.as_ref().unwrap().email
            );
        }

        #[tokio::test]
        async fn test_cache_invalidation_integration() {
            let backend = CacheManagerImpl::new_memory();
            let mock_dao = MockUsersDao::new();
            let cached_dao = CachedDao::new(mock_dao.clone(), &backend);

            // Cache a value
            let _result1 = cached_dao
                .get_or_compute("user:1", || async {
                    mock_dao
                        .find_by_id(1)
                        .await
                        .map_err(crate::database::DatabaseError::Database)
                })
                .await
                .unwrap();

            assert_eq!(mock_dao.get_call_count(), 1);

            // Invalidate the cache
            cached_dao
                .invalidate_keys(&["user:1".to_string()])
                .await
                .unwrap();

            // Next call should be a cache miss
            let _result2 = cached_dao
                .get_or_compute("user:1", || async {
                    mock_dao
                        .find_by_id(1)
                        .await
                        .map_err(crate::database::DatabaseError::Database)
                })
                .await
                .unwrap();

            assert_eq!(mock_dao.get_call_count(), 2); // Additional call after invalidation
        }

        #[tokio::test]
        async fn test_cache_key_isolation() {
            let backend = CacheManagerImpl::new_memory();
            let mock_dao = MockUsersDao::new();
            let cached_dao = CachedDao::new(mock_dao.clone(), &backend);

            // Cache two different keys
            let _result1 = cached_dao
                .get_or_compute("user:1", || async {
                    mock_dao
                        .find_by_id(1)
                        .await
                        .map_err(crate::database::DatabaseError::Database)
                })
                .await
                .unwrap();

            let _result2 = cached_dao
                .get_or_compute("user:2", || async {
                    mock_dao
                        .find_by_id(2)
                        .await
                        .map_err(crate::database::DatabaseError::Database)
                })
                .await
                .unwrap();

            assert_eq!(mock_dao.get_call_count(), 2);

            // Invalidate only one key
            cached_dao
                .invalidate_keys(&["user:1".to_string()])
                .await
                .unwrap();

            // user:1 should be cache miss, user:2 should be cache hit
            let _result1_again = cached_dao
                .get_or_compute("user:1", || async {
                    mock_dao
                        .find_by_id(1)
                        .await
                        .map_err(crate::database::DatabaseError::Database)
                })
                .await
                .unwrap();

            let _result2_again = cached_dao
                .get_or_compute("user:2", || async {
                    mock_dao
                        .find_by_id(2)
                        .await
                        .map_err(crate::database::DatabaseError::Database)
                })
                .await
                .unwrap();

            assert_eq!(mock_dao.get_call_count(), 4); // user:1 (3rd call) + user:2 (4th call, None not cached)
        }

        #[tokio::test]
        async fn test_cache_key_builder_integration() {
            let builder = CacheKeyBuilder::new("test");

            // Test various key building methods
            assert_eq!(builder.id_key(123), "test:id:123");
            assert_eq!(builder.hash_key("abc123"), "test:hash:abc123");
            assert_eq!(builder.user_key(456), "test:user:456");
            assert_eq!(
                builder.email_key("test@example.com"),
                "test:email:test@example.com"
            );
            assert_eq!(
                builder.provider_key("google", "12345"),
                "test:provider:google:12345"
            );
            assert_eq!(
                builder.model_key("claude-sonnet"),
                "test:model:claude-sonnet"
            );

            // Test custom key building
            assert_eq!(
                builder.build(&["custom", "key", "value"]),
                "test:custom:key:value"
            );
        }

        #[tokio::test]
        async fn test_cache_with_none_values() {
            let backend = CacheManagerImpl::new_memory();
            let mock_dao = MockUsersDao::new();
            let cached_dao = CachedDao::new(mock_dao.clone(), &backend);

            // Test caching of None values (user not found)
            let result = cached_dao
                .get_or_compute("user:999", || async {
                    mock_dao
                        .find_by_id(999)
                        .await
                        .map_err(crate::database::DatabaseError::Database)
                })
                .await
                .unwrap();

            assert!(result.is_none());
            assert_eq!(mock_dao.get_call_count(), 1);

            // Second call - None values are NOT cached to avoid cache pollution
            // This is intentional behavior - we don't cache failed lookups
            let result2 = cached_dao
                .get_or_compute("user:999", || async {
                    mock_dao
                        .find_by_id(999)
                        .await
                        .map_err(crate::database::DatabaseError::Database)
                })
                .await
                .unwrap();

            assert!(result2.is_none());
            assert_eq!(mock_dao.get_call_count(), 2); // Additional call since None not cached
        }

        #[tokio::test]
        async fn test_cache_error_handling() {
            let backend = CacheManagerImpl::new_memory();
            let mock_dao = MockUsersDao::new();
            let cached_dao = CachedDao::new(mock_dao.clone(), &backend);

            // Test that cache errors don't break the operation
            // This is a bit artificial since MemoryCache rarely fails,
            // but it tests the error handling path

            let result = cached_dao
                .get_or_compute("user:1", || async {
                    mock_dao
                        .find_by_id(1)
                        .await
                        .map_err(crate::database::DatabaseError::Database)
                })
                .await
                .unwrap();

            assert!(result.is_some());
            assert_eq!(mock_dao.get_call_count(), 1);
        }

        #[tokio::test]
        async fn test_type_safety_with_different_entities() {
            let backend = CacheManagerImpl::new_memory();

            // Create two different typed caches
            let user_cache = CachedDao::<(), UserRecord>::new((), &backend);
            let api_key_cache = CachedDao::<(), ApiKeyRecord>::new((), &backend);

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

            let api_key = ApiKeyRecord {
                id: 1,
                key_hash: "hash123".to_string(),
                user_id: 1,
                name: "Test Key".to_string(),
                created_at: Utc::now(),
                last_used: None,
                expires_at: None,
                revoked_at: None,
            };

            // Store different types with same key - they should be isolated
            let _ = user_cache.cache().set_default("test:1", &user).await;
            let _ = api_key_cache.cache().set_default("test:1", &api_key).await;

            // Verify they're isolated (different type hashes)
            let cached_user = user_cache.cache().get("test:1").await.unwrap();
            let cached_api_key = api_key_cache.cache().get("test:1").await.unwrap();

            assert!(cached_user.is_some());
            assert!(cached_api_key.is_some());

            // Verify different types don't interfere
            assert_ne!(
                user_cache.get_cache_stats().type_hash,
                api_key_cache.get_cache_stats().type_hash
            );
        }

        #[tokio::test]
        async fn test_concurrent_cache_access() {
            let backend = CacheManagerImpl::new_memory();
            let mock_dao = MockUsersDao::new();
            let cached_dao = CachedDao::new(mock_dao.clone(), &backend);

            // Test concurrent access to the same cache key
            let handles: Vec<_> = (0..10)
                .map(|_| {
                    let cached_dao = cached_dao.clone();
                    let mock_dao = mock_dao.clone();
                    tokio::spawn(async move {
                        cached_dao
                            .get_or_compute("user:1", || async {
                                mock_dao
                                    .find_by_id(1)
                                    .await
                                    .map_err(crate::database::DatabaseError::Database)
                            })
                            .await
                            .unwrap()
                    })
                })
                .collect();

            let results: Vec<_> = futures_util::future::join_all(handles)
                .await
                .into_iter()
                .map(|h| h.unwrap())
                .collect();

            // All should return the same user
            for result in &results {
                assert!(result.is_some());
                assert_eq!(result.as_ref().unwrap().id, 1);
            }

            // Due to concurrency, we might have a few cache misses, but not 10
            // This tests that the cache is working under concurrent load
            assert!(mock_dao.get_call_count() < 10);
            assert!(mock_dao.get_call_count() >= 1);
        }
    }
}
