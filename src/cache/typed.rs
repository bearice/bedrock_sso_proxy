//! Typed cache system with compile-time type safety and performance optimization
//!
//! This module provides a typed cache interface that ensures type safety,
//! prevents key collisions between different types, and optimizes performance
//! based on the cache backend (memory vs Redis).

use crate::cache::{Cache, CacheBackend, CacheError, CacheResult};
pub use typed_cache_macro::typed_cache;
use serde::{Deserialize, Serialize};
use std::any::type_name;
use std::marker::PhantomData;
use std::time::Duration;

/// Trait for types that can be cached with automatic structural hashing
pub trait CachedObject:
    Serialize + for<'de> Deserialize<'de> + Send + Sync + Clone + 'static
{
    /// Optional type-specific TTL override
    fn default_ttl() -> Option<Duration> {
        None
    }

    /// Generate cache prefix from type name
    /// Can be overridden for custom prefixes
    fn cache_prefix() -> String {
        type_name::<Self>()
            .split("::")
            .last()
            .unwrap_or("unknown")
            .to_string()
    }

    /// Generate structural hash from type definition using custom derive
    /// This creates a hash based on the actual type structure including
    /// field names, types, and ordering. Changes to any of these will change the hash.
    fn cache_type_hash() -> u64;
}

/// Typed cache instance for a specific type T
pub struct TypedCache<T: CachedObject> {
    backend: CacheBackend,
    prefix: String,
    type_hash: u64,
    default_ttl: Option<Duration>,
    _phantom: PhantomData<T>,
}

impl<T: CachedObject> TypedCache<T> {
    /// Create a new typed cache for type T
    pub fn new(backend: CacheBackend) -> Self {
        let prefix = T::cache_prefix();
        let type_hash = T::cache_type_hash();

        Self {
            backend,
            prefix,
            type_hash,
            default_ttl: T::default_ttl(),
            _phantom: PhantomData,
        }
    }

    /// Generate a cache key for the given key
    fn cache_key(&self, key: &str) -> String {
        format!("{}:{}:{}", self.prefix, self.type_hash, key)
    }

    /// Get value from cache
    pub async fn get(&self, key: &str) -> CacheResult<Option<T>> {
        let cache_key = self.cache_key(key);

        // Try to get the cached entry with metadata
        let cached_entry: Option<CachedEntry<T>> = match &self.backend {
            CacheBackend::Memory(cache) => cache.get(&cache_key).await?,
            CacheBackend::Redis(cache) => cache.get(&cache_key).await?,
        };

        match cached_entry {
            Some(entry) => {
                // Verify type version matches
                if entry.type_hash == self.type_hash {
                    Ok(Some(entry.value))
                } else {
                    // Type version mismatch - invalidate entry
                    let _ = match &self.backend {
                        CacheBackend::Memory(cache) => cache.delete(&cache_key).await,
                        CacheBackend::Redis(cache) => cache.delete(&cache_key).await,
                    };
                    Ok(None)
                }
            }
            None => Ok(None),
        }
    }

    /// Set value in cache with optional TTL
    pub async fn set(&self, key: &str, value: &T, ttl: Option<Duration>) -> CacheResult<()> {
        let cache_key = self.cache_key(key);
        let ttl = ttl.or(self.default_ttl);

        let entry = CachedEntry {
            value: value.clone(),
            type_hash: self.type_hash,
        };

        match &self.backend {
            CacheBackend::Memory(cache) => cache.set(&cache_key, &entry, ttl).await,
            CacheBackend::Redis(cache) => cache.set(&cache_key, &entry, ttl).await,
        }
    }

    /// Set with default TTL
    pub async fn set_default(&self, key: &str, value: &T) -> CacheResult<()> {
        self.set(key, value, None).await
    }

    /// Delete value from cache
    pub async fn delete(&self, key: &str) -> CacheResult<()> {
        let cache_key = self.cache_key(key);
        match &self.backend {
            CacheBackend::Memory(cache) => cache.delete(&cache_key).await,
            CacheBackend::Redis(cache) => cache.delete(&cache_key).await,
        }
    }

    /// Check if key exists in cache
    pub async fn exists(&self, key: &str) -> CacheResult<bool> {
        let cache_key = self.cache_key(key);
        match &self.backend {
            CacheBackend::Memory(cache) => cache.exists(&cache_key).await,
            CacheBackend::Redis(cache) => cache.exists(&cache_key).await,
        }
    }

    /// Get or compute value (cache-aside pattern)
    pub async fn get_or_compute<F, Fut>(&self, key: &str, compute: F) -> CacheResult<T>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<T, Box<dyn std::error::Error + Send + Sync>>>,
    {
        // Try cache first
        if let Some(cached_value) = self.get(key).await? {
            return Ok(cached_value);
        }

        // Compute value
        let value = compute()
            .await
            .map_err(|e| CacheError::Cache(e.to_string()))?;

        // Cache the computed value
        self.set_default(key, &value).await?;

        Ok(value)
    }

    /// Get cache statistics for this type
    pub fn get_stats(&self) -> TypedCacheStats {
        TypedCacheStats {
            type_name: type_name::<T>().to_string(),
            type_hash: self.type_hash,
            prefix: self.prefix.clone(),
        }
    }
}

/// Cache entry with type metadata
#[derive(Serialize, Deserialize, Clone)]
struct CachedEntry<T> {
    value: T,
    type_hash: u64,
}

/// Statistics for a typed cache
#[derive(Debug, Clone)]
pub struct TypedCacheStats {
    pub type_name: String,
    pub type_hash: u64,
    pub prefix: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache::{CacheBackend, memory::MemoryCache};
    use std::time::Duration;

    #[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
    #[typed_cache(ttl = 300)] // 5 minutes
    struct TestUser {
        id: i32,
        name: String,
        email: String,
    }

    #[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
    #[typed_cache(ttl = 600)] // 10 minutes
    struct TestApiKey {
        id: i32,
        key_hash: String,
    }

    #[tokio::test]
    async fn test_typed_cache_basic_operations() {
        let backend = CacheBackend::Memory(MemoryCache::new());
        let user_cache = TypedCache::<TestUser>::new(backend.clone());
        let api_key_cache = TypedCache::<TestApiKey>::new(backend.clone());

        let user = TestUser {
            id: 1,
            name: "John".to_string(),
            email: "john@example.com".to_string(),
        };

        let api_key = TestApiKey {
            id: 1,
            key_hash: "hash123".to_string(),
        };

        // Test setting and getting
        user_cache.set_default("1", &user).await.unwrap();
        api_key_cache.set_default("1", &api_key).await.unwrap();

        let cached_user = user_cache.get("1").await.unwrap();
        let cached_api_key = api_key_cache.get("1").await.unwrap();

        assert_eq!(cached_user, Some(user));
        assert_eq!(cached_api_key, Some(api_key));

        // Test key isolation - same key "1" but different types
        assert!(user_cache.get("1").await.unwrap().is_some());
        assert!(api_key_cache.get("1").await.unwrap().is_some());

        // Keys are isolated by type
        assert_ne!(user_cache.cache_key("1"), api_key_cache.cache_key("1"));
    }

    #[tokio::test]
    async fn test_auto_prefix_generation() {
        let backend = CacheBackend::Memory(MemoryCache::new());
        let user_cache = TypedCache::<TestUser>::new(backend.clone());
        let api_key_cache = TypedCache::<TestApiKey>::new(backend.clone());

        let user_stats = user_cache.get_stats();
        let api_key_stats = api_key_cache.get_stats();

        assert_eq!(user_stats.prefix, "TestUser");
        assert_eq!(api_key_stats.prefix, "TestApiKey");

        // Type hashes should be different
        assert_ne!(user_stats.type_hash, api_key_stats.type_hash);
    }

    #[tokio::test]
    async fn test_structural_hashing() {
        let _backend = CacheBackend::Memory(MemoryCache::new());

        // Create two different struct types - should have different hashes
        #[derive(Serialize, Deserialize, Clone)]
        #[typed_cache]
        struct TestUserV1 {
            id: i32,
            name: String,
        }

        #[derive(Serialize, Deserialize, Clone)]
        #[typed_cache]
        struct TestUserV2 {
            id: i32,
            name: String,
            email: String, // Added field
        }

        // Different type hashes should be generated for different types
        let hash_v1 = TestUserV1::cache_type_hash();
        let hash_v2 = TestUserV2::cache_type_hash();

        // Different types should have different hashes due to structural differences
        assert_ne!(hash_v1, hash_v2);
    }

    #[tokio::test]
    async fn test_get_or_compute() {
        let backend = CacheBackend::Memory(MemoryCache::new());
        let user_cache = TypedCache::<TestUser>::new(backend);

        let user = TestUser {
            id: 1,
            name: "John".to_string(),
            email: "john@example.com".to_string(),
        };

        let user_clone = user.clone();
        let computed_user = user_cache
            .get_or_compute("1", || async move {
                Ok::<TestUser, Box<dyn std::error::Error + Send + Sync>>(user_clone)
            })
            .await
            .unwrap();

        assert_eq!(computed_user, user);

        // Should be cached now
        let cached_user = user_cache.get("1").await.unwrap();
        assert_eq!(cached_user, Some(user));
    }

    #[tokio::test]
    async fn test_macro_implementation() {
        #[derive(Serialize, Deserialize, Clone)]
        #[typed_cache(ttl = 300)]
        struct MacroTestUser {
            id: i32,
            name: String,
        }

        let backend = CacheBackend::Memory(MemoryCache::new());
        let user_cache = TypedCache::<MacroTestUser>::new(backend);

        let stats = user_cache.get_stats();
        assert_eq!(stats.prefix, "MacroTestUser");

        // Test that TTL is set correctly
        assert_eq!(MacroTestUser::default_ttl(), Some(Duration::from_secs(300)));
    }
}
