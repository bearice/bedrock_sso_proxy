//! Typed cache system with compile-time type safety and performance optimization
//!
//! This module provides a typed cache interface that ensures type safety,
//! prevents key collisions between different types, and optimizes performance
//! based on the cache backend (memory vs Redis).
pub mod memory;
pub mod redis;
use crate::cache::{CacheError, CacheResult};
use serde::{Deserialize, Serialize};
use std::any::type_name;
use std::marker::PhantomData;
use std::time::Duration;
pub use typed_cache_macro::typed_cache;

/// Typed cache backend enum - stores CachedEntry<T> which includes type hash
#[derive(Clone)]
pub enum TypedCacheBackend<T> {
    Memory(memory::MemoryCache<T>), // JSON storage
    Redis(redis::RedisCache<T>),    // Postcard storage
}

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
    fn cache_prefix() -> &'static str;

    /// Generate structural hash from type definition using custom derive
    /// This creates a hash based on the actual type structure including
    /// field names, types, and ordering. Changes to any of these will change the hash.
    fn cache_type_hash() -> u64;
}

/// Typed cache instance for a specific type T
#[derive(Clone)]
pub struct TypedCache<T: CachedObject> {
    backend: TypedCacheBackend<T>,
    prefix: &'static str,
    type_hash: u64,
    default_ttl: Option<Duration>,
    _phantom: PhantomData<T>,
}

impl<T: CachedObject> TypedCache<T> {
    /// Create a new typed cache for type T
    pub(super) fn new(backend: TypedCacheBackend<T>) -> Self {
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

        // Get the value directly (type safety via key hash)
        let result = match &self.backend {
            TypedCacheBackend::Memory(cache) => cache.get(&cache_key).await?,
            TypedCacheBackend::Redis(cache) => cache.get(&cache_key).await?,
        };

        Ok(result)
    }

    /// Set value in cache with optional TTL
    pub async fn set_with_ttl(
        &self,
        key: &str,
        value: &T,
        ttl: Option<Duration>,
    ) -> CacheResult<()> {
        let cache_key = self.cache_key(key);
        let ttl = ttl.or(self.default_ttl);

        match &self.backend {
            TypedCacheBackend::Memory(cache) => cache.set(&cache_key, value, ttl).await,
            TypedCacheBackend::Redis(cache) => cache.set(&cache_key, value, ttl).await,
        }
    }

    /// Set with default TTL
    pub async fn set(&self, key: &str, value: &T) -> CacheResult<()> {
        self.set_with_ttl(key, value, None).await
    }

    /// Delete value from cache
    pub async fn delete(&self, key: &str) -> CacheResult<()> {
        let cache_key = self.cache_key(key);
        match &self.backend {
            TypedCacheBackend::Memory(cache) => cache.delete(&cache_key).await,
            TypedCacheBackend::Redis(cache) => cache.delete(&cache_key).await,
        }
    }

    /// Check if key exists in cache
    pub async fn exists(&self, key: &str) -> CacheResult<bool> {
        let cache_key = self.cache_key(key);
        match &self.backend {
            TypedCacheBackend::Memory(cache) => cache.exists(&cache_key).await,
            TypedCacheBackend::Redis(cache) => cache.exists(&cache_key).await,
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
        self.set(key, &value).await?;

        Ok(value)
    }

    /// Get cache statistics for this type
    pub fn get_stats(&self) -> TypedCacheStats {
        TypedCacheStats {
            type_name: type_name::<T>(),
            type_hash: self.type_hash,
            prefix: self.prefix.to_string(),
        }
    }
}

/// Statistics for a typed cache
#[derive(Debug, Clone)]
pub struct TypedCacheStats {
    pub type_name: &'static str,
    pub type_hash: u64,
    pub prefix: String,
}

#[cfg(test)]
mod tests {
    use super::memory::MemoryCache;
    use super::*;
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
        let user_backend = TypedCacheBackend::Memory(MemoryCache::new());
        let user_cache = TypedCache::<TestUser>::new(user_backend);

        let api_key_backend = TypedCacheBackend::Memory(MemoryCache::new());
        let api_key_cache = TypedCache::<TestApiKey>::new(api_key_backend);

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
        user_cache.set("1", &user).await.unwrap();
        api_key_cache.set("1", &api_key).await.unwrap();

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
        let user_backend = TypedCacheBackend::Memory(MemoryCache::new());
        let user_cache = TypedCache::<TestUser>::new(user_backend);

        let api_key_backend = TypedCacheBackend::Memory(MemoryCache::new());
        let api_key_cache = TypedCache::<TestApiKey>::new(api_key_backend);

        let user_stats = user_cache.get_stats();
        let api_key_stats = api_key_cache.get_stats();

        assert_eq!(user_stats.prefix, "TestUser");
        assert_eq!(api_key_stats.prefix, "TestApiKey");

        // Type hashes should be different
        assert_ne!(user_stats.type_hash, api_key_stats.type_hash);
    }

    #[tokio::test]
    async fn test_structural_hashing() {
        let _backend: TypedCacheBackend<i32> = TypedCacheBackend::Memory(MemoryCache::new());

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
        let backend = TypedCacheBackend::Memory(MemoryCache::new());
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

        let backend = TypedCacheBackend::Memory(MemoryCache::new());
        let user_cache = TypedCache::<MacroTestUser>::new(backend);

        let stats = user_cache.get_stats();
        assert_eq!(stats.prefix, "MacroTestUser");

        // Test that TTL is set correctly
        assert_eq!(MacroTestUser::default_ttl(), Some(Duration::from_secs(300)));
    }

    #[tokio::test]
    async fn test_postcard_serialization_round_trip() {
        use crate::database::entities::ModelCost;
        use chrono::Utc;
        use rust_decimal::Decimal;

        // Test that ModelCost can be serialized and deserialized with postcard
        let model_cost = ModelCost {
            id: 1,
            region: "us-east-1".to_string(),
            model_id: "anthropic.claude-sonnet-4-20250514-v1:0".to_string(),
            input_cost_per_1k_tokens: Decimal::new(3, 3), // 0.003
            output_cost_per_1k_tokens: Decimal::new(15, 3), // 0.015
            cache_write_cost_per_1k_tokens: Some(Decimal::new(18, 4)), // 0.0018
            cache_read_cost_per_1k_tokens: Some(Decimal::new(36, 5)), // 0.00036
            updated_at: Utc::now(),
        };

        // Test direct postcard serialization (what Redis cache uses)
        let serialized =
            postcard::to_allocvec(&model_cost).expect("ModelCost should serialize with postcard");

        let deserialized: ModelCost =
            postcard::from_bytes(&serialized).expect("ModelCost should deserialize with postcard");

        // Verify data integrity
        assert_eq!(deserialized.id, model_cost.id);
        assert_eq!(deserialized.region, model_cost.region);
        assert_eq!(deserialized.model_id, model_cost.model_id);
        assert_eq!(
            deserialized.input_cost_per_1k_tokens,
            model_cost.input_cost_per_1k_tokens
        );
        assert_eq!(
            deserialized.output_cost_per_1k_tokens,
            model_cost.output_cost_per_1k_tokens
        );
        assert_eq!(
            deserialized.cache_write_cost_per_1k_tokens,
            model_cost.cache_write_cost_per_1k_tokens
        );
        assert_eq!(
            deserialized.cache_read_cost_per_1k_tokens,
            model_cost.cache_read_cost_per_1k_tokens
        );
    }

    #[test]
    fn test_postcard_decimal_edge_cases() {
        use rust_decimal::Decimal;

        // Test various decimal values that might cause serialization issues
        let edge_cases = vec![
            Decimal::ZERO,
            Decimal::new(1, 0),                      // 1
            Decimal::new(-1, 0),                     // -1
            Decimal::new(123456789, 9),              // 0.123456789 (high precision)
            Decimal::new(999999999999999999i64, 18), // Very large with max precision
            Decimal::new(1, 28),                     // Smallest positive decimal
            Decimal::new(-1, 28),                    // Smallest negative decimal
        ];

        for decimal_value in edge_cases {
            let serialized = postcard::to_allocvec(&decimal_value)
                .unwrap_or_else(|_| panic!("Should serialize decimal: {}", decimal_value));

            let deserialized: Decimal = postcard::from_bytes(&serialized)
                .unwrap_or_else(|_| panic!("Should deserialize decimal: {}", decimal_value));

            assert_eq!(
                deserialized, decimal_value,
                "Round-trip failed for decimal: {}",
                decimal_value
            );
        }
    }

    #[test]
    fn test_postcard_vs_json_serialization_compatibility() {
        use crate::database::entities::UserRecord;
        use chrono::Utc;

        let user = UserRecord {
            id: 123,
            provider_user_id: "google_12345".to_string(),
            provider: "google".to_string(),
            email: "test@example.com".to_string(),
            display_name: Some("Test User".to_string()),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            last_login: Some(Utc::now()),
        };

        // Test that both JSON (memory cache) and postcard (Redis cache) work
        let json_serialized = serde_json::to_vec(&user).expect("Should serialize with JSON");
        let json_deserialized: UserRecord =
            serde_json::from_slice(&json_serialized).expect("Should deserialize with JSON");

        let postcard_serialized =
            postcard::to_allocvec(&user).expect("Should serialize with postcard");
        let postcard_deserialized: UserRecord =
            postcard::from_bytes(&postcard_serialized).expect("Should deserialize with postcard");

        // Both should produce identical results
        assert_eq!(json_deserialized.id, postcard_deserialized.id);
        assert_eq!(json_deserialized.email, postcard_deserialized.email);
        assert_eq!(
            json_deserialized.display_name,
            postcard_deserialized.display_name
        );
    }
}
