//! Cache layer for temporary data storage
//!
//! This module provides in-memory caching for frequently accessed data
//! and temporary storage for operations that don't require persistence.

use thiserror::Error;
use std::sync::Arc;
use std::collections::HashMap;
use tokio::sync::RwLock;

pub mod config;
pub mod counter;
pub mod object;

pub use counter::{CounterField, HashCounter, TypedHashCounter, typed_counter};
pub use object::{CachedObject, TypedCache, TypedCacheStats, typed_cache};

use crate::cache::config::CacheConfig;
use crate::cache::object::TypedCacheBackend;
use crate::health::HealthChecker;

/// Cache error types
#[derive(Error, Debug)]
pub enum CacheError {
    #[error("Cache error: {0}")]
    Cache(String),
    #[error("Connection error: {0}")]
    Connection(String),
    #[error("Key not found")]
    NotFound,
    #[error("Serialization error: {0}")]
    Serialization(String),
}

pub type CacheResult<T> = Result<T, CacheError>;

/// Shared memory store backend for both cache and counters
type SharedMemoryStore = Arc<RwLock<HashMap<String, Box<dyn std::any::Any + Send + Sync>>>>;

/// Cache manager - creates TypedCache instances
#[derive(Clone)]
pub struct CacheManager {
    config: CacheConfig,
    redis_client: Option<redis::Client>,
    memory_store: Option<SharedMemoryStore>,
}

impl CacheManager {
    /// Create new cache manager with memory cache (for testing/single instance)
    pub fn new_memory() -> Self {
        Self {
            config: CacheConfig {
                backend: "memory".to_string(),
                ..Default::default()
            },
            redis_client: None,
            memory_store: Some(Arc::new(RwLock::new(HashMap::new()))),
        }
    }

    /// Create cache manager from configuration
    pub async fn new_from_config(config: &CacheConfig) -> CacheResult<Self> {
        let redis_client = if config.backend == "redis" {
            // Create and test Redis client during initialization
            let client = redis::Client::open(config.redis_url.as_str())
                .map_err(|e| CacheError::Connection(format!("Redis client creation failed: {}", e)))?;

            // Test the connection to fail early if Redis is not available
            let mut conn = client
                .get_multiplexed_tokio_connection()
                .await
                .map_err(|e| CacheError::Connection(format!("Redis connection failed: {}", e)))?;

            // Test with a simple ping
            redis::cmd("PING")
                .query_async::<String>(&mut conn)
                .await
                .map_err(|e| CacheError::Connection(format!("Redis ping failed: {}", e)))?;

            Some(client)
        } else {
            None
        };

        let memory_store = if config.backend == "memory" {
            Some(Arc::new(RwLock::new(HashMap::new())))
        } else {
            None
        };

        Ok(Self {
            config: config.clone(),
            redis_client,
            memory_store,
        })
    }

    /// Create typed cache backend based on pre-initialized backends
    fn create_backend<T: CachedObject>(&self) -> TypedCacheBackend<T> {
        if let Some(client) = &self.redis_client {
            let redis = object::redis::RedisCache::from_client(
                client.clone(),
                self.config.redis_key_prefix.clone(),
            );
            TypedCacheBackend::Redis(redis)
        } else if let Some(store) = &self.memory_store {
            TypedCacheBackend::Memory(object::memory::MemoryCache::from_shared_store(store.clone()))
        } else {
            panic!("No backend initialized - this should never happen")
        }
    }

    /// Create counter backend based on pre-initialized backends
    fn create_counter_backend<T: CounterField>(
        &self,
        key: &str,
    ) -> counter::HashCounterBackend<T> {
        let prefixed_key: String = format!("{}:{}", T::counter_prefix(), key);

        if let Some(client) = &self.redis_client {
            let redis = counter::RedisHashCounter::from_client(client.clone(), prefixed_key);
            counter::HashCounterBackend::Redis(redis)
        } else if let Some(store) = &self.memory_store {
            // Memory counters now use shared storage for consistency with Redis behavior
            counter::HashCounterBackend::Memory(
                counter::MemoryHashCounter::from_shared_store(store.clone(), prefixed_key),
            )
        } else {
            panic!("No backend initialized - this should never happen")
        }
    }

    /// Get a typed cache for type T
    pub fn cache<T: CachedObject>(&self) -> TypedCache<T> {
        let backend = self.create_backend();
        TypedCache::new(backend)
    }

    /// Get a typed counter for the given key with automatic type prefix
    pub fn counter<T: CounterField>(&self, key: &str) -> TypedHashCounter<T> {
        let backend = self.create_counter_backend(key);
        TypedHashCounter::new(backend, key)
    }

    pub async fn health_check(&self) -> crate::health::HealthCheckResult {
        match self.config.backend.as_str() {
            "redis" => {
                // Create a temporary Redis connection to test health
                match object::redis::RedisCache::<String>::new(
                    &self.config.redis_url,
                    self.config.redis_key_prefix.clone(),
                ) {
                    Ok(redis_cache) => match redis_cache.health_check().await {
                        Ok(_) => crate::health::HealthCheckResult::healthy_with_details(
                            serde_json::json!({
                                "backend": "redis",
                                "status": "healthy",
                                "connection": "ok"
                            }),
                        ),
                        Err(err) => crate::health::HealthCheckResult::unhealthy_with_details(
                            "Redis health check failed".to_string(),
                            serde_json::json!({
                                "backend": "redis",
                                "status": "unhealthy",
                                "error": err.to_string()
                            }),
                        ),
                    },
                    Err(err) => crate::health::HealthCheckResult::unhealthy_with_details(
                        "Redis client creation failed".to_string(),
                        serde_json::json!({
                            "backend": "redis",
                            "status": "unhealthy",
                            "error": err.to_string()
                        }),
                    ),
                }
            }
            _ => {
                // Memory cache always passes health check
                crate::health::HealthCheckResult::healthy_with_details(serde_json::json!({
                    "backend": "memory",
                    "status": "healthy"
                }))
            }
        }
    }

    fn backend_type(&self) -> &str {
        &self.config.backend
    }
}

impl Default for CacheManager {
    fn default() -> Self {
        Self::new_memory()
    }
}

#[async_trait::async_trait]
impl HealthChecker for CacheManager {
    fn name(&self) -> &str {
        "cache"
    }

    async fn check(&self) -> crate::health::HealthCheckResult {
        self.health_check().await
    }

    fn info(&self) -> Option<serde_json::Value> {
        Some(serde_json::json!({
            "service": "Cache Manager",
            "backend": self.backend_type()
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use typed_cache_macro::typed_counter;

    #[typed_counter(ttl = 300)]
    enum TestCounterField {
        Requests,
        Errors,
        Warnings,
    }

    #[tokio::test]
    async fn test_memory_counter_sharing() {
        // Create a cache manager with memory backend
        let cache_manager = CacheManager::new_memory();
        
        // Get two counter instances with the same key - should be shared
        let counter1 = cache_manager.counter::<TestCounterField>("test_key");
        let counter2 = cache_manager.counter::<TestCounterField>("test_key");
        
        // Increment field in counter1
        let result = counter1.increment(TestCounterField::Requests, 5).await.unwrap();
        assert_eq!(result, 5);
        
        // Check that counter2 sees the same value (shared state)
        let value = counter2.get(TestCounterField::Requests).await.unwrap();
        assert_eq!(value, Some(5));
        
        // Increment field in counter2
        let result = counter2.increment(TestCounterField::Requests, 3).await.unwrap();
        assert_eq!(result, 8);
        
        // Check that counter1 sees the updated value
        let value = counter1.get(TestCounterField::Requests).await.unwrap();
        assert_eq!(value, Some(8));
        
        // Test different field
        counter1.set(TestCounterField::Errors, 10).await.unwrap();
        let value = counter2.get(TestCounterField::Errors).await.unwrap();
        assert_eq!(value, Some(10));
        
        // Test increment_multiple with shared state
        let updates = vec![
            (TestCounterField::Warnings, 2),
            (TestCounterField::Errors, 3),
        ];
        let results = counter1.increment_multiple(&updates).await.unwrap();
        assert_eq!(results.get(&TestCounterField::Warnings), Some(&2));
        assert_eq!(results.get(&TestCounterField::Errors), Some(&13)); // 10 + 3
        
        // Verify counter2 sees the changes
        let warnings = counter2.get(TestCounterField::Warnings).await.unwrap();
        let errors = counter2.get(TestCounterField::Errors).await.unwrap();
        assert_eq!(warnings, Some(2));
        assert_eq!(errors, Some(13));
    }

    #[tokio::test]
    async fn test_memory_counter_isolation_with_different_keys() {
        // Create a cache manager with memory backend
        let cache_manager = CacheManager::new_memory();
        
        // Get counter instances with different keys - should be isolated
        let counter1 = cache_manager.counter::<TestCounterField>("key1");
        let counter2 = cache_manager.counter::<TestCounterField>("key2");
        
        // Set values in each counter
        counter1.set(TestCounterField::Requests, 100).await.unwrap();
        counter2.set(TestCounterField::Requests, 200).await.unwrap();
        
        // Verify they are isolated
        let value1 = counter1.get(TestCounterField::Requests).await.unwrap();
        let value2 = counter2.get(TestCounterField::Requests).await.unwrap();
        
        assert_eq!(value1, Some(100));
        assert_eq!(value2, Some(200));
        
        // Modify counter1, should not affect counter2
        counter1.increment(TestCounterField::Requests, 50).await.unwrap();
        
        let value1 = counter1.get(TestCounterField::Requests).await.unwrap();
        let value2 = counter2.get(TestCounterField::Requests).await.unwrap();
        
        assert_eq!(value1, Some(150));
        assert_eq!(value2, Some(200)); // unchanged
    }

    #[tokio::test]
    async fn test_memory_counter_ttl_sharing() {
        // Create a cache manager with memory backend
        let cache_manager = CacheManager::new_memory();
        
        // Get two counter instances with the same key
        let counter1 = cache_manager.counter::<TestCounterField>("ttl_test");
        let counter2 = cache_manager.counter::<TestCounterField>("ttl_test");
        
        // Set values and TTL through counter1
        counter1.set(TestCounterField::Requests, 42).await.unwrap();
        counter1.set_ttl(std::time::Duration::from_millis(50)).await.unwrap();
        
        // Verify counter2 sees the value immediately
        let value = counter2.get(TestCounterField::Requests).await.unwrap();
        assert_eq!(value, Some(42));
        
        // Check TTL is shared
        let ttl = counter2.get_ttl().await.unwrap();
        assert!(ttl.is_some());
        assert!(ttl.unwrap() <= std::time::Duration::from_millis(50));
        
        // Wait for expiration
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        
        // Both counters should see expiration
        assert!(!counter1.exists().await.unwrap());
        assert!(!counter2.exists().await.unwrap());
    }

    #[tokio::test]
    async fn test_memory_counter_hash_operations_sharing() {
        // Create a cache manager with memory backend
        let cache_manager = CacheManager::new_memory();
        
        // Get two counter instances with the same key
        let counter1 = cache_manager.counter::<TestCounterField>("hash_test");
        let counter2 = cache_manager.counter::<TestCounterField>("hash_test");
        
        // Set multiple fields through counter1
        let fields = vec![
            (TestCounterField::Requests, 10),
            (TestCounterField::Errors, 5),
            (TestCounterField::Warnings, 2),
        ];
        counter1.set_multiple(&fields).await.unwrap();
        
        // Get all fields through counter2 - should see the same data
        let all_fields = counter2.get_all().await.unwrap();
        assert_eq!(all_fields.get(&TestCounterField::Requests), Some(&10));
        assert_eq!(all_fields.get(&TestCounterField::Errors), Some(&5));
        assert_eq!(all_fields.get(&TestCounterField::Warnings), Some(&2));
        
        // Delete a field through counter2
        counter2.delete_field(TestCounterField::Errors).await.unwrap();
        
        // Verify counter1 sees the deletion
        let errors = counter1.get(TestCounterField::Errors).await.unwrap();
        assert_eq!(errors, None);
        
        // But other fields should still exist
        let requests = counter1.get(TestCounterField::Requests).await.unwrap();
        assert_eq!(requests, Some(10));
        
        // Delete entire hash through counter1
        counter1.delete_hash().await.unwrap();
        
        // Both counters should show empty
        assert!(!counter1.exists().await.unwrap());
        assert!(!counter2.exists().await.unwrap());
    }
}
