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
        } else {
            // Memory counters use isolated storage for now since they have different data model
            counter::HashCounterBackend::Memory(
                counter::MemoryHashCounter::new(prefixed_key),
            )
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
