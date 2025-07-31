//! Cache layer for temporary data storage
//!
//! This module provides in-memory caching for frequently accessed data
//! and temporary storage for operations that don't require persistence.

use thiserror::Error;

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

/// Cache manager - creates TypedCache instances
#[derive(Clone)]
pub struct CacheManager {
    config: CacheConfig,
}

impl CacheManager {
    /// Create new cache manager with memory cache (for testing/single instance)
    pub fn new_memory() -> Self {
        Self {
            config: CacheConfig {
                backend: "memory".to_string(),
                redis_url: "redis://localhost:6379".to_string(),
                redis_key_prefix: "bedrock_sso:".to_string(),
                validation_ttl: 3600,
                max_entries: 10000,
                cleanup_interval: 3600,
            },
        }
    }

    /// Create cache manager from configuration
    pub async fn new_from_config(config: &CacheConfig) -> CacheResult<Self> {
        Ok(Self {
            config: config.clone(),
        })
    }

    /// Create typed cache backend based on configuration
    fn create_backend<T: CachedObject>(&self) -> CacheResult<TypedCacheBackend<T>> {
        match self.config.backend.as_str() {
            "redis" => {
                let redis = object::redis::RedisCache::new(
                    &self.config.redis_url,
                    self.config.redis_key_prefix.clone(),
                )?;
                Ok(TypedCacheBackend::Redis(redis))
            }
            _ => Ok(TypedCacheBackend::Memory(object::memory::MemoryCache::new())),
        }
    }

    /// Create counter backend based on configuration
    fn create_counter_backend<T: CounterField>(
        &self,
        key: &str,
    ) -> CacheResult<counter::HashCounterBackend<T>> {
        let prefixed_key: String = format!("{}:{}", T::counter_prefix(), key);

        match self.config.backend.as_str() {
            "redis" => {
                let redis = counter::RedisHashCounter::new(&self.config.redis_url, prefixed_key)?;
                Ok(counter::HashCounterBackend::Redis(redis))
            }
            _ => Ok(counter::HashCounterBackend::Memory(
                counter::MemoryHashCounter::new(prefixed_key),
            )),
        }
    }

    /// Get a typed cache for type T
    pub fn cache<T: CachedObject>(&self) -> TypedCache<T> {
        // Create backend on-demand for each type
        let backend = self.create_backend().unwrap_or_else(|_| {
            // Fallback to memory cache on error
            TypedCacheBackend::Memory(object::memory::MemoryCache::new())
        });
        TypedCache::new(backend)
    }

    /// Get a typed counter for the given key with automatic type prefix
    pub fn counter<T: CounterField>(&self, key: &str) -> TypedHashCounter<T> {
        // Create counter backend based on configuration
        let backend = self.create_counter_backend(key).unwrap_or_else(|_| {
            // Fallback to memory counter on error
            counter::HashCounterBackend::Memory(counter::MemoryHashCounter::new(format!(
                "{}:{}",
                T::counter_prefix(),
                key
            )))
        });
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
