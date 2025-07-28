//! Cache layer for temporary data storage
//!
//! This module provides in-memory caching for frequently accessed data
//! and temporary storage for operations that don't require persistence.

use thiserror::Error;

mod memory;
mod redis;
pub mod typed;

pub use typed::{CachedObject, TypedCache, TypedCacheStats, typed_cache};

use crate::{config::CacheConfig, health::HealthChecker};

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

/// Cache trait for different cache implementations
#[async_trait::async_trait]
pub trait Cache: Send + Sync {
    /// Get value by key
    async fn get<T>(&self, key: &str) -> CacheResult<Option<T>>
    where
        T: serde::de::DeserializeOwned + Send;

    /// Set value with optional expiration
    async fn set<T>(
        &self,
        key: &str,
        value: &T,
        ttl: Option<std::time::Duration>,
    ) -> CacheResult<()>
    where
        T: serde::Serialize + Send + Sync;

    /// Delete key
    async fn delete(&self, key: &str) -> CacheResult<()>;

    /// Check if key exists
    async fn exists(&self, key: &str) -> CacheResult<bool>;

    /// Clear all cache entries
    async fn clear(&self) -> CacheResult<()>;
}

/// Cache backend enum - either Redis or memory cache
#[derive(Clone)]
enum CacheBackend {
    Memory(memory::MemoryCache),
    Redis(redis::RedisCache),
}

/// Cache manager - uses either Redis or memory cache, not both
pub struct CacheManager {
    backend: CacheBackend,
}

impl CacheManager {
    /// Create new cache manager with memory cache (for testing/single instance)
    pub fn new_memory() -> Self {
        Self {
            backend: CacheBackend::Memory(memory::MemoryCache::new()),
        }
    }

    /// Create cache manager from configuration
    pub async fn new_from_config(config: &CacheConfig) -> CacheResult<Self> {
        match config.backend.as_str() {
            "redis" => {
                let redis = redis::RedisCache::new(
                    &config.redis_url,
                    config.redis_key_prefix.clone(),
                )?;
                Ok(Self{backend:CacheBackend::Redis(redis)})
            }
            _ => Ok(Self::new_memory()),
        }
    }

    /// Get a typed cache for type T
    pub fn get_typed_cache<T: CachedObject>(&self) -> TypedCache<T> {
        TypedCache::new(self.backend.clone())
    }

    /// Get value from cache
    pub async fn get<T>(&self, key: &str) -> CacheResult<Option<T>>
    where
        T: serde::de::DeserializeOwned + Send,
    {
        match &self.backend {
            CacheBackend::Memory(cache) => cache.get(key).await,
            CacheBackend::Redis(cache) => cache.get(key).await,
        }
    }

    /// Set value in cache
    pub async fn set<T>(
        &self,
        key: &str,
        value: &T,
        ttl: Option<std::time::Duration>,
    ) -> CacheResult<()>
    where
        T: serde::Serialize + Send + Sync,
    {
        match &self.backend {
            CacheBackend::Memory(cache) => cache.set(key, value, ttl).await,
            CacheBackend::Redis(cache) => cache.set(key, value, ttl).await,
        }
    }

    /// Delete from cache
    pub async fn delete(&self, key: &str) -> CacheResult<()> {
        match &self.backend {
            CacheBackend::Memory(cache) => cache.delete(key).await,
            CacheBackend::Redis(cache) => cache.delete(key).await,
        }
    }

    /// Check if key exists in cache
    pub async fn exists(&self, key: &str) -> CacheResult<bool> {
        match &self.backend {
            CacheBackend::Memory(cache) => cache.exists(key).await,
            CacheBackend::Redis(cache) => cache.exists(key).await,
        }
    }

    /// Clear cache
    pub async fn clear(&self) -> CacheResult<()> {
        match &self.backend {
            CacheBackend::Memory(cache) => cache.clear().await,
            CacheBackend::Redis(cache) => cache.clear().await,
        }
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
        match &self.backend {
            CacheBackend::Memory(_) => {
                // Memory cache always passes health check
                crate::health::HealthCheckResult::healthy_with_details(
                    serde_json::json!({
                        "backend": "memory",
                        "status": "healthy"
                    })
                )
            }
            CacheBackend::Redis(redis_cache) => {
                // Use the Redis health check function
                match redis_cache.health_check().await {
                    Ok(_) => crate::health::HealthCheckResult::healthy_with_details(
                        serde_json::json!({
                            "backend": "redis",
                            "status": "healthy",
                            "connection": "ok"
                        })
                    ),
                    Err(err) => crate::health::HealthCheckResult::unhealthy_with_details(
                        "Redis health check failed".to_string(),
                        serde_json::json!({
                            "backend": "redis",
                            "status": "unhealthy",
                            "error": err.to_string()
                        })
                    ),
                }
            }
        }
    }

    fn info(&self) -> Option<serde_json::Value> {
        Some(serde_json::json!({
            "service": "Cache Manager",
            "backend": match &self.backend {
                CacheBackend::Memory(_) => "memory",
                CacheBackend::Redis(_) => "redis",
            }
        }))
    }
}
