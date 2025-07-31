//! Cache layer for temporary data storage
//!
//! This module provides in-memory caching for frequently accessed data
//! and temporary storage for operations that don't require persistence.

use thiserror::Error;

pub mod config;
mod memory;
mod redis;
pub mod typed;

pub use typed::{CachedObject, TypedCache, TypedCacheStats, typed_cache};

use crate::cache::config::CacheConfig;
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

/// Cache manager trait for dependency injection and testing
/// Simplified to only handle TypedCache creation
#[async_trait::async_trait]
pub trait CacheManager: Send + Sync {
    // For health checking, we need non-generic methods
    async fn health_check(&self) -> crate::health::HealthCheckResult;
    fn backend_type(&self) -> &str;
}

/// Extended trait for getting typed caches - separate to avoid dyn issues
pub trait TypedCacheProvider {
    /// Get a typed cache for type T - the main interface
    fn get_typed_cache<T: CachedObject>(&self) -> TypedCache<T>;
}

/// Typed cache backend enum - stores CachedEntry<T> which includes type hash
#[derive(Clone)]
pub enum TypedCacheBackend<T> {
    Memory(memory::MemoryCache<T>),  // JSON storage
    Redis(redis::RedisCache<T>),    // Bitcode storage
}

/// Cache manager implementation - creates TypedCache instances
#[derive(Clone)]
pub struct CacheManagerImpl {
    config: CacheConfig,
}

impl CacheManagerImpl {
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
            }
        }
    }

    /// Create cache manager from configuration
    pub async fn new_from_config(config: &CacheConfig) -> CacheResult<Self> {
        Ok(Self {
            config: config.clone(),
        })
    }
}

impl CacheManagerImpl {
    /// Create typed cache backend based on configuration
    fn create_backend<T: CachedObject>(&self) -> CacheResult<TypedCacheBackend<T>> {
        match self.config.backend.as_str() {
            "redis" => {
                let redis = redis::RedisCache::new(&self.config.redis_url, self.config.redis_key_prefix.clone())?;
                Ok(TypedCacheBackend::Redis(redis))
            }
            _ => Ok(TypedCacheBackend::Memory(memory::MemoryCache::new())),
        }
    }
}

#[async_trait::async_trait]
impl CacheManager for CacheManagerImpl {
    async fn health_check(&self) -> crate::health::HealthCheckResult {
        match self.config.backend.as_str() {
            "redis" => {
                // Create a temporary Redis connection to test health
                match redis::RedisCache::<String>::new(&self.config.redis_url, self.config.redis_key_prefix.clone()) {
                    Ok(redis_cache) => {
                        match redis_cache.health_check().await {
                            Ok(_) => {
                                crate::health::HealthCheckResult::healthy_with_details(serde_json::json!({
                                    "backend": "redis",
                                    "status": "healthy",
                                    "connection": "ok"
                                }))
                            }
                            Err(err) => crate::health::HealthCheckResult::unhealthy_with_details(
                                "Redis health check failed".to_string(),
                                serde_json::json!({
                                    "backend": "redis",
                                    "status": "unhealthy",
                                    "error": err.to_string()
                                }),
                            ),
                        }
                    }
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

impl TypedCacheProvider for CacheManagerImpl {
    /// Get a typed cache for type T
    fn get_typed_cache<T: CachedObject>(&self) -> TypedCache<T> {
        // Create backend on-demand for each type
        let backend = self.create_backend().unwrap_or_else(|_| {
            // Fallback to memory cache on error
            TypedCacheBackend::Memory(memory::MemoryCache::new())
        });
        TypedCache::new(backend)
    }
}

impl Default for CacheManagerImpl {
    fn default() -> Self {
        Self::new_memory()
    }
}

#[async_trait::async_trait]
impl HealthChecker for CacheManagerImpl {
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
