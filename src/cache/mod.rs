//! Cache layer for temporary data storage
//!
//! This module provides in-memory caching for frequently accessed data
//! and temporary storage for operations that don't require persistence.

use thiserror::Error;

pub mod memory;
pub mod redis;
pub mod types;

pub use memory::MemoryCache;
pub use types::{CachedValidation, StateData};

/// Cache error types
#[derive(Error, Debug)]
pub enum CacheError {
    #[error("Cache error: {0}")]
    Cache(String),
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
pub enum CacheBackend {
    Memory(MemoryCache),
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
            backend: CacheBackend::Memory(MemoryCache::new()),
        }
    }

    /// Create cache manager with Redis cache (for production/distributed)
    pub fn new_redis(redis_cache: redis::RedisCache) -> Self {
        Self {
            backend: CacheBackend::Redis(redis_cache),
        }
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

    /// Store OAuth state data
    pub async fn store_state(
        &self,
        state: &str,
        data: &StateData,
        ttl_seconds: u64,
    ) -> CacheResult<()> {
        let key = format!("oauth_state:{}", state);
        let ttl = Some(std::time::Duration::from_secs(ttl_seconds));
        self.set(&key, data, ttl).await
    }

    /// Get OAuth state data
    pub async fn get_state(&self, state: &str) -> CacheResult<Option<StateData>> {
        let key = format!("oauth_state:{}", state);
        self.get(&key).await
    }

    /// Delete OAuth state data
    pub async fn delete_state(&self, state: &str) -> CacheResult<()> {
        let key = format!("oauth_state:{}", state);
        self.delete(&key).await
    }
}

impl Default for CacheManager {
    fn default() -> Self {
        Self::new_memory()
    }
}
