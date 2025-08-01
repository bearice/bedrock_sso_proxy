use crate::cache::CachedObject;

use super::{CacheError, CacheResult};
use redis::{AsyncCommands, Client};
use std::{sync::Arc, time::Duration};
use tokio::sync::Mutex;

/// Redis cache implementation with single connection and reconnection logic
#[derive(Clone)]
pub struct RedisCache<T> {
    client: Client,
    connection: Arc<Mutex<Option<redis::aio::MultiplexedConnection>>>,
    key_prefix: String,
    _phantom: std::marker::PhantomData<T>,
}

impl<T> RedisCache<T> {
    /// Create new Redis cache
    pub fn new(redis_url: &str, key_prefix: String) -> CacheResult<Self> {
        let client = Client::open(redis_url)
            .map_err(|e| CacheError::Cache(format!("Redis client error: {}", e)))?;

        Ok(Self {
            client,
            connection: Arc::new(Mutex::new(None)),
            key_prefix,
            _phantom: std::marker::PhantomData,
        })
    }

    /// Create Redis cache from existing client (for pre-initialized clients)
    pub fn from_client(client: Client, key_prefix: String) -> Self {
        Self {
            client,
            connection: Arc::new(Mutex::new(None)),
            key_prefix,
            _phantom: std::marker::PhantomData,
        }
    }

    /// Get a working Redis connection, creating or reusing existing one
    async fn get_connection(&self) -> CacheResult<redis::aio::MultiplexedConnection> {
        let mut conn_guard = self.connection.lock().await;

        // Try to reuse existing connection
        if let Some(conn) = conn_guard.take() {
            // Test if connection is still alive
            if self.test_connection(&conn).await.is_ok() {
                return Ok(conn);
            }
        }

        // Create new connection
        let new_conn = self
            .client
            .get_multiplexed_tokio_connection()
            .await
            .map_err(|e| CacheError::Connection(format!("Connection failed: {}", e)))?;

        Ok(new_conn)
    }

    /// Test if connection is still alive
    async fn test_connection(
        &self,
        conn: &redis::aio::MultiplexedConnection,
    ) -> Result<(), redis::RedisError> {
        let mut conn = conn.clone();
        let _: String = redis::cmd("PING").query_async(&mut conn).await?;
        Ok(())
    }

    /// Return connection to storage for reuse
    async fn return_connection(&self, conn: redis::aio::MultiplexedConnection) {
        *self.connection.lock().await = Some(conn);
    }

    /// Add key prefix to avoid conflicts
    fn prefixed_key(&self, key: &str) -> String {
        format!("{}{}", self.key_prefix, key)
    }

    /// Health check - test Redis connectivity
    pub async fn health_check(&self) -> CacheResult<()> {
        let mut conn = self.get_connection().await?;
        let _: String = redis::cmd("PING")
            .query_async(&mut conn)
            .await
            .map_err(|e| CacheError::Cache(format!("Ping failed: {}", e)))?;

        self.return_connection(conn).await;
        Ok(())
    }
}

/// Generic implementation using postcard serialization for RedisCache<T>
impl<T> RedisCache<T>
where
    T: CachedObject,
{
    /// Get value by key
    pub async fn get(&self, key: &str) -> CacheResult<Option<T>> {
        let key = self.prefixed_key(key);
        let mut conn = self.get_connection().await?;

        let result: Option<Vec<u8>> = conn
            .get(&key)
            .await
            .map_err(|e| CacheError::Cache(e.to_string()))?;

        self.return_connection(conn).await;

        match result {
            Some(data) => {
                let value: T = postcard::from_bytes(&data)
                    .map_err(|e| CacheError::Serialization(e.to_string()))?;
                Ok(Some(value))
            }
            None => Ok(None),
        }
    }

    /// Set value with optional expiration
    pub async fn set(&self, key: &str, value: &T, ttl: Option<Duration>) -> CacheResult<()> {
        let key = self.prefixed_key(key);
        let data =
            postcard::to_allocvec(value).map_err(|e| CacheError::Serialization(e.to_string()))?;

        let mut conn = self.get_connection().await?;

        if let Some(ttl) = ttl {
            let _: () = conn
                .set_ex(&key, &data, ttl.as_secs())
                .await
                .map_err(|e| CacheError::Cache(e.to_string()))?;
        } else {
            let _: () = conn
                .set(&key, &data)
                .await
                .map_err(|e| CacheError::Cache(e.to_string()))?;
        }

        self.return_connection(conn).await;
        Ok(())
    }

    /// Delete key
    pub async fn delete(&self, key: &str) -> CacheResult<()> {
        let key = self.prefixed_key(key);
        let mut conn = self.get_connection().await?;

        let _: () = conn
            .del(&key)
            .await
            .map_err(|e| CacheError::Cache(e.to_string()))?;

        self.return_connection(conn).await;
        Ok(())
    }

    /// Check if key exists
    pub async fn exists(&self, key: &str) -> CacheResult<bool> {
        let key = self.prefixed_key(key);
        let mut conn = self.get_connection().await?;

        let exists: bool = conn
            .exists(&key)
            .await
            .map_err(|e| CacheError::Cache(e.to_string()))?;

        self.return_connection(conn).await;
        Ok(exists)
    }

    /// Clear all cache entries
    pub async fn clear(&self) -> CacheResult<()> {
        let mut conn = self.get_connection().await?;

        let _: () = redis::cmd("FLUSHDB")
            .query_async(&mut conn)
            .await
            .map_err(|e| CacheError::Cache(e.to_string()))?;

        self.return_connection(conn).await;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};
    use typed_cache_macro::typed_cache;

    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
    #[typed_cache]
    struct TestData {
        id: u32,
        name: String,
    }

    #[tokio::test]
    async fn test_redis_cache_new() {
        // Test that we can create a Redis cache (even if Redis is not running)
        let result: Result<RedisCache<String>, _> =
            RedisCache::new("redis://localhost:6379", "test:".to_string());
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_redis_cache_key_prefix() {
        let cache: RedisCache<String> =
            RedisCache::new("redis://localhost:6379", "test:".to_string()).unwrap();
        let prefixed = cache.prefixed_key("my_key");
        assert_eq!(prefixed, "test:my_key");
    }

    #[tokio::test]
    async fn test_redis_cache_operations() {
        let cache: RedisCache<TestData> =
            RedisCache::new("redis://localhost:6379", "test:".to_string()).unwrap();

        let test_data = TestData {
            id: 1,
            name: "Test".to_string(),
        };

        // Test set and get
        cache.set("test_key", &test_data, None).await.unwrap();
        let result = cache.get("test_key").await.unwrap();
        assert_eq!(result, Some(test_data.clone()));

        // Test exists
        let exists = cache.exists("test_key").await.unwrap();
        assert!(exists);

        // Test delete
        cache.delete("test_key").await.unwrap();
        let result = cache.get("test_key").await.unwrap();
        assert_eq!(result, None);

        // Test TTL
        let test_data_ttl = TestData {
            id: 2,
            name: "TTL Test".to_string(),
        };
        cache
            .set("ttl_key", &test_data_ttl, Some(Duration::from_secs(1)))
            .await
            .unwrap();
        let result = cache.get("ttl_key").await.unwrap();
        assert_eq!(result, Some(test_data_ttl));

        // Wait for TTL expiration
        tokio::time::sleep(Duration::from_secs(2)).await;
        let result = cache.get("ttl_key").await.unwrap();
        assert_eq!(result, None);
    }

    #[tokio::test]
    async fn test_redis_health_check() {
        let cache: RedisCache<String> =
            RedisCache::new("redis://localhost:6379", "test:".to_string()).unwrap();
        let result = cache.health_check().await;
        assert!(result.is_ok());
    }
}
