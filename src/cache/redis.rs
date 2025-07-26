use super::{Cache, CacheError, CacheResult};
use redis::{AsyncCommands, Client};
use std::{sync::Arc, time::Duration};
use tokio::sync::Mutex;

/// Redis cache implementation with single connection and reconnection logic
pub struct RedisCache {
    client: Client,
    connection: Arc<Mutex<Option<redis::aio::MultiplexedConnection>>>,
    key_prefix: String,
}

impl RedisCache {
    /// Create new Redis cache
    pub fn new(redis_url: &str, key_prefix: String) -> CacheResult<Self> {
        let client = Client::open(redis_url)
            .map_err(|e| CacheError::Cache(format!("Redis client error: {}", e)))?;

        Ok(Self {
            client,
            connection: Arc::new(Mutex::new(None)),
            key_prefix,
        })
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
        let new_conn = self.client.get_multiplexed_tokio_connection().await
            .map_err(|e| CacheError::Connection(format!("Connection failed: {}", e)))?;

        Ok(new_conn)
    }

    /// Test if connection is still alive
    async fn test_connection(&self, conn: &redis::aio::MultiplexedConnection) -> Result<(), redis::RedisError> {
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
        let _: String = redis::cmd("PING").query_async(&mut conn).await
            .map_err(|e| CacheError::Cache(format!("Ping failed: {}", e)))?;

        self.return_connection(conn).await;
        Ok(())
    }
}

#[async_trait::async_trait]
impl Cache for RedisCache {
    async fn get<T>(&self, key: &str) -> CacheResult<Option<T>>
    where
        T: serde::de::DeserializeOwned + Send,
    {
        let key = self.prefixed_key(key);
        let mut conn = self.get_connection().await?;

        let result: Option<String> = conn.get(&key).await
            .map_err(|e| CacheError::Cache(e.to_string()))?;

        // Return connection to storage for reuse
        self.return_connection(conn).await;

        match result {
            Some(data) => {
                let value = serde_json::from_str::<T>(&data)
                    .map_err(|e| CacheError::Serialization(e.to_string()))?;
                Ok(Some(value))
            }
            None => Ok(None),
        }
    }

    async fn set<T>(
        &self,
        key: &str,
        value: &T,
        ttl: Option<Duration>,
    ) -> CacheResult<()>
    where
        T: serde::Serialize + Send + Sync,
    {
        let key = self.prefixed_key(key);
        let data = serde_json::to_string(value)
            .map_err(|e| CacheError::Serialization(e.to_string()))?;

        let mut conn = self.get_connection().await?;

        if let Some(ttl) = ttl {
            let _: () = conn.set_ex(&key, &data, ttl.as_secs()).await
                .map_err(|e| CacheError::Cache(e.to_string()))?;
        } else {
            let _: () = conn.set(&key, &data).await
                .map_err(|e| CacheError::Cache(e.to_string()))?;
        }

        // Return connection for reuse
        self.return_connection(conn).await;

        Ok(())
    }

    async fn delete(&self, key: &str) -> CacheResult<()> {
        let key = self.prefixed_key(key);
        let mut conn = self.get_connection().await?;

        let _: () = conn.del(&key).await
            .map_err(|e| CacheError::Cache(e.to_string()))?;

        self.return_connection(conn).await;
        Ok(())
    }

    async fn exists(&self, key: &str) -> CacheResult<bool> {
        let key = self.prefixed_key(key);
        let mut conn = self.get_connection().await?;

        let exists: bool = conn.exists(&key).await
            .map_err(|e| CacheError::Cache(e.to_string()))?;

        self.return_connection(conn).await;
        Ok(exists)
    }

    async fn clear(&self) -> CacheResult<()> {
        let mut conn = self.get_connection().await?;

        let _: () = redis::cmd("FLUSHDB").query_async(&mut conn).await
            .map_err(|e| CacheError::Cache(e.to_string()))?;

        self.return_connection(conn).await;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
    struct TestData {
        id: u32,
        name: String,
    }

    #[tokio::test]
    async fn test_redis_cache_new() {
        // Test that we can create a Redis cache (even if Redis is not running)
        let result = RedisCache::new("redis://localhost:6379", "test:".to_string());
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_redis_cache_key_prefix() {
        let cache = RedisCache::new("redis://localhost:6379", "test:".to_string()).unwrap();
        let prefixed = cache.prefixed_key("my_key");
        assert_eq!(prefixed, "test:my_key");
    }

    // Note: The following tests require a running Redis instance
    // They are commented out to avoid test failures in CI/CD

    /*
    #[tokio::test]
    async fn test_redis_cache_operations() {
        let cache = RedisCache::new("redis://localhost:6379", "test:".to_string()).unwrap();

        let test_data = TestData {
            id: 1,
            name: "Test".to_string(),
        };

        // Test set and get
        cache.set("test_key", &test_data, None).await.unwrap();
        let result: Option<TestData> = cache.get("test_key").await.unwrap();
        assert_eq!(result, Some(test_data));

        // Test exists
        let exists = cache.exists("test_key").await.unwrap();
        assert!(exists);

        // Test delete
        cache.delete("test_key").await.unwrap();
        let result: Option<TestData> = cache.get("test_key").await.unwrap();
        assert_eq!(result, None);

        // Test TTL
        let test_data_ttl = TestData {
            id: 2,
            name: "TTL Test".to_string(),
        };
        cache.set("ttl_key", &test_data_ttl, Some(Duration::from_secs(1))).await.unwrap();
        let result: Option<TestData> = cache.get("ttl_key").await.unwrap();
        assert_eq!(result, Some(test_data_ttl));

        // Wait for TTL expiration
        tokio::time::sleep(Duration::from_secs(2)).await;
        let result: Option<TestData> = cache.get("ttl_key").await.unwrap();
        assert_eq!(result, None);
    }

    #[tokio::test]
    async fn test_redis_health_check() {
        let cache = RedisCache::new("redis://localhost:6379", "test:".to_string()).unwrap();
        let result = cache.health_check().await;
        assert!(result.is_ok());
    }
    */
}
