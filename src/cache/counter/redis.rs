//! Redis-based hash counter implementation

use super::{CacheError, CacheResult, CounterField, HashCounter};
use async_trait::async_trait;
use redis::AsyncCommands;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

/// Redis-based hash counter implementation
#[derive(Clone)]
pub struct RedisHashCounter<T: CounterField> {
    key: String,
    client: redis::Client,
    connection: Arc<tokio::sync::Mutex<Option<redis::aio::MultiplexedConnection>>>,
    _phantom: std::marker::PhantomData<T>,
}

impl<T: CounterField> RedisHashCounter<T> {
    /// Create new Redis-based hash counter
    pub fn new(redis_url: &str, key: String) -> CacheResult<Self> {
        let client = redis::Client::open(redis_url)
            .map_err(|e| CacheError::Cache(format!("Redis client error: {}", e)))?;

        Ok(Self {
            key,
            client,
            connection: Arc::new(tokio::sync::Mutex::new(None)),
            _phantom: std::marker::PhantomData,
        })
    }

    /// Create Redis hash counter from existing client (for pre-initialized clients)
    pub fn from_client(client: redis::Client, key: String) -> Self {
        Self {
            key,
            client,
            connection: Arc::new(tokio::sync::Mutex::new(None)),
            _phantom: std::marker::PhantomData,
        }
    }

    /// Get the counter key
    pub fn key(&self) -> &str {
        &self.key
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

#[async_trait]
impl<T: CounterField> HashCounter<T> for RedisHashCounter<T> {
    async fn increment(&self, field: T, amount: i64) -> CacheResult<i64> {
        let mut conn = self.get_connection().await?;

        let result: i64 = conn
            .hincr(&self.key, field.field_name(), amount)
            .await
            .map_err(|e| CacheError::Cache(e.to_string()))?;

        self.return_connection(conn).await;
        Ok(result)
    }

    async fn decrement(&self, field: T, amount: i64) -> CacheResult<i64> {
        let mut conn = self.get_connection().await?;

        let result: i64 = conn
            .hincr(&self.key, field.field_name(), -amount)
            .await
            .map_err(|e| CacheError::Cache(e.to_string()))?;

        self.return_connection(conn).await;
        Ok(result)
    }

    async fn get(&self, field: T) -> CacheResult<Option<i64>> {
        let mut conn = self.get_connection().await?;

        let result: Option<i64> = conn
            .hget(&self.key, field.field_name())
            .await
            .map_err(|e| CacheError::Cache(e.to_string()))?;

        self.return_connection(conn).await;
        Ok(result)
    }

    async fn set(&self, field: T, value: i64) -> CacheResult<()> {
        let mut conn = self.get_connection().await?;

        let _: () = conn
            .hset(&self.key, field.field_name(), value)
            .await
            .map_err(|e| CacheError::Cache(e.to_string()))?;

        self.return_connection(conn).await;
        Ok(())
    }

    async fn get_all(&self) -> CacheResult<HashMap<T, i64>> {
        let mut conn = self.get_connection().await?;

        let result: HashMap<String, i64> = conn
            .hgetall(&self.key)
            .await
            .map_err(|e| CacheError::Cache(e.to_string()))?;

        self.return_connection(conn).await;

        // Convert string keys back to enum variants
        let mut typed_result = HashMap::new();
        for field in T::all_fields() {
            if let Some(value) = result.get(field.field_name()) {
                typed_result.insert(field, *value);
            }
        }

        Ok(typed_result)
    }

    async fn set_multiple(&self, fields: &[(T, i64)]) -> CacheResult<()> {
        let mut conn = self.get_connection().await?;

        let mut pipe = redis::pipe();
        for (field, value) in fields {
            pipe.hset(&self.key, field.field_name(), *value);
        }

        let _: () = pipe
            .query_async(&mut conn)
            .await
            .map_err(|e| CacheError::Cache(e.to_string()))?;

        self.return_connection(conn).await;
        Ok(())
    }

    async fn increment_multiple(&self, updates: &[(T, i64)]) -> CacheResult<HashMap<T, i64>> {
        let mut conn = self.get_connection().await?;

        let mut pipe = redis::pipe();
        for (field, amount) in updates {
            pipe.hincr(&self.key, field.field_name(), *amount);
        }

        let results: Vec<i64> = pipe
            .query_async(&mut conn)
            .await
            .map_err(|e| CacheError::Cache(e.to_string()))?;

        self.return_connection(conn).await;

        let mut result_map = HashMap::new();
        for ((field, _), value) in updates.iter().zip(results.iter()) {
            result_map.insert(field.clone(), *value);
        }

        Ok(result_map)
    }

    async fn delete_field(&self, field: T) -> CacheResult<()> {
        let mut conn = self.get_connection().await?;

        let _: () = conn
            .hdel(&self.key, field.field_name())
            .await
            .map_err(|e| CacheError::Cache(e.to_string()))?;

        self.return_connection(conn).await;
        Ok(())
    }

    async fn field_exists(&self, field: T) -> CacheResult<bool> {
        let mut conn = self.get_connection().await?;

        let exists: bool = conn
            .hexists(&self.key, field.field_name())
            .await
            .map_err(|e| CacheError::Cache(e.to_string()))?;

        self.return_connection(conn).await;
        Ok(exists)
    }

    async fn reset_field(&self, field: T) -> CacheResult<()> {
        let mut conn = self.get_connection().await?;

        let _: () = conn
            .hset(&self.key, field.field_name(), 0)
            .await
            .map_err(|e| CacheError::Cache(e.to_string()))?;

        self.return_connection(conn).await;
        Ok(())
    }

    async fn delete_hash(&self) -> CacheResult<()> {
        let mut conn = self.get_connection().await?;

        let _: () = conn
            .del(&self.key)
            .await
            .map_err(|e| CacheError::Cache(e.to_string()))?;

        self.return_connection(conn).await;
        Ok(())
    }

    async fn exists(&self) -> CacheResult<bool> {
        let mut conn = self.get_connection().await?;

        let exists: bool = conn
            .exists(&self.key)
            .await
            .map_err(|e| CacheError::Cache(e.to_string()))?;

        self.return_connection(conn).await;
        Ok(exists)
    }

    async fn set_ttl(&self, ttl: Duration) -> CacheResult<()> {
        let mut conn = self.get_connection().await?;

        let _: () = conn
            .expire(&self.key, ttl.as_secs() as i64)
            .await
            .map_err(|e| CacheError::Cache(e.to_string()))?;

        self.return_connection(conn).await;
        Ok(())
    }

    async fn get_ttl(&self) -> CacheResult<Option<Duration>> {
        let mut conn = self.get_connection().await?;

        let ttl_seconds: i64 = conn
            .ttl(&self.key)
            .await
            .map_err(|e| CacheError::Cache(e.to_string()))?;

        self.return_connection(conn).await;

        match ttl_seconds {
            -1 => Ok(None), // Key exists but has no associated expire
            -2 => Ok(None), // Key doesn't exist
            seconds if seconds > 0 => Ok(Some(Duration::from_secs(seconds as u64))),
            _ => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use typed_cache_macro::typed_counter;

    #[typed_counter]
    enum TestField {
        Count,
        Value,
    }

    #[tokio::test]
    async fn test_redis_hash_counter_new() {
        // Test that we can create a Redis hash counter (even if Redis is not running)
        let result: Result<RedisHashCounter<TestField>, _> =
            RedisHashCounter::new("redis://localhost:6379", "test_key".to_string());
        assert!(result.is_ok());

        let counter = result.unwrap();
        assert_eq!(counter.key(), "test_key");
    }

    #[tokio::test]
    async fn test_redis_hash_counter_health_check() {
        let counter: RedisHashCounter<TestField> =
            RedisHashCounter::new("redis://localhost:6379", "test_key".to_string()).unwrap();

        // Health check may fail if Redis is not running - that's expected
        let result = counter.health_check().await;
        // We just test that the method doesn't panic and returns a proper Result
        match result {
            Ok(_) => {
                // Redis is running, health check passed
            }
            Err(e) => {
                // Redis is not running or connection failed - expected in CI
                assert!(
                    e.to_string().contains("Connection failed")
                        || e.to_string().contains("Ping failed")
                );
            }
        }
    }

    // Note: Additional integration tests for Redis operations would require a running Redis instance
    // These should be in a separate integration test file or conditional on Redis availability
}
