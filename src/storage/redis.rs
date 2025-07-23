use super::{
    CacheStorage, CachedValidation, RateLimitData, StateData, StorageError, StorageResult,
};
use async_trait::async_trait;
use redis::{AsyncCommands, Client, RedisError, aio::ConnectionManager};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tokio::time::timeout;

/// Redis cache storage implementation
pub struct RedisCacheStorage {
    connection: ConnectionManager,
    key_prefix: String,
    command_timeout: Duration,
}

impl RedisCacheStorage {
    pub async fn new(
        redis_url: &str,
        key_prefix: &str,
        command_timeout_seconds: u64,
    ) -> StorageResult<Self> {
        let client = Client::open(redis_url)
            .map_err(|e| StorageError::Connection(format!("Redis client error: {}", e)))?;

        let connection = client
            .get_connection_manager()
            .await
            .map_err(|e| StorageError::Connection(format!("Redis connection error: {}", e)))?;

        Ok(Self {
            connection,
            key_prefix: key_prefix.to_string(),
            command_timeout: Duration::from_secs(command_timeout_seconds),
        })
    }

    fn validation_key(&self, key: &str) -> String {
        format!("{}validation:{}", self.key_prefix, key)
    }

    fn state_key(&self, key: &str) -> String {
        format!("{}state:{}", self.key_prefix, key)
    }

    fn rate_limit_key(&self, key: &str) -> String {
        format!("{}rate_limit:{}", self.key_prefix, key)
    }

    async fn set_with_ttl<T: Serialize>(
        &self,
        key: &str,
        value: &T,
        ttl_seconds: u64,
    ) -> StorageResult<()> {
        let serialized = serde_json::to_string(value)
            .map_err(|e| StorageError::Serialization(format!("Serialization error: {}", e)))?;

        let mut conn = self.connection.clone();

        timeout(self.command_timeout, async {
            let _: () = conn.set_ex(key, serialized, ttl_seconds).await?;
            Ok::<(), RedisError>(())
        })
        .await
        .map_err(|_| StorageError::Redis("Command timeout".to_string()))?
        .map_err(|e: RedisError| StorageError::Redis(format!("Redis SET error: {}", e)))?;

        Ok(())
    }

    async fn get_and_deserialize<T: for<'de> Deserialize<'de>>(
        &self,
        key: &str,
    ) -> StorageResult<Option<T>> {
        let mut conn = self.connection.clone();

        let result: Option<String> = timeout(self.command_timeout, async { conn.get(key).await })
            .await
            .map_err(|_| StorageError::Redis("Command timeout".to_string()))?
            .map_err(|e: RedisError| StorageError::Redis(format!("Redis GET error: {}", e)))?;

        match result {
            Some(data) => {
                let deserialized = serde_json::from_str(&data).map_err(|e| {
                    StorageError::Serialization(format!("Deserialization error: {}", e))
                })?;
                Ok(Some(deserialized))
            }
            None => Ok(None),
        }
    }

    async fn delete_key(&self, key: &str) -> StorageResult<()> {
        let mut conn = self.connection.clone();

        timeout(self.command_timeout, async {
            let _: () = conn.del(key).await?;
            Ok::<(), RedisError>(())
        })
        .await
        .map_err(|_| StorageError::Redis("Command timeout".to_string()))?
        .map_err(|e: RedisError| StorageError::Redis(format!("Redis DEL error: {}", e)))?;

        Ok(())
    }
}

#[async_trait]
impl CacheStorage for RedisCacheStorage {
    async fn store_validation(
        &self,
        key: &str,
        validation: &CachedValidation,
        ttl_seconds: u64,
    ) -> StorageResult<()> {
        let redis_key = self.validation_key(key);
        self.set_with_ttl(&redis_key, validation, ttl_seconds).await
    }

    async fn get_validation(&self, key: &str) -> StorageResult<Option<CachedValidation>> {
        let redis_key = self.validation_key(key);
        self.get_and_deserialize(&redis_key).await
    }

    async fn delete_validation(&self, key: &str) -> StorageResult<()> {
        let redis_key = self.validation_key(key);
        self.delete_key(&redis_key).await
    }

    async fn store_state(
        &self,
        key: &str,
        state: &StateData,
        ttl_seconds: u64,
    ) -> StorageResult<()> {
        let redis_key = self.state_key(key);
        self.set_with_ttl(&redis_key, state, ttl_seconds).await
    }

    async fn get_state(&self, key: &str) -> StorageResult<Option<StateData>> {
        let redis_key = self.state_key(key);
        self.get_and_deserialize(&redis_key).await
    }

    async fn delete_state(&self, key: &str) -> StorageResult<()> {
        let redis_key = self.state_key(key);
        self.delete_key(&redis_key).await
    }

    async fn store_rate_limit(
        &self,
        key: &str,
        rate_limit: &RateLimitData,
        ttl_seconds: u64,
    ) -> StorageResult<()> {
        let redis_key = self.rate_limit_key(key);
        self.set_with_ttl(&redis_key, rate_limit, ttl_seconds).await
    }

    async fn get_rate_limit(&self, key: &str) -> StorageResult<Option<RateLimitData>> {
        let redis_key = self.rate_limit_key(key);
        self.get_and_deserialize(&redis_key).await
    }

    async fn delete_rate_limit(&self, key: &str) -> StorageResult<()> {
        let redis_key = self.rate_limit_key(key);
        self.delete_key(&redis_key).await
    }

    async fn clear_all(&self) -> StorageResult<()> {
        let mut conn = self.connection.clone();

        // Get all keys with our prefix
        let pattern = format!("{}*", self.key_prefix);
        let keys: Vec<String> = timeout(self.command_timeout, async { conn.keys(pattern).await })
            .await
            .map_err(|_| StorageError::Redis("Command timeout".to_string()))?
            .map_err(|e: RedisError| StorageError::Redis(format!("Redis KEYS error: {}", e)))?;

        if !keys.is_empty() {
            timeout(self.command_timeout, async {
                let _: () = conn.del(keys).await?;
                Ok::<(), RedisError>(())
            })
            .await
            .map_err(|_| StorageError::Redis("Command timeout".to_string()))?
            .map_err(|e: RedisError| StorageError::Redis(format!("Redis DEL error: {}", e)))?;
        }

        Ok(())
    }

    async fn health_check(&self) -> StorageResult<()> {
        let mut conn = self.connection.clone();

        timeout(self.command_timeout, async {
            let _: String = redis::cmd("PING").query_async(&mut conn).await?;
            Ok::<(), RedisError>(())
        })
        .await
        .map_err(|_| StorageError::Redis("Health check timeout".to_string()))?
        .map_err(|e: RedisError| StorageError::Redis(format!("Redis health check error: {}", e)))?;

        Ok(())
    }
}

/// Redis configuration
#[derive(Debug, Clone)]
pub struct RedisConfig {
    pub url: String,
    pub key_prefix: String,
    pub command_timeout_seconds: u64,
    pub max_connections: u32,
}

impl Default for RedisConfig {
    fn default() -> Self {
        Self {
            url: "redis://localhost:6379".to_string(),
            key_prefix: "bedrock_sso:".to_string(),
            command_timeout_seconds: 5,
            max_connections: 10,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use tokio::time::{Duration, sleep};

    async fn setup_redis() -> Option<RedisCacheStorage> {
        // Only run Redis tests if Redis is available
        RedisCacheStorage::new("redis://localhost:6379", "test:", 5)
            .await
            .ok()
    }

    #[tokio::test]
    async fn test_redis_cache_storage() {
        let Some(cache) = setup_redis().await else {
            println!("Redis not available, skipping Redis tests");
            return;
        };

        // Clear any existing test data
        cache.clear_all().await.unwrap();

        let validation = CachedValidation {
            user_id: "user123".to_string(),
            provider: "google".to_string(),
            email: "user@example.com".to_string(),
            validated_at: Utc::now(),
            expires_at: Utc::now() + chrono::Duration::hours(1),
            scopes: vec!["read".to_string()],
        };

        // Test store and retrieve
        cache
            .store_validation("key1", &validation, 3600)
            .await
            .unwrap();
        let retrieved = cache.get_validation("key1").await.unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().user_id, "user123");

        // Test TTL expiration
        cache
            .store_validation("key2", &validation, 1)
            .await
            .unwrap();
        sleep(Duration::from_secs(2)).await;
        let expired = cache.get_validation("key2").await.unwrap();
        assert!(expired.is_none());

        // Test deletion
        cache.delete_validation("key1").await.unwrap();
        let deleted = cache.get_validation("key1").await.unwrap();
        assert!(deleted.is_none());

        // Test health check
        cache.health_check().await.unwrap();

        // Clean up
        cache.clear_all().await.unwrap();
    }

    #[tokio::test]
    async fn test_redis_state_storage() {
        let Some(cache) = setup_redis().await else {
            println!("Redis not available, skipping Redis tests");
            return;
        };

        // Clear any existing test data
        cache.clear_all().await.unwrap();

        let state = StateData {
            provider: "google".to_string(),
            redirect_uri: "https://example.com/callback".to_string(),
            created_at: Utc::now(),
            expires_at: Utc::now() + chrono::Duration::minutes(10),
        };

        // Test store and retrieve
        cache.store_state("state123", &state, 600).await.unwrap();
        let retrieved = cache.get_state("state123").await.unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().provider, "google");

        // Test deletion
        cache.delete_state("state123").await.unwrap();
        let deleted = cache.get_state("state123").await.unwrap();
        assert!(deleted.is_none());

        // Clean up
        cache.clear_all().await.unwrap();
    }

    #[tokio::test]
    async fn test_redis_rate_limit_storage() {
        let Some(cache) = setup_redis().await else {
            println!("Redis not available, skipping Redis tests");
            return;
        };

        // Clear any existing test data
        cache.clear_all().await.unwrap();

        let rate_limit = RateLimitData {
            attempts: 5,
            window_start: Utc::now(),
            blocked_until: Some(Utc::now() + chrono::Duration::minutes(15)),
        };

        // Test store and retrieve
        cache
            .store_rate_limit("user123", &rate_limit, 3600)
            .await
            .unwrap();
        let retrieved = cache.get_rate_limit("user123").await.unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().attempts, 5);

        // Test deletion
        cache.delete_rate_limit("user123").await.unwrap();
        let deleted = cache.get_rate_limit("user123").await.unwrap();
        assert!(deleted.is_none());

        // Clean up
        cache.clear_all().await.unwrap();
    }
}
