use super::{CacheStorage, CachedValidation, StateData, StorageResult};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use dashmap::DashMap;
use std::sync::Arc;
use tokio::time::{Duration, sleep};

/// TTL entry wrapper for cache data
#[derive(Clone, Debug)]
struct TtlEntry<T> {
    data: T,
    expires_at: DateTime<Utc>,
}

impl<T> TtlEntry<T> {
    fn new(data: T, ttl_seconds: u64) -> Self {
        Self {
            data,
            expires_at: Utc::now() + chrono::Duration::seconds(ttl_seconds as i64),
        }
    }

    fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }
}

/// In-memory cache storage implementation
pub struct MemoryCacheStorage {
    validations: Arc<DashMap<String, TtlEntry<CachedValidation>>>,
    states: Arc<DashMap<String, TtlEntry<StateData>>>,
    cleanup_interval: Duration,
}

impl MemoryCacheStorage {
    pub fn new(cleanup_interval_seconds: u64) -> Self {
        let storage = Self {
            validations: Arc::new(DashMap::new()),
            states: Arc::new(DashMap::new()),
            cleanup_interval: Duration::from_secs(cleanup_interval_seconds),
        };

        // Start cleanup task
        storage.start_cleanup_task();
        storage
    }

    fn start_cleanup_task(&self) {
        let validations = self.validations.clone();
        let states = self.states.clone();
        let interval = self.cleanup_interval;

        tokio::spawn(async move {
            loop {
                sleep(interval).await;

                // Clean up expired validations
                validations.retain(|_, entry| !entry.is_expired());

                // Clean up expired states
                states.retain(|_, entry| !entry.is_expired());
            }
        });
    }

    fn get_non_expired<T: Clone>(
        &self,
        map: &DashMap<String, TtlEntry<T>>,
        key: &str,
    ) -> Option<T> {
        map.get(key).and_then(|entry| {
            if entry.is_expired() {
                drop(entry);
                map.remove(key);
                None
            } else {
                Some(entry.data.clone())
            }
        })
    }
}

#[async_trait]
impl CacheStorage for MemoryCacheStorage {
    async fn store_validation(
        &self,
        key: &str,
        validation: &CachedValidation,
        ttl_seconds: u64,
    ) -> StorageResult<()> {
        self.validations.insert(
            key.to_string(),
            TtlEntry::new(validation.clone(), ttl_seconds),
        );
        Ok(())
    }

    async fn get_validation(&self, key: &str) -> StorageResult<Option<CachedValidation>> {
        Ok(self.get_non_expired(&self.validations, key))
    }

    async fn delete_validation(&self, key: &str) -> StorageResult<()> {
        self.validations.remove(key);
        Ok(())
    }

    async fn store_state(
        &self,
        key: &str,
        state: &StateData,
        ttl_seconds: u64,
    ) -> StorageResult<()> {
        self.states
            .insert(key.to_string(), TtlEntry::new(state.clone(), ttl_seconds));
        Ok(())
    }

    async fn get_state(&self, key: &str) -> StorageResult<Option<StateData>> {
        Ok(self.get_non_expired(&self.states, key))
    }

    async fn delete_state(&self, key: &str) -> StorageResult<()> {
        self.states.remove(key);
        Ok(())
    }

    async fn clear_all(&self) -> StorageResult<()> {
        self.validations.clear();
        self.states.clear();
        Ok(())
    }

    async fn health_check(&self) -> StorageResult<()> {
        // Memory storage is always healthy
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::{Duration, sleep};

    #[tokio::test]
    async fn test_memory_cache_storage() {
        let cache = MemoryCacheStorage::new(1); // 1 second cleanup interval

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
    }
}
