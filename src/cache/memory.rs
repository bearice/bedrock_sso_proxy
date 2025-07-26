use super::{Cache, CacheError, CacheResult};
use chrono::{DateTime, Utc};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Cache entry with expiration
#[derive(Clone, Debug)]
struct CacheEntry {
    data: String,
    expires_at: Option<DateTime<Utc>>,
}

impl CacheEntry {
    fn new(data: String, ttl: Option<std::time::Duration>) -> Self {
        let expires_at =
            ttl.map(|duration| Utc::now() + chrono::Duration::from_std(duration).unwrap());
        Self { data, expires_at }
    }

    fn is_expired(&self) -> bool {
        self.expires_at.is_some_and(|exp| Utc::now() > exp)
    }
}

/// In-memory cache implementation
pub struct MemoryCache {
    store: Arc<RwLock<HashMap<String, CacheEntry>>>,
}

impl MemoryCache {
    /// Create new memory cache
    pub fn new() -> Self {
        Self {
            store: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

impl Default for MemoryCache {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl Cache for MemoryCache {
    async fn get<T>(&self, key: &str) -> CacheResult<Option<T>>
    where
        T: serde::de::DeserializeOwned + Send,
    {
        let store = self.store.read().await;

        if let Some(entry) = store.get(key) {
            if entry.is_expired() {
                drop(store);
                // Clean up expired entry
                let mut store = self.store.write().await;
                store.remove(key);
                return Ok(None);
            }

            let value = serde_json::from_str(&entry.data)
                .map_err(|e| CacheError::Serialization(e.to_string()))?;
            Ok(Some(value))
        } else {
            Ok(None)
        }
    }

    async fn set<T>(
        &self,
        key: &str,
        value: &T,
        ttl: Option<std::time::Duration>,
    ) -> CacheResult<()>
    where
        T: serde::Serialize + Send + Sync,
    {
        let data =
            serde_json::to_string(value).map_err(|e| CacheError::Serialization(e.to_string()))?;

        let entry = CacheEntry::new(data, ttl);

        let mut store = self.store.write().await;
        store.insert(key.to_string(), entry);

        Ok(())
    }

    async fn delete(&self, key: &str) -> CacheResult<()> {
        let mut store = self.store.write().await;
        store.remove(key);
        Ok(())
    }

    async fn exists(&self, key: &str) -> CacheResult<bool> {
        let store = self.store.read().await;

        if let Some(entry) = store.get(key) {
            if entry.is_expired() {
                drop(store);
                // Clean up expired entry
                let mut store = self.store.write().await;
                store.remove(key);
                return Ok(false);
            }
            Ok(true)
        } else {
            Ok(false)
        }
    }

    async fn clear(&self) -> CacheResult<()> {
        let mut store = self.store.write().await;
        store.clear();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn test_memory_cache_basic_operations() {
        let cache = MemoryCache::new();

        // Test set and get
        cache.set("key1", &"value1", None).await.unwrap();
        let value: Option<String> = cache.get("key1").await.unwrap();
        assert_eq!(value, Some("value1".to_string()));

        // Test exists
        assert!(cache.exists("key1").await.unwrap());
        assert!(!cache.exists("nonexistent").await.unwrap());

        // Test delete
        cache.delete("key1").await.unwrap();
        let value: Option<String> = cache.get("key1").await.unwrap();
        assert_eq!(value, None);
    }

    #[tokio::test]
    async fn test_memory_cache_expiration() {
        let cache = MemoryCache::new();

        // Set with very short TTL
        cache
            .set("key1", &"value1", Some(Duration::from_millis(50)))
            .await
            .unwrap();

        // Should exist immediately
        assert!(cache.exists("key1").await.unwrap());

        // Wait for expiration
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Should be expired
        assert!(!cache.exists("key1").await.unwrap());
        let value: Option<String> = cache.get("key1").await.unwrap();
        assert_eq!(value, None);
    }

    #[tokio::test]
    async fn test_memory_cache_clear() {
        let cache = MemoryCache::new();

        cache.set("key1", &"value1", None).await.unwrap();
        cache.set("key2", &"value2", None).await.unwrap();

        cache.clear().await.unwrap();

        let value1: Option<String> = cache.get("key1").await.unwrap();
        let value2: Option<String> = cache.get("key2").await.unwrap();
        assert_eq!(value1, None);
        assert_eq!(value2, None);
    }
}
