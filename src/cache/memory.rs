use super::CacheResult;
use chrono::{DateTime, Utc};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Cache entry with expiration - generic over type T
#[derive(Clone, Debug)]
struct CacheEntry<T> {
    data: T,
    expires_at: Option<DateTime<Utc>>,
}

impl<T: Clone> CacheEntry<T> {
    fn new(data: T, ttl: Option<std::time::Duration>) -> Self {
        let expires_at =
            ttl.map(|duration| Utc::now() + chrono::Duration::from_std(duration).unwrap());
        Self { data, expires_at }
    }

    fn is_expired(&self) -> bool {
        self.expires_at.is_some_and(|exp| Utc::now() > exp)
    }
}

/// Generic in-memory cache implementation
#[derive(Clone)]
pub struct MemoryCache<T> {
    store: Arc<RwLock<HashMap<String, CacheEntry<T>>>>,
}

impl<T> MemoryCache<T> {
    /// Create new memory cache
    pub fn new() -> Self {
        Self {
            store: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

impl<T> Default for MemoryCache<T> {
    fn default() -> Self {
        Self::new()
    }
}

/// Generic implementation for MemoryCache<T>
impl<T: Clone + Send + Sync + 'static> MemoryCache<T> {
    /// Get value by key
    pub async fn get(&self, key: &str) -> CacheResult<Option<T>> {
        let store = self.store.read().await;

        if let Some(entry) = store.get(key) {
            if entry.is_expired() {
                drop(store);
                // Clean up expired entry
                let mut store = self.store.write().await;
                store.remove(key);
                return Ok(None);
            }

            Ok(Some(entry.data.clone()))
        } else {
            Ok(None)
        }
    }

    /// Set value with optional expiration
    pub async fn set(&self, key: &str, value: &T, ttl: Option<std::time::Duration>) -> CacheResult<()> {
        let entry = CacheEntry::new(value.clone(), ttl);

        let mut store = self.store.write().await;
        store.insert(key.to_string(), entry);

        Ok(())
    }

    /// Delete key
    pub async fn delete(&self, key: &str) -> CacheResult<()> {
        let mut store = self.store.write().await;
        store.remove(key);
        Ok(())
    }

    /// Check if key exists
    pub async fn exists(&self, key: &str) -> CacheResult<bool> {
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

    /// Clear all cache entries
    pub async fn clear(&self) -> CacheResult<()> {
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
        let cache: MemoryCache<String> = MemoryCache::new();

        // Test set and get
        cache.set("key1", &"value1".to_string(), None).await.unwrap();
        let value = cache.get("key1").await.unwrap();
        assert_eq!(value, Some("value1".to_string()));

        // Test exists
        assert!(cache.exists("key1").await.unwrap());
        assert!(!cache.exists("nonexistent").await.unwrap());

        // Test delete
        cache.delete("key1").await.unwrap();
        let value = cache.get("key1").await.unwrap();
        assert_eq!(value, None);
    }

    #[tokio::test]
    async fn test_memory_cache_expiration() {
        let cache: MemoryCache<String> = MemoryCache::new();

        // Set with very short TTL
        cache
            .set("key1", &"value1".to_string(), Some(Duration::from_millis(50)))
            .await
            .unwrap();

        // Should exist immediately
        assert!(cache.exists("key1").await.unwrap());

        // Wait for expiration
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Should be expired
        assert!(!cache.exists("key1").await.unwrap());
        let value = cache.get("key1").await.unwrap();
        assert_eq!(value, None);
    }

    #[tokio::test]
    async fn test_memory_cache_clear() {
        let cache: MemoryCache<String> = MemoryCache::new();

        cache.set("key1", &"value1".to_string(), None).await.unwrap();
        cache.set("key2", &"value2".to_string(), None).await.unwrap();

        cache.clear().await.unwrap();

        let value1 = cache.get("key1").await.unwrap();
        let value2 = cache.get("key2").await.unwrap();
        assert_eq!(value1, None);
        assert_eq!(value2, None);
    }

    #[tokio::test]
    async fn test_generic_cache_works() {
        let cache: MemoryCache<i32> = MemoryCache::new();

        // Test that generic cache works with direct types
        cache.set("number_key", &42i32, None).await.unwrap();
        let value = cache.get("number_key").await.unwrap();
        assert_eq!(value, Some(42));
    }
}
