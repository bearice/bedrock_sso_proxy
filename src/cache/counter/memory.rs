//! Memory-based hash counter implementation

use super::{CacheResult, CounterField, HashCounter};
use crate::cache::SharedMemoryStore;
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

/// Hash entry with expiration support for memory backend
#[derive(Clone, Debug)]
pub struct HashEntry<T: CounterField> {
    pub fields: HashMap<T, i64>,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
}

impl<T: CounterField> HashEntry<T> {
    pub fn new() -> Self {
        Self {
            fields: HashMap::new(),
            expires_at: None,
        }
    }

    pub fn is_expired(&self) -> bool {
        self.expires_at.is_some_and(|exp| chrono::Utc::now() > exp)
    }

    pub fn set_ttl(&mut self, ttl: Duration) {
        self.expires_at = Some(chrono::Utc::now() + chrono::Duration::from_std(ttl).unwrap());
    }

    pub fn get_ttl(&self) -> Option<Duration> {
        self.expires_at.map(|exp| {
            let remaining = exp - chrono::Utc::now();
            Duration::from_secs(remaining.num_seconds().max(0) as u64)
        })
    }
}

impl<T: CounterField> Default for HashEntry<T> {
    fn default() -> Self {
        Self::new()
    }
}

/// Memory-based hash counter implementation
#[derive(Clone)]
pub struct MemoryHashCounter<T: CounterField> {
    key: String,
    store: Arc<RwLock<HashEntry<T>>>,
    shared_store: Option<SharedMemoryStore>,
}

impl<T: CounterField> MemoryHashCounter<T> {
    /// Create new memory-based hash counter (isolated storage)
    pub fn new(key: String) -> Self {
        Self {
            key,
            store: Arc::new(RwLock::new(HashEntry::new())),
            shared_store: None,
        }
    }

    /// Create memory-based hash counter from shared store (shared storage)
    pub fn from_shared_store(shared_store: SharedMemoryStore, key: String) -> Self {
        Self {
            key,
            store: Arc::new(RwLock::new(HashEntry::new())), // Will be lazily loaded from shared store
            shared_store: Some(shared_store),
        }
    }

    /// Load data from shared store if using shared storage
    async fn load_from_shared(&self) -> CacheResult<()> {
        if let Some(shared_store) = &self.shared_store {
            let shared = shared_store.read().await;
            if let Some(boxed_entry) = shared.get(&self.key) {
                if let Some(entry) = boxed_entry.downcast_ref::<HashEntry<T>>() {
                    let mut store = self.store.write().await;
                    *store = entry.clone();
                }
            }
        }
        Ok(())
    }

    /// Save data to shared store if using shared storage
    async fn save_to_shared(&self) -> CacheResult<()> {
        if let Some(shared_store) = &self.shared_store {
            let store = self.store.read().await;
            let mut shared = shared_store.write().await;
            shared.insert(self.key.clone(), Box::new(store.clone()));
        }
        Ok(())
    }

    /// Check and clean up if expired
    async fn check_expiry(&self) -> CacheResult<bool> {
        // Load from shared store first if using shared storage
        self.load_from_shared().await?;

        let store = self.store.read().await;
        if store.is_expired() {
            drop(store);
            let mut store = self.store.write().await;
            store.fields.clear();
            store.expires_at = None;

            // Save cleared state to shared store
            drop(store);
            self.save_to_shared().await?;
            return Ok(false); // Hash was expired
        }
        Ok(true) // Hash is valid
    }

    /// Get the counter key
    pub fn key(&self) -> &str {
        &self.key
    }
}

#[async_trait]
impl<T: CounterField> HashCounter<T> for MemoryHashCounter<T> {
    async fn increment(&self, field: T, amount: i64) -> CacheResult<i64> {
        self.check_expiry().await?;
        let mut store = self.store.write().await;
        let current = store.fields.get(&field).unwrap_or(&0);
        let new_value = current + amount;
        store.fields.insert(field, new_value);
        drop(store);
        self.save_to_shared().await?;
        Ok(new_value)
    }

    async fn decrement(&self, field: T, amount: i64) -> CacheResult<i64> {
        self.check_expiry().await?;
        let mut store = self.store.write().await;
        let current = store.fields.get(&field).unwrap_or(&0);
        let new_value = current - amount;
        store.fields.insert(field, new_value);
        drop(store);
        self.save_to_shared().await?;
        Ok(new_value)
    }

    async fn get(&self, field: T) -> CacheResult<Option<i64>> {
        if !self.check_expiry().await? {
            return Ok(None);
        }
        let store = self.store.read().await;
        Ok(store.fields.get(&field).copied())
    }

    async fn set(&self, field: T, value: i64) -> CacheResult<()> {
        self.check_expiry().await?;
        let mut store = self.store.write().await;
        store.fields.insert(field, value);
        drop(store);
        self.save_to_shared().await?;
        Ok(())
    }

    async fn get_all(&self) -> CacheResult<HashMap<T, i64>> {
        if !self.check_expiry().await? {
            return Ok(HashMap::new());
        }
        let store = self.store.read().await;
        Ok(store.fields.clone())
    }

    async fn set_multiple(&self, fields: &[(T, i64)]) -> CacheResult<()> {
        self.check_expiry().await?;
        let mut store = self.store.write().await;
        for (field, value) in fields {
            store.fields.insert(field.clone(), *value);
        }
        drop(store);
        self.save_to_shared().await?;
        Ok(())
    }

    async fn increment_multiple(&self, updates: &[(T, i64)]) -> CacheResult<HashMap<T, i64>> {
        self.check_expiry().await?;
        let mut store = self.store.write().await;
        let mut results = HashMap::new();

        for (field, amount) in updates {
            let current = store.fields.get(field).unwrap_or(&0);
            let new_value = current + amount;
            store.fields.insert(field.clone(), new_value);
            results.insert(field.clone(), new_value);
        }
        drop(store);
        self.save_to_shared().await?;

        Ok(results)
    }

    async fn delete_field(&self, field: T) -> CacheResult<()> {
        self.check_expiry().await?;
        let mut store = self.store.write().await;
        store.fields.remove(&field);
        drop(store);
        self.save_to_shared().await?;
        Ok(())
    }

    async fn field_exists(&self, field: T) -> CacheResult<bool> {
        if !self.check_expiry().await? {
            return Ok(false);
        }
        let store = self.store.read().await;
        Ok(store.fields.contains_key(&field))
    }

    async fn reset_field(&self, field: T) -> CacheResult<()> {
        self.check_expiry().await?;
        let mut store = self.store.write().await;
        store.fields.insert(field, 0);
        drop(store);
        self.save_to_shared().await?;
        Ok(())
    }

    async fn delete_hash(&self) -> CacheResult<()> {
        let mut store = self.store.write().await;
        store.fields.clear();
        store.expires_at = None;
        drop(store);
        self.save_to_shared().await?;
        Ok(())
    }

    async fn exists(&self) -> CacheResult<bool> {
        if !self.check_expiry().await? {
            return Ok(false);
        }
        let store = self.store.read().await;
        Ok(!store.fields.is_empty())
    }

    async fn set_ttl(&self, ttl: Duration) -> CacheResult<()> {
        let mut store = self.store.write().await;
        store.set_ttl(ttl);
        drop(store);
        self.save_to_shared().await?;
        Ok(())
    }

    async fn get_ttl(&self) -> CacheResult<Option<Duration>> {
        let store = self.store.read().await;
        Ok(store.get_ttl())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use typed_cache_macro::typed_counter;

    #[typed_counter(ttl = 300)]
    enum TestField {
        Count,
        Value,
    }

    #[tokio::test]
    async fn test_memory_hash_counter_basic_operations() {
        let counter = MemoryHashCounter::new("test_key".to_string());

        // Test increment
        let result = counter.increment(TestField::Count, 5).await.unwrap();
        assert_eq!(result, 5);

        // Test get
        let value = counter.get(TestField::Count).await.unwrap();
        assert_eq!(value, Some(5));

        // Test increment again
        let result = counter.increment(TestField::Count, 3).await.unwrap();
        assert_eq!(result, 8);

        // Test decrement
        let result = counter.decrement(TestField::Count, 2).await.unwrap();
        assert_eq!(result, 6);

        // Test set
        counter.set(TestField::Value, 100).await.unwrap();
        let value = counter.get(TestField::Value).await.unwrap();
        assert_eq!(value, Some(100));

        // Test reset
        counter.reset_field(TestField::Count).await.unwrap();
        let value = counter.get(TestField::Count).await.unwrap();
        assert_eq!(value, Some(0));

        // Test delete field
        counter.delete_field(TestField::Value).await.unwrap();
        let value = counter.get(TestField::Value).await.unwrap();
        assert_eq!(value, None);
    }

    #[tokio::test]
    async fn test_memory_hash_counter_multiple_operations() {
        let counter = MemoryHashCounter::new("test_key".to_string());

        // Test set_multiple
        let fields = vec![(TestField::Count, 10), (TestField::Value, 20)];
        counter.set_multiple(&fields).await.unwrap();

        // Test get_all
        let all_fields = counter.get_all().await.unwrap();
        assert_eq!(all_fields.get(&TestField::Count), Some(&10));
        assert_eq!(all_fields.get(&TestField::Value), Some(&20));

        // Test increment_multiple
        let updates = vec![(TestField::Count, 5), (TestField::Value, 15)];
        let results = counter.increment_multiple(&updates).await.unwrap();
        assert_eq!(results.get(&TestField::Count), Some(&15));
        assert_eq!(results.get(&TestField::Value), Some(&35));

        // Verify final values
        assert_eq!(counter.get(TestField::Count).await.unwrap(), Some(15));
        assert_eq!(counter.get(TestField::Value).await.unwrap(), Some(35));
    }

    #[tokio::test]
    async fn test_memory_hash_counter_ttl() {
        let counter = MemoryHashCounter::new("test_key".to_string());

        // Set some fields
        counter.set(TestField::Count, 10).await.unwrap();
        counter.set(TestField::Value, 20).await.unwrap();

        // Set TTL
        counter.set_ttl(Duration::from_millis(50)).await.unwrap();

        // Should exist immediately
        assert!(counter.exists().await.unwrap());
        assert_eq!(counter.get(TestField::Count).await.unwrap(), Some(10));

        // Wait for expiration
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Should be expired
        assert!(!counter.exists().await.unwrap());
        assert_eq!(counter.get(TestField::Count).await.unwrap(), None);
    }

    #[tokio::test]
    async fn test_memory_hash_counter_exists_and_delete() {
        let counter = MemoryHashCounter::new("test_key".to_string());

        // Initially should not exist
        assert!(!counter.exists().await.unwrap());

        // Add a field
        counter.set(TestField::Count, 5).await.unwrap();
        assert!(counter.exists().await.unwrap());
        assert!(counter.field_exists(TestField::Count).await.unwrap());
        assert!(!counter.field_exists(TestField::Value).await.unwrap());

        // Delete entire hash
        counter.delete_hash().await.unwrap();
        assert!(!counter.exists().await.unwrap());
        assert!(!counter.field_exists(TestField::Count).await.unwrap());
    }
}
