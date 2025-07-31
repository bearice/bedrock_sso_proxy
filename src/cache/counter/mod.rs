//! Enum-based atomic counter system for usage caps and rate limiting
//!
//! This module provides thread-safe hash-based counters using Redis HINCRBY operations.
//! Counters are stored as Redis hashes with automatic TTL management and type prefixes.

use super::{CacheError, CacheResult};
use async_trait::async_trait;
use std::collections::HashMap;
use std::time::Duration;

pub mod memory;
pub mod redis;

pub use memory::MemoryHashCounter;
pub use redis::RedisHashCounter;

/// Trait for counter field enums - auto-implemented by typed_counter macro
pub trait CounterField:
    Clone + Send + Sync + std::fmt::Debug + PartialEq + Eq + std::hash::Hash + 'static
{
    /// Get the string representation of this field for Redis hash operations
    fn field_name(&self) -> &'static str;

    /// Get all possible field variants
    fn all_fields() -> Vec<Self>;

    /// Optional default TTL for counters of this type
    fn default_ttl() -> Option<Duration> {
        None
    }

    /// Generate counter prefix from type name (like CachedObject::cache_prefix)
    fn counter_prefix() -> &'static str;
}

/// Hash-based atomic counter operations for a specific enum type
#[async_trait]
pub trait HashCounter<T: CounterField>: Send + Sync {
    /// Increment field in hash by amount, returns new value
    async fn increment(&self, field: T, amount: i64) -> CacheResult<i64>;

    /// Decrement field in hash by amount, returns new value
    async fn decrement(&self, field: T, amount: i64) -> CacheResult<i64>;

    /// Get field value from hash
    async fn get(&self, field: T) -> CacheResult<Option<i64>>;

    /// Set field to specific value
    async fn set(&self, field: T, value: i64) -> CacheResult<()>;

    /// Get all fields and values from hash
    async fn get_all(&self) -> CacheResult<HashMap<T, i64>>;

    /// Set multiple fields at once
    async fn set_multiple(&self, fields: &[(T, i64)]) -> CacheResult<()>;

    /// Increment multiple fields at once, returns new values
    async fn increment_multiple(&self, updates: &[(T, i64)]) -> CacheResult<HashMap<T, i64>>;

    /// Delete field from hash
    async fn delete_field(&self, field: T) -> CacheResult<()>;

    /// Check if field exists in hash
    async fn field_exists(&self, field: T) -> CacheResult<bool>;

    /// Reset field to zero
    async fn reset_field(&self, field: T) -> CacheResult<()>;

    /// Delete entire hash
    async fn delete_hash(&self) -> CacheResult<()>;

    /// Check if hash exists
    async fn exists(&self) -> CacheResult<bool>;

    /// Set TTL for entire hash
    async fn set_ttl(&self, ttl: Duration) -> CacheResult<()>;

    /// Get TTL remaining for hash
    async fn get_ttl(&self) -> CacheResult<Option<Duration>>;
}

/// Hash counter backend implementations
#[derive(Clone)]
pub enum HashCounterBackend<T: CounterField> {
    Memory(MemoryHashCounter<T>),
    Redis(RedisHashCounter<T>),
}

/// Typed hash counter with automatic TTL and type prefix
#[derive(Clone)]
pub struct TypedHashCounter<T: CounterField> {
    backend: HashCounterBackend<T>,
    prefix: &'static str,
    key: String,
    _phantom: std::marker::PhantomData<T>,
}

impl<T: CounterField> TypedHashCounter<T> {
    /// Create new typed hash counter with type prefix
    pub fn new(backend: HashCounterBackend<T>, key: &str) -> Self {
        let prefix = T::counter_prefix();
        let prefixed_key = format!("{}:{}", prefix, key);

        Self {
            backend,
            prefix,
            key: prefixed_key,
            _phantom: std::marker::PhantomData,
        }
    }

    /// Get the counter prefix
    pub fn prefix(&self) -> &str {
        self.prefix
    }

    /// Get the full prefixed key
    pub fn key(&self) -> &str {
        &self.key
    }

    /// Initialize counter with default TTL if specified by the enum type
    pub async fn init_with_default_ttl(&self) -> CacheResult<()> {
        if let Some(ttl) = T::default_ttl() {
            self.set_ttl(ttl).await?;
        }
        Ok(())
    }
}

/// Macro to generate HashCounter methods with enum delegation
macro_rules! impl_enum_delegation {
    ($($method:ident($($param:ident: $param_type:ty),*) -> $return_type:ty;)*) => {
        $(
            pub async fn $method(&self, $($param: $param_type),*) -> CacheResult<$return_type> {
                match &self.backend {
                    HashCounterBackend::Memory(counter) => counter.$method($($param),*).await,
                    HashCounterBackend::Redis(counter) => counter.$method($($param),*).await,
                }
            }
        )*
    };
}
impl<T: CounterField> TypedHashCounter<T> {
    impl_enum_delegation! {
        increment(field: T, amount: i64) -> i64;
        decrement(field: T, amount: i64) -> i64;
        get(field: T) -> Option<i64>;
        set(field: T, value: i64) -> ();
        get_all() -> HashMap<T, i64>;
        set_multiple(fields: &[(T, i64)]) -> ();
        increment_multiple(updates: &[(T, i64)]) -> HashMap<T, i64>;
        delete_field(field: T) -> ();
        field_exists(field: T) -> bool;
        reset_field(field: T) -> ();
        delete_hash() -> ();
        exists() -> bool;
        set_ttl(ttl: Duration) -> ();
        get_ttl() -> Option<Duration>;
    }
}
// Export macro for convenience
pub use typed_cache_macro::typed_counter;

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[typed_counter(ttl = 300)]
    enum TestUsageCounter {
        Requests,
        InputTokens,
        OutputTokens,
        CostCents,
    }

    #[typed_counter]
    enum TestRateLimitCounter {
        Count,
        WindowStart,
        WindowEnd,
    }

    #[tokio::test]
    async fn test_counter_field_trait() {
        // Test field name conversion
        assert_eq!(TestUsageCounter::Requests.field_name(), "Requests");
        assert_eq!(TestUsageCounter::InputTokens.field_name(), "InputTokens");
        assert_eq!(TestUsageCounter::OutputTokens.field_name(), "OutputTokens");
        assert_eq!(TestUsageCounter::CostCents.field_name(), "CostCents");

        // Test all_fields
        let all_fields = TestUsageCounter::all_fields();
        assert_eq!(all_fields.len(), 4);
        assert!(all_fields.contains(&TestUsageCounter::Requests));
        assert!(all_fields.contains(&TestUsageCounter::InputTokens));
        assert!(all_fields.contains(&TestUsageCounter::OutputTokens));
        assert!(all_fields.contains(&TestUsageCounter::CostCents));

        // Test default TTL
        assert_eq!(
            TestUsageCounter::default_ttl(),
            Some(Duration::from_secs(300))
        );
        assert_eq!(TestRateLimitCounter::default_ttl(), None);

        // Test counter prefix
        assert_eq!(TestUsageCounter::counter_prefix(), "TestUsageCounter");
        assert_eq!(
            TestRateLimitCounter::counter_prefix(),
            "TestRateLimitCounter"
        );
    }

    #[tokio::test]
    async fn test_typed_hash_counter_prefix() {
        let backend =
            HashCounterBackend::Memory(MemoryHashCounter::new("test_counter:user_123".to_string()));
        let counter = TypedHashCounter::<TestUsageCounter>::new(backend, "user_123");

        // Test prefix and key generation
        assert_eq!(counter.prefix(), "TestUsageCounter");
        assert_eq!(counter.key(), "TestUsageCounter:user_123");
    }

    #[tokio::test]
    async fn test_different_counter_types_isolation() {
        let usage_backend = HashCounterBackend::Memory(MemoryHashCounter::new(
            "TestUsageCounter:user_123".to_string(),
        ));
        let usage_counter = TypedHashCounter::<TestUsageCounter>::new(usage_backend, "user_123");

        let rate_backend = HashCounterBackend::Memory(MemoryHashCounter::new(
            "TestRateLimitCounter:user_123".to_string(),
        ));
        let rate_counter = TypedHashCounter::<TestRateLimitCounter>::new(rate_backend, "user_123");

        // Same user key but different prefixes should be isolated
        usage_counter
            .increment(TestUsageCounter::Requests, 5)
            .await
            .unwrap();
        rate_counter
            .increment(TestRateLimitCounter::Count, 10)
            .await
            .unwrap();

        assert_eq!(
            usage_counter.get(TestUsageCounter::Requests).await.unwrap(),
            Some(5)
        );
        assert_eq!(
            rate_counter.get(TestRateLimitCounter::Count).await.unwrap(),
            Some(10)
        );

        // Verify they have different keys due to type prefixes
        assert_ne!(usage_counter.key(), rate_counter.key());
        assert_eq!(usage_counter.key(), "TestUsageCounter:user_123");
        assert_eq!(rate_counter.key(), "TestRateLimitCounter:user_123");
    }
}
