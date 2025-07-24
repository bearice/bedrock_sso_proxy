use super::{
    AuditLogEntry, CacheStorage, CachedValidation, DatabaseStorage,
    RefreshTokenData, StateData, StorageResult, UserRecord,
};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use dashmap::DashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicI32, Ordering};
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

/// In-memory database storage implementation
pub struct MemoryDatabaseStorage {
    users: Arc<DashMap<String, UserRecord>>, // key: provider:provider_user_id
    users_by_email: Arc<DashMap<String, UserRecord>>, // key: email
    refresh_tokens: Arc<DashMap<String, RefreshTokenData>>, // key: token_hash
    audit_logs: Arc<DashMap<i32, AuditLogEntry>>, // key: entry_id
    next_user_id: AtomicI32,
    next_audit_id: AtomicI32,
}

impl MemoryDatabaseStorage {
    pub fn new() -> Self {
        Self {
            users: Arc::new(DashMap::new()),
            users_by_email: Arc::new(DashMap::new()),
            refresh_tokens: Arc::new(DashMap::new()),
            audit_logs: Arc::new(DashMap::new()),
            next_user_id: AtomicI32::new(1),
            next_audit_id: AtomicI32::new(1),
        }
    }

    fn generate_user_key(provider: &str, provider_user_id: &str) -> String {
        format!("{}:{}", provider, provider_user_id)
    }
}

#[async_trait]
impl DatabaseStorage for MemoryDatabaseStorage {
    async fn upsert_user(&self, user: &UserRecord) -> StorageResult<i32> {
        let key = Self::generate_user_key(&user.provider, &user.provider_user_id);

        let user_id = if let Some(existing) = self.users.get(&key) {
            existing.id.unwrap_or(1)
        } else {
            self.next_user_id.fetch_add(1, Ordering::SeqCst)
        };

        let mut updated_user = user.clone();
        updated_user.id = Some(user_id);
        updated_user.updated_at = Utc::now();

        // Store in both maps
        self.users.insert(key, updated_user.clone());
        self.users_by_email.insert(user.email.clone(), updated_user);

        Ok(user_id)
    }

    async fn get_user_by_provider(
        &self,
        provider: &str,
        provider_user_id: &str,
    ) -> StorageResult<Option<UserRecord>> {
        let key = Self::generate_user_key(provider, provider_user_id);
        Ok(self.users.get(&key).map(|user| user.clone()))
    }

    async fn get_user_by_email(&self, email: &str) -> StorageResult<Option<UserRecord>> {
        Ok(self.users_by_email.get(email).map(|user| user.clone()))
    }

    async fn update_last_login(&self, user_id: i32) -> StorageResult<()> {
        let now = Utc::now();

        // Update in both maps
        for mut user in self.users.iter_mut() {
            if user.id == Some(user_id) {
                user.last_login = Some(now);
                user.updated_at = now;
                break;
            }
        }

        for mut user in self.users_by_email.iter_mut() {
            if user.id == Some(user_id) {
                user.last_login = Some(now);
                user.updated_at = now;
                break;
            }
        }

        Ok(())
    }

    async fn store_refresh_token(&self, token: &RefreshTokenData) -> StorageResult<()> {
        self.refresh_tokens
            .insert(token.token_hash.clone(), token.clone());
        Ok(())
    }

    async fn get_refresh_token(&self, token_hash: &str) -> StorageResult<Option<RefreshTokenData>> {
        Ok(self
            .refresh_tokens
            .get(token_hash)
            .map(|token| token.clone()))
    }

    async fn revoke_refresh_token(&self, token_hash: &str) -> StorageResult<()> {
        if let Some(mut token) = self.refresh_tokens.get_mut(token_hash) {
            token.revoked_at = Some(Utc::now());
        }
        Ok(())
    }

    async fn cleanup_expired_tokens(&self) -> StorageResult<u64> {
        let now = Utc::now();
        let mut removed_count = 0;

        self.refresh_tokens.retain(|_, token| {
            if token.expires_at <= now || token.revoked_at.is_some() {
                removed_count += 1;
                false
            } else {
                true
            }
        });

        Ok(removed_count)
    }

    async fn store_audit_log(&self, entry: &AuditLogEntry) -> StorageResult<()> {
        let id = self.next_audit_id.fetch_add(1, Ordering::SeqCst);
        let mut new_entry = entry.clone();
        new_entry.id = Some(id);
        new_entry.created_at = Utc::now();

        self.audit_logs.insert(id, new_entry);
        Ok(())
    }

    async fn get_audit_logs_for_user(
        &self,
        user_id: i32,
        limit: u32,
        offset: u32,
    ) -> StorageResult<Vec<AuditLogEntry>> {
        let mut logs: Vec<AuditLogEntry> = self
            .audit_logs
            .iter()
            .filter(|entry| entry.user_id == Some(user_id))
            .map(|entry| entry.clone())
            .collect();

        // Sort by created_at descending
        logs.sort_by(|a, b| b.created_at.cmp(&a.created_at));

        // Apply pagination
        let start = offset as usize;
        let end = start + limit as usize;

        if start < logs.len() {
            Ok(logs[start..end.min(logs.len())].to_vec())
        } else {
            Ok(vec![])
        }
    }

    async fn cleanup_old_audit_logs(&self, retention_days: u32) -> StorageResult<u64> {
        let cutoff_date = Utc::now() - chrono::Duration::days(retention_days as i64);
        let mut removed_count = 0;

        self.audit_logs.retain(|_, entry| {
            if entry.created_at < cutoff_date {
                removed_count += 1;
                false
            } else {
                true
            }
        });

        Ok(removed_count)
    }

    async fn health_check(&self) -> StorageResult<()> {
        // Memory storage is always healthy
        Ok(())
    }

    async fn migrate(&self) -> StorageResult<()> {
        // No migrations needed for memory storage
        Ok(())
    }
}

impl Default for MemoryDatabaseStorage {
    fn default() -> Self {
        Self::new()
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

    #[tokio::test]
    async fn test_memory_database_storage() {
        let db = MemoryDatabaseStorage::new();

        let user = UserRecord {
            id: None,
            provider_user_id: "user123".to_string(),
            provider: "google".to_string(),
            email: "user@example.com".to_string(),
            display_name: Some("Test User".to_string()),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            last_login: None,
        };

        // Test user upsert
        let user_id = db.upsert_user(&user).await.unwrap();
        assert_eq!(user_id, 1);

        // Test get user by provider
        let retrieved = db.get_user_by_provider("google", "user123").await.unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().email, "user@example.com");

        // Test get user by email
        let retrieved = db.get_user_by_email("user@example.com").await.unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().provider, "google");

        // Test refresh token storage
        let token = RefreshTokenData {
            token_hash: "hash123".to_string(),
            user_id: "user123".to_string(),
            provider: "google".to_string(),
            email: "user@example.com".to_string(),
            created_at: Utc::now(),
            expires_at: Utc::now() + chrono::Duration::days(90),
            rotation_count: 0,
            revoked_at: None,
        };

        db.store_refresh_token(&token).await.unwrap();
        let retrieved_token = db.get_refresh_token("hash123").await.unwrap();
        assert!(retrieved_token.is_some());
        assert_eq!(retrieved_token.unwrap().user_id, "user123");
    }
}
