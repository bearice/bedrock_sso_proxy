//! Cached Users DAO with transparent caching for user operations
//!
//! This module provides a cached wrapper around UsersDao that implements
//! transparent caching for user lookups with automatic invalidation.

use super::cached::{CacheKeyBuilder, CachedDao};
use super::users::UsersDao;
use crate::cache::CacheManager;
use crate::database::DatabaseResult;
use crate::database::entities::UserRecord;

/// Cached Users DAO providing transparent caching for user operations
pub struct CachedUsersDao {
    cached_dao: CachedDao<UsersDao, UserRecord>,
    key_builder: CacheKeyBuilder,
}

impl CachedUsersDao {
    /// Create a new cached users DAO
    pub fn new(users_dao: UsersDao, cache: &CacheManager) -> Self {
        Self {
            cached_dao: CachedDao::new(users_dao, cache),
            key_builder: CacheKeyBuilder::new("user"),
        }
    }

    /// Get the inner UsersDao reference
    pub fn inner(&self) -> &UsersDao {
        self.cached_dao.inner()
    }

    /// Find user by ID with caching
    pub async fn find_by_id(&self, user_id: i32) -> DatabaseResult<Option<UserRecord>> {
        let cache_key = self.key_builder.id_key(user_id);

        self.cached_dao
            .get_or_compute(&cache_key, || async {
                self.cached_dao.inner().find_by_id(user_id).await
            })
            .await
    }

    /// Find user by provider and provider user ID with caching
    pub async fn find_by_provider(
        &self,
        provider: &str,
        provider_user_id: &str,
    ) -> DatabaseResult<Option<UserRecord>> {
        let cache_key = self.key_builder.provider_key(provider, provider_user_id);

        self.cached_dao
            .get_or_compute(&cache_key, || async {
                self.cached_dao
                    .inner()
                    .find_by_provider(provider, provider_user_id)
                    .await
            })
            .await
    }

    /// Find user by email with caching
    pub async fn find_by_email(&self, email: &str) -> DatabaseResult<Option<UserRecord>> {
        let cache_key = self.key_builder.email_key(email);

        self.cached_dao
            .get_or_compute(&cache_key, || async {
                self.cached_dao.inner().find_by_email(email).await
            })
            .await
    }

    /// Create or update user with cache invalidation
    pub async fn upsert(&self, user: &UserRecord) -> DatabaseResult<i32> {
        // Generate cache keys that might be affected by this operation
        let cache_keys = self.generate_user_cache_keys(user);

        self.cached_dao
            .update_and_invalidate(
                || async { self.cached_dao.inner().upsert(user).await.map(|_| ()) },
                &cache_keys,
            )
            .await?;

        // Return the result by calling the inner DAO again
        // In practice, you might want to cache the ID as well
        self.cached_dao.inner().upsert(user).await
    }

    /// Update last login timestamp with cache invalidation
    pub async fn update_last_login(&self, user: UserRecord) -> DatabaseResult<UserRecord> {
        // Generate cache keys that might be affected
        let cache_keys = vec![self.key_builder.id_key(user.id)];

        self.cached_dao
            .update_and_invalidate(
                || async { self.cached_dao.inner().update_last_login(user).await },
                &cache_keys,
            )
            .await
    }

    /// Invalidate all cache entries for a user
    pub async fn invalidate_user_cache(&self, user: &UserRecord) -> DatabaseResult<()> {
        let cache_keys = self.generate_user_cache_keys(user);
        self.cached_dao.invalidate_keys(&cache_keys).await
    }

    /// Invalidate cache entry by user ID
    pub async fn invalidate_user_cache_by_id(&self, user_id: i32) -> DatabaseResult<()> {
        let cache_keys = vec![self.key_builder.id_key(user_id)];
        self.cached_dao.invalidate_keys(&cache_keys).await
    }

    /// Generate all possible cache keys for a user
    fn generate_user_cache_keys(&self, user: &UserRecord) -> Vec<String> {
        vec![
            self.key_builder.id_key(user.id),
            self.key_builder
                .provider_key(&user.provider, &user.provider_user_id),
            self.key_builder.email_key(&user.email),
        ]
    }

    /// Get cache statistics
    pub fn get_cache_stats(&self) -> crate::cache::object::TypedCacheStats {
        self.cached_dao.get_cache_stats()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // Note: Database import not needed for these tests
    use chrono::Utc;
    use sea_orm::DatabaseConnection;

    async fn create_test_user() -> UserRecord {
        UserRecord {
            id: 1,
            provider_user_id: "test123".to_string(),
            provider: "google".to_string(),
            email: "test@example.com".to_string(),
            display_name: Some("Test User".to_string()),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            last_login: None,
        }
    }

    #[tokio::test]
    async fn test_cache_key_generation() {
        let cache = CacheManager::new_memory();
        let users_dao = UsersDao::new(DatabaseConnection::default());
        let cached_dao = CachedUsersDao::new(users_dao, &cache);

        let user = create_test_user().await;
        let cache_keys = cached_dao.generate_user_cache_keys(&user);

        assert_eq!(cache_keys.len(), 3);
        assert!(cache_keys.contains(&"user:id:1".to_string()));
        assert!(cache_keys.contains(&"user:provider:google:test123".to_string()));
        assert!(cache_keys.contains(&"user:email:test@example.com".to_string()));
    }

    #[tokio::test]
    async fn test_cache_key_builder() {
        let builder = CacheKeyBuilder::new("user");

        assert_eq!(builder.id_key(123), "user:id:123");
        assert_eq!(
            builder.email_key("test@example.com"),
            "user:email:test@example.com"
        );
        assert_eq!(
            builder.provider_key("google", "12345"),
            "user:provider:google:12345"
        );
    }

    // Note: Full integration tests would require a real database connection
    // These are primarily unit tests for the caching logic
}
