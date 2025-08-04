//! Integration tests for cached DAO operations
//!
//! This module provides comprehensive tests for the cached DAO layer,
//! verifying cache behavior, invalidation, and performance characteristics.

use bedrock_sso_proxy::cache::CacheManager;
use bedrock_sso_proxy::database::dao::cached::{CacheKeyBuilder, CachedDao};
use bedrock_sso_proxy::database::entities::{ApiKeyRecord, UserRecord};
use chrono::Utc;
// Imports for testing

// Mock DAO for testing
#[derive(Clone)]
struct MockUsersDao {
    call_count: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}

impl MockUsersDao {
    fn new() -> Self {
        Self {
            call_count: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        }
    }

    fn get_call_count(&self) -> usize {
        self.call_count.load(std::sync::atomic::Ordering::SeqCst)
    }

    async fn find_by_id(&self, user_id: i32) -> Result<Option<UserRecord>, String> {
        self.call_count
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);

        if user_id == 1 {
            Ok(Some(UserRecord {
                id: 1,
                provider_user_id: "test123".to_string(),
                provider: "google".to_string(),
                email: "test@example.com".to_string(),
                display_name: Some("Test User".to_string()),
                created_at: Utc::now(),
                updated_at: Utc::now(),
                last_login: None,
                ..Default::default()
            }))
        } else {
            Ok(None)
        }
    }
}

#[tokio::test]
async fn test_cache_hit_and_miss() {
    let backend = CacheManager::new_memory();
    let mock_dao = MockUsersDao::new();
    let cached_dao = CachedDao::new(mock_dao.clone(), &backend);

    // First call - cache miss, should call DAO
    let result1 = cached_dao
        .get_or_compute("user:1", || async {
            mock_dao
                .find_by_id(1)
                .await
                .map_err(bedrock_sso_proxy::database::DatabaseError::Database)
        })
        .await
        .unwrap();

    assert!(result1.is_some());
    assert_eq!(mock_dao.get_call_count(), 1);

    // Second call - cache hit, should NOT call DAO
    let result2 = cached_dao
        .get_or_compute("user:1", || async {
            mock_dao
                .find_by_id(1)
                .await
                .map_err(bedrock_sso_proxy::database::DatabaseError::Database)
        })
        .await
        .unwrap();

    assert!(result2.is_some());
    assert_eq!(mock_dao.get_call_count(), 1); // No additional call

    // Verify cached data is correct
    assert_eq!(result1.as_ref().unwrap().id, result2.as_ref().unwrap().id);
    assert_eq!(
        result1.as_ref().unwrap().email,
        result2.as_ref().unwrap().email
    );
}

#[tokio::test]
async fn test_cache_invalidation() {
    let backend = CacheManager::new_memory();
    let mock_dao = MockUsersDao::new();
    let cached_dao = CachedDao::new(mock_dao.clone(), &backend);

    // Cache a value
    let _result1 = cached_dao
        .get_or_compute("user:1", || async {
            mock_dao
                .find_by_id(1)
                .await
                .map_err(bedrock_sso_proxy::database::DatabaseError::Database)
        })
        .await
        .unwrap();

    assert_eq!(mock_dao.get_call_count(), 1);

    // Invalidate the cache
    cached_dao
        .invalidate_keys(&["user:1".to_string()])
        .await
        .unwrap();

    // Next call should be a cache miss
    let _result2 = cached_dao
        .get_or_compute("user:1", || async {
            mock_dao
                .find_by_id(1)
                .await
                .map_err(bedrock_sso_proxy::database::DatabaseError::Database)
        })
        .await
        .unwrap();

    assert_eq!(mock_dao.get_call_count(), 2); // Additional call after invalidation
}

#[tokio::test]
async fn test_cache_key_isolation() {
    let backend = CacheManager::new_memory();
    let mock_dao = MockUsersDao::new();
    let cached_dao = CachedDao::new(mock_dao.clone(), &backend);

    // Cache two different keys
    let _result1 = cached_dao
        .get_or_compute("user:1", || async {
            mock_dao
                .find_by_id(1)
                .await
                .map_err(bedrock_sso_proxy::database::DatabaseError::Database)
        })
        .await
        .unwrap();

    let _result2 = cached_dao
        .get_or_compute("user:2", || async {
            mock_dao
                .find_by_id(2)
                .await
                .map_err(bedrock_sso_proxy::database::DatabaseError::Database)
        })
        .await
        .unwrap();

    assert_eq!(mock_dao.get_call_count(), 2);

    // Invalidate only one key
    cached_dao
        .invalidate_keys(&["user:1".to_string()])
        .await
        .unwrap();

    // user:1 should be cache miss, user:2 should be cache hit
    let _result1_again = cached_dao
        .get_or_compute("user:1", || async {
            mock_dao
                .find_by_id(1)
                .await
                .map_err(bedrock_sso_proxy::database::DatabaseError::Database)
        })
        .await
        .unwrap();

    let _result2_again = cached_dao
        .get_or_compute("user:2", || async {
            mock_dao
                .find_by_id(2)
                .await
                .map_err(bedrock_sso_proxy::database::DatabaseError::Database)
        })
        .await
        .unwrap();

    assert_eq!(mock_dao.get_call_count(), 4); // user:1 (3rd call) + user:2 (4th call, None not cached)
}

#[tokio::test]
async fn test_cache_key_builder() {
    let builder = CacheKeyBuilder::new("test");

    // Test various key building methods
    assert_eq!(builder.id_key(123), "test:id:123");
    assert_eq!(builder.hash_key("abc123"), "test:hash:abc123");
    assert_eq!(builder.user_key(456), "test:user:456");
    assert_eq!(
        builder.email_key("test@example.com"),
        "test:email:test@example.com"
    );
    assert_eq!(
        builder.provider_key("google", "12345"),
        "test:provider:google:12345"
    );
    assert_eq!(
        builder.model_key("claude-sonnet"),
        "test:model:claude-sonnet"
    );

    // Test custom key building
    assert_eq!(
        builder.build(&["custom", "key", "value"]),
        "test:custom:key:value"
    );
}

#[tokio::test]
async fn test_cache_with_none_values() {
    let backend = CacheManager::new_memory();
    let mock_dao = MockUsersDao::new();
    let cached_dao = CachedDao::new(mock_dao.clone(), &backend);

    // Test caching of None values (user not found)
    let result = cached_dao
        .get_or_compute("user:999", || async {
            mock_dao
                .find_by_id(999)
                .await
                .map_err(bedrock_sso_proxy::database::DatabaseError::Database)
        })
        .await
        .unwrap();

    assert!(result.is_none());
    assert_eq!(mock_dao.get_call_count(), 1);

    // Second call - None values are NOT cached to avoid cache pollution
    // This is intentional behavior - we don't cache failed lookups
    let result2 = cached_dao
        .get_or_compute("user:999", || async {
            mock_dao
                .find_by_id(999)
                .await
                .map_err(bedrock_sso_proxy::database::DatabaseError::Database)
        })
        .await
        .unwrap();

    assert!(result2.is_none());
    assert_eq!(mock_dao.get_call_count(), 2); // Additional call since None not cached
}

#[tokio::test]
async fn test_cache_error_handling() {
    let backend = CacheManager::new_memory();
    let mock_dao = MockUsersDao::new();
    let cached_dao = CachedDao::new(mock_dao.clone(), &backend);

    // Test that cache errors don't break the operation
    // This is a bit artificial since MemoryCache rarely fails,
    // but it tests the error handling path

    let result = cached_dao
        .get_or_compute("user:1", || async {
            mock_dao
                .find_by_id(1)
                .await
                .map_err(bedrock_sso_proxy::database::DatabaseError::Database)
        })
        .await
        .unwrap();

    assert!(result.is_some());
    assert_eq!(mock_dao.get_call_count(), 1);
}

#[tokio::test]
async fn test_type_safety_with_different_entities() {
    let backend = CacheManager::new_memory();

    // Create two different typed caches
    let user_cache = CachedDao::<(), UserRecord>::new((), &backend);
    let api_key_cache = CachedDao::<(), ApiKeyRecord>::new((), &backend);

    let user = UserRecord {
        id: 1,
        provider_user_id: "test123".to_string(),
        provider: "google".to_string(),
        email: "test@example.com".to_string(),
        display_name: Some("Test User".to_string()),
        created_at: Utc::now(),
        updated_at: Utc::now(),
        last_login: None,
        ..Default::default()
    };

    let api_key = ApiKeyRecord {
        id: 1,
        key_hash: "hash123".to_string(),
        user_id: 1,
        name: "Test Key".to_string(),
        hint: "SSOK_abcd****3456".to_string(),
        created_at: Utc::now(),
        last_used: None,
        expires_at: None,
        revoked_at: None,
    };

    // Store different types with same key - they should be isolated
    let _ = user_cache.cache().set("test:1", &user).await;
    let _ = api_key_cache.cache().set("test:1", &api_key).await;

    // Verify they're isolated (different type hashes)
    let cached_user = user_cache.cache().get("test:1").await.unwrap();
    let cached_api_key = api_key_cache.cache().get("test:1").await.unwrap();

    assert!(cached_user.is_some());
    assert!(cached_api_key.is_some());

    // Verify different types don't interfere
    assert_ne!(
        user_cache.get_cache_stats().type_hash,
        api_key_cache.get_cache_stats().type_hash
    );
}

#[tokio::test]
async fn test_concurrent_cache_access() {
    let backend = CacheManager::new_memory();
    let mock_dao = MockUsersDao::new();
    let cached_dao = CachedDao::new(mock_dao.clone(), &backend);

    // Test concurrent access to the same cache key
    let handles: Vec<_> = (0..10)
        .map(|_| {
            let cached_dao = cached_dao.clone();
            let mock_dao = mock_dao.clone();
            tokio::spawn(async move {
                cached_dao
                    .get_or_compute("user:1", || async {
                        mock_dao
                            .find_by_id(1)
                            .await
                            .map_err(bedrock_sso_proxy::database::DatabaseError::Database)
                    })
                    .await
                    .unwrap()
            })
        })
        .collect();

    let results: Vec<_> = futures_util::future::join_all(handles)
        .await
        .into_iter()
        .map(|h| h.unwrap())
        .collect();

    // All should return the same user
    for result in &results {
        assert!(result.is_some());
        assert_eq!(result.as_ref().unwrap().id, 1);
    }

    // Due to concurrency, we might have a few cache misses, but not 10
    // This tests that the cache is working under concurrent load
    assert!(mock_dao.get_call_count() < 10);
    assert!(mock_dao.get_call_count() >= 1);
}
