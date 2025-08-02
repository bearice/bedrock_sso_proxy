use bedrock_sso_proxy::cache::CacheManager;
use bedrock_sso_proxy::database::entities::{ApiKeyRecord, UserRecord};
use chrono::Utc;

#[tokio::test]
async fn test_cache_manager_memory_sharing() {
    // Create a single CacheManager instance
    let cache_manager = CacheManager::new_memory();

    // Get two cache instances of the same type from the same manager
    let cache1 = cache_manager.cache::<UserRecord>();
    let cache2 = cache_manager.cache::<UserRecord>();

    let test_user = UserRecord {
        id: 42,
        provider_user_id: "test123".to_string(),
        provider: "google".to_string(),
        email: "test@example.com".to_string(),
        display_name: Some("Test User".to_string()),
        created_at: Utc::now(),
        updated_at: Utc::now(),
        last_login: None,
    };

    // Set a value using cache1
    cache1.set("shared_test_key", &test_user).await.unwrap();

    // Should be able to get the same value from cache2
    let retrieved = cache2.get("shared_test_key").await.unwrap();
    assert_eq!(retrieved, Some(test_user.clone()));

    // Delete using cache2
    cache2.delete("shared_test_key").await.unwrap();

    // Should be gone from cache1 too
    let retrieved = cache1.get("shared_test_key").await.unwrap();
    assert_eq!(retrieved, None);
}

#[tokio::test]
async fn test_different_cache_managers_are_isolated() {
    // Create two different CacheManager instances
    let cache_manager1 = CacheManager::new_memory();
    let cache_manager2 = CacheManager::new_memory();

    // Get cache instances from different managers
    let cache1 = cache_manager1.cache::<UserRecord>();
    let cache2 = cache_manager2.cache::<UserRecord>();

    let test_user = UserRecord {
        id: 42,
        provider_user_id: "test123".to_string(),
        provider: "google".to_string(),
        email: "test@example.com".to_string(),
        display_name: Some("Test User".to_string()),
        created_at: Utc::now(),
        updated_at: Utc::now(),
        last_login: None,
    };

    // Set a value using cache1 (from manager1)
    cache1.set("isolation_test_key", &test_user).await.unwrap();

    // Should NOT be visible from cache2 (from manager2)
    let retrieved = cache2.get("isolation_test_key").await.unwrap();
    assert_eq!(retrieved, None);

    // But should still be visible from another cache instance from the same manager
    let cache1_alt = cache_manager1.cache::<UserRecord>();
    let retrieved = cache1_alt.get("isolation_test_key").await.unwrap();
    assert_eq!(retrieved, Some(test_user));
}

#[tokio::test]
async fn test_type_safety_with_shared_store() {
    let cache_manager = CacheManager::new_memory();

    // Get caches for different types from the same manager
    let user_cache = cache_manager.cache::<UserRecord>();
    let api_key_cache = cache_manager.cache::<ApiKeyRecord>();

    let test_user = UserRecord {
        id: 123,
        provider_user_id: "test123".to_string(),
        provider: "google".to_string(),
        email: "type_test@example.com".to_string(),
        display_name: Some("Type Test User".to_string()),
        created_at: Utc::now(),
        updated_at: Utc::now(),
        last_login: None,
    };

    let test_api_key = ApiKeyRecord {
        id: 456,
        key_hash: "hash456".to_string(),
        user_id: 123,
        name: "Type Test Key".to_string(),
        hint: "SSOK_test****type".to_string(),
        created_at: Utc::now(),
        last_used: None,
        expires_at: None,
        revoked_at: None,
    };

    // Set values with the same key but different types
    user_cache.set("type_test_key", &test_user).await.unwrap();
    api_key_cache
        .set("type_test_key", &test_api_key)
        .await
        .unwrap();

    // Both should be retrievable with correct types
    let retrieved_user = user_cache.get("type_test_key").await.unwrap();
    let retrieved_api_key = api_key_cache.get("type_test_key").await.unwrap();

    assert_eq!(retrieved_user, Some(test_user));
    assert_eq!(retrieved_api_key, Some(test_api_key));
}
