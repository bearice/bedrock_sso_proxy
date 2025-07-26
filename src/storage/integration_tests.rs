use crate::storage::factory::{CacheBackend, DatabaseBackend, StorageFactory};
use crate::storage::{AuditLogEntry, CachedValidation, RefreshTokenData, StateData, UserRecord};
use chrono::Utc;
use std::collections::HashMap;

#[tokio::test]
async fn test_full_storage_integration() {
    // Create storage with memory backends
    let storage = StorageFactory::create_test_storage().await.unwrap();

    // Test cache operations
    let validation = CachedValidation {
        user_id: "user123".to_string(),
        provider: "google".to_string(),
        email: "user@example.com".to_string(),
        validated_at: Utc::now(),
        expires_at: Utc::now() + chrono::Duration::hours(1),
        scopes: vec!["bedrock:invoke".to_string()],
    };

    // Store validation in cache
    storage
        .cache
        .store_validation("test_key", &validation, 3600)
        .await
        .unwrap();

    // Retrieve validation from cache
    let retrieved = storage.cache.get_validation("test_key").await.unwrap();
    assert!(retrieved.is_some());
    assert_eq!(retrieved.unwrap().user_id, "user123");

    // Test state storage
    let state = StateData {
        provider: "google".to_string(),
        redirect_uri: "https://example.com/callback".to_string(),
        created_at: Utc::now(),
        expires_at: Utc::now() + chrono::Duration::minutes(10),
    };

    storage
        .cache
        .store_state("state_key", &state, 600)
        .await
        .unwrap();
    let retrieved_state = storage.cache.get_state("state_key").await.unwrap();
    assert!(retrieved_state.is_some());
    assert_eq!(retrieved_state.unwrap().provider, "google");

    // Test database operations
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

    // Store user
    let user_id = storage.database.upsert_user(&user).await.unwrap();
    assert!(user_id > 0);

    // Retrieve user by provider
    let retrieved_user = storage
        .database
        .get_user_by_provider("google", "user123")
        .await
        .unwrap();
    assert!(retrieved_user.is_some());
    assert_eq!(retrieved_user.unwrap().email, "user@example.com");

    // Test refresh token operations
    let refresh_token = RefreshTokenData {
        token_hash: "hash123".to_string(),
        user_id: "user123".to_string(),
        provider: "google".to_string(),
        email: "user@example.com".to_string(),
        created_at: Utc::now(),
        expires_at: Utc::now() + chrono::Duration::days(90),
        rotation_count: 0,
        revoked_at: None,
    };

    storage
        .database
        .store_refresh_token(&refresh_token)
        .await
        .unwrap();
    let retrieved_token = storage.database.get_refresh_token("hash123").await.unwrap();
    assert!(retrieved_token.is_some());
    assert_eq!(retrieved_token.unwrap().user_id, "user123");

    // Test audit logging
    let mut metadata = HashMap::new();
    metadata.insert(
        "ip".to_string(),
        serde_json::Value::String("127.0.0.1".to_string()),
    );

    let audit_entry = AuditLogEntry {
        id: None,
        user_id: Some(user_id),
        event_type: "login".to_string(),
        provider: Some("google".to_string()),
        ip_address: Some("127.0.0.1".to_string()),
        user_agent: Some("Test Agent".to_string()),
        success: true,
        error_message: None,
        created_at: Utc::now(),
        metadata: Some(metadata),
    };

    storage
        .database
        .store_audit_log(&audit_entry)
        .await
        .unwrap();
    let logs = storage
        .database
        .get_audit_logs_for_user(user_id, 10, 0)
        .await
        .unwrap();
    assert_eq!(logs.len(), 1);
    assert_eq!(logs[0].event_type, "login");

    // Test health check
    storage.health_check().await.unwrap();

    // Test cleanup operations
    let cleaned_tokens = storage.database.cleanup_expired_tokens().await.unwrap();
    assert_eq!(cleaned_tokens, 0); // No expired tokens yet

    let cleaned_logs = storage.database.cleanup_old_audit_logs(0).await.unwrap();
    assert!(cleaned_logs > 0); // Should clean up the log we just created

    // Test cache clear
    storage.cache.clear_all().await.unwrap();
    let cleared = storage.cache.get_validation("test_key").await.unwrap();
    assert!(cleared.is_none());
}

#[tokio::test]
async fn test_storage_configuration_from_config() {
    use crate::config::Config;

    let mut config = Config::default();
    config.storage.redis.enabled = true;
    config.storage.redis.url = "redis://localhost:6379".to_string();
    config.storage.database.enabled = true;
    config.storage.database.url = "sqlite://memory:".to_string();

    // Note: This test would require Redis to be running for the Redis backend
    // For now, we'll just test that the configuration extraction works
    let storage_config = StorageFactory::extract_storage_config(&config);

    match storage_config.cache_backend {
        CacheBackend::Redis => {
            assert_eq!(storage_config.redis_config.url, "redis://localhost:6379");
        }
        _ => panic!("Expected Redis backend"),
    }

    match storage_config.database_backend {
        DatabaseBackend::Sqlite => {
            assert_eq!(storage_config.database_config.url, "sqlite://memory:");
        }
        _ => panic!("Expected SQLite backend"),
    }
}

#[tokio::test]
async fn test_cache_ttl_expiration() {
    let storage = StorageFactory::create_test_storage().await.unwrap();

    let validation = CachedValidation {
        user_id: "user123".to_string(),
        provider: "google".to_string(),
        email: "user@example.com".to_string(),
        validated_at: Utc::now(),
        expires_at: Utc::now() + chrono::Duration::hours(1),
        scopes: vec!["bedrock:invoke".to_string()],
    };

    // Store with 1 second TTL
    storage
        .cache
        .store_validation("ttl_key", &validation, 1)
        .await
        .unwrap();

    // Should exist immediately
    let immediate = storage.cache.get_validation("ttl_key").await.unwrap();
    assert!(immediate.is_some());

    // Wait for expiration
    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

    // Should be expired now
    let expired = storage.cache.get_validation("ttl_key").await.unwrap();
    assert!(expired.is_none());
}

#[tokio::test]
async fn test_user_upsert_behavior() {
    let storage = StorageFactory::create_test_storage().await.unwrap();

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

    // First upsert - should create new user
    let user_id_1 = storage.database.upsert_user(&user).await.unwrap();
    assert_eq!(user_id_1, 1);

    // Second upsert with same provider_user_id - should update existing user
    let mut updated_user = user.clone();
    updated_user.display_name = Some("Updated User".to_string());
    updated_user.email = "updated@example.com".to_string();

    let user_id_2 = storage.database.upsert_user(&updated_user).await.unwrap();
    assert_eq!(user_id_2, user_id_1); // Should be the same user ID

    // Verify the user was updated
    let retrieved = storage
        .database
        .get_user_by_provider("google", "user123")
        .await
        .unwrap();
    assert!(retrieved.is_some());
    let retrieved_user = retrieved.unwrap();
    assert_eq!(retrieved_user.email, "updated@example.com");
    assert_eq!(
        retrieved_user.display_name,
        Some("Updated User".to_string())
    );
}

#[tokio::test]
async fn test_refresh_token_rotation() {
    let storage = StorageFactory::create_test_storage().await.unwrap();

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

    // Store initial token
    storage.database.store_refresh_token(&token).await.unwrap();

    // Simulate token rotation
    let mut rotated_token = token.clone();
    rotated_token.rotation_count = 1;

    // Store rotated token (should update existing)
    storage
        .database
        .store_refresh_token(&rotated_token)
        .await
        .unwrap();

    // Verify rotation count was updated
    let retrieved = storage.database.get_refresh_token("hash123").await.unwrap();
    assert!(retrieved.is_some());
    assert_eq!(retrieved.unwrap().rotation_count, 1);

    // Test token revocation
    storage
        .database
        .revoke_refresh_token("hash123")
        .await
        .unwrap();

    let revoked = storage.database.get_refresh_token("hash123").await.unwrap();
    assert!(revoked.is_some());
    assert!(revoked.unwrap().revoked_at.is_some());
}
