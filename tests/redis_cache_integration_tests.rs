//! Redis cache integration tests
//!
//! These tests verify that the Redis cache backend properly serializes and deserializes
//! complex types including those with rust_decimal::Decimal fields.
//!
//! Note: These tests will be skipped if Redis is not available on localhost:6379

use bedrock_sso_proxy::cache::CacheManager;
use bedrock_sso_proxy::database::entities::{ApiKeyRecord, ModelCost, UserRecord};
use chrono::Utc;
use rust_decimal::Decimal;
use serial_test::serial;
use std::time::Duration;

// Test helper function to create Redis cache manager
async fn create_redis_cache_manager() -> Option<CacheManager> {
    let redis_url =
        std::env::var("TEST_REDIS_URL").unwrap_or_else(|_| "redis://localhost:6379".to_string());
    let is_explicit = std::env::var("TEST_REDIS_URL").is_ok();

    let config = bedrock_sso_proxy::cache::config::CacheConfig {
        backend: "redis".to_string(),
        redis_url,
        redis_key_prefix: "test_redis_cache:".to_string(),
        validation_ttl: 3600,
        max_entries: 1000,
        cleanup_interval: 3600,
    };

    match CacheManager::new_from_config(&config).await {
        Ok(manager) => Some(manager),
        Err(e) => {
            if is_explicit {
                // TEST_REDIS_URL was explicitly set, so this should be an error
                panic!("Redis connection failed (TEST_REDIS_URL is set): {}", e);
            } else {
                // TEST_REDIS_URL was not set, skip test gracefully
                println!("Redis not available, skipping test: {}", e);
                None
            }
        }
    }
}

macro_rules! get_redis_cache_manager {
    () => {
        match create_redis_cache_manager().await {
            Some(manager) => manager,
            None => {
                return;
            }
        }
    };
}

#[tokio::test]
#[serial] // Ensure Redis tests don't interfere with each other
async fn test_redis_model_cost_serialization() {
    let cache_manager = get_redis_cache_manager!();
    let typed_cache = cache_manager.cache::<ModelCost>();

    // Create a ModelCost with complex Decimal values
    let model_cost = ModelCost {
        id: 1,
        region: "us-east-1".to_string(),
        model_id: "anthropic.claude-sonnet-4-20250514-v1:0".to_string(),
        input_cost_per_1k_tokens: Decimal::new(3, 3), // 0.003
        output_cost_per_1k_tokens: Decimal::new(15, 3), // 0.015
        cache_write_cost_per_1k_tokens: Some(Decimal::new(18, 4)), // 0.0018
        cache_read_cost_per_1k_tokens: Some(Decimal::new(36, 5)), // 0.00036
        updated_at: Utc::now(),
    };

    // Test set operation (this would fail with bincode due to deserialize_any)
    typed_cache
        .set("model_cost_test", &model_cost)
        .await
        .expect("Failed to set ModelCost in Redis cache - postcard serialization should work");

    // Test get operation
    let cached_model_cost = typed_cache
        .get("model_cost_test")
        .await
        .expect("Failed to get ModelCost from Redis cache")
        .expect("ModelCost should exist in cache");

    // Verify data integrity
    assert_eq!(cached_model_cost.id, model_cost.id);
    assert_eq!(cached_model_cost.region, model_cost.region);
    assert_eq!(cached_model_cost.model_id, model_cost.model_id);
    assert_eq!(
        cached_model_cost.input_cost_per_1k_tokens,
        model_cost.input_cost_per_1k_tokens
    );
    assert_eq!(
        cached_model_cost.output_cost_per_1k_tokens,
        model_cost.output_cost_per_1k_tokens
    );
    assert_eq!(
        cached_model_cost.cache_write_cost_per_1k_tokens,
        model_cost.cache_write_cost_per_1k_tokens
    );
    assert_eq!(
        cached_model_cost.cache_read_cost_per_1k_tokens,
        model_cost.cache_read_cost_per_1k_tokens
    );

    // Test exists operation
    assert!(typed_cache.exists("model_cost_test").await.unwrap());
    assert!(!typed_cache.exists("nonexistent_key").await.unwrap());

    // Test delete operation
    typed_cache.delete("model_cost_test").await.unwrap();
    assert!(!typed_cache.exists("model_cost_test").await.unwrap());
}

#[tokio::test]
#[serial]
async fn test_redis_user_record_serialization() {
    let cache_manager = get_redis_cache_manager!();
    let typed_cache = cache_manager.cache::<UserRecord>();

    let user = UserRecord {
        id: 123,
        provider_user_id: "google_12345".to_string(),
        provider: "google".to_string(),
        email: "test@example.com".to_string(),
        display_name: Some("Test User".to_string()),
        created_at: Utc::now(),
        updated_at: Utc::now(),
        last_login: Some(Utc::now()),
        ..Default::default()
    };

    // Test serialization round-trip
    typed_cache.set("user_test", &user).await.unwrap();
    let cached_user = typed_cache.get("user_test").await.unwrap().unwrap();

    assert_eq!(cached_user.id, user.id);
    assert_eq!(cached_user.email, user.email);
    assert_eq!(cached_user.display_name, user.display_name);

    // Cleanup
    typed_cache.delete("user_test").await.unwrap();
}

#[tokio::test]
#[serial]
async fn test_redis_api_key_record_serialization() {
    let cache_manager = get_redis_cache_manager!();
    let typed_cache = cache_manager.cache::<ApiKeyRecord>();

    let api_key = ApiKeyRecord {
        id: 1,
        user_id: 123,
        name: "Test API Key".to_string(),
        key_hash: "hash123".to_string(),
        hint: "SSOK_abcd****3456".to_string(),
        created_at: Utc::now(),
        expires_at: Some(Utc::now() + chrono::Duration::days(30)),
        last_used: None,
        revoked_at: None,
    };

    // Test serialization round-trip
    typed_cache.set("api_key_test", &api_key).await.unwrap();
    let cached_api_key = typed_cache.get("api_key_test").await.unwrap().unwrap();

    assert_eq!(cached_api_key.id, api_key.id);
    assert_eq!(cached_api_key.name, api_key.name);
    assert_eq!(cached_api_key.key_hash, api_key.key_hash);
    assert_eq!(cached_api_key.hint, api_key.hint);

    // Cleanup
    typed_cache.delete("api_key_test").await.unwrap();
}

#[tokio::test]
#[serial]
async fn test_redis_cache_ttl_functionality() {
    let cache_manager = get_redis_cache_manager!();
    let typed_cache = cache_manager.cache::<UserRecord>();

    let test_user = UserRecord {
        id: 999,
        provider_user_id: "ttl_test".to_string(),
        provider: "test".to_string(),
        email: "ttl@example.com".to_string(),
        display_name: Some("TTL Test User".to_string()),
        created_at: Utc::now(),
        updated_at: Utc::now(),
        last_login: None,
        ..Default::default()
    };

    // Set with 1 second TTL
    typed_cache
        .set_with_ttl("ttl_test", &test_user, Some(Duration::from_secs(1)))
        .await
        .unwrap();

    // Should exist immediately
    assert!(typed_cache.exists("ttl_test").await.unwrap());
    let cached = typed_cache.get("ttl_test").await.unwrap();
    assert_eq!(cached, Some(test_user));

    // Wait for expiration
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Should be expired
    assert!(!typed_cache.exists("ttl_test").await.unwrap());
    let cached = typed_cache.get("ttl_test").await.unwrap();
    assert_eq!(cached, None);
}

#[tokio::test]
#[serial]
async fn test_redis_cache_type_isolation() {
    let cache_manager = get_redis_cache_manager!();

    let user_cache = cache_manager.cache::<UserRecord>();
    let model_cache = cache_manager.cache::<ModelCost>();

    // Use same key for different types
    let key = "isolation_test";

    let test_user = UserRecord {
        id: 1,
        provider_user_id: "isolation_test".to_string(),
        provider: "test".to_string(),
        email: "isolation@example.com".to_string(),
        display_name: Some("Isolation Test".to_string()),
        created_at: Utc::now(),
        updated_at: Utc::now(),
        last_login: None,
        ..Default::default()
    };

    let test_model = ModelCost {
        id: 1,
        region: "isolation-region".to_string(),
        model_id: "isolation-model".to_string(),
        input_cost_per_1k_tokens: Decimal::new(1, 3),
        output_cost_per_1k_tokens: Decimal::new(2, 3),
        cache_write_cost_per_1k_tokens: None,
        cache_read_cost_per_1k_tokens: None,
        updated_at: Utc::now(),
    };

    user_cache.set(key, &test_user).await.unwrap();
    model_cache.set(key, &test_model).await.unwrap();

    // Both should coexist due to type-based key prefixing
    let cached_user = user_cache.get(key).await.unwrap();
    let cached_model = model_cache.get(key).await.unwrap();

    assert_eq!(cached_user, Some(test_user));
    assert_eq!(cached_model, Some(test_model));

    // Cleanup
    user_cache.delete(key).await.unwrap();
    model_cache.delete(key).await.unwrap();
}

#[tokio::test]
#[serial]
async fn test_redis_cache_complex_decimal_operations() {
    let cache_manager = get_redis_cache_manager!();
    let typed_cache = cache_manager.cache::<ModelCost>();

    // Test various decimal precision scenarios that might trigger deserialize_any
    let test_cases = vec![
        ("high_precision", Decimal::new(123456789, 9)), // 0.123456789
        ("zero_value", Decimal::ZERO),
        ("negative_value", Decimal::new(-12345, 4)), // -1.2345
        ("large_scale", Decimal::new(999999999999999999i64, 18)),
    ];

    for (test_name, decimal_value) in test_cases {
        let model_cost = ModelCost {
            id: 1,
            region: "test-region".to_string(),
            model_id: format!("test-model-{test_name}"),
            input_cost_per_1k_tokens: decimal_value,
            output_cost_per_1k_tokens: decimal_value,
            cache_write_cost_per_1k_tokens: Some(decimal_value),
            cache_read_cost_per_1k_tokens: Some(decimal_value),
            updated_at: Utc::now(),
        };

        // This would fail with bincode for certain decimal values
        typed_cache
            .set(&format!("decimal_test_{test_name}"), &model_cost)
            .await
            .unwrap_or_else(|_| {
                panic!("Failed to serialize ModelCost with decimal: {decimal_value}")
            });

        let cached = typed_cache
            .get(&format!("decimal_test_{test_name}"))
            .await
            .unwrap()
            .unwrap();

        assert_eq!(cached.input_cost_per_1k_tokens, decimal_value);
        assert_eq!(cached.output_cost_per_1k_tokens, decimal_value);
        assert_eq!(cached.cache_write_cost_per_1k_tokens, Some(decimal_value));
        assert_eq!(cached.cache_read_cost_per_1k_tokens, Some(decimal_value));

        // Cleanup
        typed_cache
            .delete(&format!("decimal_test_{test_name}"))
            .await
            .unwrap();
    }
}

#[tokio::test]
#[serial]
async fn test_redis_cache_get_or_compute() {
    let cache_manager = get_redis_cache_manager!();
    let typed_cache = cache_manager.cache::<UserRecord>();

    let key = "compute_test";
    let expected_user = UserRecord {
        id: 777,
        provider_user_id: "compute_test".to_string(),
        provider: "test".to_string(),
        email: "compute@example.com".to_string(),
        display_name: Some("Compute Test".to_string()),
        created_at: Utc::now(),
        updated_at: Utc::now(),
        last_login: None,
        ..Default::default()
    };

    // First call should compute and cache
    let result = typed_cache
        .get_or_compute(key, || async {
            Ok::<UserRecord, Box<dyn std::error::Error + Send + Sync>>(expected_user.clone())
        })
        .await
        .unwrap();

    assert_eq!(result.id, expected_user.id);
    assert_eq!(result.email, expected_user.email);

    // Second call should return cached value (no computation)
    let different_user = UserRecord {
        id: 888,
        provider_user_id: "different".to_string(),
        provider: "different".to_string(),
        email: "different@example.com".to_string(),
        display_name: Some("Different".to_string()),
        created_at: Utc::now(),
        updated_at: Utc::now(),
        last_login: None,
        ..Default::default()
    };

    let result = typed_cache
        .get_or_compute(key, || async {
            // This should not be called due to cache hit
            Ok::<UserRecord, Box<dyn std::error::Error + Send + Sync>>(different_user)
        })
        .await
        .unwrap();

    // Should still be the original user due to cache hit
    assert_eq!(result.id, expected_user.id);
    assert_eq!(result.email, expected_user.email);

    // Cleanup
    typed_cache.delete(key).await.unwrap();
}

#[tokio::test]
#[serial]
async fn test_redis_health_check() {
    let cache_manager = get_redis_cache_manager!();

    // Test health check passes
    let result = cache_manager.health_check().await;
    assert!(matches!(
        result.status,
        bedrock_sso_proxy::health::HealthStatus::Healthy
    ));

    let details = result.details.unwrap();
    assert_eq!(details["backend"], "redis");
    assert_eq!(details["status"], "healthy");
}

// Test with existing ModelCost entity instead of custom struct
#[tokio::test]
#[serial]
async fn test_redis_complex_model_cost_decimals() {
    let cache_manager = get_redis_cache_manager!();
    let typed_cache = cache_manager.cache::<ModelCost>();

    let test_model_cost = ModelCost {
        id: 12345,
        region: "test-complex".to_string(),
        model_id: "complex-model".to_string(),
        input_cost_per_1k_tokens: Decimal::new(314159, 5), // π approximation
        output_cost_per_1k_tokens: Decimal::new(271828, 5), // e approximation
        cache_write_cost_per_1k_tokens: Some(Decimal::new(141421, 5)), // √2 approximation
        cache_read_cost_per_1k_tokens: Some(Decimal::new(173205, 5)), // √3 approximation
        updated_at: Utc::now(),
    };

    // Test that complex structs with decimals serialize properly
    typed_cache
        .set("complex_test", &test_model_cost)
        .await
        .unwrap();
    let cached = typed_cache.get("complex_test").await.unwrap().unwrap();

    assert_eq!(cached.id, test_model_cost.id);
    assert_eq!(
        cached.input_cost_per_1k_tokens,
        test_model_cost.input_cost_per_1k_tokens
    );
    assert_eq!(
        cached.output_cost_per_1k_tokens,
        test_model_cost.output_cost_per_1k_tokens
    );
    assert_eq!(
        cached.cache_write_cost_per_1k_tokens,
        test_model_cost.cache_write_cost_per_1k_tokens
    );
    assert_eq!(
        cached.cache_read_cost_per_1k_tokens,
        test_model_cost.cache_read_cost_per_1k_tokens
    );

    // Cleanup
    typed_cache.delete("complex_test").await.unwrap();
}
