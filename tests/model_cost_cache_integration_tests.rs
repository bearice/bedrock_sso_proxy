//! ModelCost cache integration tests
//!
//! These tests specifically verify ModelCost caching with both memory and Redis backends.
//! The Redis tests would have caught the original bincode serialization error.

use bedrock_sso_proxy::cache::{CacheManager, config::CacheConfig};
use bedrock_sso_proxy::database::dao::cached::CachedDao;
use bedrock_sso_proxy::database::entities::ModelCost;
use chrono::Utc;
use rust_decimal::Decimal;
use serial_test::serial;

// Mock ModelCostsDao for testing
#[derive(Clone)]
struct MockModelCostsDao {
    call_count: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}

impl MockModelCostsDao {
    fn new() -> Self {
        Self {
            call_count: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        }
    }

    fn get_call_count(&self) -> usize {
        self.call_count.load(std::sync::atomic::Ordering::SeqCst)
    }

    async fn find_by_region_and_model(
        &self,
        region: &str,
        model_id: &str,
    ) -> Result<Option<ModelCost>, String> {
        self.call_count
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);

        if region == "us-east-1" && model_id == "anthropic.claude-sonnet-4-20250514-v1:0" {
            Ok(Some(ModelCost {
                id: 1,
                region: region.to_string(),
                model_id: model_id.to_string(),
                input_cost_per_1k_tokens: Decimal::new(3, 3), // 0.003 - this would trigger bincode error
                output_cost_per_1k_tokens: Decimal::new(15, 3), // 0.015
                cache_write_cost_per_1k_tokens: Some(Decimal::new(18, 4)), // 0.0018
                cache_read_cost_per_1k_tokens: Some(Decimal::new(36, 5)), // 0.00036
                updated_at: Utc::now(),
            }))
        } else {
            Ok(None)
        }
    }
}

#[tokio::test]
async fn test_model_cost_cache_with_memory_backend() {
    let cache_manager = CacheManager::new_memory();
    let mock_dao = MockModelCostsDao::new();
    let cached_dao = CachedDao::new(mock_dao.clone(), &cache_manager);

    let cache_key = "us-east-1:anthropic.claude-sonnet-4-20250514-v1:0";

    // First call - cache miss
    let result1 = cached_dao
        .get_or_compute(cache_key, || async {
            mock_dao
                .find_by_region_and_model("us-east-1", "anthropic.claude-sonnet-4-20250514-v1:0")
                .await
                .map_err(bedrock_sso_proxy::database::DatabaseError::Database)
        })
        .await
        .unwrap();

    assert!(result1.is_some());
    assert_eq!(mock_dao.get_call_count(), 1);

    let model_cost = result1.unwrap();
    assert_eq!(model_cost.region, "us-east-1");
    assert_eq!(
        model_cost.model_id,
        "anthropic.claude-sonnet-4-20250514-v1:0"
    );
    assert_eq!(model_cost.input_cost_per_1k_tokens, Decimal::new(3, 3));
    assert_eq!(model_cost.output_cost_per_1k_tokens, Decimal::new(15, 3));

    // Second call - cache hit
    let result2 = cached_dao
        .get_or_compute(cache_key, || async {
            mock_dao
                .find_by_region_and_model("us-east-1", "anthropic.claude-sonnet-4-20250514-v1:0")
                .await
                .map_err(bedrock_sso_proxy::database::DatabaseError::Database)
        })
        .await
        .unwrap();

    assert!(result2.is_some());
    assert_eq!(mock_dao.get_call_count(), 1); // No additional call due to cache hit
}

#[tokio::test]
#[serial] // Redis tests need to be serial to avoid conflicts
async fn test_model_cost_cache_with_redis_backend() {
    // Create Redis cache manager
    let config = CacheConfig {
        backend: "redis".to_string(),
        redis_url: "redis://localhost:6379".to_string(),
        redis_key_prefix: "test_model_cost:".to_string(),
        validation_ttl: 3600,
        max_entries: 1000,
        cleanup_interval: 3600,
    };

    let cache_manager = CacheManager::new_from_config(&config)
        .await
        .expect("Failed to create Redis cache manager - ensure Redis is running");

    let mock_dao = MockModelCostsDao::new();
    let cached_dao = CachedDao::new(mock_dao.clone(), &cache_manager);

    let cache_key = "us-east-1:anthropic.claude-sonnet-4-20250514-v1:0";

    // First call - cache miss, this would fail with bincode due to Decimal serialization
    let result1 = cached_dao
        .get_or_compute(cache_key, || async {
            mock_dao
                .find_by_region_and_model("us-east-1", "anthropic.claude-sonnet-4-20250514-v1:0")
                .await
                .map_err(bedrock_sso_proxy::database::DatabaseError::Database)
        })
        .await
        .expect("Failed to cache ModelCost with Redis - this should work with postcard");

    assert!(result1.is_some());
    assert_eq!(mock_dao.get_call_count(), 1);

    let model_cost = result1.unwrap();
    assert_eq!(model_cost.region, "us-east-1");
    assert_eq!(
        model_cost.model_id,
        "anthropic.claude-sonnet-4-20250514-v1:0"
    );
    assert_eq!(model_cost.input_cost_per_1k_tokens, Decimal::new(3, 3));
    assert_eq!(model_cost.output_cost_per_1k_tokens, Decimal::new(15, 3));
    assert_eq!(
        model_cost.cache_write_cost_per_1k_tokens,
        Some(Decimal::new(18, 4))
    );
    assert_eq!(
        model_cost.cache_read_cost_per_1k_tokens,
        Some(Decimal::new(36, 5))
    );

    // Second call - cache hit (verify deserialization works)
    let result2 = cached_dao
        .get_or_compute(cache_key, || async {
            mock_dao
                .find_by_region_and_model("us-east-1", "anthropic.claude-sonnet-4-20250514-v1:0")
                .await
                .map_err(bedrock_sso_proxy::database::DatabaseError::Database)
        })
        .await
        .expect("Failed to retrieve cached ModelCost from Redis");

    assert!(result2.is_some());
    assert_eq!(mock_dao.get_call_count(), 1); // No additional call due to cache hit

    // Verify cached data matches original
    let cached_model_cost = result2.unwrap();
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

    // Cleanup
    cached_dao
        .invalidate_keys(&[cache_key.to_string()])
        .await
        .unwrap();
}

#[tokio::test]
#[serial]
async fn test_model_cost_cache_edge_case_decimals() {
    let config = CacheConfig {
        backend: "redis".to_string(),
        redis_url: "redis://localhost:6379".to_string(),
        redis_key_prefix: "test_edge_cases:".to_string(),
        validation_ttl: 3600,
        max_entries: 1000,
        cleanup_interval: 3600,
    };

    let cache_manager = CacheManager::new_from_config(&config)
        .await
        .expect("Failed to create Redis cache manager");

    let typed_cache = cache_manager.cache::<ModelCost>();

    // Test edge case decimal values that might trigger deserialize_any
    let edge_cases = vec![
        ("zero", Decimal::ZERO),
        ("negative", Decimal::new(-12345, 4)), // -1.2345
        ("high_precision", Decimal::new(123456789, 9)), // 0.123456789
        ("very_small", Decimal::new(1, 10)),   // 0.0000000001
        ("large_number", Decimal::new(999999999999999999i64, 6)), // Very large with precision
    ];

    for (test_name, decimal_value) in edge_cases {
        let model_cost = ModelCost {
            id: 1,
            region: "test-region".to_string(),
            model_id: format!("test-model-{}", test_name),
            input_cost_per_1k_tokens: decimal_value,
            output_cost_per_1k_tokens: decimal_value,
            cache_write_cost_per_1k_tokens: Some(decimal_value),
            cache_read_cost_per_1k_tokens: Some(decimal_value),
            updated_at: Utc::now(),
        };

        let cache_key = format!("edge_case_{}", test_name);

        // This would fail with bincode for certain decimal values
        typed_cache
            .set(&cache_key, &model_cost)
            .await
            .unwrap_or_else(|_| {
                panic!("Failed to cache ModelCost with decimal: {}", decimal_value)
            });

        let cached = typed_cache
            .get(&cache_key)
            .await
            .expect("Failed to retrieve cached ModelCost")
            .expect("Cached ModelCost should exist");

        assert_eq!(cached.input_cost_per_1k_tokens, decimal_value);
        assert_eq!(cached.output_cost_per_1k_tokens, decimal_value);
        assert_eq!(cached.cache_write_cost_per_1k_tokens, Some(decimal_value));
        assert_eq!(cached.cache_read_cost_per_1k_tokens, Some(decimal_value));

        // Cleanup
        typed_cache.delete(&cache_key).await.unwrap();
    }
}

#[tokio::test]
async fn test_model_cost_cache_comparison_memory_vs_redis() {
    // Test both backends with the same data to ensure they behave identically
    let memory_cache = CacheManager::new_memory();

    let redis_config = CacheConfig {
        backend: "redis".to_string(),
        redis_url: "redis://localhost:6379".to_string(),
        redis_key_prefix: "test_comparison:".to_string(),
        validation_ttl: 3600,
        max_entries: 1000,
        cleanup_interval: 3600,
    };

    let redis_cache = match CacheManager::new_from_config(&redis_config).await {
        Ok(cache) => cache,
        Err(_) => {
            // Skip Redis comparison if Redis is not available
            println!("Skipping Redis comparison - Redis not available");
            return;
        }
    };

    let memory_typed_cache = memory_cache.cache::<ModelCost>();
    let redis_typed_cache = redis_cache.cache::<ModelCost>();

    let model_cost = ModelCost {
        id: 1,
        region: "comparison-test".to_string(),
        model_id: "test-model".to_string(),
        input_cost_per_1k_tokens: Decimal::new(314159, 5), // π approximation
        output_cost_per_1k_tokens: Decimal::new(271828, 5), // e approximation
        cache_write_cost_per_1k_tokens: Some(Decimal::new(123456, 6)),
        cache_read_cost_per_1k_tokens: Some(Decimal::new(789012, 7)),
        updated_at: Utc::now(),
    };

    let cache_key = "comparison_test";

    // Store in both caches
    memory_typed_cache
        .set(cache_key, &model_cost)
        .await
        .unwrap();
    redis_typed_cache.set(cache_key, &model_cost).await.unwrap();

    // Retrieve from both caches
    let memory_result = memory_typed_cache.get(cache_key).await.unwrap().unwrap();
    let redis_result = redis_typed_cache.get(cache_key).await.unwrap().unwrap();

    // They should be identical
    assert_eq!(memory_result.id, redis_result.id);
    assert_eq!(memory_result.region, redis_result.region);
    assert_eq!(memory_result.model_id, redis_result.model_id);
    assert_eq!(
        memory_result.input_cost_per_1k_tokens,
        redis_result.input_cost_per_1k_tokens
    );
    assert_eq!(
        memory_result.output_cost_per_1k_tokens,
        redis_result.output_cost_per_1k_tokens
    );
    assert_eq!(
        memory_result.cache_write_cost_per_1k_tokens,
        redis_result.cache_write_cost_per_1k_tokens
    );
    assert_eq!(
        memory_result.cache_read_cost_per_1k_tokens,
        redis_result.cache_read_cost_per_1k_tokens
    );

    // Cleanup Redis
    redis_typed_cache.delete(cache_key).await.unwrap();
}
