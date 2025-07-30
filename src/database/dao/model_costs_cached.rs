//! Cached model costs DAO providing transparent caching for model cost lookups
//!
//! This module provides a cached version of the ModelCostsDao that uses TypedCache
//! for efficient cost lookups. Since model costs change infrequently, this significantly
//! improves performance for high-frequency cost calculations.

use crate::cache::CacheManagerImpl;
use crate::database::DatabaseResult;
use crate::database::dao::ModelCostsDao;
use crate::database::dao::cached::CachedDao;
use crate::database::entities::ModelCost;
use tracing::{debug, trace};

/// Cached model costs DAO with automatic cache management
#[derive(Clone)]
pub struct CachedModelCostsDao {
    /// Cached DAO wrapper
    cached_dao: CachedDao<ModelCostsDao, ModelCost>,
}

impl CachedModelCostsDao {
    /// Create a new cached model costs DAO
    pub fn new(inner: ModelCostsDao, cache_manager: &CacheManagerImpl) -> Self {
        Self {
            cached_dao: CachedDao::new(inner, cache_manager),
        }
    }

    /// Get model cost by region and model ID with caching
    pub async fn find_by_region_and_model(
        &self,
        region: &str,
        model_id: &str,
    ) -> DatabaseResult<Option<ModelCost>> {
        let cache_key = format!("{}:{}", region, model_id);

        self.cached_dao
            .get_or_compute(&cache_key, || async {
                trace!(
                    "Cache miss for model cost: region={}, model_id={}",
                    region, model_id
                );
                self.cached_dao
                    .inner()
                    .find_by_region_and_model(region, model_id)
                    .await
            })
            .await
    }

    /// Get model cost by model ID with caching (deprecated - use find_by_region_and_model)
    /// This method uses a default region for backward compatibility
    pub async fn find_by_model(&self, model_id: &str) -> DatabaseResult<Option<ModelCost>> {
        // Use default region for backward compatibility
        let default_region = "us-east-1";
        self.find_by_region_and_model(default_region, model_id)
            .await
    }

    /// Store or update model costs with cache invalidation
    pub async fn upsert_many(&self, costs: &[ModelCost]) -> DatabaseResult<()> {
        debug!(
            "Upserting {} model costs with cache invalidation",
            costs.len()
        );

        // Collect all cache keys that need invalidation (region+model only)
        let mut cache_keys = Vec::new();
        for cost in costs {
            cache_keys.push(format!("{}:{}", cost.region, cost.model_id));
        }

        // Update database and invalidate cache
        self.cached_dao
            .update_and_invalidate(
                || async { self.cached_dao.inner().upsert_many(costs).await },
                &cache_keys,
            )
            .await
    }

    /// Get all model costs (not cached due to potential large size)
    pub async fn get_all(&self) -> DatabaseResult<Vec<ModelCost>> {
        debug!("Getting all model costs (bypassing cache)");
        self.cached_dao.inner().get_all().await
    }

    /// Delete model cost by region and model ID with cache invalidation
    pub async fn delete_by_region_and_model(
        &self,
        region: &str,
        model_id: &str,
    ) -> DatabaseResult<()> {
        let cache_keys = vec![format!("{}:{}", region, model_id)];

        self.cached_dao
            .delete_and_invalidate(
                || async {
                    self.cached_dao
                        .inner()
                        .delete_by_region_and_model(region, model_id)
                        .await
                },
                &cache_keys,
            )
            .await
    }

    /// Get the inner DAO reference
    pub fn inner(&self) -> &ModelCostsDao {
        self.cached_dao.inner()
    }

    /// Get cache statistics
    pub fn get_cache_stats(&self) -> crate::cache::typed::TypedCacheStats {
        self.cached_dao.get_cache_stats()
    }

    /// Invalidate all cache entries for a specific region and model
    pub async fn invalidate_region_model_cache(
        &self,
        region: &str,
        model_id: &str,
    ) -> DatabaseResult<()> {
        let cache_keys = vec![format!("{}:{}", region, model_id)];

        self.cached_dao.invalidate_keys(&cache_keys).await
    }
}
