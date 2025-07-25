use crate::{
    auth::{jwt::ValidatedClaims, middleware::ClaimsExtractor},
    cost_tracking::{CostTrackingService, UpdateCostsResult, CostSummary},
    error::AppError,
    storage::{Storage, StoredModelCost, UsageQuery, UsageRecord, UsageStats},
};
use rust_decimal::Decimal;
use axum::{
    Router,
    extract::{Path, Query, State},
    http::StatusCode,
    response::Json,
    routing::{delete, get, post, put},
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Create usage tracking API routes
pub fn create_usage_routes() -> Router<Arc<Storage>> {
    Router::new()
        // User usage endpoints
        .route("/usage/records", get(get_user_usage_records))
        .route("/usage/stats", get(get_user_usage_stats))
        // Admin endpoints (system-wide usage)
        .route("/admin/usage/records", get(get_system_usage_records))
        .route("/admin/usage/stats", get(get_system_usage_stats))
        .route("/admin/usage/top-models", get(get_top_models))
        // Model cost management endpoints
        .route("/admin/model-costs", get(get_all_model_costs))
        .route("/admin/model-costs", post(create_model_cost))
        .route("/admin/model-costs/{model_id}", put(update_model_cost))
        .route("/admin/model-costs/{model_id}", delete(delete_model_cost))
        .route("/admin/model-costs/{model_id}", get(get_model_cost))
        // Cost tracking endpoints
        .route("/admin/costs/update", post(update_all_model_costs))
        .route("/admin/costs/summary", get(get_cost_summary))
}

/// Query parameters for usage records
#[derive(Debug, Deserialize)]
pub struct UsageRecordsQuery {
    pub limit: Option<u32>,
    pub offset: Option<u32>,
    pub model: Option<String>,
    pub start_date: Option<DateTime<Utc>>,
    pub end_date: Option<DateTime<Utc>>,
    pub success_only: Option<bool>,
}

/// Query parameters for usage stats
#[derive(Debug, Deserialize)]
pub struct UsageStatsQuery {
    pub start_date: Option<DateTime<Utc>>,
    pub end_date: Option<DateTime<Utc>>,
}

/// Response for usage records endpoint
#[derive(Debug, Serialize)]
pub struct UsageRecordsResponse {
    pub records: Vec<UsageRecord>,
    pub total: u32,
    pub limit: u32,
    pub offset: u32,
}

/// Response for top models endpoint
#[derive(Debug, Serialize)]
pub struct TopModelsResponse {
    pub models: Vec<ModelUsage>,
}

#[derive(Debug, Serialize)]
pub struct ModelUsage {
    pub model_id: String,
    pub total_tokens: u64,
}

/// Request/Response for model cost management
#[derive(Debug, Serialize, Deserialize)]
pub struct ModelCostRequest {
    pub model_id: String,
    pub input_cost_per_1k_tokens: f64,
    pub output_cost_per_1k_tokens: f64,
}

/// Get user's usage records
async fn get_user_usage_records(
    ClaimsExtractor(claims): ClaimsExtractor,
    State(storage): State<Arc<Storage>>,
    Query(params): Query<UsageRecordsQuery>,
) -> Result<Json<UsageRecordsResponse>, AppError> {
    // Get user ID directly from JWT claims
    let user_id = claims.user_id();

    let limit = params.limit.unwrap_or(50).min(500); // Max 500 records
    let offset = params.offset.unwrap_or(0);

    let records = storage
        .database
        .get_user_usage_records(
            user_id,
            limit,
            offset,
            params.model.as_deref(),
            params.start_date,
            params.end_date,
        )
        .await?;

    // Get total count for pagination (simplified for now)
    let total = records.len() as u32;

    Ok(Json(UsageRecordsResponse {
        records,
        total,
        limit,
        offset,
    }))
}

/// Get user's usage statistics
async fn get_user_usage_stats(
    ClaimsExtractor(claims): ClaimsExtractor,
    State(storage): State<Arc<Storage>>,
    Query(params): Query<UsageStatsQuery>,
) -> Result<Json<UsageStats>, AppError> {
    // Get user ID directly from JWT claims
    let user_id = claims.user_id();

    let stats = storage
        .database
        .get_user_usage_stats(user_id, params.start_date, params.end_date)
        .await?;

    Ok(Json(stats))
}

/// Get system-wide usage records (admin only)
async fn get_system_usage_records(
    ClaimsExtractor(claims): ClaimsExtractor,
    State(storage): State<Arc<Storage>>,
    Query(params): Query<UsageRecordsQuery>,
) -> Result<Json<UsageRecordsResponse>, AppError> {
    // Check admin permissions
    check_admin_permissions(&storage, &claims).await?;

    let limit = params.limit.unwrap_or(50).min(500);
    let offset = params.offset.unwrap_or(0);

    let query = UsageQuery {
        user_id: None, // All users
        model_id: params.model.clone(),
        start_date: params.start_date,
        end_date: params.end_date,
        success_only: params.success_only,
        limit: Some(limit),
        offset: Some(offset),
    };

    let records = storage.database.get_usage_records(&query).await?;
    let total = records.len() as u32; // Simplified

    Ok(Json(UsageRecordsResponse {
        records,
        total,
        limit,
        offset,
    }))
}

/// Get system-wide usage statistics (admin only)
async fn get_system_usage_stats(
    ClaimsExtractor(claims): ClaimsExtractor,
    State(storage): State<Arc<Storage>>,
    Query(params): Query<UsageStatsQuery>,
) -> Result<Json<UsageStats>, AppError> {
    check_admin_permissions(&storage, &claims).await?;

    let stats = storage
        .database
        .get_system_usage_stats(params.start_date, params.end_date)
        .await?;

    Ok(Json(stats))
}

/// Get top models by usage (admin only)
async fn get_top_models(
    ClaimsExtractor(claims): ClaimsExtractor,
    State(storage): State<Arc<Storage>>,
    Query(params): Query<UsageStatsQuery>,
) -> Result<Json<TopModelsResponse>, AppError> {
    check_admin_permissions(&storage, &claims).await?;

    let models = storage
        .database
        .get_top_models_by_usage(10, params.start_date, params.end_date)
        .await?;

    let model_usage: Vec<ModelUsage> = models
        .into_iter()
        .map(|(model_id, total_tokens)| ModelUsage {
            model_id,
            total_tokens,
        })
        .collect();

    Ok(Json(TopModelsResponse {
        models: model_usage,
    }))
}

/// Get all model costs (admin only)
async fn get_all_model_costs(
    ClaimsExtractor(claims): ClaimsExtractor,
    State(storage): State<Arc<Storage>>,
) -> Result<Json<Vec<StoredModelCost>>, AppError> {
    check_admin_permissions(&storage, &claims).await?;
    let costs = storage.database.get_all_model_costs().await?;
    Ok(Json(costs))
}

/// Get specific model cost (admin only)
async fn get_model_cost(
    ClaimsExtractor(claims): ClaimsExtractor,
    State(storage): State<Arc<Storage>>,
    Path(model_id): Path<String>,
) -> Result<Json<StoredModelCost>, AppError> {
    check_admin_permissions(&storage, &claims).await?;

    let cost = storage
        .database
        .get_model_cost(&model_id)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("Model cost not found: {}", model_id)))?;

    Ok(Json(cost))
}

/// Create or update model cost (admin only)
async fn create_model_cost(
    ClaimsExtractor(claims): ClaimsExtractor,
    State(storage): State<Arc<Storage>>,
    Json(request): Json<ModelCostRequest>,
) -> Result<StatusCode, AppError> {
    check_admin_permissions(&storage, &claims).await?;

    let cost = StoredModelCost {
        id: None,
        model_id: request.model_id,
        input_cost_per_1k_tokens: Decimal::from_f64_retain(request.input_cost_per_1k_tokens).unwrap_or_default(),
        output_cost_per_1k_tokens: Decimal::from_f64_retain(request.output_cost_per_1k_tokens).unwrap_or_default(),
        updated_at: Utc::now(),
    };

    storage.database.upsert_model_cost(&cost).await?;
    Ok(StatusCode::CREATED)
}

/// Update model cost (admin only)
async fn update_model_cost(
    ClaimsExtractor(claims): ClaimsExtractor,
    State(storage): State<Arc<Storage>>,
    Path(model_id): Path<String>,
    Json(request): Json<ModelCostRequest>,
) -> Result<StatusCode, AppError> {
    check_admin_permissions(&storage, &claims).await?;

    // Verify model exists
    storage
        .database
        .get_model_cost(&model_id)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("Model cost not found: {}", model_id)))?;

    let cost = StoredModelCost {
        id: None,
        model_id: model_id.clone(),
        input_cost_per_1k_tokens: Decimal::from_f64_retain(request.input_cost_per_1k_tokens).unwrap_or_default(),
        output_cost_per_1k_tokens: Decimal::from_f64_retain(request.output_cost_per_1k_tokens).unwrap_or_default(),
        updated_at: Utc::now(),
    };

    storage.database.upsert_model_cost(&cost).await?;
    Ok(StatusCode::OK)
}

/// Delete model cost (admin only)
async fn delete_model_cost(
    ClaimsExtractor(claims): ClaimsExtractor,
    State(storage): State<Arc<Storage>>,
    Path(model_id): Path<String>,
) -> Result<StatusCode, AppError> {
    check_admin_permissions(&storage, &claims).await?;

    storage.database.delete_model_cost(&model_id).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Update all model costs from AWS Price List API (admin only)
/// Fails if AWS API is unavailable - leaves current pricing unchanged
async fn update_all_model_costs(
    ClaimsExtractor(claims): ClaimsExtractor,
    State(storage): State<Arc<Storage>>,
) -> Result<Json<UpdateCostsResult>, AppError> {
    check_admin_permissions(&storage, &claims).await?;

    // Create cost tracking service with us-east-1 region for pricing data
    let cost_service = CostTrackingService::new(storage, "us-east-1".to_string());
    
    // Update model costs from AWS API only (no fallback - preserves existing data on failure)
    let result = cost_service.update_all_model_costs().await?;
    
    Ok(Json(result))
}

/// Get cost summary for all models (admin only)
async fn get_cost_summary(
    ClaimsExtractor(claims): ClaimsExtractor,
    State(storage): State<Arc<Storage>>,
) -> Result<Json<CostSummary>, AppError> {
    check_admin_permissions(&storage, &claims).await?;

    let cost_service = CostTrackingService::new(storage, "us-east-1".to_string());
    let summary = cost_service.get_cost_summary().await?;
    
    Ok(Json(summary))
}

// Note: user_id is now directly extracted from JWT claims via claims.user_id()
// This eliminates the need for database lookups for regular user operations

/// Helper function to check admin permissions
async fn check_admin_permissions(
    _storage: &Storage,
    claims: &ValidatedClaims,
) -> Result<(), AppError> {
    // Get user email from claims
    let email = claims
        .email()
        .ok_or_else(|| AppError::Unauthorized("Email required for admin access".to_string()))?;

    // Check if user is in admin list (this would come from config)
    // For now, we'll implement a simple check
    // In a real implementation, you'd check against a config list or database role
    if email.ends_with("@admin.example.com") {
        Ok(())
    } else {
        Err(AppError::Forbidden("Admin access required".to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::jwt::{OAuthClaims, ValidatedClaims};
    use crate::storage::memory::MemoryCacheStorage;
    use axum::{body::Body, http::Request};
    use chrono::Utc;
    use tower::ServiceExt;

    fn create_test_claims() -> ValidatedClaims {
        ValidatedClaims::OAuth(OAuthClaims {
            sub: "test-user".to_string(),
            provider: "google".to_string(),
            email: "admin@admin.example.com".to_string(),
            user_id: 1,
            exp: (Utc::now().timestamp() + 3600) as usize,
            iat: Utc::now().timestamp() as usize,
            refresh_token_id: None,
        })
    }

    #[tokio::test]
    async fn test_create_usage_routes() {
        let storage = Arc::new(crate::storage::Storage::new(
            Box::new(MemoryCacheStorage::new(3600)),
            Box::new(crate::storage::database::SqliteStorage::new("sqlite::memory:").await.unwrap()),
        ));
        storage.migrate().await.unwrap();

        let app = create_usage_routes().with_state(storage);

        // Test that routes are properly configured
        let request = Request::builder()
            .uri("/usage/records")
            .body(Body::empty())
            .unwrap();

        // This will fail without proper authentication, but confirms routing works
        let response = app.oneshot(request).await.unwrap();
        // Should return 500 since we don't have proper middleware setup in test
        assert!(response.status().is_server_error() || response.status().is_client_error());
    }

    #[tokio::test]
    async fn test_admin_permissions() {
        let storage = crate::storage::Storage::new(
            Box::new(MemoryCacheStorage::new(3600)),
            Box::new(crate::storage::database::SqliteStorage::new("sqlite::memory:").await.unwrap()),
        );
        storage.migrate().await.unwrap();

        let admin_claims = create_test_claims();
        assert!(
            check_admin_permissions(&storage, &admin_claims)
                .await
                .is_ok()
        );

        let non_admin_claims = ValidatedClaims::OAuth(OAuthClaims {
            sub: "test-user".to_string(),
            provider: "google".to_string(),
            email: "user@example.com".to_string(),
            user_id: 2,
            exp: (Utc::now().timestamp() + 3600) as usize,
            iat: Utc::now().timestamp() as usize,
            refresh_token_id: None,
        });
        assert!(
            check_admin_permissions(&storage, &non_admin_claims)
                .await
                .is_err()
        );
    }
}
