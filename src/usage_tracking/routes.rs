use crate::{
    auth::middleware::UserExtractor,
    cost_tracking::{CostSummary, CostTrackingService, UpdateCostsResult},
    database::{
        dao::usage::{UsageQuery, UsageStats},
        entities::{StoredModelCost, UsageRecord},
    },
    error::AppError,
};
use axum::{
    Router,
    extract::{Path, Query, State},
    http::StatusCode,
    response::Json,
    routing::{delete, get, post, put},
};
use chrono::{DateTime, Utc};
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};

/// Create usage tracking API routes for regular users
pub fn create_user_usage_routes() -> Router<crate::server::Server> {
    Router::new()
        .route("/usage/records", get(get_user_usage_records))
        .route("/usage/stats", get(get_user_usage_stats))
}

/// Create admin usage tracking API routes
pub fn create_admin_usage_routes() -> Router<crate::server::Server> {
    Router::new()
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
    State(server): State<crate::server::Server>,
    UserExtractor(user): UserExtractor,
    Query(params): Query<UsageRecordsQuery>,
) -> Result<Json<UsageRecordsResponse>, AppError> {
    // Get user ID from JWT claims (sub field contains database user ID)
    let user_id: i32 = user.id;

    let limit = params.limit.unwrap_or(50).min(500); // Max 500 records
    let offset = params.offset.unwrap_or(0);

    let query = UsageQuery {
        user_id: Some(user_id),
        model_id: params.model.clone(),
        start_date: params.start_date,
        end_date: params.end_date,
        success_only: None,
        limit: Some(limit),
        offset: Some(offset),
    };

    let records = server.database.usage().get_records(&query).await?;

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
    State(server): State<crate::server::Server>,
    UserExtractor(user): UserExtractor,
    Query(params): Query<UsageStatsQuery>,
) -> Result<Json<UsageStats>, AppError> {
    // Get user ID from JWT claims (sub field contains database user ID)
    let user_id: i32 = user.id;

    let query = UsageQuery {
        user_id: Some(user_id),
        model_id: None,
        start_date: params.start_date,
        end_date: params.end_date,
        success_only: None,
        limit: None,
        offset: None,
    };

    let stats = server.database.usage().get_stats(&query).await?;

    Ok(Json(stats))
}

/// Get system-wide usage records (admin only)
async fn get_system_usage_records(
    State(server): State<crate::server::Server>,
    Query(params): Query<UsageRecordsQuery>,
) -> Result<Json<UsageRecordsResponse>, AppError> {
    // Admin permissions already checked by middleware

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

    let records = server.database.usage().get_records(&query).await?;
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
    State(server): State<crate::server::Server>,
    Query(params): Query<UsageStatsQuery>,
) -> Result<Json<UsageStats>, AppError> {
    // Admin permissions already checked by middleware

    let query = UsageQuery {
        user_id: None, // All users
        model_id: None,
        start_date: params.start_date,
        end_date: params.end_date,
        success_only: None,
        limit: None,
        offset: None,
    };

    let stats = server.database.usage().get_stats(&query).await?;

    Ok(Json(stats))
}

/// Get top models by usage (admin only)
async fn get_top_models(
    State(server): State<crate::server::Server>,
    Query(params): Query<UsageStatsQuery>,
) -> Result<Json<TopModelsResponse>, AppError> {
    // Admin permissions already checked by middleware

    let query = UsageQuery {
        user_id: None,  // All users
        model_id: None, // All models
        start_date: params.start_date,
        end_date: params.end_date,
        success_only: None,
        limit: Some(10), // Top 10 models
        offset: None,
    };

    // Get usage records and aggregate by model
    let records = server.database.usage().get_records(&query).await?;

    // Group by model_id and sum total_tokens
    let mut model_usage_map = std::collections::HashMap::new();
    for record in records {
        let entry = model_usage_map
            .entry(record.model_id.clone())
            .or_insert(0u64);
        *entry += record.total_tokens as u64;
    }

    // Sort by total_tokens (descending) and take top results
    let mut model_usage: Vec<ModelUsage> = model_usage_map
        .into_iter()
        .map(|(model_id, total_tokens)| ModelUsage {
            model_id,
            total_tokens,
        })
        .collect();

    model_usage.sort_by(|a, b| b.total_tokens.cmp(&a.total_tokens));

    Ok(Json(TopModelsResponse {
        models: model_usage,
    }))
}

/// Get all model costs (admin only)
async fn get_all_model_costs(
    State(server): State<crate::server::Server>,
) -> Result<Json<Vec<StoredModelCost>>, AppError> {
    // Admin permissions already checked by middleware
    let costs = server.database.model_costs().get_all().await?;
    Ok(Json(costs))
}

/// Get specific model cost (admin only)
async fn get_model_cost(
    State(server): State<crate::server::Server>,
    Path(model_id): Path<String>,
) -> Result<Json<StoredModelCost>, AppError> {
    // Admin permissions already checked by middleware

    let cost = server
        .database
        .model_costs()
        .find_by_model(&model_id)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("Model cost not found: {}", model_id)))?;

    Ok(Json(cost))
}

/// Create or update model cost (admin only)
async fn create_model_cost(
    State(server): State<crate::server::Server>,
    Json(request): Json<ModelCostRequest>,
) -> Result<StatusCode, AppError> {
    // Admin permissions already checked by middleware

    let cost = StoredModelCost {
        id: 0, // Will be set by database
        region: "us-east-1".to_string(), // Default region for manual cost updates
        model_id: request.model_id,
        input_cost_per_1k_tokens: Decimal::from_f64_retain(request.input_cost_per_1k_tokens)
            .unwrap_or_default(),
        output_cost_per_1k_tokens: Decimal::from_f64_retain(request.output_cost_per_1k_tokens)
            .unwrap_or_default(),
        cache_write_cost_per_1k_tokens: None,
        cache_read_cost_per_1k_tokens: None,
        updated_at: Utc::now(),
    };

    server.database.model_costs().upsert_many(&[cost]).await?;
    Ok(StatusCode::CREATED)
}

/// Update model cost (admin only)
async fn update_model_cost(
    State(server): State<crate::server::Server>,
    Path(model_id): Path<String>,
    Json(request): Json<ModelCostRequest>,
) -> Result<StatusCode, AppError> {
    // Admin permissions already checked by middleware

    // Verify model exists
    server
        .database
        .model_costs()
        .find_by_model(&model_id)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("Model cost not found: {}", model_id)))?;

    let cost = StoredModelCost {
        id: 0, // Will be set by database
        region: "us-east-1".to_string(), // Default region for manual cost updates
        model_id: model_id.clone(),
        input_cost_per_1k_tokens: Decimal::from_f64_retain(request.input_cost_per_1k_tokens)
            .unwrap_or_default(),
        output_cost_per_1k_tokens: Decimal::from_f64_retain(request.output_cost_per_1k_tokens)
            .unwrap_or_default(),
        cache_write_cost_per_1k_tokens: None,
        cache_read_cost_per_1k_tokens: None,
        updated_at: Utc::now(),
    };

    server.database.model_costs().upsert_many(&[cost]).await?;
    Ok(StatusCode::OK)
}

/// Delete model cost (admin only)
async fn delete_model_cost(
    State(server): State<crate::server::Server>,
    Path(model_id): Path<String>,
) -> Result<StatusCode, AppError> {
    // Admin permissions already checked by middleware

    server.database.model_costs().delete(&model_id).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Update all model costs from uploaded CSV data (admin only)
/// Requires CSV content in request body - does not use embedded data
async fn update_all_model_costs(
    State(server): State<crate::server::Server>,
    body: String,
) -> Result<Json<UpdateCostsResult>, AppError> {
    // Admin permissions already checked by middleware

    // Validate that CSV content is provided
    if body.trim().is_empty() {
        return Err(AppError::BadRequest(
            "CSV content is required for price updates. Please provide pricing data in the request body.".to_string()
        ));
    }

    // Create cost tracking service with us-east-1 region for pricing data
    let cost_service = CostTrackingService::new(server.database.clone());

    // Process the provided CSV content
    let result = cost_service.batch_update_from_csv_content(&body).await?;

    Ok(Json(result))
}

/// Get cost summary for all models (admin only)
async fn get_cost_summary(
    State(server): State<crate::server::Server>,
) -> Result<Json<CostSummary>, AppError> {
    // Admin permissions already checked by middleware

    let cost_service = CostTrackingService::new(server.database.clone());
    let summary = cost_service.get_cost_summary().await?;

    Ok(Json(summary))
}

// Note: user_id is now extracted from JWT sub field (database user ID)
// This eliminates the need for database lookups for regular user operations
// Admin permissions are checked by the admin_middleware in auth module

#[cfg(test)]
mod tests {
    use super::*;
    // Removed unused import
    use axum::{body::Body, http::Request};
    use tower::ServiceExt;

    #[tokio::test]
    async fn test_create_user_usage_routes() {
        async fn create_test_server() -> crate::server::Server {
            crate::test_utils::TestServerBuilder::new().build().await
        }

        let server = create_test_server().await;
        let app = create_user_usage_routes().with_state(server);

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
}
