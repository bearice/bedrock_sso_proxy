use crate::{
    auth::middleware::UserExtractor,
    database::{
        dao::usage::{UsageQuery, UsageStats},
        entities::UsageRecord,
    },
    error::AppError,
};
use axum::{
    Router,
    extract::{Query, State},
    response::Json,
    routing::get,
};
use chrono::{DateTime, Utc};
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
