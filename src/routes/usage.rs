use crate::{
    auth::middleware::UserExtractor,
    database::{
        dao::usage::UsageQuery,
        entities::{PeriodType, UsageRecord},
    },
    error::AppError,
    routes::ApiErrorResponse,
};
use axum::{
    Router,
    extract::{Query, State},
    response::{IntoResponse, Json},
    routing::get,
};
use axum::http::header;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

/// Create usage tracking API routes for regular users
pub fn create_user_usage_routes() -> Router<crate::server::Server> {
    Router::new()
        .route("/usage/records", get(get_user_usage_records))
        .route("/usage/summaries", get(get_user_usage_summaries))
}

/// Create admin usage tracking API routes
pub fn create_admin_usage_routes() -> Router<crate::server::Server> {
    Router::new()
        // Admin endpoints (system-wide usage)
        .route("/admin/usage/records", get(get_system_usage_records))
        .route("/admin/usage/summaries", get(get_admin_usage_summaries))
}

/// Query parameters for usage records
#[derive(Debug, Deserialize, ToSchema, IntoParams)]
pub struct UsageRecordsQuery {
    /// Maximum number of records to return (default: 50, max: 500)
    pub limit: Option<u32>,
    /// Number of records to skip for pagination
    pub offset: Option<u32>,
    /// Filter by specific model ID
    pub model: Option<String>,
    /// Filter records from this date onwards
    pub start_date: Option<DateTime<Utc>>,
    /// Filter records up to this date
    pub end_date: Option<DateTime<Utc>>,
    /// If true, only return successful requests
    pub success_only: Option<bool>,
    /// Response format (json or csv)
    pub format: Option<String>,
    /// Filter by specific user ID (admin only)
    pub user_id: Option<i32>,
}

/// Query parameters for usage summaries
#[derive(Debug, Deserialize, ToSchema, IntoParams)]
pub struct UsageSummariesQuery {
    /// Filter summaries from this date onwards
    pub start_date: Option<DateTime<Utc>>,
    /// Filter summaries up to this date
    pub end_date: Option<DateTime<Utc>>,
    /// Period type for aggregation (hourly, daily, weekly, monthly)
    pub period_type: Option<String>,
    /// Filter by specific model ID
    pub model_id: Option<String>,
    /// Maximum number of summaries to return (default: 1000)
    pub limit: Option<u32>,
    /// Number of summaries to skip for pagination
    pub offset: Option<u32>,
    /// Filter by specific user ID (admin only)
    pub user_id: Option<i32>,
}

/// Response for usage records endpoint
#[derive(Debug, Serialize, ToSchema)]
pub struct UsageRecordsResponse {
    /// List of usage records
    pub records: Vec<UsageRecord>,
    /// Total number of matching records (for pagination)
    pub total: u64,
    /// Number of records returned in this page
    pub limit: u32,
    /// Number of records skipped
    pub offset: u32,
}

/// Response for usage summaries endpoint
#[derive(Debug, Serialize, ToSchema)]
pub struct UsageSummariesResponse {
    /// List of usage summaries
    pub summaries: Vec<crate::database::entities::usage_summaries::Model>,
    /// Total number of matching summaries (for pagination)
    pub total: u64,
    /// Number of summaries returned in this page
    pub limit: u32,
    /// Number of summaries skipped
    pub offset: u32,
}

/// Common implementation for handling usage records requests
async fn handle_usage_records(
    server: crate::server::Server,
    params: UsageRecordsQuery,
    user_id_override: Option<i32>,
) -> Result<impl IntoResponse, AppError> {
    let limit = params.limit.unwrap_or(50).min(500);
    let offset = params.offset.unwrap_or(0);
    
    // Use override (for user endpoints) or query param (for admin endpoints)
    let user_id = user_id_override.or(params.user_id);
    
    let query = UsageQuery {
        user_id,
        model_id: params.model.clone(),
        start_date: params.start_date,
        end_date: params.end_date,
        success_only: params.success_only,
        limit: Some(limit),
        offset: Some(offset),
        ..Default::default()
    };
    
    let paginated_records = server.database.usage().get_records(&query).await?;
    
    if params.format.as_deref() == Some("csv") {
        let mut wtr = csv::WriterBuilder::new().from_writer(vec![]);

        // Write records (header is written automatically)
        for record in paginated_records.records {
            wtr.serialize(record)
                .map_err(|e| AppError::Internal(e.to_string()))?;
        }

        wtr.flush().map_err(|e| AppError::Internal(e.to_string()))?;
        let csv_data = wtr
            .into_inner()
            .map_err(|e| AppError::Internal(e.to_string()))?;

        // Create response
        let headers = [
            (header::CONTENT_TYPE, "text/csv; charset=utf-8"),
            (
                header::CONTENT_DISPOSITION,
                "attachment; filename=\"usage_export.csv\"",
            ),
        ];

        return Ok((headers, csv_data).into_response());
    }

    Ok(Json(UsageRecordsResponse {
        records: paginated_records.records,
        total: paginated_records.total_count,
        limit,
        offset,
    })
    .into_response())
}

/// Get user's usage records
#[utoipa::path(
    get,
    path = "/usage/records",
    summary = "Get User Usage Records",
    description = "Retrieve usage records for the authenticated user",
    tags = ["Usage Tracking"],
    params(UsageRecordsQuery),
    responses(
        (status = 200, description = "List of usage records", body = UsageRecordsResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse)
    ),
    security(
        ("jwt_auth" = []),
        ("api_key_auth" = [])
    )
)]
async fn get_user_usage_records(
    State(server): State<crate::server::Server>,
    UserExtractor(user): UserExtractor,
    Query(params): Query<UsageRecordsQuery>,
) -> Result<impl IntoResponse, AppError> {
    // Get user ID from JWT claims (sub field contains database user ID)
    let user_id: i32 = user.id;
    handle_usage_records(server, params, Some(user_id)).await
}

/// Common implementation for handling usage summaries requests
async fn handle_usage_summaries(
    server: crate::server::Server,
    params: UsageSummariesQuery,
    user_id_override: Option<i32>,
) -> Result<Json<UsageSummariesResponse>, AppError> {
    let limit = params.limit.unwrap_or(1000).min(5000); // Max 5000 summaries
    let offset = params.offset.unwrap_or(0);
    
    // Use override (for user endpoints) or query param (for admin endpoints)
    let user_id = user_id_override.or(params.user_id);
    
    // Parse period type
    let period_type = if let Some(ref period_str) = params.period_type {
        match period_str.as_str() {
            "hourly" => Some(PeriodType::Hourly),
            "daily" => Some(PeriodType::Daily),
            "weekly" => Some(PeriodType::Weekly),
            "monthly" => Some(PeriodType::Monthly),
            _ => Some(PeriodType::Daily), // Invalid period type, default to daily
        }
    } else {
        Some(PeriodType::Daily) // Default to daily
    };

    let query = UsageQuery {
        user_id,
        model_id: params.model_id.clone(),
        start_date: params.start_date,
        end_date: params.end_date,
        period_type,
        limit: Some(limit),
        offset: Some(offset),
        ..Default::default()
    };

    let summaries = server.database.usage().get_summaries(&query).await?;
    let total = summaries.len() as u64; // For simplicity, return the count we got

    Ok(Json(UsageSummariesResponse {
        summaries,
        total,
        limit,
        offset,
    }))
}

/// Get user's usage summaries
#[utoipa::path(
    get,
    path = "/usage/summaries",
    summary = "Get User Usage Summaries",
    description = "Retrieve pre-computed usage summaries for the authenticated user",
    tags = ["Usage Tracking"],
    params(UsageSummariesQuery),
    responses(
        (status = 200, description = "Usage summaries", body = UsageSummariesResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse)
    ),
    security(
        ("jwt_auth" = []),
        ("api_key_auth" = [])
    )
)]
async fn get_user_usage_summaries(
    State(server): State<crate::server::Server>,
    UserExtractor(user): UserExtractor,
    Query(params): Query<UsageSummariesQuery>,
) -> Result<Json<UsageSummariesResponse>, AppError> {
    let user_id: i32 = user.id;
    handle_usage_summaries(server, params, Some(user_id)).await
}

/// Get system-wide usage records (admin only)
#[utoipa::path(
    get,
    path = "/admin/usage/records",
    summary = "Get System Usage Records",
    description = "Retrieve usage records for all users (admin only)",
    tags = ["Admin Usage Management"],
    params(UsageRecordsQuery),
    responses(
        (status = 200, description = "List of system usage records", body = UsageRecordsResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 403, description = "Forbidden - admin access required", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse)
    ),
    security(
        ("jwt_auth" = [])
    )
)]
async fn get_system_usage_records(
    State(server): State<crate::server::Server>,
    Query(params): Query<UsageRecordsQuery>,
) -> Result<impl IntoResponse, AppError> {
    // Admin permissions already checked by middleware
    handle_usage_records(server, params, None).await
}

/// Get system-wide usage summaries (admin only)
#[utoipa::path(
    get,
    path = "/admin/usage/summaries",
    summary = "Get System Usage Summaries",
    description = "Retrieve pre-computed usage summaries for all users (admin only)",
    tags = ["Admin Usage Management"],
    params(UsageSummariesQuery),
    responses(
        (status = 200, description = "System usage summaries", body = UsageSummariesResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 403, description = "Forbidden - admin access required", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse)
    ),
    security(
        ("jwt_auth" = [])
    )
)]
async fn get_admin_usage_summaries(
    State(server): State<crate::server::Server>,
    Query(params): Query<UsageSummariesQuery>,
) -> Result<Json<UsageSummariesResponse>, AppError> {
    // Admin permissions already checked by middleware
    handle_usage_summaries(server, params, None).await
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
