use crate::{
    cost::UpdateCostsResult, database::entities::ModelCost, error::AppError,
    routes::ApiErrorResponse,
};
use axum::{
    Router,
    extract::{Path, State},
    http::StatusCode,
    response::Json,
    routing::{delete, get, post, put},
};
use chrono::Utc;
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// Create admin cost tracking API routes
pub fn create_admin_cost_routes() -> Router<crate::server::Server> {
    Router::new()
        // Cost tracking endpoints
        .route("/admin/costs", get(get_all_model_costs))
        .route("/admin/costs", post(update_all_model_costs))
        .route("/admin/costs/{region}/{model_id}", put(upsert_model_cost))
        .route(
            "/admin/costs/{region}/{model_id}",
            delete(delete_model_cost),
        )
        .route("/admin/costs/{region}/{model_id}", get(get_model_cost))
}

/// Request/Response for model cost management
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct ModelCostRequest {
    /// AWS region (e.g., "us-east-1")
    pub region: String,
    /// Model identifier (e.g., "anthropic.claude-sonnet-4-20250514-v1:0")
    pub model_id: String,
    /// Cost per 1000 input tokens in USD
    pub input_cost_per_1k_tokens: f64,
    /// Cost per 1000 output tokens in USD
    pub output_cost_per_1k_tokens: f64,
    /// Optional cost per 1000 cache write tokens in USD
    pub cache_write_cost_per_1k_tokens: Option<f64>,
    /// Optional cost per 1000 cache read tokens in USD
    pub cache_read_cost_per_1k_tokens: Option<f64>,
}

/// Get all model costs (admin only)
#[utoipa::path(
    get,
    path = "/admin/costs",
    summary = "Get All Model Costs",
    description = "Retrieve all model cost configurations (admin only)",
    tags = ["Cost Management"],
    responses(
        (status = 200, description = "List of all model costs", body = Vec<ModelCost>),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 403, description = "Forbidden - admin access required", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse)
    ),
    security(
        ("jwt_auth" = [])
    )
)]
async fn get_all_model_costs(
    State(server): State<crate::server::Server>,
) -> Result<Json<Vec<ModelCost>>, AppError> {
    // Admin permissions already checked by middleware
    let costs = server.database.model_costs().get_all().await?;
    Ok(Json(costs))
}

/// Get specific model cost (admin only)
#[utoipa::path(
    get,
    path = "/admin/costs/{region}/{model_id}",
    summary = "Get Model Cost",
    description = "Retrieve cost configuration for a specific model in a region (admin only)",
    tags = ["Cost Management"],
    params(
        ("region" = String, Path, description = "AWS region (e.g., us-east-1)"),
        ("model_id" = String, Path, description = "Model identifier")
    ),
    responses(
        (status = 200, description = "Model cost configuration", body = ModelCost),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 403, description = "Forbidden - admin access required", body = ApiErrorResponse),
        (status = 404, description = "Model cost not found", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse)
    ),
    security(
        ("jwt_auth" = [])
    )
)]
async fn get_model_cost(
    State(server): State<crate::server::Server>,
    Path((region, model_id)): Path<(String, String)>,
) -> Result<Json<ModelCost>, AppError> {
    // Admin permissions already checked by middleware

    let cost = server
        .database
        .model_costs()
        .find_by_region_and_model(&region, &model_id)
        .await?
        .ok_or_else(|| {
            AppError::NotFound(format!(
                "Model cost not found: {} in region {}",
                model_id, region
            ))
        })?;

    Ok(Json(cost))
}

/// Upsert model cost (create or update) (admin only)
#[utoipa::path(
    put,
    path = "/admin/costs/{region}/{model_id}",
    summary = "Create or Update Model Cost",
    description = "Create or update cost configuration for a specific model (admin only)",
    tags = ["Cost Management"],
    params(
        ("region" = String, Path, description = "AWS region (e.g., us-east-1)"),
        ("model_id" = String, Path, description = "Model identifier")
    ),
    request_body = ModelCostRequest,
    responses(
        (status = 200, description = "Model cost updated successfully"),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 403, description = "Forbidden - admin access required", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse)
    ),
    security(
        ("jwt_auth" = [])
    )
)]
async fn upsert_model_cost(
    State(server): State<crate::server::Server>,
    Path((region, model_id)): Path<(String, String)>,
    Json(request): Json<ModelCostRequest>,
) -> Result<StatusCode, AppError> {
    // Admin permissions already checked by middleware

    let cost = ModelCost {
        id: 0, // Will be set by database
        region: region.clone(),
        model_id: model_id.clone(),
        input_cost_per_1k_tokens: Decimal::from_f64_retain(request.input_cost_per_1k_tokens)
            .unwrap_or_default(),
        output_cost_per_1k_tokens: Decimal::from_f64_retain(request.output_cost_per_1k_tokens)
            .unwrap_or_default(),
        cache_write_cost_per_1k_tokens: request
            .cache_write_cost_per_1k_tokens
            .map(|c| Decimal::from_f64_retain(c).unwrap_or_default()),
        cache_read_cost_per_1k_tokens: request
            .cache_read_cost_per_1k_tokens
            .map(|c| Decimal::from_f64_retain(c).unwrap_or_default()),
        updated_at: Utc::now(),
    };

    server.database.model_costs().upsert_many(&[cost]).await?;
    Ok(StatusCode::OK)
}

/// Delete model cost (admin only)
#[utoipa::path(
    delete,
    path = "/admin/costs/{region}/{model_id}",
    summary = "Delete Model Cost",
    description = "Delete cost configuration for a specific model (admin only)",
    tags = ["Cost Management"],
    params(
        ("region" = String, Path, description = "AWS region (e.g., us-east-1)"),
        ("model_id" = String, Path, description = "Model identifier")
    ),
    responses(
        (status = 204, description = "Model cost deleted successfully"),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 403, description = "Forbidden - admin access required", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse)
    ),
    security(
        ("jwt_auth" = [])
    )
)]
async fn delete_model_cost(
    State(server): State<crate::server::Server>,
    Path((region, model_id)): Path<(String, String)>,
) -> Result<StatusCode, AppError> {
    // Admin permissions already checked by middleware

    server
        .database
        .model_costs()
        .delete_by_region_and_model(&region, &model_id)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Update all model costs from uploaded CSV data (admin only)
/// Requires CSV content in request body - does not use embedded data
#[utoipa::path(
    post,
    path = "/admin/costs",
    summary = "Batch Update Model Costs",
    description = "Update multiple model costs from CSV data (admin only)",
    tags = ["Cost Management"],
    request_body(
        content = String,
        description = "CSV content with model cost data",
        content_type = "text/csv"
    ),
    responses(
        (status = 200, description = "Batch update results", body = UpdateCostsResult),
        (status = 400, description = "Bad request - invalid CSV", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 403, description = "Forbidden - admin access required", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse)
    ),
    security(
        ("jwt_auth" = [])
    )
)]
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

    // Process the provided CSV content
    let result = server
        .cost_service
        .batch_update_from_csv_content(&body)
        .await?;

    Ok(Json(result))
}
