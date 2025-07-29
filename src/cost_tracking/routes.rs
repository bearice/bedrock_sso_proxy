use crate::{
    cost_tracking::{CostTrackingService, UpdateCostsResult},
    database::entities::StoredModelCost,
    error::AppError,
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

/// Create admin cost tracking API routes
pub fn create_admin_cost_routes() -> Router<crate::server::Server> {
    Router::new()
        // Cost tracking endpoints
        .route("/admin/costs", get(get_all_model_costs))
        .route("/admin/costs", post(update_all_model_costs))
        .route("/admin/costs/{region}/{model_id}", put(upsert_model_cost))
        .route("/admin/costs/{region}/{model_id}", delete(delete_model_cost))
        .route("/admin/costs/{region}/{model_id}", get(get_model_cost))
}

/// Request/Response for model cost management
#[derive(Debug, Serialize, Deserialize)]
pub struct ModelCostRequest {
    pub region: String,
    pub model_id: String,
    pub input_cost_per_1k_tokens: f64,
    pub output_cost_per_1k_tokens: f64,
    pub cache_write_cost_per_1k_tokens: Option<f64>,
    pub cache_read_cost_per_1k_tokens: Option<f64>,
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
    Path((region, model_id)): Path<(String, String)>,
) -> Result<Json<StoredModelCost>, AppError> {
    // Admin permissions already checked by middleware

    let cost = server
        .database
        .model_costs()
        .find_by_region_and_model(&region, &model_id)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("Model cost not found: {} in region {}", model_id, region)))?;

    Ok(Json(cost))
}

/// Upsert model cost (create or update) (admin only)
async fn upsert_model_cost(
    State(server): State<crate::server::Server>,
    Path((region, model_id)): Path<(String, String)>,
    Json(request): Json<ModelCostRequest>,
) -> Result<StatusCode, AppError> {
    // Admin permissions already checked by middleware

    let cost = StoredModelCost {
        id: 0, // Will be set by database
        region: region.clone(),
        model_id: model_id.clone(),
        input_cost_per_1k_tokens: Decimal::from_f64_retain(request.input_cost_per_1k_tokens)
            .unwrap_or_default(),
        output_cost_per_1k_tokens: Decimal::from_f64_retain(request.output_cost_per_1k_tokens)
            .unwrap_or_default(),
        cache_write_cost_per_1k_tokens: request.cache_write_cost_per_1k_tokens
            .map(|c| Decimal::from_f64_retain(c).unwrap_or_default()),
        cache_read_cost_per_1k_tokens: request.cache_read_cost_per_1k_tokens
            .map(|c| Decimal::from_f64_retain(c).unwrap_or_default()),
        updated_at: Utc::now(),
    };

    server.database.model_costs().upsert_many(&[cost]).await?;
    Ok(StatusCode::OK)
}

/// Delete model cost (admin only)
async fn delete_model_cost(
    State(server): State<crate::server::Server>,
    Path((region, model_id)): Path<(String, String)>,
) -> Result<StatusCode, AppError> {
    // Admin permissions already checked by middleware

    server.database.model_costs().delete_by_region_and_model(&region, &model_id).await?;
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

