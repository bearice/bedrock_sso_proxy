pub mod anthropic;
pub mod api_keys;
pub mod audit_logs;
pub mod auth;
pub mod bedrock;
pub mod cost;
pub mod docs;
pub mod frontend;
pub mod graphql;
pub mod health;
pub mod usage;

pub use anthropic::create_anthropic_routes;
pub use api_keys::create_api_key_routes;
pub use audit_logs::create_admin_audit_logs_routes;
pub use auth::{create_auth_routes, create_protected_auth_routes};
pub use bedrock::create_bedrock_routes;
pub use cost::create_admin_cost_routes;
pub use docs::create_docs_routes;
pub use frontend::create_frontend_router;
pub use graphql::{create_graphql_routes, create_graphql_playground_routes};
pub use health::create_health_routes;
pub use usage::{create_admin_usage_routes, create_user_usage_routes};

use crate::Server;
use axum::Router;
use serde::Serialize;
use utoipa::ToSchema;

/// API Error response for documentation
#[derive(Debug, Serialize, ToSchema)]
pub struct ApiErrorResponse {
    /// Error message
    pub error: String,
    /// Error code
    pub code: String,
}

/// Create admin-only API routes
pub fn create_admin_api_routes() -> Router<Server> {
    Router::new()
        .merge(create_admin_usage_routes())
        .merge(create_admin_cost_routes())
        .merge(create_admin_audit_logs_routes())
}

/// Create user API routes
pub fn create_user_api_routes() -> Router<Server> {
    Router::new()
        .merge(create_user_usage_routes())
        .merge(create_api_key_routes())
}
