use crate::{error::AppError, server::Server};
use axum::{Router, http::header, routing::get};
use utoipa::openapi::security::{ApiKey, ApiKeyValue, Http, HttpAuthScheme, SecurityScheme};
use utoipa::{Modify, OpenApi};
use utoipa_swagger_ui::SwaggerUi;

#[derive(OpenApi)]
#[openapi(
    info(
        title = "Bedrock SSO Proxy API",
        version = "1.0.0",
        description = "JWT-authenticated HTTP proxy server that provides secure access to AWS Bedrock APIs"
    ),
    paths(
        crate::routes::health::health_check,
        crate::routes::api_keys::create_api_key,
        crate::routes::api_keys::list_api_keys,
        crate::routes::api_keys::revoke_api_key,
        crate::routes::bedrock::invoke_model,
        crate::routes::bedrock::invoke_model_with_response_stream,
        crate::routes::anthropic::create_message,
        crate::routes::cost::get_all_model_costs,
        crate::routes::cost::get_model_cost,
        crate::routes::cost::upsert_model_cost,
        crate::routes::cost::delete_model_cost,
        crate::routes::cost::update_all_model_costs,
        crate::routes::usage::get_user_usage_records,
        crate::routes::usage::get_user_usage_stats,
        crate::routes::usage::get_system_usage_records,
        crate::routes::usage::get_system_usage_stats,
        crate::routes::usage::get_top_models,
        crate::routes::audit_logs::get_audit_logs,
    ),
    components(
        schemas(
            crate::routes::health::HealthCheckQuery,
            crate::routes::ApiErrorResponse,
            crate::health::HealthResponse,
            crate::health::HealthStatus,
            crate::health::HealthCheckResult,
            crate::health::HealthSummary,
            crate::auth::api_key::CreateApiKeyRequest,
            crate::auth::api_key::CreateApiKeyResponse,
            crate::auth::api_key::ApiKey,
            crate::anthropic::AnthropicRequest,
            crate::anthropic::Message,
            crate::routes::cost::ModelCostRequest,
            crate::database::entities::ModelCost,
            crate::cost::UpdateCostsResult,
            crate::routes::usage::UsageRecordsQuery,
            crate::routes::usage::UsageStatsQuery,
            crate::routes::usage::UsageRecordsResponse,
            crate::routes::usage::TopModelsResponse,
            crate::routes::usage::ModelUsage,
            crate::database::entities::UsageRecord,
            crate::database::dao::usage::UsageStats,
            crate::database::AuditLogQueryParams,
            crate::routes::audit_logs::AuditLogsResponse,
            crate::routes::audit_logs::AuditLogEntry,
        )
    ),
    tags(
        (name = "Health", description = "Health check endpoints"),
        (name = "API Keys", description = "API key management endpoints"),
        (name = "Bedrock Models", description = "AWS Bedrock model invocation endpoints"),
        (name = "Anthropic API", description = "Standard Anthropic API format endpoints"),
        (name = "Cost Management", description = "Model cost tracking and management endpoints (admin only)"),
        (name = "Usage Tracking", description = "User usage tracking endpoints"),
        (name = "Admin Usage Management", description = "System-wide usage tracking endpoints (admin only)"),
        (name = "admin-audit", description = "Admin audit log operations (admin only)"),
    ),
    modifiers(&SecurityAddon)
)]
pub struct ApiDoc;

/// Security scheme modifier for OpenAPI documentation
struct SecurityAddon;

impl Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        let components = openapi.components.as_mut().unwrap();

        // JWT Bearer Authentication
        components.add_security_scheme(
            "jwt_auth",
            SecurityScheme::Http(Http::new(HttpAuthScheme::Bearer)),
        );

        // API Key Authentication (Bearer token style)
        components.add_security_scheme(
            "api_key_auth",
            SecurityScheme::Http(Http::new(HttpAuthScheme::Bearer)),
        );

        // API Key Authentication (X-API-Key header style)
        components.add_security_scheme(
            "x_api_key_auth",
            SecurityScheme::ApiKey(ApiKey::Header(ApiKeyValue::new("X-API-Key"))),
        );
    }
}

/// Create documentation routes
pub fn create_docs_routes() -> Router<Server> {
    Router::new()
        .merge(SwaggerUi::new("/docs").url("/docs/openapi.json", ApiDoc::openapi()))
        .route("/openapi.json", get(openapi_json))
        .route("/openapi.yaml", get(openapi_yaml))
}

/// Serve OpenAPI specification as JSON
async fn openapi_json() -> axum::Json<utoipa::openapi::OpenApi> {
    axum::Json(ApiDoc::openapi())
}

/// Serve OpenAPI specification as YAML
async fn openapi_yaml() -> Result<([(header::HeaderName, &'static str); 1], String), AppError> {
    let spec = ApiDoc::openapi();
    let yaml = serde_yaml_ng::to_string(&spec).map_err(|e| {
        AppError::Internal(format!("Failed to serialize OpenAPI spec to YAML: {}", e))
    })?;

    Ok(([(header::CONTENT_TYPE, "application/yaml")], yaml))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;

    #[tokio::test]
    async fn test_openapi_json() {
        let server = crate::test_utils::TestServerBuilder::new().build().await;
        let app = create_docs_routes().with_state(server);

        let request = Request::builder()
            .uri("/openapi.json")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let content_type = response.headers().get("content-type").unwrap();
        assert!(content_type.to_str().unwrap().contains("application/json"));
    }

    #[tokio::test]
    async fn test_openapi_yaml() {
        let server = crate::test_utils::TestServerBuilder::new().build().await;
        let app = create_docs_routes().with_state(server);

        let request = Request::builder()
            .uri("/openapi.yaml")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let content_type = response.headers().get("content-type").unwrap();
        assert!(content_type.to_str().unwrap().contains("application/yaml"));
    }

    #[tokio::test]
    async fn test_swagger_ui() {
        let server = crate::test_utils::TestServerBuilder::new().build().await;
        let app = create_docs_routes().with_state(server);

        // Test that the /docs path redirects (which is normal for Swagger UI)
        let request = Request::builder().uri("/docs").body(Body::empty()).unwrap();

        let response = app.oneshot(request).await.unwrap();
        // Swagger UI typically redirects to /docs/ (with trailing slash)
        assert!(response.status().is_redirection() || response.status() == StatusCode::OK);
    }
}
