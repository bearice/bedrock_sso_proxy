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
        crate::routes::auth::authorize_handler,
        crate::routes::auth::token_handler,
        crate::routes::auth::refresh_handler,
        crate::routes::auth::providers_handler,
        crate::routes::auth::me_handler,
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
        crate::routes::usage::get_user_usage_summaries,
        crate::routes::usage::get_system_usage_records,
        crate::routes::usage::get_admin_usage_summaries,
        crate::routes::audit_logs::get_audit_logs,
        crate::routes::users::list_users,
        crate::routes::users::get_user_by_id,
        crate::routes::users::search_users,
        crate::routes::users::update_user_state,
    ),
    components(
        schemas(
            crate::routes::health::HealthCheckQuery,
            crate::routes::ApiErrorResponse,
            crate::health::HealthResponse,
            crate::health::HealthStatus,
            crate::health::HealthCheckResult,
            crate::health::HealthSummary,
            crate::routes::auth::AuthorizeQuery,
            crate::routes::auth::CallbackQuery,
            crate::auth::oauth::AuthorizeResponse,
            crate::auth::oauth::TokenRequest,
            crate::auth::oauth::RefreshRequest,
            crate::auth::oauth::TokenResponse,
            crate::auth::oauth::ProviderInfo,
            crate::auth::oauth::ProvidersResponse,
            crate::database::entities::UserRecord,
            crate::auth::api_key::CreateApiKeyRequest,
            crate::auth::api_key::CreateApiKeyResponse,
            crate::auth::api_key::ApiKey,
            crate::anthropic::AnthropicRequest,
            crate::anthropic::Message,
            crate::routes::cost::ModelCostRequest,
            crate::database::entities::ModelCost,
            crate::cost::UpdateCostsResult,
            crate::routes::usage::UsageRecordsQuery,
            crate::routes::usage::UsageSummariesQuery,
            crate::routes::usage::UsageRecordsResponse,
            crate::routes::usage::UsageSummariesResponse,
            crate::database::entities::UsageRecord,
            crate::database::entities::UsageSummary,
            crate::database::entities::PeriodType,
            crate::database::AuditLogQueryParams,
            crate::routes::audit_logs::AuditLogsResponse,
            crate::routes::audit_logs::AuditLogEntry,
            crate::routes::users::UserResponse,
            crate::routes::users::UserListResponse,
            crate::routes::users::UserSearchQuery,
            crate::routes::users::UserListQuery,
            crate::routes::users::UpdateUserStateRequest,
            crate::database::entities::UserState,
        )
    ),
    tags(
        (name = "Health", description = "Health check endpoints"),
        (name = "Authentication", description = "OAuth authentication endpoints"),
        (name = "API Keys", description = "API key management endpoints"),
        (name = "Bedrock Models", description = "AWS Bedrock model invocation endpoints"),
        (name = "Anthropic API", description = "Standard Anthropic API format endpoints"),
        (name = "Cost Management", description = "Model cost tracking and management endpoints (admin only)"),
        (name = "Usage Tracking", description = "User usage tracking endpoints"),
        (name = "Admin Usage Management", description = "System-wide usage tracking endpoints (admin only)"),
        (name = "Admin Audit Logs", description = "Admin audit log operations (admin only)"),
        (name = "Admin User Management", description = "Admin user management endpoints (admin only)"),
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
        .route("/docs/openapi.yaml", get(openapi_yaml))
}

/// Serve OpenAPI specification as YAML
async fn openapi_yaml() -> Result<([(header::HeaderName, &'static str); 1], String), AppError> {
    let spec = ApiDoc::openapi();
    let yaml = serde_yaml_ng::to_string(&spec).map_err(|e| {
        AppError::Internal(format!("Failed to serialize OpenAPI spec to YAML: {e}"))
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
            .uri("/docs/openapi.json")
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
            .uri("/docs/openapi.yaml")
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
