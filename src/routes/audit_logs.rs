use crate::Server;
use crate::auth::middleware::UserExtractor;
use crate::database::AuditLogQueryParams;
use crate::database::entities::AuditEventType;
use crate::error::AppError;
use crate::routes::ApiErrorResponse;
use axum::Router;
use axum::extract::{Query, State};
use axum::response::Json;
use axum::routing::get;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::{OpenApi, ToSchema};

/// Admin audit logs API endpoints
#[derive(OpenApi)]
#[openapi(
    paths(
        get_audit_logs,
    ),
    components(
        schemas(
            AuditLogsResponse,
            AuditLogQueryParams,
            ApiErrorResponse,
        )
    ),
    tags(
        (name = "admin-audit", description = "Admin audit log operations")
    )
)]
pub struct AdminAuditLogsApi;

/// Audit log entry for API response
#[derive(Debug, Deserialize, Serialize, ToSchema)]
pub struct AuditLogEntry {
    /// Unique identifier
    pub id: i32,
    /// User ID (nullable for system events)
    pub user_id: Option<i32>,
    /// Event type
    pub event_type: AuditEventType,
    /// OAuth provider (nullable)
    pub provider: Option<String>,
    /// Client IP address (nullable)
    pub ip_address: Option<String>,
    /// User agent string (nullable)
    pub user_agent: Option<String>,
    /// Whether the event was successful
    pub success: bool,
    /// Error message if not successful (nullable)
    pub error_message: Option<String>,
    /// Event timestamp
    pub created_at: DateTime<Utc>,
    /// Additional metadata as JSON (nullable)
    pub metadata: Option<serde_json::Value>,
}

/// Response for audit logs query
#[derive(Debug, Deserialize, Serialize, ToSchema)]
pub struct AuditLogsResponse {
    /// List of audit log entries
    pub logs: Vec<AuditLogEntry>,
    /// Total number of matching records
    pub total: u64,
    /// Current page offset
    pub offset: u64,
    /// Records per page
    pub limit: u64,
}

impl From<crate::database::entities::audit_logs::Model> for AuditLogEntry {
    fn from(entry: crate::database::entities::audit_logs::Model) -> Self {
        // Parse metadata JSON string to serde_json::Value if present
        let metadata = entry
            .metadata
            .and_then(|json_str| serde_json::from_str(&json_str).ok());

        Self {
            id: entry.id,
            user_id: entry.user_id,
            event_type: entry.event_type,
            provider: entry.provider,
            ip_address: entry.ip_address,
            user_agent: entry.user_agent,
            success: entry.success,
            error_message: entry.error_message,
            created_at: entry.created_at,
            metadata,
        }
    }
}

/// Get audit logs with optional filtering
#[utoipa::path(
    get,
    path = "/api/admin/audit-logs",
    params(AuditLogQueryParams),
    responses(
        (status = 200, description = "Audit logs retrieved successfully", body = AuditLogsResponse),
        (status = 400, description = "Invalid query parameters", body = ApiErrorResponse),
        (status = 401, description = "Authentication required", body = ApiErrorResponse),
        (status = 403, description = "Admin access required", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(
        ("bearer_auth" = [])
    ),
    tag = "admin-audit"
)]
pub async fn get_audit_logs(
    State(server): State<Server>,
    Query(mut params): Query<AuditLogQueryParams>,
    _user: UserExtractor,
) -> Result<Json<AuditLogsResponse>, AppError> {
    // Validate and set defaults for pagination
    params.limit = params.limit.or(Some(50)).map(|x| x.clamp(1, 1000));
    params.offset = params.offset.or(Some(0));

    // Validate date range
    if let (Some(start), Some(end)) = (params.start_date, params.end_date) {
        if start > end {
            return Err(AppError::BadRequest(
                "start_date must be before end_date".to_string(),
            ));
        }
    }

    let audit_dao = server.database.audit_logs();

    // Get total count for pagination
    let total = audit_dao
        .count_all(&params)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to count audit logs: {e}")))?;

    // Get audit logs with filtering
    let logs = audit_dao
        .find_all(&params)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to fetch audit logs: {e}")))?;

    let response = AuditLogsResponse {
        logs: logs.into_iter().map(AuditLogEntry::from).collect(),
        total,
        offset: params.offset.unwrap(),
        limit: params.limit.unwrap(),
    };

    Ok(Json(response))
}

/// Create admin audit logs API routes
pub fn create_admin_audit_logs_routes() -> Router<Server> {
    Router::new().route("/admin/audit-logs", get(get_audit_logs))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::middleware::{admin_middleware, jwt_auth_middleware};
    use crate::database::DatabaseManager;
    use crate::database::entities::{AuditEventType, AuditLogEntry as DbAuditLogEntry};
    use crate::test_utils::TestServerBuilder;
    use axum::body::Body;
    use axum::http::Request;
    use axum::http::StatusCode;
    use axum::middleware;
    use chrono::Utc;
    use serde_json::json;
    use std::sync::Arc;
    use tower::ServiceExt;

    async fn create_test_audit_log(
        database: &Arc<dyn DatabaseManager>,
        user_id: Option<i32>,
        event_type: AuditEventType,
        success: bool,
    ) -> i32 {
        let entry = DbAuditLogEntry {
            id: 0, // Will be assigned by database
            user_id,
            event_type,
            provider: Some("test".to_string()),
            ip_address: Some("127.0.0.1".to_string()),
            user_agent: Some("test-agent".to_string()),
            success,
            error_message: if success {
                None
            } else {
                Some("Test error".to_string())
            },
            created_at: Utc::now(),
            metadata: Some(json!({"test": "value"}).to_string()),
        };

        database.audit_logs().store(&entry).await.unwrap();
        // Return a fake ID since we can't get the real one from store method
        1
    }

    #[tokio::test]
    async fn test_get_audit_logs_success() {
        let mut config = crate::config::Config::default();
        config.admin.emails = vec!["admin@example.com".to_string()];

        let server = TestServerBuilder::new().with_config(config).build().await;

        // Create test user
        let user = crate::database::entities::UserRecord {
            id: 0,
            provider_user_id: "test_user".to_string(),
            provider: "test".to_string(),
            email: "admin@example.com".to_string(),
            display_name: Some("Test Admin".to_string()),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            last_login: Some(Utc::now()),
        };
        let user_id = server.database.users().upsert(&user).await.unwrap();

        // Create test audit logs
        create_test_audit_log(&server.database, Some(user_id), AuditEventType::Login, true).await;
        create_test_audit_log(
            &server.database,
            Some(user_id),
            AuditEventType::Logout,
            true,
        )
        .await;

        // Create JWT token
        let claims = crate::auth::jwt::OAuthClaims::new(user_id, 3600);
        let token = server.jwt_service.create_oauth_token(&claims).unwrap();

        let app = create_admin_audit_logs_routes()
            .with_state(server.clone())
            .layer(middleware::from_fn_with_state(
                server.clone(),
                admin_middleware,
            ))
            .layer(middleware::from_fn_with_state(
                server.clone(),
                jwt_auth_middleware,
            ));

        let request = Request::builder()
            .uri("/admin/audit-logs")
            .header("Authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let response_data: AuditLogsResponse = serde_json::from_slice(&body).unwrap();

        assert!(response_data.total >= 2);
        assert!(!response_data.logs.is_empty());
        assert_eq!(response_data.limit, 50); // Default limit
        assert_eq!(response_data.offset, 0); // Default offset
    }

    #[tokio::test]
    async fn test_get_audit_logs_with_filters() {
        let mut config = crate::config::Config::default();
        config.admin.emails = vec!["admin@example.com".to_string()];

        let server = TestServerBuilder::new().with_config(config).build().await;

        // Create test user
        let user = crate::database::entities::UserRecord {
            id: 0,
            provider_user_id: "test_user".to_string(),
            provider: "test".to_string(),
            email: "admin@example.com".to_string(),
            display_name: Some("Test Admin".to_string()),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            last_login: Some(Utc::now()),
        };
        let user_id = server.database.users().upsert(&user).await.unwrap();

        // Create test audit logs
        create_test_audit_log(&server.database, Some(user_id), AuditEventType::Login, true).await;
        create_test_audit_log(
            &server.database,
            Some(user_id),
            AuditEventType::ApiCall,
            false,
        )
        .await;

        // Create JWT token
        let claims = crate::auth::jwt::OAuthClaims::new(user_id, 3600);
        let token = server.jwt_service.create_oauth_token(&claims).unwrap();

        let app = create_admin_audit_logs_routes()
            .with_state(server.clone())
            .layer(middleware::from_fn_with_state(
                server.clone(),
                admin_middleware,
            ))
            .layer(middleware::from_fn_with_state(
                server.clone(),
                jwt_auth_middleware,
            ));

        // Test filtering by success=false
        let request = Request::builder()
            .uri("/admin/audit-logs?success=false&limit=10")
            .header("Authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let response_data: AuditLogsResponse = serde_json::from_slice(&body).unwrap();

        assert_eq!(response_data.limit, 10);
        // Should have at least one failed entry
        assert!(response_data.logs.iter().any(|log| !log.success));
    }

    #[tokio::test]
    async fn test_get_audit_logs_forbidden_non_admin() {
        let mut config = crate::config::Config::default();
        config.admin.emails = vec!["admin@example.com".to_string()];

        let server = TestServerBuilder::new().with_config(config).build().await;

        // Create non-admin user
        let user = crate::database::entities::UserRecord {
            id: 0,
            provider_user_id: "test_user".to_string(),
            provider: "test".to_string(),
            email: "user@example.com".to_string(), // Not admin
            display_name: Some("Test User".to_string()),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            last_login: Some(Utc::now()),
        };
        let user_id = server.database.users().upsert(&user).await.unwrap();

        // Create JWT token
        let claims = crate::auth::jwt::OAuthClaims::new(user_id, 3600);
        let token = server.jwt_service.create_oauth_token(&claims).unwrap();

        let app = create_admin_audit_logs_routes()
            .with_state(server.clone())
            .layer(middleware::from_fn_with_state(
                server.clone(),
                admin_middleware,
            ))
            .layer(middleware::from_fn_with_state(
                server.clone(),
                jwt_auth_middleware,
            ));

        let request = Request::builder()
            .uri("/admin/audit-logs")
            .header("Authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_get_audit_logs_unauthorized() {
        let server = TestServerBuilder::new().build().await;

        let app = create_admin_audit_logs_routes()
            .with_state(server.clone())
            .layer(middleware::from_fn_with_state(
                server.clone(),
                admin_middleware,
            ))
            .layer(middleware::from_fn_with_state(
                server.clone(),
                jwt_auth_middleware,
            ));

        let request = Request::builder()
            .uri("/admin/audit-logs")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_get_audit_logs_invalid_date_range() {
        let mut config = crate::config::Config::default();
        config.admin.emails = vec!["admin@example.com".to_string()];

        let server = TestServerBuilder::new().with_config(config).build().await;

        // Create test user
        let user = crate::database::entities::UserRecord {
            id: 0,
            provider_user_id: "test_user".to_string(),
            provider: "test".to_string(),
            email: "admin@example.com".to_string(),
            display_name: Some("Test Admin".to_string()),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            last_login: Some(Utc::now()),
        };
        let user_id = server.database.users().upsert(&user).await.unwrap();

        // Create JWT token
        let claims = crate::auth::jwt::OAuthClaims::new(user_id, 3600);
        let token = server.jwt_service.create_oauth_token(&claims).unwrap();

        let app = create_admin_audit_logs_routes()
            .with_state(server.clone())
            .layer(middleware::from_fn_with_state(
                server.clone(),
                admin_middleware,
            ))
            .layer(middleware::from_fn_with_state(
                server.clone(),
                jwt_auth_middleware,
            ));

        // Invalid date range (start > end)
        let request = Request::builder()
            .uri("/admin/audit-logs?start_date=2024-01-02T00:00:00Z&end_date=2024-01-01T00:00:00Z")
            .header("Authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
}
