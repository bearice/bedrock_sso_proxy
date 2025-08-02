use crate::{
    auth::{
        api_key::{ApiKey, CreateApiKeyRequest, CreateApiKeyResponse},
        middleware::UserExtractor,
    },
    error::AppError,
    routes::ApiErrorResponse,
    server::Server,
};
use axum::{
    Router,
    extract::{Path, State},
    response::Json,
    routing::{delete, get, post},
};
use chrono::{Duration, Utc};

/// Create API key management routes (requires JWT authentication)
pub fn create_api_key_routes() -> Router<Server> {
    Router::new()
        .route("/keys", post(create_api_key))
        .route("/keys", get(list_api_keys))
        .route("/keys/{key}", delete(revoke_api_key))
}

/// Create a new API key for the authenticated user
#[utoipa::path(
    post,
    path = "/api/keys",
    summary = "Create API Key",
    description = "Create a new API key for programmatic access to the proxy",
    tags = ["API Keys"],
    request_body = CreateApiKeyRequest,
    responses(
        (status = 200, description = "API key created successfully", body = CreateApiKeyResponse),
        (status = 400, description = "Bad request", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse)
    ),
    security(
        ("jwt_auth" = [])
    )
)]
pub async fn create_api_key(
    State(server): State<Server>,
    UserExtractor(user): UserExtractor,
    Json(request): Json<CreateApiKeyRequest>,
) -> Result<Json<CreateApiKeyResponse>, AppError> {
    // Validate request
    if request.name.trim().is_empty() {
        return Err(AppError::BadRequest(
            "API key name cannot be empty".to_string(),
        ));
    }

    if request.name.len() > 100 {
        return Err(AppError::BadRequest(
            "API key name too long (max 100 characters)".to_string(),
        ));
    }

    // Calculate expiration date if provided
    let expires_at = request
        .expires_in_days
        .map(|days| Utc::now() + Duration::days(days as i64));

    // Check user's existing API key count
    let existing_keys = server
        .database
        .api_keys()
        .find_by_user(user.id)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to check existing API keys: {e}")))?;

    // Get max keys from config
    let max_keys_per_user = server.config.api_keys.max_keys_per_user as usize;
    if existing_keys.len() >= max_keys_per_user {
        return Err(AppError::BadRequest(format!(
            "Maximum number of API keys exceeded ({max_keys_per_user})"
        )));
    }

    // Create new API key
    let (api_key, raw_key) = ApiKey::new(user.id, request.name.trim().to_string(), expires_at);

    // Store in database
    let key_id = server
        .database
        .api_keys()
        .store(&api_key)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to store API key: {e}")))?;

    // Return response with the raw key (only time it's returned)
    Ok(Json(CreateApiKeyResponse {
        id: key_id,
        name: api_key.name,
        key: raw_key,
        created_at: api_key.created_at,
        expires_at: api_key.expires_at,
    }))
}

/// List all API keys for the authenticated user
#[utoipa::path(
    get,
    path = "/api/keys",
    summary = "List API Keys",
    description = "Get all API keys for the authenticated user",
    tags = ["API Keys"],
    responses(
        (status = 200, description = "List of API keys", body = Vec<ApiKey>),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse)
    ),
    security(
        ("jwt_auth" = [])
    )
)]
pub async fn list_api_keys(
    State(server): State<Server>,
    UserExtractor(user): UserExtractor,
) -> Result<Json<Vec<ApiKey>>, AppError> {
    let api_keys = server
        .database
        .api_keys()
        .find_by_user(user.id)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to get API keys: {e}")))?;

    let api_key_infos: Vec<ApiKey> = api_keys.into_iter().collect();

    Ok(Json(api_key_infos))
}

/// Revoke an API key (mark as revoked)
#[utoipa::path(
    delete,
    path = "/api/keys/{key_hash}",
    summary = "Revoke API Key",
    description = "Revoke an API key, making it invalid for future requests",
    tags = ["API Keys"],
    params(
        ("key_hash" = String, Path, description = "Hash of the API key to revoke")
    ),
    responses(
        (status = 200, description = "API key revoked successfully", body = serde_json::Value),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 403, description = "Forbidden - not the owner", body = ApiErrorResponse),
        (status = 404, description = "API key not found", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse)
    ),
    security(
        ("jwt_auth" = [])
    )
)]
pub async fn revoke_api_key(
    State(server): State<Server>,
    UserExtractor(user): UserExtractor,
    Path(key_hash): Path<String>,
) -> Result<Json<serde_json::Value>, AppError> {
    let key = server
        .database
        .api_keys()
        .find_by_hash(&key_hash)
        .await
        .map_err(AppError::Database)?
        .ok_or_else(|| AppError::NotFound("Key not found".to_string()))?;

    if key.user_id != user.id {
        return Err(AppError::Forbidden("Owner mismatch".to_string()));
    }
    // Revoke the API key
    server
        .database
        .api_keys()
        .revoke(key)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to revoke API key: {e}")))?;

    Ok(Json(serde_json::json!({
        "message": "API key revoked successfully",
        "key_hash": key_hash
    })))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        auth::{jwt::JwtService, middleware::jwt_auth_middleware},
        database::{DatabaseManager, entities::UserRecord},
    };
    use axum::{
        body::Body,
        http::{Request, StatusCode},
        middleware,
    };
    use chrono::Utc;
    use serde_json;
    use std::sync::Arc;
    use tower::ServiceExt;

    async fn create_test_user(database: &Arc<dyn DatabaseManager>) -> i32 {
        let user = UserRecord {
            id: 0,
            provider_user_id: "test_user_123".to_string(),
            provider: "test".to_string(),
            email: "test@example.com".to_string(),
            display_name: Some("Test User".to_string()),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            last_login: Some(Utc::now()),
        };
        database.users().upsert(&user).await.unwrap()
    }

    fn create_test_jwt(jwt_service: &dyn JwtService, user_id: i32) -> String {
        let claims = crate::auth::jwt::OAuthClaims::new(user_id, 3600);
        jwt_service.create_oauth_token(&claims).unwrap()
    }

    async fn create_test_server() -> Server {
        crate::test_utils::TestServerBuilder::new().build().await
    }

    #[tokio::test]
    async fn test_create_api_key() {
        let server = create_test_server().await;
        let user_id = create_test_user(&server.database).await;

        let app = create_api_key_routes().with_state(server.clone()).layer(
            middleware::from_fn_with_state(server.clone(), jwt_auth_middleware),
        );

        let token = create_test_jwt(server.jwt_service.as_ref(), user_id);
        let request_body = CreateApiKeyRequest {
            name: "Test Key".to_string(),
            expires_in_days: Some(30),
        };

        let request = Request::builder()
            .uri("/keys")
            .method("POST")
            .header("Authorization", format!("Bearer {token}"))
            .header("Content-Type", "application/json")
            .body(Body::from(serde_json::to_string(&request_body).unwrap()))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let response_body: CreateApiKeyResponse = serde_json::from_slice(&body).unwrap();

        assert_eq!(response_body.name, "Test Key");
        assert!(response_body.key.starts_with("SSOK_"));
        assert!(response_body.expires_at.is_some());
    }

    #[tokio::test]
    async fn test_list_api_keys() {
        let server = create_test_server().await;
        let user_id = create_test_user(&server.database).await;

        // Create a test API key first
        let (api_key, _) = ApiKey::new(user_id, "Test Key".to_string(), None);
        server.database.api_keys().store(&api_key).await.unwrap();

        let app = create_api_key_routes().with_state(server.clone()).layer(
            middleware::from_fn_with_state(server.clone(), jwt_auth_middleware),
        );

        let token = create_test_jwt(server.jwt_service.as_ref(), user_id);

        let request = Request::builder()
            .uri("/keys")
            .method("GET")
            .header("Authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let api_keys: Vec<ApiKey> = serde_json::from_slice(&body).unwrap();

        assert_eq!(api_keys.len(), 1);
        assert_eq!(api_keys[0].name, "Test Key");
    }

    #[tokio::test]
    async fn test_create_api_key_invalid_name() {
        let server = create_test_server().await;
        let user_id = create_test_user(&server.database).await;

        let app = create_api_key_routes().with_state(server.clone()).layer(
            middleware::from_fn_with_state(server.clone(), jwt_auth_middleware),
        );

        let token = create_test_jwt(server.jwt_service.as_ref(), user_id);
        let request_body = CreateApiKeyRequest {
            name: "".to_string(), // Empty name
            expires_in_days: None,
        };

        let request = Request::builder()
            .uri("/keys")
            .method("POST")
            .header("Authorization", format!("Bearer {token}"))
            .header("Content-Type", "application/json")
            .body(Body::from(serde_json::to_string(&request_body).unwrap()))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
}
