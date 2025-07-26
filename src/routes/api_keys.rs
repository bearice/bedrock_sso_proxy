use crate::{
    auth::{
        api_key::{ApiKey, ApiKeyInfo, CreateApiKeyRequest, CreateApiKeyResponse},
        middleware::UserExtractor,
    },
    error::AppError,
    storage::Storage,
};
use axum::{
    extract::{Path, State},
    response::Json,
    routing::{delete, get, post},
    Router,
};
use chrono::{Duration, Utc};
use std::sync::Arc;

/// Create API key management routes (requires JWT authentication)
pub fn create_api_key_routes() -> Router<Arc<Storage>> {
    Router::new()
        .route("/", post(create_api_key))
        .route("/", get(list_api_keys))
        .route("/{key_id}", delete(revoke_api_key))
}

/// Create a new API key for the authenticated user
pub async fn create_api_key(
    State(storage): State<Arc<Storage>>,
    UserExtractor(user): UserExtractor,
    Json(request): Json<CreateApiKeyRequest>,
) -> Result<Json<CreateApiKeyResponse>, AppError> {
    // Validate request
    if request.name.trim().is_empty() {
        return Err(AppError::BadRequest("API key name cannot be empty".to_string()));
    }

    if request.name.len() > 100 {
        return Err(AppError::BadRequest("API key name too long (max 100 characters)".to_string()));
    }

    // Calculate expiration date if provided
    let expires_at = request.expires_in_days.map(|days| {
        Utc::now() + Duration::days(days as i64)
    });

    // Check user's existing API key count
    let existing_keys = storage
        .database
        .get_api_keys_for_user(user.id.unwrap())
        .await
        .map_err(|e| AppError::Internal(format!("Failed to check existing API keys: {}", e)))?;

    // TODO: Get max keys from config (hardcoded to 10 for now)
    const MAX_KEYS_PER_USER: usize = 10;
    if existing_keys.len() >= MAX_KEYS_PER_USER {
        return Err(AppError::BadRequest(format!(
            "Maximum number of API keys exceeded ({})",
            MAX_KEYS_PER_USER
        )));
    }

    // Create new API key
    let (api_key, raw_key) = ApiKey::new(user.id.unwrap(), request.name.trim().to_string(), expires_at);

    // Store in database
    let key_id = storage
        .database
        .store_api_key(&api_key)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to store API key: {}", e)))?;

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
pub async fn list_api_keys(
    State(storage): State<Arc<Storage>>,
    UserExtractor(user): UserExtractor,
) -> Result<Json<Vec<ApiKeyInfo>>, AppError> {
    let api_keys = storage
        .database
        .get_api_keys_for_user(user.id.unwrap())
        .await
        .map_err(|e| AppError::Internal(format!("Failed to get API keys: {}", e)))?;

    let api_key_infos: Vec<ApiKeyInfo> = api_keys.into_iter().map(|key| key.into()).collect();

    Ok(Json(api_key_infos))
}

/// Revoke an API key (mark as revoked)
pub async fn revoke_api_key(
    State(storage): State<Arc<Storage>>,
    UserExtractor(user): UserExtractor,
    Path(key_id): Path<i32>,
) -> Result<Json<serde_json::Value>, AppError> {
    // Verify the API key belongs to the user
    let api_keys = storage
        .database
        .get_api_keys_for_user(user.id.unwrap())
        .await
        .map_err(|e| AppError::Internal(format!("Failed to get API keys: {}", e)))?;

    let key_exists = api_keys.iter().any(|key| key.id == Some(key_id));
    if !key_exists {
        return Err(AppError::NotFound("API key not found".to_string()));
    }

    // Revoke the API key
    storage
        .database
        .revoke_api_key(key_id)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to revoke API key: {}", e)))?;

    Ok(Json(serde_json::json!({
        "message": "API key revoked successfully",
        "key_id": key_id
    })))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        auth::{jwt::JwtService, middleware::jwt_auth_middleware},
        config::Config,
        storage::{Storage, UserRecord},
    };
    use axum::{
        body::Body,
        http::{Request, StatusCode},
        middleware,
    };
    use chrono::Utc;
    use jsonwebtoken::Algorithm;
    use serde_json;
    use tower::ServiceExt;

    async fn create_test_storage() -> Arc<Storage> {
        let storage = Arc::new(Storage::new(
            Box::new(crate::storage::memory::MemoryCacheStorage::new(3600)),
            Box::new(
                crate::storage::database::SqliteStorage::new("sqlite::memory:")
                    .await
                    .unwrap(),
            ),
        ));
        storage.migrate().await.unwrap();
        storage
    }

    async fn create_test_user(storage: &Arc<Storage>) -> i32 {
        let user = UserRecord {
            id: None,
            provider_user_id: "test_user_123".to_string(),
            provider: "test".to_string(),
            email: "test@example.com".to_string(),
            display_name: Some("Test User".to_string()),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            last_login: Some(Utc::now()),
        };
        storage.database.upsert_user(&user).await.unwrap()
    }

    fn create_test_jwt(jwt_service: &JwtService, user_id: i32) -> String {
        let claims = crate::auth::jwt::OAuthClaims::new(user_id, 3600);
        jwt_service.create_oauth_token(&claims).unwrap()
    }

    async fn create_test_server() -> (Arc<Storage>, JwtService) {
        let storage = create_test_storage().await;
        let jwt_service = JwtService::new("test-secret".to_string(), Algorithm::HS256).unwrap();
        (storage, jwt_service)
    }

    #[tokio::test]
    async fn test_create_api_key() {
        let (storage, jwt_service) = create_test_server().await;
        let user_id = create_test_user(&storage).await;

        // Create server state for middleware
        let config = Config::default();
        let server = crate::server::Server {
            config: Arc::new(config),
            jwt_service: Arc::new(jwt_service.clone()),
            model_service: Arc::new(crate::model_service::ModelService::new(storage.clone(), Config::default())),
            oauth_service: Arc::new(crate::auth::oauth::OAuthService::new(
                Config::default(),
                jwt_service.clone(),
                storage.clone(),
            )),
            health_service: Arc::new(crate::health::HealthService::new()),
            storage: storage.clone(),
        };

        let app = create_api_key_routes()
            .with_state(storage.clone())
            .layer(middleware::from_fn_with_state(server, jwt_auth_middleware));

        let token = create_test_jwt(&jwt_service, user_id);
        let request_body = CreateApiKeyRequest {
            name: "Test Key".to_string(),
            expires_in_days: Some(30),
        };

        let request = Request::builder()
            .uri("/")
            .method("POST")
            .header("Authorization", format!("Bearer {}", token))
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
        let (storage, jwt_service) = create_test_server().await;
        let user_id = create_test_user(&storage).await;

        // Create a test API key first
        let (api_key, _) = ApiKey::new(user_id, "Test Key".to_string(), None);
        storage.database.store_api_key(&api_key).await.unwrap();

        // Create server state for middleware
        let config = Config::default();
        let server = crate::server::Server {
            config: Arc::new(config),
            jwt_service: Arc::new(jwt_service.clone()),
            model_service: Arc::new(crate::model_service::ModelService::new(storage.clone(), Config::default())),
            oauth_service: Arc::new(crate::auth::oauth::OAuthService::new(
                Config::default(),
                jwt_service.clone(),
                storage.clone(),
            )),
            health_service: Arc::new(crate::health::HealthService::new()),
            storage: storage.clone(),
        };

        let app = create_api_key_routes()
            .with_state(storage.clone())
            .layer(middleware::from_fn_with_state(server, jwt_auth_middleware));

        let token = create_test_jwt(&jwt_service, user_id);

        let request = Request::builder()
            .uri("/")
            .method("GET")
            .header("Authorization", format!("Bearer {}", token))
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let api_keys: Vec<ApiKeyInfo> = serde_json::from_slice(&body).unwrap();

        assert_eq!(api_keys.len(), 1);
        assert_eq!(api_keys[0].name, "Test Key");
    }

    #[tokio::test]
    async fn test_create_api_key_invalid_name() {
        let (storage, jwt_service) = create_test_server().await;
        let user_id = create_test_user(&storage).await;

        // Create server state for middleware
        let config = Config::default();
        let server = crate::server::Server {
            config: Arc::new(config),
            jwt_service: Arc::new(jwt_service.clone()),
            model_service: Arc::new(crate::model_service::ModelService::new(storage.clone(), Config::default())),
            oauth_service: Arc::new(crate::auth::oauth::OAuthService::new(
                Config::default(),
                jwt_service.clone(),
                storage.clone(),
            )),
            health_service: Arc::new(crate::health::HealthService::new()),
            storage: storage.clone(),
        };

        let app = create_api_key_routes()
            .with_state(storage.clone())
            .layer(middleware::from_fn_with_state(server, jwt_auth_middleware));

        let token = create_test_jwt(&jwt_service, user_id);
        let request_body = CreateApiKeyRequest {
            name: "".to_string(), // Empty name
            expires_in_days: None,
        };

        let request = Request::builder()
            .uri("/")
            .method("POST")
            .header("Authorization", format!("Bearer {}", token))
            .header("Content-Type", "application/json")
            .body(Body::from(serde_json::to_string(&request_body).unwrap()))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
}