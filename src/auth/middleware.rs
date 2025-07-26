use crate::auth::jwt::JwtService;
use crate::config::Config;
use crate::database::DatabaseManager;
use crate::database::entities::UserRecord;
use crate::database::entities::api_keys::{hash_api_key, validate_api_key_format};
use crate::error::AppError;
use crate::server::Server;
use axum::{
    extract::{FromRequestParts, Request, State},
    http::{HeaderName, header::AUTHORIZATION, request::Parts},
    middleware::Next,
    response::Response,
};
use std::sync::Arc;

/// Static header name for API key
static X_API_KEY: HeaderName = HeaderName::from_static("x-api-key");

/// Unified authentication middleware that handles both JWT and API key authentication
/// Returns a cached UserRecord for both authentication methods
pub async fn auth_middleware(
    State(server): State<Server>,
    mut request: Request,
    next: Next,
) -> Result<Response, AppError> {
    // Try JWT authentication first
    let user = if let Some(auth_header) = request.headers().get(AUTHORIZATION) {
        if let Ok(auth_str) = auth_header.to_str() {
            if let Some(token) = auth_str.strip_prefix("Bearer ") {
                // Check if it's an API key (has the configured prefix)
                if token.starts_with(&server.config.api_keys.prefix) {
                    if !server.config.api_keys.enabled {
                        return Err(AppError::Unauthorized(
                            "API key authentication is disabled".to_string(),
                        ));
                    }
                    authenticate_with_api_key(token, &server.database, &server.config).await?
                } else {
                    // Try JWT authentication
                    authenticate_with_jwt(token, &server.database, &server.jwt_service).await?
                }
            } else {
                return Err(AppError::Unauthorized(
                    "Invalid Authorization format".to_string(),
                ));
            }
        } else {
            return Err(AppError::Unauthorized(
                "Invalid Authorization header".to_string(),
            ));
        }
    } else if let Some(api_key_header) = request.headers().get(&X_API_KEY) {
        // Try X-API-Key header
        if !server.config.api_keys.enabled {
            return Err(AppError::Unauthorized(
                "API key authentication is disabled".to_string(),
            ));
        }
        if let Ok(api_key) = api_key_header.to_str() {
            authenticate_with_api_key(api_key, &server.database, &server.config).await?
        } else {
            return Err(AppError::Unauthorized("Invalid API key header".to_string()));
        }
    } else {
        return Err(AppError::Unauthorized(
            "Missing authentication credentials".to_string(),
        ));
    };

    // Add UserRecord to request extensions for downstream handlers
    request.extensions_mut().insert(user);

    // Remove authentication headers before forwarding to AWS
    request.headers_mut().remove(AUTHORIZATION);
    request.headers_mut().remove(&X_API_KEY);

    Ok(next.run(request).await)
}

/// Authenticate with JWT token and return cached UserRecord
async fn authenticate_with_jwt(
    token: &str,
    database: &Arc<DatabaseManager>,
    jwt_service: &Arc<JwtService>,
) -> Result<UserRecord, AppError> {
    // Validate JWT token and get claims
    let claims = jwt_service.validate_oauth_token(token)?;
    let user_id = claims.sub;

    // Get cached or lookup UserRecord
    get_cached_user_record(user_id, database).await
}

/// Authenticate with API key and return cached UserRecord
async fn authenticate_with_api_key(
    api_key: &str,
    database: &Arc<DatabaseManager>,
    config: &Arc<Config>,
) -> Result<UserRecord, AppError> {
    // Validate API key format
    validate_api_key_format(api_key, &config.api_keys.prefix)?;

    // Hash the API key for database lookup
    let key_hash = hash_api_key(api_key);

    // Look up API key in database
    let stored_key = database
        .api_keys()
        .find_by_hash(&key_hash)
        .await
        .map_err(|e| AppError::Internal(format!("Database error: {}", e)))?
        .ok_or_else(|| AppError::Unauthorized("Invalid API key".to_string()))?;

    // Check if API key is valid (not expired, not revoked)
    if !stored_key.is_valid() {
        return Err(AppError::Unauthorized(
            "API key expired or revoked".to_string(),
        ));
    }

    // // Update API key last used timestamp asynchronously
    // let database_clone = database.clone();
    // let key_hash_clone = key_hash.clone();
    // tokio::spawn(async move {
    //     let _ = database_clone.api_keys().update_last_used(&key_hash_clone).await;
    // });

    // Get cached or lookup UserRecord
    get_cached_user_record(stored_key.user_id, database).await
}

/// Get UserRecord with caching support
async fn get_cached_user_record(
    user_id: i32,
    database: &Arc<DatabaseManager>,
) -> Result<UserRecord, AppError> {
    // let cache_key = format!("user:id:{}", user_id);

    // Try cache first
    // match cache.get::<UserRecord>(&cache_key).await {
    //     Ok(Some(user)) => {
    //         tracing::debug!("User {} found in cache", user_id);
    //         return Ok(user);
    //     },
    //     Ok(None) => {
    //         tracing::debug!("User {} not in cache, checking database", user_id);
    //     },
    //     Err(e) => {
    //         tracing::warn!("Cache error for user {}: {}", user_id, e);
    //     }
    // }

    // Cache miss - fetch from database
    let user = database
        .users()
        .find_by_id(user_id)
        .await
        .map_err(|e| AppError::Internal(format!("Database error: {}", e)))?
        .ok_or_else(|| AppError::Unauthorized("User not found".to_string()))?;

    // Store in cache (fire-and-forget to avoid blocking request)
    // let cache_clone = cache.clone();
    // let cache_key_clone = cache_key.clone();
    // let user_clone = user.clone();
    // tokio::spawn(async move {
    //     if let Err(e) = cache_clone.set(&cache_key_clone, &user_clone, Some(std::time::Duration::from_secs(900))).await {
    //         tracing::warn!("Failed to cache user {}: {}", user_id, e);
    //     }
    // });

    Ok(user)
}

/// JWT-only authentication middleware (for web UI routes that don't support API keys)
pub async fn jwt_only_middleware(
    State(jwt_service): State<Arc<JwtService>>,
    State(database): State<Arc<DatabaseManager>>,
    mut request: Request,
    next: Next,
) -> Result<Response, AppError> {
    let auth_header = request
        .headers()
        .get(AUTHORIZATION)
        .and_then(|header| header.to_str().ok())
        .ok_or_else(|| AppError::Unauthorized("Missing Authorization header".to_string()))?;

    if !auth_header.starts_with("Bearer ") {
        return Err(AppError::Unauthorized(
            "Invalid Authorization format".to_string(),
        ));
    }

    let token = &auth_header[7..];

    // Authenticate with JWT and get UserRecord
    let user = authenticate_with_jwt(token, &database, &jwt_service).await?;

    // Add UserRecord to request extensions for downstream handlers
    request.extensions_mut().insert(user);

    // Remove Authorization header before forwarding
    request.headers_mut().remove(AUTHORIZATION);

    Ok(next.run(request).await)
}

/// Legacy JWT authentication middleware (for backward compatibility)
/// Consider using jwt_only_middleware or auth_middleware instead
pub async fn jwt_auth_middleware(
    State(server): State<Server>,
    mut request: Request,
    next: Next,
) -> Result<Response, AppError> {
    let auth_header = request
        .headers()
        .get(AUTHORIZATION)
        .and_then(|header| header.to_str().ok())
        .ok_or_else(|| AppError::Unauthorized("Missing Authorization header".to_string()))?;

    if !auth_header.starts_with("Bearer ") {
        return Err(AppError::Unauthorized(
            "Invalid Authorization format".to_string(),
        ));
    }

    let token = &auth_header[7..];

    // Validate token and get claims
    let claims = server.jwt_service.validate_oauth_token(token)?;

    // Get UserRecord for the user
    let user = get_cached_user_record(claims.sub, &server.database).await?;

    // Add both claims and UserRecord to request extensions for downstream handlers
    request.extensions_mut().insert(claims.clone());
    request.extensions_mut().insert(user);

    // Remove Authorization header before forwarding to AWS
    request.headers_mut().remove(AUTHORIZATION);

    Ok(next.run(request).await)
}

/// Admin middleware that checks if the authenticated user has admin permissions
/// Can be used after any authentication middleware that provides UserRecord in extensions
pub async fn admin_middleware(
    State(server): State<Server>,
    request: Request,
    next: Next,
) -> Result<Response, AppError> {
    // Get UserRecord from request extensions (should be set by auth middleware)
    let user = request
        .extensions()
        .get::<UserRecord>()
        .ok_or_else(|| AppError::Unauthorized("Missing user authentication".to_string()))?;

    // Check if user email is in admin list
    if !server.config.is_admin(&user.email) {
        return Err(AppError::Forbidden("Admin access required".to_string()));
    }

    Ok(next.run(request).await)
}

/// Custom extractor for UserRecord from request extensions
/// Use this in route handlers that need access to authenticated user information
pub struct UserExtractor(pub UserRecord);

impl<S> FromRequestParts<S> for UserExtractor
where
    S: Send + Sync,
{
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<UserRecord>()
            .cloned()
            .map(UserExtractor)
            .ok_or_else(|| AppError::Unauthorized("Missing user authentication".to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::jwt::{JwtService, OAuthClaims};
    use axum::{
        Router,
        body::Body,
        extract::Request as ExtractRequest,
        http::{Request, StatusCode},
        middleware,
        routing::get,
    };
    use tower::ServiceExt;

    async fn test_handler() -> &'static str {
        "success"
    }

    async fn test_claims_handler(request: ExtractRequest) -> &'static str {
        let claims = request.extensions().get::<OAuthClaims>();
        match claims {
            Some(_) => "oauth_success",
            None => "no_claims",
        }
    }

    fn create_test_token(jwt_service: &JwtService, user_id: i32) -> String {
        let claims = OAuthClaims::new(user_id, 3600);
        jwt_service.create_oauth_token(&claims).unwrap()
    }

    async fn create_test_server() -> crate::server::Server {
        let mut config = crate::config::Config::default();
        config.storage.redis.enabled = false;
        config.storage.database.enabled = true;
        config.storage.database.url = "sqlite::memory:".to_string(); // Use in-memory database
        config.metrics.enabled = false;

        let server = crate::server::Server::new(config).await.unwrap();

        // Run migrations to create tables
        server.database.migrate().await.unwrap();

        server
    }

    async fn create_test_user(
        server: &crate::server::Server,
        requested_id: i32,
        email: &str,
    ) -> i32 {
        let user = crate::database::entities::UserRecord {
            id: 0, // Let database assign ID
            provider_user_id: format!("test_user_{}", requested_id),
            provider: "test".to_string(),
            email: email.to_string(),
            display_name: Some(format!("Test User {}", requested_id)),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            last_login: Some(chrono::Utc::now()),
        };
        server.database.users().upsert(&user).await.unwrap()
    }

    #[tokio::test]
    async fn test_jwt_auth_middleware_oauth_token() {
        let server = create_test_server().await;

        // Create test user first
        let user_id = create_test_user(&server, 123, "test@example.com").await;

        let app =
            Router::new()
                .route("/test", get(test_handler))
                .layer(middleware::from_fn_with_state(
                    server.clone(),
                    jwt_auth_middleware,
                ));

        let token = create_test_token(&server.jwt_service, user_id);
        let request = Request::builder()
            .uri("/test")
            .header("Authorization", format!("Bearer {}", token))
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_jwt_auth_middleware_with_claims() {
        let server = create_test_server().await;

        // Create test user first
        let user_id = create_test_user(&server, 123, "test@example.com").await;
        let oauth_token = create_test_token(&server.jwt_service, user_id);

        let app =
            Router::new()
                .route("/test", get(test_handler))
                .layer(middleware::from_fn_with_state(
                    server.clone(),
                    jwt_auth_middleware,
                ));

        let request = Request::builder()
            .uri("/test")
            .header("Authorization", format!("Bearer {}", oauth_token))
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_jwt_auth_middleware_with_claims_extraction() {
        let server = create_test_server().await;

        // Create test user first
        let user_id = create_test_user(&server, 123, "test@example.com").await;
        let oauth_token = create_test_token(&server.jwt_service, user_id);

        let app = Router::new()
            .route("/test", get(test_claims_handler))
            .layer(middleware::from_fn_with_state(
                server.clone(),
                jwt_auth_middleware,
            ));

        let request = Request::builder()
            .uri("/test")
            .header("Authorization", format!("Bearer {}", oauth_token))
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body_str = String::from_utf8(body.to_vec()).unwrap();
        assert_eq!(body_str, "oauth_success");
    }

    #[tokio::test]
    async fn test_jwt_auth_middleware_missing_header() {
        let server = create_test_server().await;

        let app =
            Router::new()
                .route("/test", get(test_handler))
                .layer(middleware::from_fn_with_state(
                    server.clone(),
                    jwt_auth_middleware,
                ));

        let request = Request::builder().uri("/test").body(Body::empty()).unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_jwt_auth_middleware_invalid_format() {
        let server = create_test_server().await;

        let app =
            Router::new()
                .route("/test", get(test_handler))
                .layer(middleware::from_fn_with_state(
                    server.clone(),
                    jwt_auth_middleware,
                ));

        let request = Request::builder()
            .uri("/test")
            .header("Authorization", "Invalid token")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_jwt_auth_middleware_invalid_token() {
        let server = create_test_server().await;

        let app =
            Router::new()
                .route("/test", get(test_handler))
                .layer(middleware::from_fn_with_state(
                    server.clone(),
                    jwt_auth_middleware,
                ));

        let request = Request::builder()
            .uri("/test")
            .header("Authorization", "Bearer invalid.jwt.token")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_jwt_auth_middleware_expired_token() {
        let server = create_test_server().await;

        // Create test user first
        let user_id = create_test_user(&server, 123, "test@example.com").await;

        let app =
            Router::new()
                .route("/test", get(test_handler))
                .layer(middleware::from_fn_with_state(
                    server.clone(),
                    jwt_auth_middleware,
                ));

        // Create expired token by manually crafting claims
        let mut claims = OAuthClaims::new(user_id, 3600);
        claims.exp = (claims.iat as i64 - 3600) as usize; // Set to past
        let token = server.jwt_service.create_oauth_token(&claims).unwrap();
        let request = Request::builder()
            .uri("/test")
            .header("Authorization", format!("Bearer {}", token))
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_authorization_header_removed() {
        let server = create_test_server().await;

        // Create test user first
        let user_id = create_test_user(&server, 123, "test@example.com").await;

        async fn header_check_handler(request: ExtractRequest) -> String {
            match request.headers().get(AUTHORIZATION) {
                Some(_) => "header_present".to_string(),
                None => "header_removed".to_string(),
            }
        }

        let app = Router::new()
            .route("/test", get(header_check_handler))
            .layer(middleware::from_fn_with_state(
                server.clone(),
                jwt_auth_middleware,
            ));

        let token = create_test_token(&server.jwt_service, user_id);
        let request = Request::builder()
            .uri("/test")
            .header("Authorization", format!("Bearer {}", token))
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body_str = String::from_utf8(body.to_vec()).unwrap();
        assert_eq!(body_str, "header_removed");
    }

    // Admin middleware tests
    mod admin_middleware_tests {
        use super::*;
        use crate::config::Config;

        use crate::database::entities::UserRecord;
        use chrono::Utc;

        async fn create_test_server_with_admins(
            admin_emails: Vec<String>,
        ) -> crate::server::Server {
            let mut config = Config::default();
            config.admin.emails = admin_emails;
            config.storage.redis.enabled = false;
            config.storage.database.enabled = true;
            config.storage.database.url = "sqlite::memory:".to_string(); // Use in-memory database
            config.metrics.enabled = false;

            let server = crate::server::Server::new(config).await.unwrap();

            // Run migrations to create tables
            server.database.migrate().await.unwrap();

            server
        }

        async fn create_admin_test_user(
            server: &crate::server::Server,
            user_id: i32,
            email: &str,
        ) -> i32 {
            let user = UserRecord {
                id: 0, // Let database assign ID
                provider_user_id: format!("provider_user_{}", user_id),
                provider: "test".to_string(),
                email: email.to_string(),
                display_name: Some("Test User".to_string()),
                created_at: Utc::now(),
                updated_at: Utc::now(),
                last_login: None,
            };
            server.database.users().upsert(&user).await.unwrap()
        }

        fn create_test_app(server: crate::server::Server) -> Router {
            Router::new()
                .route("/admin", get(test_handler))
                .layer(middleware::from_fn_with_state(
                    server.clone(),
                    admin_middleware,
                ))
                .layer(middleware::from_fn_with_state(
                    server.clone(),
                    jwt_auth_middleware,
                ))
        }

        #[tokio::test]
        async fn test_admin_middleware_success() {
            let server =
                create_test_server_with_admins(vec!["admin@example.com".to_string()]).await;

            // Create test user with admin email and get the actual user ID
            let user_id = create_admin_test_user(&server, 123, "admin@example.com").await;

            let app = create_test_app(server.clone());

            let token = create_test_token(&server.jwt_service, user_id);
            let request = Request::builder()
                .uri("/admin")
                .header("Authorization", format!("Bearer {}", token))
                .body(Body::empty())
                .unwrap();

            let response = app.oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);
        }

        #[tokio::test]
        async fn test_admin_middleware_forbidden_non_admin() {
            let server =
                create_test_server_with_admins(vec!["admin@example.com".to_string()]).await;

            // Create test user with non-admin email
            let user_id = create_admin_test_user(&server, 123, "user@example.com").await;

            let app = create_test_app(server.clone());

            let token = create_test_token(&server.jwt_service, user_id);
            let request = Request::builder()
                .uri("/admin")
                .header("Authorization", format!("Bearer {}", token))
                .body(Body::empty())
                .unwrap();

            let response = app.oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::FORBIDDEN);
        }

        #[tokio::test]
        async fn test_admin_middleware_case_insensitive() {
            let server =
                create_test_server_with_admins(vec!["ADMIN@EXAMPLE.COM".to_string()]).await;

            // Create test user with lowercase email
            let user_id = create_admin_test_user(&server, 123, "admin@example.com").await;

            let app = create_test_app(server.clone());

            let token = create_test_token(&server.jwt_service, user_id);
            let request = Request::builder()
                .uri("/admin")
                .header("Authorization", format!("Bearer {}", token))
                .body(Body::empty())
                .unwrap();

            let response = app.oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);
        }

        #[tokio::test]
        async fn test_admin_middleware_missing_claims() {
            let server =
                create_test_server_with_admins(vec!["admin@example.com".to_string()]).await;

            let app = Router::new().route("/admin", get(test_handler)).layer(
                middleware::from_fn_with_state(server.clone(), admin_middleware),
            );

            let request = Request::builder()
                .uri("/admin")
                .body(Body::empty())
                .unwrap();

            let response = app.oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        }

        #[tokio::test]
        async fn test_admin_middleware_user_not_found() {
            let server =
                create_test_server_with_admins(vec!["admin@example.com".to_string()]).await;

            // Don't create user - user ID 999 won't exist

            let app = create_test_app(server.clone());

            let token = create_test_token(&server.jwt_service, 999);
            let request = Request::builder()
                .uri("/admin")
                .header("Authorization", format!("Bearer {}", token))
                .body(Body::empty())
                .unwrap();

            let response = app.oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        }

        #[tokio::test]
        async fn test_admin_middleware_empty_admin_list() {
            let server = create_test_server_with_admins(vec![]).await; // No admins configured

            // Create test user
            let user_id = create_admin_test_user(&server, 123, "user@example.com").await;

            let app = create_test_app(server.clone());

            let token = create_test_token(&server.jwt_service, user_id);
            let request = Request::builder()
                .uri("/admin")
                .header("Authorization", format!("Bearer {}", token))
                .body(Body::empty())
                .unwrap();

            let response = app.oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::FORBIDDEN);
        }

        #[tokio::test]
        async fn test_admin_middleware_multiple_admins() {
            let server = create_test_server_with_admins(vec![
                "admin1@example.com".to_string(),
                "admin2@example.com".to_string(),
                "superuser@company.com".to_string(),
            ])
            .await;

            // Test first admin
            let user_id1 = create_admin_test_user(&server, 1, "admin1@example.com").await;

            let app = create_test_app(server.clone());

            let token = create_test_token(&server.jwt_service, user_id1);
            let request = Request::builder()
                .uri("/admin")
                .header("Authorization", format!("Bearer {}", token))
                .body(Body::empty())
                .unwrap();

            let response = app.oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);

            // Test second admin
            let user_id2 = create_admin_test_user(&server, 2, "superuser@company.com").await;

            let app2 = create_test_app(server.clone());

            let token2 = create_test_token(&server.jwt_service, user_id2);
            let request2 = Request::builder()
                .uri("/admin")
                .header("Authorization", format!("Bearer {}", token2))
                .body(Body::empty())
                .unwrap();

            let response2 = app2.oneshot(request2).await.unwrap();
            assert_eq!(response2.status(), StatusCode::OK);
        }
    }
}
