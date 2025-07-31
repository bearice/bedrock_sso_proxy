use crate::auth::jwt::JwtService;
use crate::database::DatabaseManager;
use crate::database::entities::UserRecord;
use crate::database::entities::api_keys::{API_KEY_PREFIX, hash_api_key, validate_api_key_format};
use crate::error::AppError;
use crate::middleware::RequestIdExt;
use crate::server::Server;
use axum::{
    extract::{FromRequestParts, Request, State},
    http::{HeaderName, header::AUTHORIZATION, request::Parts},
    middleware::Next,
    response::Response,
};
use std::sync::Arc;
use tracing::{trace, warn};

/// Static header name for API key
static X_API_KEY: HeaderName = HeaderName::from_static("x-api-key");

/// Unified authentication middleware that handles both JWT and API key authentication
/// Returns a UserRecord for both authentication methods
pub async fn auth_middleware(
    State(server): State<Server>,
    mut request: Request,
    next: Next,
) -> Result<Response, AppError> {
    let request_id = request.extensions().request_id().as_str();
    // Try JWT authentication first
    let user = if let Some(auth_header) = request.headers().get(AUTHORIZATION) {
        if let Ok(auth_str) = auth_header.to_str() {
            if let Some(token) = auth_str.strip_prefix("Bearer ") {
                // Check if it's an API key (has the SSOK_ prefix)
                if token.starts_with(API_KEY_PREFIX) {
                    if !server.config.api_keys.enabled {
                        warn!(request_id = %request_id, "API key authentication disabled");
                        return Err(AppError::Unauthorized(
                            "API key authentication is disabled".to_string(),
                        ));
                    }
                    trace!(request_id = %request_id, auth_method = "api_key", "Authenticating request");
                    authenticate_with_api_key(token, &server.database, &request_id).await?
                } else {
                    // Try JWT authentication
                    trace!(request_id = %request_id, auth_method = "jwt", "Authenticating request");
                    authenticate_with_jwt(token, &server.database, &server.jwt_service, &request_id)
                        .await?
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
            trace!(request_id = %request_id, auth_method = "x_api_key", "Authenticating request");
            authenticate_with_api_key(api_key, &server.database, &request_id).await?
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

    Ok(next.run(request).await)
}

/// Authenticate with JWT token and return UserRecord
async fn authenticate_with_jwt(
    token: &str,
    database: &Arc<dyn DatabaseManager>,
    jwt_service: &Arc<dyn JwtService>,
    request_id: &str,
) -> Result<UserRecord, AppError> {
    // Validate JWT token and get claims
    let claims = jwt_service.validate_oauth_token(token)?;
    let user_id = claims.sub;

    // lookup UserRecord
    get_user_record(user_id, database, request_id).await
}

/// Authenticate with API key and return UserRecord
async fn authenticate_with_api_key(
    api_key: &str,
    database: &Arc<dyn DatabaseManager>,
    request_id: &str,
) -> Result<UserRecord, AppError> {
    // Validate API key format
    validate_api_key_format(api_key, API_KEY_PREFIX)?;

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
        warn!(user_id = %stored_key.user_id, request_id = %request_id, "API key expired or revoked");
        return Err(AppError::Unauthorized(
            "API key expired or revoked".to_string(),
        ));
    }

    trace!(user_id = %stored_key.user_id, request_id = %request_id, "API key authentication successful");
    get_user_record(stored_key.user_id, database, request_id).await
}

async fn get_user_record(
    user_id: i32,
    database: &Arc<dyn DatabaseManager>,
    request_id: &str,
) -> Result<UserRecord, AppError> {
    let user = database
        .users()
        .find_by_id(user_id)
        .await
        .map_err(|e| AppError::Internal(format!("Database error: {}", e)))?
        .ok_or_else(|| {
            warn!(user_id = %user_id, request_id = %request_id, "User not found");
            AppError::Unauthorized("User not found".to_string())
        })?;

    // Only log user authentication success at trace level to reduce noise
    trace!(user_id = %user.id, email = %user.email, request_id = %request_id, "User authentication successful");
    Ok(user)
}

/// JWT-only authentication middleware (for web UI routes that don't support API keys)
pub async fn jwt_only_middleware(
    State(jwt_service): State<Arc<dyn JwtService>>,
    State(database): State<Arc<dyn DatabaseManager>>,
    mut request: Request,
    next: Next,
) -> Result<Response, AppError> {
    let request_id = request.extensions().request_id().as_str();
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
    let user = authenticate_with_jwt(token, &database, &jwt_service, &request_id).await?;

    // Add UserRecord to request extensions for downstream handlers
    request.extensions_mut().insert(user);

    Ok(next.run(request).await)
}

/// Legacy JWT authentication middleware (for backward compatibility)
/// Consider using jwt_only_middleware or auth_middleware instead
pub async fn jwt_auth_middleware(
    State(server): State<Server>,
    mut request: Request,
    next: Next,
) -> Result<Response, AppError> {
    let request_id = request.extensions().request_id().as_str();
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
    let user = get_user_record(claims.sub, &server.database, &request_id).await?;

    // Add both claims and UserRecord to request extensions for downstream handlers
    request.extensions_mut().insert(claims.clone());
    request.extensions_mut().insert(user);

    Ok(next.run(request).await)
}

/// Admin middleware that checks if the authenticated user has admin permissions
/// Can be used after any authentication middleware that provides UserRecord in extensions
pub async fn admin_middleware(
    State(server): State<Server>,
    request: Request,
    next: Next,
) -> Result<Response, AppError> {
    let request_id = request.extensions().request_id().as_str();
    // Get UserRecord from request extensions (should be set by auth middleware)
    let user = request
        .extensions()
        .get::<UserRecord>()
        .ok_or_else(|| AppError::Unauthorized("Missing user authentication".to_string()))?;

    // Check if user email is in admin list
    if !server.config.is_admin(&user.email) {
        warn!(user_id = %user.id, email = %user.email, request_id = %request_id, "Admin access denied");
        return Err(AppError::Forbidden("Admin access required".to_string()));
    }

    trace!(user_id = %user.id, email = %user.email, request_id = %request_id, "Admin access granted");

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

    fn create_test_token(jwt_service: &dyn JwtService, user_id: i32) -> String {
        let claims = OAuthClaims::new(user_id, 3600);
        jwt_service.create_oauth_token(&claims).unwrap()
    }

    async fn create_test_server() -> crate::server::Server {
        crate::test_utils::TestServerBuilder::new().build().await
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

        let token = create_test_token(server.jwt_service.as_ref(), user_id);
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
        let oauth_token = create_test_token(server.jwt_service.as_ref(), user_id);

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
        let oauth_token = create_test_token(server.jwt_service.as_ref(), user_id);

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
    async fn test_authorization_header_preserved() {
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

        let token = create_test_token(server.jwt_service.as_ref(), user_id);
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
        assert_eq!(body_str, "header_present");
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

            crate::test_utils::TestServerBuilder::new()
                .with_config(config)
                .build()
                .await
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

            let token = create_test_token(server.jwt_service.as_ref(), user_id);
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

            let token = create_test_token(server.jwt_service.as_ref(), user_id);
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

            let token = create_test_token(server.jwt_service.as_ref(), user_id);
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

            let token = create_test_token(server.jwt_service.as_ref(), 999);
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

            let token = create_test_token(server.jwt_service.as_ref(), user_id);
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

            let token = create_test_token(server.jwt_service.as_ref(), user_id1);
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

            let token2 = create_test_token(server.jwt_service.as_ref(), user_id2);
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
