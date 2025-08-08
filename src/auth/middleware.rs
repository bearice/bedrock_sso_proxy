use crate::database::DatabaseManager;
use crate::database::entities::{UserRecord, UserState};
use crate::database::entities::api_keys::{API_KEY_PREFIX, hash_api_key, validate_api_key_format};
use crate::error::AppError;
use crate::server::Server;
use crate::utils::RequestIdExt;
use chrono::{Duration, Utc};
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

/// Extracts bearer token from Authorization header string.
/// 
/// **Expected format:** `"Bearer <token>"`
/// **Returns:** The token portion (everything after "Bearer ")
fn extract_bearer_token(auth_header: &str) -> Result<&str, AppError> {
    if !auth_header.starts_with("Bearer ") {
        return Err(AppError::Unauthorized(
            "Invalid Authorization format".to_string(),
        ));
    }
    Ok(&auth_header[7..])
}

/// Universal authentication middleware supporting multiple authentication methods:
/// 
/// **JWT Authentication:**
/// - `Authorization: Bearer <jwt_token>`
/// 
/// **API Key Authentication:**
/// - `Authorization: Bearer SSOK_<api_key>` (API key with Bearer prefix)
/// - `X-API-Key: SSOK_<api_key>` (API key in dedicated header)
/// 
/// Returns authenticated UserRecord in request extensions for downstream handlers.
/// Validates user account state and performs background OAuth provider verification.
pub async fn universal_auth_middleware(
    State(server): State<Server>,
    mut request: Request,
    next: Next,
) -> Result<Response, AppError> {
    let request_id = request.extensions().request_id().as_str();
    // Try JWT authentication first
    let user = if let Some(auth_header) = request.headers().get(AUTHORIZATION) {
        let auth_str = auth_header.to_str()
            .map_err(|_| AppError::Unauthorized("Invalid Authorization header".to_string()))?;
        
        let token = extract_bearer_token(auth_str)?;
        
        // Check if it's an API key (has the SSOK_ prefix)
        if token.starts_with(API_KEY_PREFIX) {
            if !server.config.api_keys.enabled {
                warn!(request_id = %request_id, "API key authentication disabled");
                return Err(AppError::Unauthorized(
                    "API key authentication is disabled".to_string(),
                ));
            }
            trace!(request_id = %request_id, auth_method = "api_key", "Authenticating request");
            authenticate_with_api_key(token, &server, &request_id).await?
        } else {
            // Try JWT authentication
            trace!(request_id = %request_id, auth_method = "jwt", "Authenticating request");
            authenticate_with_jwt(token, &server, &request_id).await?
        }
    } else if let Some(api_key_header) = request.headers().get(&X_API_KEY) {
        // Try X-API-Key header
        if !server.config.api_keys.enabled {
            return Err(AppError::Unauthorized(
                "API key authentication is disabled".to_string(),
            ));
        }
        let api_key = api_key_header.to_str()
            .map_err(|_| AppError::Unauthorized("Invalid API key header".to_string()))?;
        
        trace!(request_id = %request_id, auth_method = "x_api_key", "Authenticating request");
        authenticate_with_api_key(api_key, &server, &request_id).await?
    } else {
        return Err(AppError::Unauthorized(
            "Missing authentication credentials".to_string(),
        ));
    };

    // Add UserRecord to request extensions for downstream handlers
    request.extensions_mut().insert(user);

    Ok(next.run(request).await)
}

/// Authenticates JWT token and returns associated UserRecord.
/// 
/// **Process:**
/// 1. Validates JWT signature and expiration
/// 2. Extracts user ID from token claims
/// 3. Looks up user in database
/// 4. Validates user account state (active, not disabled/expired)
/// 5. Triggers background OAuth provider verification if needed
async fn authenticate_with_jwt(
    token: &str,
    server: &Server,
    request_id: &str,
) -> Result<UserRecord, AppError> {
    // Validate JWT token and get claims
    let claims = server.jwt_service.validate_oauth_token(token)?;
    let user_id = claims.sub;

    // lookup UserRecord
    get_user_record(user_id, server, request_id).await
}

/// Authenticates API key and returns associated UserRecord.
/// 
/// **Process:**
/// 1. Validates API key format (SSOK_ prefix)
/// 2. Hashes API key for secure database lookup
/// 3. Verifies API key exists and is not expired/revoked
/// 4. Looks up associated user in database
/// 5. Validates user account state (active, not disabled/expired)
async fn authenticate_with_api_key(
    api_key: &str,
    server: &Server,
    request_id: &str,
) -> Result<UserRecord, AppError> {
    let database = &server.database;
    // Validate API key format
    validate_api_key_format(api_key, API_KEY_PREFIX)?;

    // Hash the API key for database lookup
    let key_hash = hash_api_key(api_key);

    // Look up API key in database
    let stored_key = database
        .api_keys()
        .find_by_hash(&key_hash)
        .await
        .map_err(|e| AppError::Internal(format!("Database error: {e}")))?
        .ok_or_else(|| AppError::Unauthorized("Invalid API key".to_string()))?;

    // Check if API key is valid (not expired, not revoked)
    if !stored_key.is_valid() {
        warn!(user_id = %stored_key.user_id, request_id = %request_id, "API key expired or revoked");
        return Err(AppError::Unauthorized(
            "API key expired or revoked".to_string(),
        ));
    }

    trace!(user_id = %stored_key.user_id, request_id = %request_id, "API key authentication successful");
    get_user_record(stored_key.user_id, server, request_id).await
}

async fn get_user_record(
    user_id: i32,
    server: &Server,
    request_id: &str,
) -> Result<UserRecord, AppError> {
    let database = &server.database;
    let user = database
        .users()
        .find_by_id(user_id)
        .await
        .map_err(|e| AppError::Internal(format!("Database error: {e}")))?
        .ok_or_else(|| {
            warn!(user_id = %user_id, request_id = %request_id, "User not found");
            AppError::Unauthorized("User not found".to_string())
        })?;

    // Check if user account is active
    if !user.state.is_active() {
        warn!(
            user_id = %user.id, 
            email = %user.email, 
            state = ?user.state,
            request_id = %request_id, 
            "User account is not active"
        );
        return Err(AppError::Unauthorized(format!(
            "Account is {}: {}",
            user.state.as_str(),
            user.state.description()
        )));
    }

    // Check if we need to verify OAuth provider status (every 24 hours)
    let needs_oauth_check = user.last_oauth_check
        .map(|last_check| Utc::now() - last_check > Duration::hours(24))
        .unwrap_or(true); // Check if never verified

    if needs_oauth_check {
        // Perform OAuth provider verification in background (non-blocking)
        let oauth_service_clone = server.oauth_service.clone();
        let database_clone = server.database.clone();
        let user_clone = user.clone();
        let request_id_clone = request_id.to_string();
        
        tokio::spawn(async move {
            if let Err(e) = perform_oauth_verification(&user_clone, &oauth_service_clone, &database_clone, &request_id_clone).await {
                warn!(
                    user_id = %user_clone.id,
                    error = %e,
                    request_id = %request_id_clone,
                    "Background OAuth verification failed"
                );
            }
        });
    }

    // Only log user authentication success at trace level to reduce noise
    trace!(user_id = %user.id, email = %user.email, request_id = %request_id, "User authentication successful");
    Ok(user)
}

/// JWT-only authentication middleware for web UI routes.
/// 
/// **Accepts only:**
/// - `Authorization: Bearer <jwt_token>`
/// 
/// **Rejects:**
/// - API keys (SSOK_ prefixed tokens)
/// - X-API-Key headers
/// 
/// Returns authenticated UserRecord in request extensions for downstream handlers.
pub async fn jwt_only_auth_middleware(
    State(server): State<Server>,
    mut request: Request,
    next: Next,
) -> Result<Response, AppError> {
    let request_id = request.extensions().request_id().as_str();
    
    // Extract and validate Authorization header
    let auth_header = request
        .headers()
        .get(AUTHORIZATION)
        .and_then(|header| header.to_str().ok())
        .ok_or_else(|| AppError::Unauthorized("Missing Authorization header".to_string()))?;

    let token = extract_bearer_token(auth_header)?;

    // Authenticate with JWT and get UserRecord
    let user = authenticate_with_jwt(token, &server, &request_id).await?;

    // Add UserRecord to request extensions for downstream handlers
    request.extensions_mut().insert(user);

    Ok(next.run(request).await)
}


/// Admin authorization middleware that verifies user has admin permissions.
/// 
/// **Requirements:**
/// - Must be used after an authentication middleware (universal_auth_middleware or jwt_only_auth_middleware)
/// - User's email must be in the configured admin.emails list
/// - Email comparison is case-insensitive
/// 
/// **Returns:**
/// - 200: User is authenticated admin
/// - 401: No UserRecord found in extensions (authentication middleware missing)
/// - 403: User is authenticated but not an admin
pub async fn admin_auth_middleware(
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

/// Axum extractor for authenticated UserRecord from request extensions.
/// 
/// **Usage in route handlers:**
/// ```rust
/// async fn my_handler(UserExtractor(user): UserExtractor) -> impl IntoResponse {
///     format!("Hello, {}!", user.email)
/// }
/// ```
/// 
/// **Requirements:**
/// - Route must use an authentication middleware that sets UserRecord in extensions
/// - Returns 401 Unauthorized if no UserRecord is found
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

/// Background task: Verifies user account with OAuth provider and updates state.
/// 
/// **Process:**
/// 1. Contacts OAuth provider to verify user account status
/// 2. Updates user.last_oauth_check timestamp
/// 3. If verification succeeds: Sets user state to Active
/// 4. If verification fails: Sets user state to Expired
/// 
/// **Frequency:** Runs every 24 hours per user (non-blocking background task)
async fn perform_oauth_verification(
    user: &UserRecord,
    oauth_service: &Arc<crate::auth::oauth::OAuthService>,
    database: &Arc<dyn DatabaseManager>,
    request_id: &str,
) -> Result<(), AppError> {
    let now = Utc::now();
    
    // Try to verify with OAuth provider
    match oauth_service.verify_user_with_provider(user).await {
        Ok(()) => {
            // Verification successful - update last check time
            let updated_user = UserRecord {
                last_oauth_check: Some(now),
                state: UserState::Active,
                updated_at: now,
                ..user.clone()
            };
            
            if let Err(e) = database.users().upsert(&updated_user).await {
                warn!(
                    user_id = %user.id,
                    error = %e,
                    request_id = %request_id,
                    "Failed to update OAuth verification success timestamp"
                );
            } else {
                trace!(
                    user_id = %user.id,
                    provider = %user.provider,
                    request_id = %request_id,
                    "OAuth provider verification successful"
                );
            }
        },
        Err(_) => {
            // Verification failed - mark user as expired
            let updated_user = UserRecord {
                last_oauth_check: Some(now),
                state: UserState::Expired,
                updated_at: now,
                ..user.clone()
            };
            
            if let Err(e) = database.users().upsert(&updated_user).await {
                warn!(
                    user_id = %user.id,
                    error = %e,
                    request_id = %request_id,
                    "Failed to update OAuth verification failure timestamp"
                );
            } else {
                warn!(
                    user_id = %user.id,
                    provider = %user.provider,
                    request_id = %request_id,
                    "OAuth provider verification failed - user marked as expired"
                );
            }
            
            return Err(AppError::Unauthorized("Account no longer valid with OAuth provider".to_string()));
        }
    }
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::jwt::JwtService;
    use axum::{
        Router,
        body::Body,
        http::{Request, StatusCode},
        middleware,
        routing::get,
    };
    use tower::ServiceExt;

    async fn test_handler() -> &'static str {
        "success"
    }


    fn create_test_token(jwt_service: &dyn JwtService, user_id: i32) -> String {
        let claims = crate::auth::jwt::OAuthClaims::new(user_id, 3600);
        jwt_service.create_oauth_token(&claims).unwrap()
    }


    async fn create_test_user(
        server: &crate::server::Server,
        requested_id: i32,
        email: &str,
    ) -> i32 {
        let user = crate::database::entities::UserRecord {
            id: 0, // Let database assign ID
            provider_user_id: format!("test_user_{requested_id}"),
            provider: "test".to_string(),
            email: email.to_string(),
            display_name: Some(format!("Test User {requested_id}")),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            last_login: Some(chrono::Utc::now()),
            ..Default::default() // Uses default state and other fields
        };
        server.database.users().upsert(&user).await.unwrap()
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
                provider_user_id: format!("provider_user_{user_id}"),
                provider: "test".to_string(),
                email: email.to_string(),
                display_name: Some("Test User".to_string()),
                created_at: Utc::now(),
                updated_at: Utc::now(),
                last_login: None,
                ..Default::default() // Uses default state and other fields
            };
            server.database.users().upsert(&user).await.unwrap()
        }

        fn create_test_app(server: crate::server::Server) -> Router {
            Router::new()
                .route("/admin", get(test_handler))
                .layer(middleware::from_fn_with_state(
                    server.clone(),
                    admin_auth_middleware,
                ))
                .layer(middleware::from_fn_with_state(
                    server.clone(),
                    jwt_only_auth_middleware,
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
                .header("Authorization", format!("Bearer {token}"))
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
                .header("Authorization", format!("Bearer {token}"))
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
                .header("Authorization", format!("Bearer {token}"))
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
                middleware::from_fn_with_state(server.clone(), admin_auth_middleware),
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
                .header("Authorization", format!("Bearer {token}"))
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
                .header("Authorization", format!("Bearer {token}"))
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
                .header("Authorization", format!("Bearer {token}"))
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
                .header("Authorization", format!("Bearer {token2}"))
                .body(Body::empty())
                .unwrap();

            let response2 = app2.oneshot(request2).await.unwrap();
            assert_eq!(response2.status(), StatusCode::OK);
        }
    }
}
