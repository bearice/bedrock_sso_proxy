use crate::auth::jwt::{JwtService, OAuthClaims};
use crate::config::Config;
use crate::error::AppError;
use crate::storage::Storage;
use axum::{
    extract::{FromRequestParts, Request, State},
    http::{header::AUTHORIZATION, request::Parts},
    middleware::Next,
    response::Response,
};
use std::sync::Arc;

// Enhanced middleware that provides claims to the request
pub async fn jwt_auth_middleware(
    State(jwt_service): State<Arc<JwtService>>,
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
    let claims = jwt_service.validate_oauth_token(token)?;

    // Add claims to request extensions for downstream handlers
    request.extensions_mut().insert(claims);

    // Remove Authorization header before forwarding to AWS
    request.headers_mut().remove(AUTHORIZATION);

    Ok(next.run(request).await)
}

/// Admin middleware that checks if the user has admin permissions
/// Must be used after JWT authentication middleware
pub async fn admin_middleware(
    State(config): State<Arc<Config>>,
    State(storage): State<Arc<Storage>>,
    request: Request,
    next: Next,
) -> Result<Response, AppError> {
    // Get claims from JWT middleware (should already be validated)
    let claims = request
        .extensions()
        .get::<OAuthClaims>()
        .ok_or_else(|| AppError::Unauthorized("Missing authentication claims".to_string()))?;

    // Get user by ID to retrieve email
    let user = storage
        .database
        .get_user_by_id(claims.sub)
        .await
        .map_err(|e| AppError::Internal(format!("Database error: {}", e)))?
        .ok_or_else(|| AppError::Forbidden("User not found".to_string()))?;

    // Check if user email is in admin list
    if !config.is_admin(&user.email) {
        return Err(AppError::Forbidden("Admin access required".to_string()));
    }

    Ok(next.run(request).await)
}

/// Custom extractor for OAuthClaims from request extensions
/// Use this in route handlers that need access to JWT claims
pub struct ClaimsExtractor(pub OAuthClaims);

impl<S> FromRequestParts<S> for ClaimsExtractor
where
    S: Send + Sync,
{
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<OAuthClaims>()
            .cloned()
            .map(ClaimsExtractor)
            .ok_or_else(|| AppError::Unauthorized("Missing authentication claims".to_string()))
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
    use jsonwebtoken::Algorithm;
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

    #[tokio::test]
    async fn test_jwt_auth_middleware_oauth_token() {
        let jwt_service =
            Arc::new(JwtService::new("test-secret".to_string(), Algorithm::HS256).unwrap());

        let app =
            Router::new()
                .route("/test", get(test_handler))
                .layer(middleware::from_fn_with_state(
                    jwt_service.clone(),
                    jwt_auth_middleware,
                ));

        let token = create_test_token(&jwt_service, 123);
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
        let jwt_service =
            Arc::new(JwtService::new("test-secret".to_string(), Algorithm::HS256).unwrap());
        let oauth_token = create_test_token(&jwt_service, 123);

        let app =
            Router::new()
                .route("/test", get(test_handler))
                .layer(middleware::from_fn_with_state(
                    jwt_service.clone(),
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
        let jwt_service =
            Arc::new(JwtService::new("test-secret".to_string(), Algorithm::HS256).unwrap());
        let oauth_token = create_test_token(&jwt_service, 123);

        let app = Router::new()
            .route("/test", get(test_claims_handler))
            .layer(middleware::from_fn_with_state(
                jwt_service.clone(),
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
        let jwt_service =
            Arc::new(JwtService::new("test-secret".to_string(), Algorithm::HS256).unwrap());

        let app =
            Router::new()
                .route("/test", get(test_handler))
                .layer(middleware::from_fn_with_state(
                    jwt_service.clone(),
                    jwt_auth_middleware,
                ));

        let request = Request::builder().uri("/test").body(Body::empty()).unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_jwt_auth_middleware_invalid_format() {
        let jwt_service =
            Arc::new(JwtService::new("test-secret".to_string(), Algorithm::HS256).unwrap());

        let app =
            Router::new()
                .route("/test", get(test_handler))
                .layer(middleware::from_fn_with_state(
                    jwt_service.clone(),
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
        let jwt_service =
            Arc::new(JwtService::new("test-secret".to_string(), Algorithm::HS256).unwrap());

        let app =
            Router::new()
                .route("/test", get(test_handler))
                .layer(middleware::from_fn_with_state(
                    jwt_service.clone(),
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
        let jwt_service =
            Arc::new(JwtService::new("test-secret".to_string(), Algorithm::HS256).unwrap());

        let app =
            Router::new()
                .route("/test", get(test_handler))
                .layer(middleware::from_fn_with_state(
                    jwt_service.clone(),
                    jwt_auth_middleware,
                ));

        // Create expired token by manually crafting claims
        let mut claims = OAuthClaims::new(123, 3600);
        claims.exp = (claims.iat as i64 - 3600) as usize; // Set to past
        let token = jwt_service.create_oauth_token(&claims).unwrap();
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
        let jwt_service =
            Arc::new(JwtService::new("test-secret".to_string(), Algorithm::HS256).unwrap());

        async fn header_check_handler(request: ExtractRequest) -> String {
            match request.headers().get(AUTHORIZATION) {
                Some(_) => "header_present".to_string(),
                None => "header_removed".to_string(),
            }
        }

        let app = Router::new()
            .route("/test", get(header_check_handler))
            .layer(middleware::from_fn_with_state(
                jwt_service.clone(),
                jwt_auth_middleware,
            ));

        let token = create_test_token(&jwt_service, 123);
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
        use crate::storage::sqlite::SqliteStorage;
        use crate::storage::{Storage, UserRecord, memory::MemoryCacheStorage};
        use chrono::Utc;

        #[derive(Clone)]
        struct TestAppState {
            config: Arc<Config>,
            storage: Arc<Storage>,
            jwt_service: Arc<JwtService>,
        }

        async fn create_test_storage() -> Arc<Storage> {
            let cache = Box::new(MemoryCacheStorage::new(3600));
            let database = Box::new(SqliteStorage::new(":memory:").await.unwrap());
            database.migrate().await.unwrap();
            Arc::new(Storage::new(cache, database))
        }

        fn create_test_config(admin_emails: Vec<String>) -> Arc<Config> {
            let mut config = Config::default();
            config.admin.emails = admin_emails;
            Arc::new(config)
        }

        async fn create_test_user(storage: &Storage, user_id: i32, email: &str) -> i32 {
            let user = UserRecord {
                id: None, // Let database assign ID
                provider_user_id: format!("provider_user_{}", user_id),
                provider: "test".to_string(),
                email: email.to_string(),
                display_name: Some("Test User".to_string()),
                created_at: Utc::now(),
                updated_at: Utc::now(),
                last_login: None,
            };
            storage.database.upsert_user(&user).await.unwrap()
        }

        fn create_test_app(state: TestAppState) -> Router {
            Router::new()
                .route("/admin", get(test_handler))
                .layer(middleware::from_fn_with_state(
                    (state.config.clone(), state.storage.clone()),
                    |State((config, storage)): State<(Arc<Config>, Arc<Storage>)>,
                     request,
                     next| async move {
                        admin_middleware(State(config), State(storage), request, next).await
                    },
                ))
                .layer(middleware::from_fn_with_state(
                    state.jwt_service.clone(),
                    jwt_auth_middleware,
                ))
        }

        #[tokio::test]
        async fn test_admin_middleware_success() {
            let jwt_service =
                Arc::new(JwtService::new("test-secret".to_string(), Algorithm::HS256).unwrap());
            let storage = create_test_storage().await;
            let config = create_test_config(vec!["admin@example.com".to_string()]);

            // Create test user with admin email and get the actual user ID
            let user_id = create_test_user(&storage, 123, "admin@example.com").await;

            let state = TestAppState {
                config,
                storage,
                jwt_service: jwt_service.clone(),
            };
            let app = create_test_app(state);

            let token = create_test_token(&jwt_service, user_id);
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
            let jwt_service =
                Arc::new(JwtService::new("test-secret".to_string(), Algorithm::HS256).unwrap());
            let storage = create_test_storage().await;
            let config = create_test_config(vec!["admin@example.com".to_string()]);

            // Create test user with non-admin email
            let user_id = create_test_user(&storage, 123, "user@example.com").await;

            let state = TestAppState {
                config,
                storage,
                jwt_service: jwt_service.clone(),
            };
            let app = create_test_app(state);

            let token = create_test_token(&jwt_service, user_id);
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
            let jwt_service =
                Arc::new(JwtService::new("test-secret".to_string(), Algorithm::HS256).unwrap());
            let storage = create_test_storage().await;
            let config = create_test_config(vec!["ADMIN@EXAMPLE.COM".to_string()]);

            // Create test user with lowercase email
            let user_id = create_test_user(&storage, 123, "admin@example.com").await;

            let state = TestAppState {
                config,
                storage,
                jwt_service: jwt_service.clone(),
            };
            let app = create_test_app(state);

            let token = create_test_token(&jwt_service, user_id);
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
            let storage = create_test_storage().await;
            let config = create_test_config(vec!["admin@example.com".to_string()]);

            let app = Router::new().route("/admin", get(test_handler)).layer(
                middleware::from_fn_with_state(
                    (config.clone(), storage.clone()),
                    |State((config, storage)): State<(Arc<Config>, Arc<Storage>)>,
                     request,
                     next| async move {
                        admin_middleware(State(config), State(storage), request, next).await
                    },
                ),
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
            let jwt_service =
                Arc::new(JwtService::new("test-secret".to_string(), Algorithm::HS256).unwrap());
            let storage = create_test_storage().await;
            let config = create_test_config(vec!["admin@example.com".to_string()]);

            // Don't create user - user ID 999 won't exist

            let state = TestAppState {
                config,
                storage,
                jwt_service: jwt_service.clone(),
            };
            let app = create_test_app(state);

            let token = create_test_token(&jwt_service, 999);
            let request = Request::builder()
                .uri("/admin")
                .header("Authorization", format!("Bearer {}", token))
                .body(Body::empty())
                .unwrap();

            let response = app.oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::FORBIDDEN);
        }

        #[tokio::test]
        async fn test_admin_middleware_empty_admin_list() {
            let jwt_service =
                Arc::new(JwtService::new("test-secret".to_string(), Algorithm::HS256).unwrap());
            let storage = create_test_storage().await;
            let config = create_test_config(vec![]); // No admins configured

            // Create test user
            let user_id = create_test_user(&storage, 123, "user@example.com").await;

            let state = TestAppState {
                config,
                storage,
                jwt_service: jwt_service.clone(),
            };
            let app = create_test_app(state);

            let token = create_test_token(&jwt_service, user_id);
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
            let jwt_service =
                Arc::new(JwtService::new("test-secret".to_string(), Algorithm::HS256).unwrap());
            let storage = create_test_storage().await;
            let config = create_test_config(vec![
                "admin1@example.com".to_string(),
                "admin2@example.com".to_string(),
                "superuser@company.com".to_string(),
            ]);

            // Test first admin
            let user_id1 = create_test_user(&storage, 1, "admin1@example.com").await;

            let state = TestAppState {
                config: config.clone(),
                storage: storage.clone(),
                jwt_service: jwt_service.clone(),
            };
            let app = create_test_app(state);

            let token = create_test_token(&jwt_service, user_id1);
            let request = Request::builder()
                .uri("/admin")
                .header("Authorization", format!("Bearer {}", token))
                .body(Body::empty())
                .unwrap();

            let response = app.oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);

            // Test second admin
            let user_id2 = create_test_user(&storage, 2, "superuser@company.com").await;

            let state2 = TestAppState {
                config,
                storage,
                jwt_service: jwt_service.clone(),
            };
            let app2 = create_test_app(state2);

            let token2 = create_test_token(&jwt_service, user_id2);
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
