use crate::{
    auth::{
        jwt::{JwtService, parse_algorithm},
        middleware::{AuthConfig, jwt_auth_middleware},
        oauth::OAuthService,
    },
    aws_http::AwsHttpClient,
    config::Config,
    error::AppError,
    health::HealthService,
    routes::{
        create_auth_routes, create_bedrock_routes, create_frontend_router,
        create_protected_bedrock_routes,
    },
    shutdown::{HttpServerShutdown, ShutdownCoordinator, ShutdownManager, StorageShutdown},
    storage::{StorageHealthChecker, factory::StorageFactory},
};
use axum::{Router, middleware};
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::net::TcpListener;
use tracing::{error, info};

pub struct Server {
    config: Config,
}

impl Server {
    pub fn new(config: Config) -> Self {
        Self { config }
    }

    pub async fn run(&self) -> Result<(), AppError> {
        // Initialize shutdown coordinator
        let shutdown_coordinator = ShutdownCoordinator::new();
        let mut shutdown_manager = ShutdownManager::new(Duration::from_secs(30));

        // Initialize metrics and rate limiting (disabled for now)
        if self.config.metrics.enabled {
            info!("Metrics configuration found but not fully implemented yet");
        }
        if self.config.rate_limit.enabled {
            info!("Rate limiting configuration found but not fully implemented yet");
        }

        let jwt_algorithm = parse_algorithm(&self.config.jwt.algorithm)?;
        let jwt_service = JwtService::new(self.config.jwt.secret.clone(), jwt_algorithm)?;
        let auth_config = Arc::new(AuthConfig::new(jwt_service.clone()));

        let aws_http_client = AwsHttpClient::new(self.config.aws.clone());

        // Initialize storage system
        let storage = Arc::new(
            StorageFactory::create_from_config(&self.config)
                .await
                .map_err(|e| AppError::Internal(format!("Failed to initialize storage: {}", e)))?,
        );

        // Register storage for graceful shutdown
        shutdown_manager.register(StorageShutdown::new(storage.clone()));

        // OAuth is always enabled

        let oauth_service = Arc::new(OAuthService::new(
            self.config.clone(),
            jwt_service.clone(),
            storage.clone(),
        ));

        // Create centralized health service and register health checkers
        let health_service = Arc::new(HealthService::new());

        // Register AWS health checker
        health_service
            .register(Arc::new(aws_http_client.clone().health_checker()))
            .await;

        // Register OAuth health checker
        health_service
            .register(Arc::new(oauth_service.health_checker()))
            .await;

        // Register JWT health checker
        health_service
            .register(Arc::new(jwt_service.health_checker()))
            .await;

        // Register storage health checker
        let storage_health_checker = storage.clone();
        health_service
            .register(Arc::new(StorageHealthChecker::new(storage_health_checker)))
            .await;

        let app =
            self.create_oauth_app(auth_config, aws_http_client, oauth_service, health_service);

        let addr = SocketAddr::from(([0, 0, 0, 0], self.config.server.port));
        let listener = TcpListener::bind(addr)
            .await
            .map_err(|e| AppError::Internal(format!("Failed to bind to address: {}", e)))?;

        info!("Server listening on http://{}", addr);

        // Register HTTP server for graceful shutdown
        shutdown_manager.register(HttpServerShutdown::new("HTTP Server".to_string()));

        // Spawn shutdown signal handler
        let shutdown_coordinator_clone = shutdown_coordinator.clone();
        tokio::spawn(async move {
            shutdown_coordinator_clone.wait_for_shutdown_signal().await;
        });

        // Run server with graceful shutdown
        let shutdown_rx = shutdown_coordinator.subscribe();
        let serve_future = axum::serve(listener, app).with_graceful_shutdown(async move {
            let mut rx = shutdown_rx;
            let _ = rx.changed().await;
            info!("Graceful shutdown initiated");
        });

        tokio::select! {
            result = serve_future => {
                if let Err(e) = result {
                    error!("Server error: {}", e);
                }
            }
        }

        // Perform graceful shutdown
        shutdown_manager.shutdown_all().await;
        info!("Server shutdown complete");

        Ok(())
    }

    fn create_oauth_app(
        &self,
        auth_config: Arc<AuthConfig>,
        aws_http_client: AwsHttpClient,
        oauth_service: Arc<OAuthService>,
        health_service: Arc<HealthService>,
    ) -> Router {
        Router::new()
            // OAuth authentication routes (no auth required)
            .nest("/auth", create_auth_routes().with_state(oauth_service))
            // Health check (no auth required)
            .merge(create_bedrock_routes().with_state((aws_http_client.clone(), health_service)))
            // Protected Bedrock API routes
            .merge(
                create_protected_bedrock_routes()
                    .with_state(aws_http_client)
                    .layer(middleware::from_fn_with_state(
                        auth_config,
                        jwt_auth_middleware,
                    )),
            )
            // Frontend routes (serve last to not conflict with API routes)
            .fallback_service(create_frontend_router(self.config.frontend.clone()))
    }

    // For testing - OAuth always enabled
    pub async fn create_app(
        &self,
        auth_config: Arc<AuthConfig>,
        aws_http_client: AwsHttpClient,
    ) -> Result<Router, AppError> {
        let jwt_service = JwtService::new(
            self.config.jwt.secret.clone(),
            parse_algorithm(&self.config.jwt.algorithm).unwrap(),
        )?;

        // Create temporary storage for testing
        let temp_storage = Arc::new(crate::storage::Storage::new(
            Box::new(crate::storage::memory::MemoryCacheStorage::new(3600)),
            Box::new(crate::storage::memory::MemoryDatabaseStorage::new()),
        ));

        let oauth_service = Arc::new(OAuthService::new(
            self.config.clone(),
            jwt_service.clone(),
            temp_storage,
        ));

        // Create health service for testing
        let health_service = Arc::new(HealthService::new());
        health_service
            .register(Arc::new(aws_http_client.clone().health_checker()))
            .await;
        health_service
            .register(Arc::new(oauth_service.health_checker()))
            .await;
        health_service
            .register(Arc::new(jwt_service.health_checker()))
            .await;

        Ok(Router::new()
            .nest("/auth", create_auth_routes().with_state(oauth_service))
            .merge(create_bedrock_routes().with_state((aws_http_client.clone(), health_service)))
            .merge(
                create_protected_bedrock_routes()
                    .with_state(aws_http_client)
                    .layer(middleware::from_fn_with_state(
                        auth_config,
                        jwt_auth_middleware,
                    )),
            )
            .fallback_service(create_frontend_router(self.config.frontend.clone())))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::jwt::JwtService;
    use crate::auth::middleware::AuthConfig;
    use crate::aws_http::AwsHttpClient;
    use crate::config::Config;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
    use serde::{Deserialize, Serialize};
    use std::time::{SystemTime, UNIX_EPOCH};
    use tower::ServiceExt;

    #[derive(Debug, Serialize, Deserialize)]
    struct TestClaims {
        sub: String,
        exp: usize,
    }

    fn create_test_token(secret: &str, sub: &str, exp_offset: i64) -> String {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let exp = (now + exp_offset) as usize;

        let claims = TestClaims {
            sub: sub.to_string(),
            exp,
        };

        encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(secret.as_ref()),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn test_health_check_with_valid_jwt() {
        let config = Config::default();
        let jwt_service = JwtService::new(config.jwt.secret.clone(), Algorithm::HS256).unwrap();
        let auth_config = Arc::new(AuthConfig::new(jwt_service));
        let aws_http_client = AwsHttpClient::new_test();

        let server = Server::new(config.clone());
        let app = server
            .create_app(auth_config, aws_http_client)
            .await
            .unwrap();

        let token = create_test_token(&config.jwt.secret, "user123", 3600);
        let request = Request::builder()
            .uri("/health")
            .header("Authorization", format!("Bearer {}", token))
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_health_check_without_jwt() {
        let config = Config::default();
        let jwt_service = JwtService::new(config.jwt.secret.clone(), Algorithm::HS256).unwrap();
        let auth_config = Arc::new(AuthConfig::new(jwt_service));
        let aws_http_client = AwsHttpClient::new_test();

        let server = Server::new(config);
        let app = server
            .create_app(auth_config, aws_http_client)
            .await
            .unwrap();

        let request = Request::builder()
            .uri("/health")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[test]
    fn test_server_creation() {
        let config = Config::default();
        let server = Server::new(config.clone());
        assert_eq!(server.config.server.port, config.server.port);
    }

    #[tokio::test]
    async fn test_invoke_model_with_valid_jwt() {
        let config = Config::default();
        let jwt_service = JwtService::new(config.jwt.secret.clone(), Algorithm::HS256).unwrap();
        let auth_config = Arc::new(AuthConfig::new(jwt_service));
        let aws_http_client = AwsHttpClient::new_test();

        let server = Server::new(config.clone());
        let app = server
            .create_app(auth_config, aws_http_client)
            .await
            .unwrap();

        let token = create_test_token(&config.jwt.secret, "user123", 3600);
        let request = Request::builder()
            .uri("/model/anthropic.claude-v2/invoke")
            .method("POST")
            .header("Authorization", format!("Bearer {}", token))
            .header("Content-Type", "application/json")
            .body(Body::from(
                r#"{"messages": [{"role": "user", "content": "Hello"}]}"#,
            ))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        // Note: This will fail in tests because we don't have real AWS credentials
        // But we can verify the authentication and routing is working
        // Expected statuses: 500 (internal error), 400 (bad request), or other error codes
        assert!(
            response.status() == StatusCode::INTERNAL_SERVER_ERROR
                || response.status() == StatusCode::BAD_REQUEST
                || response.status() == StatusCode::FORBIDDEN
                || response.status() == StatusCode::OK
        );
    }

    #[tokio::test]
    async fn test_invoke_model_without_jwt() {
        let config = Config::default();
        let jwt_service = JwtService::new(config.jwt.secret.clone(), Algorithm::HS256).unwrap();
        let auth_config = Arc::new(AuthConfig::new(jwt_service));
        let aws_http_client = AwsHttpClient::new_test();

        let server = Server::new(config);
        let app = server
            .create_app(auth_config, aws_http_client)
            .await
            .unwrap();

        let request = Request::builder()
            .uri("/model/anthropic.claude-v2/invoke")
            .method("POST")
            .header("Content-Type", "application/json")
            .body(Body::from(
                r#"{"messages": [{"role": "user", "content": "Hello"}]}"#,
            ))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}
