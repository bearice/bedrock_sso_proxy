use crate::{
    auth::{
        jwt::{JwtService, parse_algorithm, ValidatedClaims},
        middleware::{AuthConfig, jwt_auth_middleware},
        oauth::OAuthService,
    },
    model_service::ModelService,
    config::Config,
    error::AppError,
    health::HealthService,
    metrics,
    usage_tracking::create_usage_routes,
    routes::{
        create_anthropic_routes, create_auth_routes, create_bedrock_routes, create_frontend_router,
        create_health_routes,
    },
    shutdown::{HttpServerShutdown, ShutdownCoordinator, ShutdownManager, StorageShutdown},
    storage::factory::StorageFactory,
};
use axum::{
    Router, body::Body, extract::DefaultBodyLimit, http::Request, middleware, middleware::Next,
    response::Response,
};
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::net::TcpListener;
use tracing::{error, info};

/// Maximum request body size (10MB) to prevent DoS attacks
const MAX_BODY_SIZE: usize = 10 * 1024 * 1024;


pub struct Server {
    pub config: Config,
    pub auth_config: Arc<AuthConfig>,
    pub model_service: Arc<ModelService>,
    pub oauth_service: Arc<OAuthService>,
    pub health_service: Arc<HealthService>,
    pub storage: Arc<crate::storage::Storage>,
}

impl Server {
    pub async fn new(config: Config) -> Result<Self, AppError> {
        // Initialize metrics if enabled
        let _metrics_handle = if config.metrics.enabled {
            match metrics::init_metrics_with_port(config.metrics.port) {
                Ok(handle) => {
                    info!("Metrics server started on port {}", config.metrics.port);
                    Some(handle)
                }
                Err(e) => {
                    error!("Failed to start metrics server on port {}: {}",
                        config.metrics.port, e);
                    return Err(AppError::Internal(format!("Failed to start metrics server: {}", e)));
                }
            }
        } else {
            None
        };

        // Initialize JWT service
        let jwt_algorithm = parse_algorithm(&config.jwt.algorithm)?;
        let jwt_service = JwtService::new(config.jwt.secret.clone(), jwt_algorithm)?;
        let auth_config = Arc::new(AuthConfig::new(jwt_service.clone()));

        // Initialize storage
        let storage = Arc::new(
            StorageFactory::create_from_config(&config)
                .await
                .map_err(AppError::Storage)?
        );

        // Initialize model service
        let model_service = Arc::new(ModelService::new(storage.clone(), config.clone()));

        // Initialize OAuth service
        let oauth_service = Arc::new(OAuthService::new(
            config.clone(),
            jwt_service.clone(),
            storage.clone(),
        ));

        // Initialize health service
        let health_service = Arc::new(HealthService::new());

        Ok(Self {
            config,
            auth_config,
            model_service,
            oauth_service,
            health_service,
            storage,
        })
    }


    pub async fn run(&self) -> Result<(), AppError> {
        // Initialize shutdown coordinator
        let shutdown_coordinator = ShutdownCoordinator::new();
        let mut shutdown_manager = ShutdownManager::new(Duration::from_secs(30));

        // Initialize model costs in the background
        let model_service_clone = self.model_service.clone();
        tokio::spawn(async move {
            if let Err(e) = model_service_clone.initialize_model_costs().await {
                tracing::warn!("Failed to initialize model costs: {}", e);
            }
        });

        // Register storage for graceful shutdown
        shutdown_manager.register(StorageShutdown::new(self.storage.clone()));

        let app = self.create_app();

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
        let serve_future = axum::serve(
            listener,
            // Use socket addresses in the app
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(async move {
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

    // Creates an application router
    pub fn create_app(&self) -> Router {
        self.create_app_internal()
    }

    // Internal method that actually creates the application router
    fn create_app_internal(&self) -> Router {
        let mut app = Router::new()
            // OAuth authentication routes (no auth required)
            .nest("/auth", create_auth_routes().with_state(self.oauth_service.clone()))
            // Health check routes (no auth required)
            .nest("/health", create_health_routes().with_state(self.health_service.clone()))
            // Protected usage tracking API routes
            .nest(
                "/api",
                create_usage_routes()
                    .with_state(self.storage.clone())
                    .layer(middleware::from_fn_with_state(
                        self.auth_config.clone(),
                        jwt_auth_middleware,
                    )),
            )
            // Protected Bedrock API routes - usage tracking now handled by ModelService
            .nest(
                "/bedrock",
                create_bedrock_routes()
                    .with_state(self.model_service.clone())
                    .layer(DefaultBodyLimit::max(MAX_BODY_SIZE))
                    .layer(middleware::from_fn_with_state(
                        self.auth_config.clone(),
                        jwt_auth_middleware,
                    )),
            )
            // Protected Anthropic API routes - usage tracking now handled by ModelService
            .nest(
                "/anthropic",
                create_anthropic_routes()
                    .with_state(self.model_service.clone())
                    .layer(DefaultBodyLimit::max(MAX_BODY_SIZE))
                    .layer(middleware::from_fn_with_state(
                        self.auth_config.clone(),
                        jwt_auth_middleware,
                    )),
            )
            // Frontend routes (serve last to not conflict with API routes)
            .fallback_service(create_frontend_router(self.config.frontend.clone()));

        // Add metrics middleware if enabled
        if self.config.metrics.enabled {
            app = app.layer(middleware::from_fn(metrics::metrics_middleware));
        }

        // Add request logging middleware if enabled
        if self.config.logging.log_request {
            // Enhanced request/response logging middleware
            async fn request_response_logger(
                req: Request<Body>,
                next: Next,
            ) -> Response {
                // Get method and path
                let method = req.method().to_string();
                let path = req.uri().path().to_string();

                // Skip logging for static files and frontend routes
                // Only log API routes that start with /bedrock, /anthropic, /auth, or /health
                let is_api_route = path.starts_with("/bedrock")
                    || path.starts_with("/anthropic")
                    || path.starts_with("/auth")
                    || path.starts_with("/health");

                if is_api_route {
                    // Get IP from extensions if available (from ConnectInfo)
                    let ip = req
                        .extensions()
                        .get::<axum::extract::ConnectInfo<SocketAddr>>()
                        .map(|connect_info| connect_info.0.ip().to_string())
                        .unwrap_or_else(|| "unknown".to_string());

                    // Get user from JWT claims if available
                    let user = req
                        .extensions()
                        .get::<ValidatedClaims>()
                        .map(|claims| claims.subject().to_string())
                        .unwrap_or_else(|| "anonymous".to_string());

                    // Log request with simple format - only for API routes
                    info!("Request: {} {} ip={} user={}", method, path, ip, user);

                    // Track request start time for latency calculation
                    let start = std::time::Instant::now();

                    // Continue with the request
                    let response = next.run(req).await;

                    // Calculate request duration
                    let duration = start.elapsed();

                    // Log response
                    info!(
                        "Response: {} {} status={} latency={}ms",
                        method,
                        path,
                        response.status().as_u16(),
                        duration.as_millis()
                    );

                    response
                } else {
                    // Skip logging for non-API routes
                    next.run(req).await
                }
            }

            app = app.layer(middleware::from_fn(request_response_logger));
        }

        app
    }

}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use jsonwebtoken::{EncodingKey, Header, encode};
    use std::time::{SystemTime, UNIX_EPOCH};
    use tower::ServiceExt;

    // Common test setup function
    async fn create_test_server() -> (Server, Config) {
        let mut config = Config::default();
        config.storage.redis.enabled = false;
        config.storage.database.enabled = false;
        config.metrics.enabled = false;

        let server = Server::new(config.clone()).await.unwrap();
        (server, config)
    }

    use crate::auth::jwt::Claims;

    fn create_test_token(secret: &str, sub: &str, exp_offset: i64) -> String {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let exp = (now + exp_offset) as usize;

        let claims = Claims {
            sub: sub.to_string(),
            exp,
            user_id: 123,
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
        let (server, config) = create_test_server().await;
        let app = server.create_app();

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
        let (server, _config) = create_test_server().await;
        let app = server.create_app();

        let request = Request::builder()
            .uri("/health")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_server_creation() {
        let (server, config) = create_test_server().await;
        assert_eq!(server.config.server.port, config.server.port);
    }

    #[tokio::test]
    async fn test_invoke_model_with_valid_jwt() {
        let (server, config) = create_test_server().await;
        let app = server.create_app();

        let token = create_test_token(&config.jwt.secret, "user123", 3600);
        let request = Request::builder()
            .uri("/bedrock/model/anthropic.claude-v2/invoke")
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
        let (server, _config) = create_test_server().await;
        let app = server.create_app();

        let request = Request::builder()
            .uri("/bedrock/model/anthropic.claude-v2/invoke")
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
