pub mod config;
pub mod route_builder;

use crate::{
    auth::{
        jwt::{JwtService, JwtServiceImpl, parse_algorithm},
        middleware::{admin_middleware, auth_middleware, jwt_auth_middleware},
        oauth::OAuthService,
    },
    aws::bedrock::BedrockRuntimeImpl,
    cache::{CacheManager, CacheManagerImpl},
    config::Config,
    database::{DatabaseManager, DatabaseManagerImpl},
    error::AppError,
    health::HealthService,
    metrics,
    model_service::{ModelService, ModelServiceImpl},
    routes::{
        create_admin_api_routes, create_anthropic_routes, create_auth_routes,
        create_bedrock_routes, create_frontend_router, create_health_routes,
        create_protected_auth_routes, create_user_api_routes,
    },
    server::route_builder::middleware_factories::request_response_logger,
    shutdown::{ShutdownCoordinator, ShutdownManager, StreamingConnectionManager},
};
use axum::{
    Router,
    extract::DefaultBodyLimit,
    middleware::{self},
};
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::net::TcpListener;
use tracing::{error, info};

/// Maximum request body size (10MB) to prevent DoS attacks
const MAX_BODY_SIZE: usize = 10 * 1024 * 1024;

#[derive(Clone)]
pub struct Server {
    pub config: Arc<Config>,
    pub jwt_service: Arc<dyn JwtService>,
    pub model_service: Arc<dyn ModelService>,
    pub oauth_service: Arc<OAuthService>,
    pub health_service: Arc<HealthService>,
    pub database: Arc<dyn DatabaseManager>,
    pub cache: Arc<dyn CacheManager>,
    pub streaming_manager: Arc<StreamingConnectionManager>,
    pub shutdown_coordinator: Arc<ShutdownCoordinator>,
    pub cost_service: Arc<crate::cost::CostTrackingService>,
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
                    error!(
                        "Failed to start metrics server on port {}: {}",
                        config.metrics.port, e
                    );
                    return Err(AppError::Internal(format!(
                        "Failed to start metrics server: {}",
                        e
                    )));
                }
            }
        } else {
            None
        };

        // Initialize JWT service
        let jwt_algorithm = parse_algorithm(&config.jwt.algorithm)?;
        let jwt_service: Arc<dyn JwtService> = Arc::new(JwtServiceImpl::new(
            config.jwt.secret.clone(),
            jwt_algorithm,
        )?);

        // Initialize cache (create concrete instances for services that need them)
        let cache_impl = Arc::new(CacheManagerImpl::new_from_config(&config.cache).await?);
        let cache: Arc<dyn CacheManager> = cache_impl.clone();

        // Initialize database
        let database_impl = Arc::new(
            DatabaseManagerImpl::new_from_config(&config, cache_impl.clone())
                .await
                .map_err(AppError::Database)?,
        );
        let database: Arc<dyn DatabaseManager> = database_impl.clone();

        let bedrock_impl = Arc::new(BedrockRuntimeImpl::new(config.aws.clone()));
        let bedrock: Arc<dyn crate::aws::bedrock::BedrockRuntime> = bedrock_impl.clone();

        // Initialize shutdown coordinator and streaming manager
        let shutdown_coordinator = Arc::new(ShutdownCoordinator::new());
        let streaming_manager = Arc::new(StreamingConnectionManager::new(
            shutdown_coordinator.clone(),
        ));

        // Initialize model service with streaming manager
        let model_service: Arc<dyn ModelService> = Arc::new(
            ModelServiceImpl::new(bedrock.clone(), database.clone(), config.clone())
                .with_streaming_manager(streaming_manager.clone()),
        );

        // Initialize OAuth service (needs concrete cache type)
        let oauth_service = Arc::new(OAuthService::new(
            config.clone(),
            jwt_service.clone(),
            database.clone(),
            cache_impl.clone(),
        )?);

        // Initialize health service
        let health_service = Arc::new(HealthService::new());

        // Create concrete instances for health registration
        let jwt_service_impl = JwtServiceImpl::new(config.jwt.secret.clone(), jwt_algorithm)?;

        health_service.register(cache_impl).await;
        health_service.register(database_impl).await;
        health_service.register(bedrock_impl.health_checker()).await;
        health_service
            .register(jwt_service_impl.health_checker())
            .await;
        health_service
            .register(oauth_service.health_checker())
            .await;

        // Initialize cost service
        let cost_service = Arc::new(crate::cost::CostTrackingService::new(database.clone()));

        let config = Arc::new(config);
        Ok(Self {
            config,
            jwt_service,
            model_service,
            oauth_service,
            health_service,
            database,
            cache,
            streaming_manager,
            shutdown_coordinator,
            cost_service,
        })
    }

    pub async fn run(&self) -> Result<(), AppError> {
        // Run database migrations on startup to ensure tables exist
        info!("Running database migrations");
        self.database.migrate().await.map_err(AppError::Database)?;
        info!("Database migrations completed successfully");

        // Initialize shutdown manager
        let mut shutdown_manager = ShutdownManager::new(Duration::from_secs(30));

        // Initialize model costs in the background (now that migrations are complete)
        let cost_service = self.cost_service.clone();
        let cost_init = tokio::spawn(async move {
            if let Err(e) = cost_service.initialize_model_costs().await {
                tracing::warn!("Failed to initialize model costs: {}", e);
            }
        });

        // Register all server components for shutdown
        shutdown_manager.register_server_components(self);
        shutdown_manager.register_background_task(cost_init, "cost init");

        let app = self.create_app();

        let addr = SocketAddr::from(([0, 0, 0, 0], self.config.server.port));
        let listener = TcpListener::bind(addr)
            .await
            .map_err(|e| AppError::Internal(format!("Failed to bind to address: {}", e)))?;

        info!("Server listening on http://{}", addr);

        // Spawn shutdown signal handler
        let shutdown_coordinator_clone = self.shutdown_coordinator.clone();
        tokio::spawn(async move {
            shutdown_coordinator_clone.wait_for_shutdown_signal().await;
        });

        // Run server with graceful shutdown
        let shutdown_rx = self.shutdown_coordinator.subscribe();
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
        let mut app = Router::new()
            // OAuth authentication routes
            .nest("/auth", create_auth_routes())
            .nest("/auth", self.protected_auth_routes())
            // Health check routes
            .nest("/health", create_health_routes())
            // API routes
            .nest("/api", self.user_api_routes())
            .nest("/api", self.admin_api_routes())
            // Model API routes
            .nest("/bedrock", self.bedrock_routes())
            .nest("/anthropic", self.anthropic_routes())
            // Frontend routes
            .fallback_service(create_frontend_router(self.config.frontend.clone()))
            // All routes use Server as state
            .with_state(self.clone());

        // Add conditional middleware
        app = self.add_conditional_middleware(app);
        app
    }

    /// Helper method for protected auth routes
    fn protected_auth_routes(&self) -> Router<Server> {
        create_protected_auth_routes().layer(middleware::from_fn_with_state(
            self.clone(),
            jwt_auth_middleware,
        ))
    }

    /// Helper method for user API routes
    fn user_api_routes(&self) -> Router<Server> {
        create_user_api_routes().layer(middleware::from_fn_with_state(
            self.clone(),
            jwt_auth_middleware,
        ))
    }

    /// Helper method for admin API routes
    fn admin_api_routes(&self) -> Router<Server> {
        create_admin_api_routes()
            .layer(middleware::from_fn_with_state(
                self.clone(),
                jwt_auth_middleware,
            ))
            .layer(middleware::from_fn_with_state(
                self.clone(),
                admin_middleware,
            ))
    }

    /// Helper method for bedrock routes
    fn bedrock_routes(&self) -> Router<Server> {
        create_bedrock_routes()
            .layer(DefaultBodyLimit::max(MAX_BODY_SIZE))
            .layer(middleware::from_fn_with_state(
                self.clone(),
                auth_middleware,
            ))
    }

    /// Helper method for anthropic routes
    fn anthropic_routes(&self) -> Router<Server> {
        create_anthropic_routes()
            .layer(DefaultBodyLimit::max(MAX_BODY_SIZE))
            .layer(middleware::from_fn_with_state(
                self.clone(),
                auth_middleware,
            ))
    }

    /// Helper method for adding conditional middleware
    fn add_conditional_middleware(&self, mut app: Router) -> Router {
        if self.config.metrics.enabled {
            app = app.layer(middleware::from_fn(metrics::metrics_middleware));
        }
        if self.config.logging.log_request {
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
    use tower::ServiceExt;

    // Common test setup function
    async fn create_test_server() -> (Server, Config) {
        let server = crate::test_utils::TestServerBuilder::new().build().await;
        let config = (*server.config).clone();
        (server, config)
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
