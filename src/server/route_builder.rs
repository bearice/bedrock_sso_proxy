use crate::{
    auth::middleware::{admin_middleware, auth_middleware, jwt_auth_middleware},
    middleware::RequestIdExt,
    server::Server,
};
use axum::{
    Router,
    extract::{DefaultBodyLimit, Request},
    middleware::{self, Next},
    response::Response,
};

/// Helper functions for creating routes with common middleware patterns
pub struct RouteHelpers;

impl RouteHelpers {
    /// Create routes with JWT authentication
    pub fn with_jwt_auth(path: &str, routes: Router<Server>, server: &Server) -> Router<Server> {
        Router::new().nest(
            path,
            routes.layer(middleware::from_fn_with_state(
                server.clone(),
                jwt_auth_middleware,
            )),
        )
    }

    /// Create routes with admin authentication (JWT + admin middleware)
    pub fn with_admin_auth(path: &str, routes: Router<Server>, server: &Server) -> Router<Server> {
        Router::new().nest(
            path,
            routes
                .layer(middleware::from_fn_with_state(
                    server.clone(),
                    jwt_auth_middleware,
                ))
                .layer(middleware::from_fn_with_state(
                    server.clone(),
                    admin_middleware,
                )),
        )
    }

    /// Create routes with unified authentication (JWT or API key)
    pub fn with_unified_auth(
        path: &str,
        routes: Router<Server>,
        server: &Server,
    ) -> Router<Server> {
        Router::new().nest(
            path,
            routes.layer(middleware::from_fn_with_state(
                server.clone(),
                auth_middleware,
            )),
        )
    }

    /// Create routes with body limit and unified authentication
    pub fn with_body_limit_auth(
        path: &str,
        routes: Router<Server>,
        server: &Server,
        max_size: usize,
    ) -> Router<Server> {
        Router::new().nest(
            path,
            routes
                .layer(DefaultBodyLimit::max(max_size))
                .layer(middleware::from_fn_with_state(
                    server.clone(),
                    auth_middleware,
                )),
        )
    }

    /// Create routes without authentication
    pub fn without_auth(path: &str, routes: Router<Server>, _server: &Server) -> Router<Server> {
        Router::new().nest(path, routes)
    }

    /// Create routes with custom state (for services that need specific state types)
    pub fn with_custom_state<S>(path: &str, routes: Router<S>, state: S) -> Router
    where
        S: Clone + Send + Sync + 'static,
    {
        Router::new().nest(path, routes.with_state(state))
    }
}

/// Middleware factory functions for common patterns
pub mod middleware_factories {
    use super::*;
    use crate::database::entities::UserRecord;
    use axum::body::Body;
    use axum::extract::ConnectInfo;
    use std::net::SocketAddr;
    use tracing::info;

    /// Enhanced request/response logging middleware
    pub async fn request_response_logger(req: Request<Body>, next: Next) -> Response {
        // Get method and path
        let method = req.method().to_string();
        let path = req.uri().path().to_string();

        // Get request ID from extensions
        let request_id = req.extensions().request_id().as_str();

        // Skip logging for static files and frontend routes
        // Only log API routes that start with /bedrock, /anthropic, /auth, or /health
        let is_api_route = path.starts_with("/bedrock")
            || path.starts_with("/anthropic")
            || path.starts_with("/auth")
            || path.starts_with("/api")
            || path.starts_with("/health");

        if is_api_route {
            // Get IP from extensions if available (from ConnectInfo)
            let ip = req
                .extensions()
                .get::<ConnectInfo<SocketAddr>>()
                .map(|connect_info| connect_info.0.ip().to_string())
                .unwrap_or_else(|| "unknown".to_string());

            // Get user from JWT claims if available
            let user = req
                .extensions()
                .get::<UserRecord>()
                .map(|user| user.provider_user_id.clone())
                .unwrap_or_else(|| "anonymous".to_string());

            // Log request with structured format - only for API routes
            info!(
                method = %method,
                path = %path,
                ip = %ip,
                user = %user,
                request_id = %request_id,
                "API request"
            );

            // Track request start time for latency calculation
            let start = std::time::Instant::now();

            // Continue with the request
            let response = next.run(req).await;

            // Calculate request duration
            let duration = start.elapsed();

            // Log response with structured format
            info!(
                method = %method,
                path = %path,
                status = %response.status().as_u16(),
                latency_ms = %duration.as_millis(),
                request_id = %request_id,
                "API response"
            );

            response
        } else {
            // Skip logging for non-API routes
            next.run(req).await
        }
    }
}
