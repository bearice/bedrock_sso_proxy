use crate::{auth::AuthConfig, aws::AwsClients, config::Config, error::AppError};
use axum::{Router, extract::State, middleware, response::Json, routing::get};
use serde_json::{Value, json};
use std::{net::SocketAddr, sync::Arc};
use tokio::net::TcpListener;
use tracing::info;

pub struct Server {
    config: Config,
}

impl Server {
    pub fn new(config: Config) -> Self {
        Self { config }
    }

    pub async fn run(&self) -> Result<(), AppError> {
        let auth_config = Arc::new(AuthConfig {
            jwt_secret: self.config.jwt.secret.clone(),
        });

        let aws_clients = AwsClients::new(&self.config.aws.region).await;

        let app = Router::new()
            .route("/health", get(health_check))
            .with_state(aws_clients)
            .layer(middleware::from_fn_with_state(
                auth_config.clone(),
                crate::auth::jwt_auth_middleware,
            ));

        let addr = SocketAddr::from(([0, 0, 0, 0], self.config.server.port));
        let listener = TcpListener::bind(addr)
            .await
            .map_err(|e| AppError::Internal(format!("Failed to bind to address: {}", e)))?;

        info!("Server listening on http://{}", addr);

        axum::serve(listener, app)
            .await
            .map_err(|e| AppError::Internal(format!("Server error: {}", e)))?;

        Ok(())
    }
}

async fn health_check(State(_aws_clients): State<AwsClients>) -> Result<Json<Value>, AppError> {
    Ok(Json(json!({
        "status": "healthy",
        "service": "bedrock-sso-proxy",
        "version": env!("CARGO_PKG_VERSION")
    })))
}
