use crate::{auth::AuthConfig, aws::AwsClients, config::Config, error::AppError};
use axum::{
    Router,
    extract::{Query, State},
    middleware,
    response::Json,
    routing::get,
};
use serde::Deserialize;
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

        let aws_clients = AwsClients::new(&self.config.aws).await;

        let app = self.create_app(auth_config, aws_clients);

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

    pub fn create_app(&self, auth_config: Arc<AuthConfig>, aws_clients: AwsClients) -> Router {
        Router::new()
            .route("/health", get(health_check))
            .with_state(aws_clients.clone())
            .merge(
                Router::new()
                    .with_state(aws_clients)
                    .layer(middleware::from_fn_with_state(
                        auth_config,
                        crate::auth::jwt_auth_middleware,
                    )),
            )
    }
}

#[derive(Debug, Deserialize)]
struct HealthCheckQuery {
    #[serde(default)]
    check: Option<String>,
}

async fn health_check(
    State(aws_clients): State<AwsClients>,
    Query(params): Query<HealthCheckQuery>,
) -> Result<Json<Value>, AppError> {
    let mut response = json!({
        "status": "healthy",
        "service": "bedrock-sso-proxy",
        "version": env!("CARGO_PKG_VERSION")
    });

    // Determine which checks to run
    let run_aws_check = match params.check.as_deref() {
        Some("aws") => true,
        Some("all") => true,
        Some(_) => false, // Unknown check type
        None => false,    // No specific check requested
    };

    // Run AWS check if requested
    if run_aws_check {
        match aws_clients.health_check().await {
            Ok(()) => {
                response["aws_connection"] = json!("connected");
            }
            Err(err) => {
                tracing::warn!("AWS health check failed: {}", err);
                response["status"] = json!("degraded");
                response["aws_connection"] = json!("failed");
                response["error"] = json!(err.to_string());
            }
        }
    } else if params.check.is_some() {
        // Check was requested but not recognized or bypassed
        let check_type = params.check.as_ref().unwrap();
        if check_type != "all" {
            response["error"] = json!(format!("Unknown check type: {}", check_type));
        }
        response["aws_connection"] = json!("skipped");
    }

    Ok(Json(response))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::AuthConfig;
    use crate::aws::AwsClients;
    use crate::config::Config;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use jsonwebtoken::{EncodingKey, Header, encode};
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
        let auth_config = Arc::new(AuthConfig {
            jwt_secret: config.jwt.secret.clone(),
        });
        let aws_clients = AwsClients::new_test();

        let server = Server::new(config.clone());
        let app = server.create_app(auth_config, aws_clients);

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
        let auth_config = Arc::new(AuthConfig {
            jwt_secret: config.jwt.secret.clone(),
        });
        let aws_clients = AwsClients::new_test();

        let server = Server::new(config);
        let app = server.create_app(auth_config, aws_clients);

        let request = Request::builder()
            .uri("/health")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_health_check_with_invalid_jwt() {
        let config = Config::default();
        let auth_config = Arc::new(AuthConfig {
            jwt_secret: config.jwt.secret.clone(),
        });
        let aws_clients = AwsClients::new_test();

        let server = Server::new(config);
        let app = server.create_app(auth_config, aws_clients);

        let request = Request::builder()
            .uri("/health")
            .header("Authorization", "Bearer invalid.jwt.token")
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
    async fn test_health_check_with_aws_query() {
        let config = Config::default();
        let auth_config = Arc::new(AuthConfig {
            jwt_secret: config.jwt.secret.clone(),
        });
        let aws_clients = AwsClients::new_test();

        let server = Server::new(config);
        let app = server.create_app(auth_config, aws_clients);

        let request = Request::builder()
            .uri("/health?check=aws")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_health_check_with_unknown_query() {
        let config = Config::default();
        let auth_config = Arc::new(AuthConfig {
            jwt_secret: config.jwt.secret.clone(),
        });
        let aws_clients = AwsClients::new_test();

        let server = Server::new(config);
        let app = server.create_app(auth_config, aws_clients);

        let request = Request::builder()
            .uri("/health?check=unknown")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_health_check_with_all_query() {
        let config = Config::default();
        let auth_config = Arc::new(AuthConfig {
            jwt_secret: config.jwt.secret.clone(),
        });
        let aws_clients = AwsClients::new_test();

        let server = Server::new(config);
        let app = server.create_app(auth_config, aws_clients);

        let request = Request::builder()
            .uri("/health?check=all")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }
}
