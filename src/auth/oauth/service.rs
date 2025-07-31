use crate::{
    auth::{
        jwt::JwtService,
        oauth::{
            flows::{
                AuthorizeResponse, OAuthFlows, ProvidersResponse, RefreshRequest, TokenRequest,
                TokenResponse,
            },
            health::OAuthHealthChecker,
            providers::initialize_oauth_clients,
        }
    },
    cache::CacheManagerImpl,
    config::Config,
    database::{DatabaseManager, entities::UserRecord},
    error::AppError,
    health::{HealthCheckResult, HealthChecker},
    utils::request_context::RequestContext,
};
use std::sync::Arc;

pub struct OAuthService {
    config: Config,
    database: Arc<dyn DatabaseManager>,
    flows: OAuthFlows,
}

impl OAuthService {
    pub fn new(
        config: Config,
        jwt_service: Arc<dyn JwtService>,
        database: Arc<dyn DatabaseManager>,
        cache: Arc<CacheManagerImpl>,
    ) -> Result<Self, AppError> {
        let oauth_clients = initialize_oauth_clients(&config)?;
        let flows = OAuthFlows::new(
            config.clone(),
            jwt_service.clone(),
            database.clone(),
            cache.clone(),
            oauth_clients,
        );

        Ok(Self {
            config,
            database,
            flows,
        })
    }

    /// Get user by database ID
    pub async fn get_user_by_id(
        &self,
        user_id: i32,
    ) -> Result<Option<UserRecord>, crate::database::DatabaseError> {
        self.database.users().find_by_id(user_id).await
    }

    pub async fn get_authorization_url(
        &self,
        provider_name: &str,
        redirect_uri: &str,
    ) -> Result<AuthorizeResponse, AppError> {
        self.flows
            .get_authorization_url(provider_name, redirect_uri)
            .await
    }

    pub async fn exchange_code_for_token(
        &self,
        request: TokenRequest,
        context: RequestContext,
    ) -> Result<TokenResponse, AppError> {
        self.flows.exchange_code_for_token(request, context).await
    }

    pub async fn refresh_token(
        &self,
        request: RefreshRequest,
        context: RequestContext,
    ) -> Result<TokenResponse, AppError> {
        self.flows.refresh_token(request, context).await
    }

    pub fn list_providers(&self) -> ProvidersResponse {
        self.flows.list_providers()
    }

    pub async fn get_redirect_uri_for_state(&self, state: &str) -> Option<String> {
        self.flows.get_redirect_uri_for_state(state).await
    }

    /// Create a health checker for this OAuth service
    pub fn health_checker(self: &Arc<Self>) -> Arc<OAuthHealthChecker> {
        Arc::new(OAuthHealthChecker::new(Arc::new(self.config.clone())))
    }
}

/// Health checker implementation for OAuth service
pub struct OAuthHealthCheckerWrapper {
    service: Arc<OAuthService>,
}

#[async_trait::async_trait]
impl HealthChecker for OAuthHealthCheckerWrapper {
    fn name(&self) -> &str {
        "oauth"
    }

    async fn check(&self) -> HealthCheckResult {
        let health_checker = OAuthHealthChecker::new(Arc::new(self.service.config.clone()));
        health_checker.check().await
    }

    fn info(&self) -> Option<serde_json::Value> {
        let health_checker = OAuthHealthChecker::new(Arc::new(self.service.config.clone()));
        health_checker.info()
    }
}

// Re-export types for backward compatibility
pub use super::{OAUTH_STATE_TTL_SECONDS, ProviderInfo, StateData};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::config::{JwtConfig, OAuthConfig, OAuthProvider};
    use crate::cache::config::CacheConfig;
    use crate::database::DatabaseManagerImpl;
    use jsonwebtoken::Algorithm;
    use std::collections::HashMap;

    fn create_test_config() -> Config {
        let mut providers = HashMap::new();
        providers.insert(
            "google".to_string(),
            OAuthProvider {
                client_id: "test-client-id".to_string(),
                client_secret: "test-client-secret".to_string(),
                redirect_uri: Some("http://localhost:3000/callback".to_string()),
                scopes: vec!["openid".to_string(), "email".to_string()],
                authorization_url: Some("https://accounts.google.com/o/oauth2/v2/auth".to_string()),
                token_url: Some("https://oauth2.googleapis.com/token".to_string()),
                user_info_url: Some("https://www.googleapis.com/oauth2/v2/userinfo".to_string()),
                user_id_field: "id".to_string(),
                email_field: "email".to_string(),
                tenant_id: None,
                instance_url: None,
                domain: None,
            },
        );

        Config {
            oauth: OAuthConfig { providers },
            jwt: JwtConfig {
                secret: "test-secret".to_string(),
                algorithm: "HS256".to_string(),
                access_token_ttl: 3600,
                refresh_token_ttl: 86400,
            },
            cache: CacheConfig {
                validation_ttl: 3600,
                max_entries: 1000,
                cleanup_interval: 300,
                backend: "memory".to_string(),
                redis_url: "redis://localhost:6379".to_string(),
                redis_key_prefix: "test:".to_string(),
            },
            ..Default::default()
        }
    }

    async fn create_test_components() -> (Arc<dyn DatabaseManager>, Arc<CacheManagerImpl>) {
        let mut config = Config::default();
        config.cache.backend = "memory".to_string();
        config.database.enabled = true;
        config.database.url = "sqlite::memory:".to_string();
        let cache = Arc::new(CacheManagerImpl::new_memory());
        let database = Arc::new(
            DatabaseManagerImpl::new_from_config(&config, cache.clone())
                .await
                .unwrap(),
        );

        (database, cache)
    }

    #[tokio::test]
    async fn test_oauth_service_creation() {
        let config = create_test_config();
        let (database, cache) = create_test_components().await;
        let jwt_service = Arc::new(
            crate::auth::jwt::JwtServiceImpl::new("test-secret".to_string(), Algorithm::HS256)
                .unwrap(),
        );

        let oauth_service = OAuthService::new(config, jwt_service, database, cache).unwrap();

        // Test that service was created successfully
        let providers = oauth_service.list_providers();
        assert_eq!(providers.providers.len(), 1);
        assert_eq!(providers.providers[0].name, "google");
        assert_eq!(providers.providers[0].display_name, "Google");
    }

    #[tokio::test]
    async fn test_get_authorization_url() {
        let config = create_test_config();
        let (database, cache) = create_test_components().await;
        let jwt_service = Arc::new(
            crate::auth::jwt::JwtServiceImpl::new("test-secret".to_string(), Algorithm::HS256)
                .unwrap(),
        );
        let oauth_service = OAuthService::new(config, jwt_service, database, cache).unwrap();

        let result = oauth_service
            .get_authorization_url("google", "http://localhost:3000/callback")
            .await;
        assert!(result.is_ok());

        let response = result.unwrap();
        assert_eq!(response.provider, "google");
        assert!(
            response
                .authorization_url
                .starts_with("https://accounts.google.com/o/oauth2/v2/auth")
        );
        assert!(!response.state.is_empty());
    }

    #[tokio::test]
    async fn test_get_authorization_url_unknown_provider() {
        let config = create_test_config();
        let (database, cache) = create_test_components().await;
        let jwt_service = Arc::new(
            crate::auth::jwt::JwtServiceImpl::new("test-secret".to_string(), Algorithm::HS256)
                .unwrap(),
        );
        let oauth_service = OAuthService::new(config, jwt_service, database, cache).unwrap();

        let result = oauth_service
            .get_authorization_url("unknown", "http://localhost:3000/callback")
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_list_providers() {
        let config = create_test_config();
        let (database, cache) = create_test_components().await;
        let jwt_service = Arc::new(
            crate::auth::jwt::JwtServiceImpl::new("test-secret".to_string(), Algorithm::HS256)
                .unwrap(),
        );
        let oauth_service = OAuthService::new(config, jwt_service, database, cache).unwrap();

        let providers = oauth_service.list_providers();
        assert_eq!(providers.providers.len(), 1);

        let google_provider = &providers.providers[0];
        assert_eq!(google_provider.name, "google");
        assert_eq!(google_provider.display_name, "Google");
        assert_eq!(google_provider.scopes, vec!["openid", "email"]);
    }
}
