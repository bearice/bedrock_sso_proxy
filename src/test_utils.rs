use crate::{
    auth::jwt::{JwtService, JwtServiceImpl, OAuthClaims},
    config::Config,
    database::{DatabaseManager, entities::UserRecord},
    server::Server,
};
use chrono::Utc;
use jsonwebtoken::Algorithm;
use std::sync::Arc;

/// Test server builder for creating test instances with configurable backends
pub struct TestServerBuilder {
    config: Config,
    use_memory_db: bool,
    use_memory_cache: bool,
    jwt_secret: Option<String>,
    use_mock_aws: bool,
}

impl TestServerBuilder {
    pub fn new() -> Self {
        Self {
            config: Config::default(),
            use_memory_db: true,    // Default to memory for tests
            use_memory_cache: true, // Default to memory for tests
            jwt_secret: Some("test-secret".to_string()),
            use_mock_aws: false, // Default to real AWS client for backward compatibility
        }
    }

    /// Use a real database instead of in-memory SQLite
    pub fn with_real_database(mut self) -> Self {
        self.use_memory_db = false;
        self
    }

    /// Use a real cache instead of in-memory cache
    pub fn with_real_cache(mut self) -> Self {
        self.use_memory_cache = false;
        self
    }

    /// Set a custom JWT secret for testing
    pub fn with_jwt_secret(mut self, secret: String) -> Self {
        self.jwt_secret = Some(secret);
        self
    }

    /// Set a custom configuration
    pub fn with_config(mut self, config: Config) -> Self {
        self.config = config;
        self
    }

    /// Use mock AWS client instead of real AWS client
    pub fn with_mock_aws(mut self) -> Self {
        self.use_mock_aws = true;
        self
    }

    /// Build the test server with configured settings
    pub async fn build(self) -> Server {
        let mut config = self.config;

        // Configure database backend
        if self.use_memory_db {
            config.database.enabled = true;
            config.database.url = "sqlite::memory:".to_string();
        }

        // Configure cache backend
        if self.use_memory_cache {
            config.cache.backend = "memory".to_string();
        }

        // Configure JWT secret
        if let Some(secret) = &self.jwt_secret {
            config.jwt.secret = secret.clone();
            config.jwt.algorithm = "HS256".to_string();
        }

        // Disable metrics for tests
        config.metrics.enabled = false;

        // Use the regular Server::new method with in-memory backends
        let server = if self.use_mock_aws {
            Self::build_with_mock_aws_static(config).await.unwrap()
        } else {
            Server::new(config).await.unwrap()
        };

        server.database.migrate().await.unwrap();
        server
    }

    /// Build server with mock AWS client for security testing
    async fn build_with_mock_aws_static(config: Config) -> Result<Server, crate::error::AppError> {
        use crate::{
            auth::{
                jwt::{JwtServiceImpl, parse_algorithm},
                oauth::OAuthService,
            },
            aws::mock::MockBedrockRuntime,
            cache::CacheManagerImpl,
            database::DatabaseManagerImpl,
            health::HealthService,
            model_service::ModelServiceImpl,
        };
        use std::sync::Arc;

        let config = Arc::new(config);

        // Initialize JWT service
        let jwt_algorithm = parse_algorithm(&config.jwt.algorithm)?;
        let jwt_service: Arc<dyn JwtService> = Arc::new(JwtServiceImpl::new(
            config.jwt.secret.clone(),
            jwt_algorithm,
        )?);

        // Initialize cache
        let cache_impl = Arc::new(CacheManagerImpl::new_from_config(&config.cache).await?);
        let cache: Arc<dyn crate::cache::CacheManager> = cache_impl.clone();

        // Initialize database
        let database_impl = Arc::new(
            DatabaseManagerImpl::new_from_config(&config, cache_impl.clone())
                .await
                .map_err(crate::error::AppError::Database)?,
        );
        let database: Arc<dyn DatabaseManager> = database_impl.clone();

        // Use mock AWS client for security tests
        let bedrock: Arc<dyn crate::aws::bedrock::BedrockRuntime> =
            Arc::new(MockBedrockRuntime::for_security_tests());

        // Initialize model service with mock AWS client
        let model_service: Arc<dyn crate::model_service::ModelService> = Arc::new(
            ModelServiceImpl::new(bedrock.clone(), database.clone(), (*config).clone()),
        );

        // Initialize OAuth service
        let oauth_service = Arc::new(OAuthService::new(
            (*config).clone(),
            jwt_service.clone(),
            database.clone(),
            cache_impl.clone(),
        )?);

        // Initialize health service
        let health_service = Arc::new(HealthService::new());

        // Register health checkers
        health_service.register(cache_impl).await;
        health_service.register(database_impl).await;
        health_service.register(bedrock.health_checker()).await;

        // Create concrete JWT service for health registration
        let jwt_service_impl = JwtServiceImpl::new(config.jwt.secret.clone(), jwt_algorithm)?;
        health_service
            .register(jwt_service_impl.health_checker())
            .await;

        health_service
            .register(oauth_service.health_checker())
            .await;

        let shutdown_coordinator = Arc::new(crate::shutdown::ShutdownCoordinator::new());
        let cost_service = Arc::new(crate::cost::CostTrackingService::new(database.clone()));

        // Create test job scheduler (disabled by default for tests)
        let test_jobs_config = crate::jobs::JobsConfig {
            enabled: false,
            ..Default::default()
        };
        let job_scheduler = Arc::new(tokio::sync::RwLock::new(
            crate::jobs::JobScheduler::with_shutdown_coordinator(
                test_jobs_config,
                shutdown_coordinator.subscribe(),
            ),
        ));

        Ok(Server {
            config,
            jwt_service,
            model_service,
            oauth_service,
            health_service,
            database,
            cache,
            streaming_manager: Arc::new(crate::shutdown::StreamingConnectionManager::new(
                shutdown_coordinator.clone(),
            )),
            shutdown_coordinator,
            cost_service,
            job_scheduler,
        })
    }
}

impl Default for TestServerBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Create a test user in the database
pub async fn create_test_user(database: &Arc<dyn DatabaseManager>) -> i32 {
    let user = UserRecord {
        id: 0,
        provider_user_id: "test_user_123".to_string(),
        provider: "test".to_string(),
        email: "test@example.com".to_string(),
        display_name: Some("Test User".to_string()),
        created_at: Utc::now(),
        updated_at: Utc::now(),
        last_login: Some(Utc::now()),
    };
    database.users().upsert(&user).await.unwrap()
}

/// Create a test user with custom data
pub async fn create_test_user_with_data(
    database: &Arc<dyn DatabaseManager>,
    provider_user_id: &str,
    provider: &str,
    email: &str,
) -> i32 {
    let user = UserRecord {
        id: 0,
        provider_user_id: provider_user_id.to_string(),
        provider: provider.to_string(),
        email: email.to_string(),
        display_name: Some("Test User".to_string()),
        created_at: Utc::now(),
        updated_at: Utc::now(),
        last_login: Some(Utc::now()),
    };
    database.users().upsert(&user).await.unwrap()
}

/// Create a test JWT token for the given user
pub fn create_test_jwt(jwt_service: &Arc<dyn JwtService>, user_id: i32) -> String {
    let claims = OAuthClaims::new(user_id, 3600);
    jwt_service.create_oauth_token(&claims).unwrap()
}

/// Create a JWT service for testing
pub fn create_test_jwt_service() -> JwtServiceImpl {
    JwtServiceImpl::new("test-secret".to_string(), Algorithm::HS256).unwrap()
}

/// Create a test JWT token with custom claims
pub fn create_test_jwt_with_expiry(
    jwt_service: &Arc<dyn JwtService>,
    user_id: i32,
    expires_in: u64,
) -> String {
    let claims = OAuthClaims::new(user_id, expires_in);
    jwt_service.create_oauth_token(&claims).unwrap()
}

/// Create an invalid JWT token for testing error cases
pub fn create_invalid_jwt_token() -> String {
    "invalid.jwt.token".to_string()
}

/// Create an expired JWT token for testing expiration
pub fn create_expired_jwt_token() -> String {
    use jsonwebtoken::{EncodingKey, Header, encode};
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Serialize, Deserialize)]
    struct ExpiredClaims {
        sub: i32,
        iat: i64,
        exp: i64,
    }

    let now = chrono::Utc::now().timestamp();
    let expired_claims = ExpiredClaims {
        sub: 1,
        iat: now - 3600, // 1 hour ago
        exp: now - 1800, // 30 minutes ago (expired)
    };

    let key = EncodingKey::from_secret("test-secret".as_ref());
    encode(&Header::default(), &expired_claims, &key).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::api_key::ApiKey;

    #[tokio::test]
    async fn test_server_builder_default() {
        let server = TestServerBuilder::new().build().await;

        // Verify server is created successfully
        assert!(server.config.database.enabled);
        assert_eq!(server.config.database.url, "sqlite::memory:");
        assert_eq!(server.config.cache.backend, "memory");
        assert_eq!(server.config.jwt.secret, "test-secret");
        assert!(!server.config.metrics.enabled);
    }

    #[tokio::test]
    async fn test_server_builder_with_real_database() {
        let server = TestServerBuilder::new().with_real_database().build().await;

        // Should not use in-memory database
        assert_ne!(server.config.database.url, "sqlite::memory:");
    }

    #[tokio::test]
    async fn test_server_builder_with_custom_jwt_secret() {
        let custom_secret = "custom-test-secret";
        let server = TestServerBuilder::new()
            .with_jwt_secret(custom_secret.to_string())
            .build()
            .await;

        assert_eq!(server.config.jwt.secret, custom_secret);
    }

    #[tokio::test]
    async fn test_create_test_user() {
        let server = TestServerBuilder::new().build().await;
        let user_id = create_test_user(&server.database).await;

        // Verify user was created
        assert!(user_id > 0);

        // Verify user can be retrieved
        let user = server.database.users().find_by_id(user_id).await.unwrap();
        assert!(user.is_some());
        assert_eq!(user.unwrap().email, "test@example.com");
    }

    #[tokio::test]
    async fn test_create_test_user_with_data() {
        let server = TestServerBuilder::new().build().await;
        let user_id = create_test_user_with_data(
            &server.database,
            "custom_user_123",
            "custom_provider",
            "custom@example.com",
        )
        .await;

        // Verify user was created with custom data
        let user = server.database.users().find_by_id(user_id).await.unwrap();
        assert!(user.is_some());
        let user = user.unwrap();
        assert_eq!(user.provider_user_id, "custom_user_123");
        assert_eq!(user.provider, "custom_provider");
        assert_eq!(user.email, "custom@example.com");
    }

    #[tokio::test]
    async fn test_create_test_jwt() {
        let server = TestServerBuilder::new().build().await;
        let user_id = create_test_user(&server.database).await;
        let token = create_test_jwt(&server.jwt_service, user_id);

        // Verify token can be validated
        let claims = server.jwt_service.validate_oauth_token(&token).unwrap();
        assert_eq!(claims.sub, user_id);
    }

    #[tokio::test]
    async fn test_create_test_jwt_with_expiry() {
        let server = TestServerBuilder::new().build().await;
        let user_id = create_test_user(&server.database).await;
        let token = create_test_jwt_with_expiry(&server.jwt_service, user_id, 7200);

        // Verify token can be validated
        let claims = server.jwt_service.validate_oauth_token(&token).unwrap();
        assert_eq!(claims.sub, user_id);
    }

    #[tokio::test]
    async fn test_invalid_jwt_token() {
        let server = TestServerBuilder::new().build().await;
        let invalid_token = create_invalid_jwt_token();

        // Verify token validation fails
        let result = server.jwt_service.validate_oauth_token(&invalid_token);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_expired_jwt_token() {
        let expired_token = create_expired_jwt_token();
        let jwt_service = create_test_jwt_service();

        // Verify token validation fails due to expiration
        let result = jwt_service.validate_oauth_token(&expired_token);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_full_test_workflow() {
        // Test a complete workflow using the test utilities
        let server = TestServerBuilder::new().build().await;

        // Create a test user
        let user_id = create_test_user(&server.database).await;

        // Create a JWT token
        let token = create_test_jwt(&server.jwt_service, user_id);

        // Validate the token
        let claims = server.jwt_service.validate_oauth_token(&token).unwrap();
        assert_eq!(claims.sub, user_id);

        // Create an API key for the user
        let (api_key, _) = ApiKey::new(user_id, "Test Key".to_string(), None);
        let key_id = server.database.api_keys().store(&api_key).await.unwrap();

        // Verify API key was created
        assert!(key_id > 0);

        // Verify API key can be retrieved
        let stored_key = server
            .database
            .api_keys()
            .inner()
            .find_by_id(key_id)
            .await
            .unwrap();
        assert!(stored_key.is_some());
        assert_eq!(stored_key.unwrap().name, "Test Key");
    }
}
