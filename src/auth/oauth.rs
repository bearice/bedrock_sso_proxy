use crate::{
    auth::{OAuthClaims, jwt::JwtService},
    cache::{CacheManager, StateData},
    config::{Config, OAuthProvider},
    database::{DatabaseManager, entities::UserRecord},
    error::AppError,
    health::{HealthCheckResult, HealthChecker},
};
use chrono::{Duration as ChronoDuration, Utc};
use oauth2::{
    AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, EndpointNotSet, EndpointSet,
    RedirectUrl, Scope, TokenResponse as OAuth2TokenResponse, TokenUrl, basic::BasicClient,
};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{collections::HashMap, sync::Arc};
use uuid::Uuid;

/// Default OAuth state token TTL (10 minutes)
const OAUTH_STATE_TTL_SECONDS: i64 = 600;

// Avoid oauth2 type madness
pub type Oauth2Client =
    BasicClient<EndpointSet, EndpointNotSet, EndpointNotSet, EndpointNotSet, EndpointSet>;

#[derive(Debug, Serialize)]
pub struct AuthorizeResponse {
    pub authorization_url: String,
    pub state: String,
    pub provider: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct TokenRequest {
    pub provider: String,
    pub authorization_code: String,
    pub redirect_uri: String,
    pub state: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct RefreshRequest {
    pub refresh_token: String,
}

#[derive(Debug, Serialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: u64,
    pub refresh_token: String,
    pub scope: String,
}

#[derive(Debug, Serialize)]
pub struct ProviderInfo {
    pub name: String,
    pub display_name: String,
    pub scopes: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct ProvidersResponse {
    pub providers: Vec<ProviderInfo>,
}

pub struct OAuthService {
    config: Config,
    jwt_service: JwtService,
    http_client: Client,
    database: Arc<DatabaseManager>,
    cache: Arc<CacheManager>,
    oauth_clients: HashMap<String, Arc<Oauth2Client>>,
}

impl OAuthService {
    pub fn new(
        config: Config,
        jwt_service: JwtService,
        database: Arc<DatabaseManager>,
        cache: Arc<CacheManager>,
    ) -> Result<Self, AppError> {
        let oauth_clients = Self::initialize_oauth_clients(&config)?;

        Ok(Self {
            config,
            jwt_service,
            http_client: Client::new(),
            database,
            cache,
            oauth_clients,
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
        let provider = self
            .config
            .get_oauth_provider(provider_name)
            .ok_or_else(|| {
                AppError::BadRequest(format!("Unknown OAuth provider: {}", provider_name))
            })?;

        // Use the configured redirect URI if available, otherwise use the provided one
        let actual_redirect_uri = provider.redirect_uri.as_deref().unwrap_or(redirect_uri);

        let client = self.get_oauth_client(provider_name)?;

        // Create CSRF state token - store the actual redirect URI being used
        let state = self
            .create_state_internal(provider_name.to_string(), actual_redirect_uri.to_string())
            .await?;

        let (authorization_url, _csrf_token) = client
            .authorize_url(|| CsrfToken::new(state.clone()))
            .add_scopes(provider.scopes.iter().map(|s| Scope::new(s.clone())))
            .url();

        Ok(AuthorizeResponse {
            authorization_url: authorization_url.to_string(),
            state,
            provider: provider_name.to_string(),
        })
    }

    pub async fn exchange_code_for_token(
        &self,
        request: TokenRequest,
    ) -> Result<TokenResponse, AppError> {
        // Perform the authentication flow and log the result
        match self.exchange_code_for_token_internal(request.clone()).await {
            Ok(response) => Ok(response),
            Err(e) => {
                // Log authentication failure if database is available
                {
                    let audit_entry = crate::database::entities::audit_logs::Model {
                        id: 0, // Will be set by database
                        user_id: None,
                        event_type: "oauth_login_failed".to_string(),
                        provider: Some(request.provider.clone()),
                        ip_address: None, // TODO: Extract from request context
                        user_agent: None, // TODO: Extract from request context
                        success: false,
                        error_message: Some(e.to_string()),
                        created_at: Utc::now(),
                        metadata: Some({
                            let mut metadata = std::collections::HashMap::new();
                            metadata.insert(
                                "provider".to_string(),
                                serde_json::Value::String(request.provider.clone()),
                            );
                            metadata.insert(
                                "redirect_uri".to_string(),
                                serde_json::Value::String(request.redirect_uri.clone()),
                            );
                            serde_json::to_string(&metadata).unwrap_or_default()
                        }),
                    };

                    // Store audit log (log errors but don't mask the original error)
                    if let Err(audit_err) = self.database.audit_logs().store(&audit_entry).await {
                        tracing::warn!(
                            "Failed to store OAuth authorization failure audit log: {}",
                            audit_err
                        );
                    }
                }
                Err(e)
            }
        }
    }

    async fn exchange_code_for_token_internal(
        &self,
        request: TokenRequest,
    ) -> Result<TokenResponse, AppError> {
        // Validate state token
        let state_data = self
            .get_and_remove_state_internal(&request.state)
            .await?
            .ok_or_else(|| AppError::BadRequest("Invalid or expired state token".to_string()))?;

        if state_data.provider != request.provider {
            return Err(AppError::BadRequest(
                "State token provider mismatch".to_string(),
            ));
        }

        if state_data.redirect_uri != request.redirect_uri {
            return Err(AppError::BadRequest("Redirect URI mismatch".to_string()));
        }

        let provider = self
            .config
            .get_oauth_provider(&request.provider)
            .ok_or_else(|| {
                AppError::BadRequest(format!("Unknown OAuth provider: {}", request.provider))
            })?;

        let client = self.get_oauth_client(&request.provider)?;
        let http_client = reqwest::ClientBuilder::new()
            // Following redirects opens the client up to SSRF vulnerabilities.
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| AppError::Internal(format!("reqwest build error: {}", e)))?;

        // Exchange authorization code for access token
        let token_result = client
            .exchange_code(AuthorizationCode::new(request.authorization_code))
            .request_async(&http_client)
            .await
            .map_err(|e| AppError::BadRequest(format!("Token exchange failed: {}", e)))?;

        // Get user info from OAuth provider
        let user_info = self
            .get_user_info(&provider, token_result.access_token().secret())
            .await?;

        // Extract user ID and email based on provider configuration
        let user_id = user_info
            .get(&provider.user_id_field)
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                AppError::BadRequest("User ID not found in provider response".to_string())
            })?;

        let email = user_info
            .get(&provider.email_field)
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                AppError::BadRequest("Email not found in provider response".to_string())
            })?;

        // Get display name from user info
        let display_name = user_info
            .get("name")
            .and_then(|v| v.as_str())
            .or_else(|| user_info.get("display_name").and_then(|v| v.as_str()))
            .or_else(|| user_info.get("full_name").and_then(|v| v.as_str()))
            .map(|s| s.to_string());

        // Store user information persistently if storage is available
        let db_user_id = {
            let now = Utc::now();
            let user_record = UserRecord {
                id: 0, // Will be set by database
                provider_user_id: user_id.to_string(),
                provider: request.provider.clone(),
                email: email.to_string(),
                display_name,
                created_at: now,
                updated_at: now,
                last_login: Some(now),
            };

            let db_user_id = self
                .database
                .users()
                .upsert(&user_record)
                .await
                .map_err(|e| AppError::Internal(format!("Failed to store user: {}", e)))?;

            // Update last login time
            self.database
                .users()
                .update_last_login(db_user_id)
                .await
                .map_err(|e| AppError::Internal(format!("Failed to update last login: {}", e)))?;

            // Log successful authentication
            let audit_entry = crate::database::entities::audit_logs::Model {
                id: 0, // Will be set by database
                user_id: Some(db_user_id),
                event_type: "oauth_login".to_string(),
                provider: Some(request.provider.clone()),
                ip_address: None, // TODO: Extract from request context
                user_agent: None, // TODO: Extract from request context
                success: true,
                error_message: None,
                created_at: Utc::now(),
                metadata: Some({
                    let mut metadata = std::collections::HashMap::new();
                    metadata.insert(
                        "provider".to_string(),
                        serde_json::Value::String(request.provider.clone()),
                    );
                    metadata.insert(
                        "user_id".to_string(),
                        serde_json::Value::String(user_id.to_string()),
                    );
                    metadata.insert(
                        "email".to_string(),
                        serde_json::Value::String(email.to_string()),
                    );
                    serde_json::to_string(&metadata).unwrap_or_default()
                }),
            };

            // Store audit log (log errors but don't block authentication)
            if let Err(audit_err) = self.database.audit_logs().store(&audit_entry).await {
                tracing::warn!(
                    "Failed to store OAuth token exchange success audit log: {}",
                    audit_err
                );
            }

            db_user_id
        };

        // Create OAuth JWT token (long-lived, no refresh token needed for Claude Code)
        let oauth_claims = OAuthClaims::new(
            db_user_id, // Use database user ID as subject
            self.config.jwt.access_token_ttl,
        );

        let access_token = self.jwt_service.create_oauth_token(&oauth_claims)?;

        Ok(TokenResponse {
            access_token,
            token_type: "Bearer".to_string(),
            expires_in: self.config.jwt.access_token_ttl,
            refresh_token: String::new(), // Empty - not used for Claude Code
            scope: provider.scopes.join(" "),
        })
    }

    pub async fn refresh_token(&self, request: RefreshRequest) -> Result<TokenResponse, AppError> {
        // Perform token refresh and log the result
        match self.refresh_token_internal(request.clone()).await {
            Ok(response) => Ok(response),
            Err(e) => {
                // Log refresh token failure if database is available
                {
                    let audit_entry = crate::database::entities::audit_logs::Model {
                        id: 0, // Will be set by database
                        user_id: None,
                        event_type: "token_refresh_failed".to_string(),
                        provider: None,   // Provider unknown at this point
                        ip_address: None, // TODO: Extract from request context
                        user_agent: None, // TODO: Extract from request context
                        success: false,
                        error_message: Some(e.to_string()),
                        created_at: Utc::now(),
                        metadata: None,
                    };

                    // Store audit log (log errors but don't mask the original error)
                    if let Err(audit_err) = self.database.audit_logs().store(&audit_entry).await {
                        tracing::warn!(
                            "Failed to store OAuth token validation failure audit log: {}",
                            audit_err
                        );
                    }
                }
                Err(e)
            }
        }
    }

    async fn refresh_token_internal(
        &self,
        request: RefreshRequest,
    ) -> Result<TokenResponse, AppError> {
        // Use database storage
        let (token_data, new_refresh_token) = {
            // Hash the token for database lookup
            let token_hash = self.hash_token(&request.refresh_token);

            // Get refresh token data from database
            let token_data = self
                .database
                .refresh_tokens()
                .find_by_hash(&token_hash)
                .await
                .map_err(|e| AppError::Internal(format!("Database error: {}", e)))?
                .ok_or_else(|| {
                    AppError::Unauthorized("Invalid or expired refresh token".to_string())
                })?;

            // Check if token is expired or revoked
            if token_data.expires_at <= Utc::now() || token_data.revoked_at.is_some() {
                return Err(AppError::Unauthorized(
                    "Refresh token expired or revoked".to_string(),
                ));
            }

            // Revoke old token
            self.database
                .refresh_tokens()
                .revoke(&token_hash)
                .await
                .map_err(|e| AppError::Internal(format!("Failed to revoke token: {}", e)))?;

            // Create new refresh token
            let new_token = Uuid::new_v4().to_string();
            let new_token_hash = self.hash_token(&new_token);
            let new_token_data = crate::database::entities::refresh_tokens::Model {
                id: 0, // Will be set by database
                token_hash: new_token_hash,
                user_id: token_data.user_id.clone(),
                provider: token_data.provider.clone(),
                email: token_data.email.clone(),
                created_at: Utc::now(),
                expires_at: Utc::now()
                    + chrono::Duration::seconds(self.config.jwt.refresh_token_ttl as i64),
                rotation_count: token_data.rotation_count + 1,
                revoked_at: None,
            };

            // Store new refresh token
            self.database
                .refresh_tokens()
                .store(&new_token_data)
                .await
                .map_err(|e| AppError::Internal(format!("Failed to store new token: {}", e)))?;

            // Log successful token refresh
            let audit_entry = crate::database::entities::audit_logs::Model {
                id: 0,         // Will be set by database
                user_id: None, // Would need user lookup by composite ID
                event_type: "token_refresh".to_string(),
                provider: Some(token_data.provider.clone()),
                ip_address: None, // TODO: Extract from request context
                user_agent: None, // TODO: Extract from request context
                success: true,
                error_message: None,
                created_at: Utc::now(),
                metadata: Some({
                    let mut metadata = std::collections::HashMap::new();
                    metadata.insert(
                        "provider".to_string(),
                        serde_json::Value::String(token_data.provider.clone()),
                    );
                    metadata.insert(
                        "user_id".to_string(),
                        serde_json::Value::String(token_data.user_id.clone()),
                    );
                    metadata.insert(
                        "rotation_count".to_string(),
                        serde_json::Value::Number(serde_json::Number::from(
                            new_token_data.rotation_count,
                        )),
                    );
                    serde_json::to_string(&metadata).unwrap_or_default()
                }),
            };

            // Store audit log (log errors but don't block token refresh)
            if let Err(audit_err) = self.database.audit_logs().store(&audit_entry).await {
                tracing::warn!(
                    "Failed to store OAuth token refresh success audit log: {}",
                    audit_err
                );
            }

            (token_data, new_token)
        };

        // Get provider config for scopes
        let provider = self
            .config
            .get_oauth_provider(&token_data.provider)
            .ok_or_else(|| {
                AppError::BadRequest(format!("Unknown OAuth provider: {}", token_data.provider))
            })?;

        // Use email from token data (available from database storage)
        let _email = if token_data.email.is_empty() {
            // Fallback for cache-based tokens that don't have email
            format!("user@{}.com", token_data.provider)
        } else {
            token_data.email.clone()
        };

        // Lookup database user ID from composite user_id
        // Extract provider user ID from composite (format: "provider:user_id")
        let provider_user_id = token_data
            .user_id
            .split_once(':')
            .map(|(_, id)| id)
            .unwrap_or(&token_data.user_id);

        let db_user_id = self
            .database
            .users()
            .find_by_provider(&token_data.provider, provider_user_id)
            .await
            .map_err(|e| AppError::Internal(format!("Failed to lookup user: {}", e)))?
            .map(|user| user.id)
            .ok_or_else(|| AppError::NotFound("User not found in database".to_string()))?;

        // Create new OAuth JWT token
        let oauth_claims = OAuthClaims::new(
            db_user_id, // Use database user ID as subject
            self.config.jwt.access_token_ttl,
        );

        let access_token = self.jwt_service.create_oauth_token(&oauth_claims)?;

        Ok(TokenResponse {
            access_token,
            token_type: "Bearer".to_string(),
            expires_in: self.config.jwt.access_token_ttl,
            refresh_token: new_refresh_token,
            scope: provider.scopes.join(" "),
        })
    }

    pub fn list_providers(&self) -> ProvidersResponse {
        let providers = self
            .config
            .list_oauth_providers()
            .into_iter()
            .filter_map(|name| {
                self.config
                    .get_oauth_provider(&name)
                    .map(|provider| ProviderInfo {
                        name: name.clone(),
                        display_name: self.get_display_name(&name),
                        scopes: provider.scopes,
                    })
            })
            .collect();

        ProvidersResponse { providers }
    }

    pub async fn get_redirect_uri_for_state(&self, state: &str) -> Option<String> {
        self.get_state_data_internal(state)
            .await
            .ok()
            .flatten()
            .map(|state_data| state_data.redirect_uri)
    }

    fn get_oauth_client(&self, provider_name: &str) -> Result<Arc<Oauth2Client>, AppError> {
        self.oauth_clients
            .get(provider_name)
            .cloned()
            .ok_or_else(|| {
                AppError::BadRequest(format!("Unknown OAuth provider: {}", provider_name))
            })
    }

    fn initialize_oauth_clients(
        config: &Config,
    ) -> Result<HashMap<String, Arc<Oauth2Client>>, AppError> {
        let mut clients = HashMap::new();

        for provider_name in config.list_oauth_providers() {
            if let Some(provider) = config.get_oauth_provider(&provider_name) {
                let client = Arc::new(Self::create_oauth_client_static(&provider)?);
                clients.insert(provider_name, client);
            }
        }

        Ok(clients)
    }

    fn create_oauth_client_static(provider: &OAuthProvider) -> Result<Oauth2Client, AppError> {
        let auth_url = AuthUrl::new(
            provider
                .authorization_url
                .as_ref()
                .ok_or_else(|| {
                    AppError::BadRequest("Authorization URL not configured".to_string())
                })?
                .clone(),
        )
        .map_err(|e| AppError::BadRequest(format!("Invalid authorization URL: {}", e)))?;

        let token_url = TokenUrl::new(
            provider
                .token_url
                .as_ref()
                .ok_or_else(|| AppError::BadRequest("Token URL not configured".to_string()))?
                .clone(),
        )
        .map_err(|e| AppError::BadRequest(format!("Invalid token URL: {}", e)))?;

        let redirect_url = provider
            .redirect_uri
            .as_ref()
            .map(|uri| RedirectUrl::new(uri.clone()))
            .transpose()
            .map_err(|e| AppError::BadRequest(format!("Invalid redirect URI: {}", e)))?;

        let mut client = BasicClient::new(ClientId::new(provider.client_id.clone()))
            .set_client_secret(ClientSecret::new(provider.client_secret.clone()))
            .set_auth_uri(auth_url)
            .set_token_uri(token_url);

        if let Some(redirect_url) = redirect_url {
            client = client.set_redirect_uri(redirect_url);
        }

        Ok(client)
    }

    async fn get_user_info(
        &self,
        provider: &OAuthProvider,
        access_token: &str,
    ) -> Result<HashMap<String, Value>, AppError> {
        let user_info_url = provider
            .user_info_url
            .as_ref()
            .ok_or_else(|| AppError::BadRequest("User info URL not configured".to_string()))?;

        let response = self
            .http_client
            .get(user_info_url)
            .bearer_auth(access_token)
            .send()
            .await
            .map_err(|e| AppError::BadRequest(format!("Failed to fetch user info: {}", e)))?;

        if !response.status().is_success() {
            return Err(AppError::BadRequest(format!(
                "User info request failed with status: {}",
                response.status()
            )));
        }

        let user_info: HashMap<String, Value> = response
            .json()
            .await
            .map_err(|e| AppError::BadRequest(format!("Failed to parse user info: {}", e)))?;

        Ok(user_info)
    }

    fn get_display_name(&self, provider_name: &str) -> String {
        match provider_name {
            "google" => "Google".to_string(),
            "github" => "GitHub".to_string(),
            "microsoft" => "Microsoft".to_string(),
            "gitlab" => "GitLab".to_string(),
            "auth0" => "Auth0".to_string(),
            "okta" => "Okta".to_string(),
            _ => provider_name.to_string(),
        }
    }

    /// Hash a token for secure storage
    fn hash_token(&self, token: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(token.as_bytes());
        format!("{:x}", hasher.finalize())
    }

    /// Create a health checker for this OAuth service
    pub fn health_checker(self: &std::sync::Arc<Self>) -> OAuthHealthChecker {
        OAuthHealthChecker {
            service: self.clone(),
        }
    }
}

/// Health checker implementation for OAuth service
pub struct OAuthHealthChecker {
    service: std::sync::Arc<OAuthService>,
}

#[async_trait::async_trait]
impl HealthChecker for OAuthHealthChecker {
    fn name(&self) -> &str {
        "oauth"
    }

    async fn check(&self) -> HealthCheckResult {
        let providers = self.service.list_providers();
        let provider_count = providers.providers.len();

        if provider_count == 0 {
            HealthCheckResult::degraded_with_details(
                "No OAuth providers configured".to_string(),
                serde_json::json!({
                    "provider_count": 0,
                    "available_providers": []
                }),
            )
        } else {
            // Check if providers have required configuration
            let mut configured_providers = vec![];
            let mut misconfigured_providers = vec![];

            for provider_info in &providers.providers {
                if let Some(provider) = self.service.config.get_oauth_provider(&provider_info.name)
                {
                    if provider.client_id.is_empty() || provider.client_secret.is_empty() {
                        misconfigured_providers.push(&provider_info.name);
                    } else {
                        configured_providers.push(&provider_info.name);
                    }
                }
            }

            if misconfigured_providers.is_empty() {
                HealthCheckResult::healthy_with_details(serde_json::json!({
                    "provider_count": provider_count,
                    "configured_providers": configured_providers,
                    "cache_status": "active"
                }))
            } else {
                HealthCheckResult::degraded_with_details(
                    format!(
                        "Some OAuth providers are misconfigured: {:?}",
                        misconfigured_providers
                    ),
                    serde_json::json!({
                        "provider_count": provider_count,
                        "configured_providers": configured_providers,
                        "misconfigured_providers": misconfigured_providers,
                        "cache_status": "active"
                    }),
                )
            }
        }
    }

    fn info(&self) -> Option<serde_json::Value> {
        let providers = self.service.list_providers();
        Some(serde_json::json!({
            "service": "OAuth Authentication",
            "providers": providers.providers.iter().map(|p| serde_json::json!({
                "name": p.name,
                "display_name": p.display_name,
                "scopes": p.scopes
            })).collect::<Vec<_>>()
        }))
    }
}

impl OAuthService {
    // State management methods
    async fn create_state_internal(
        &self,
        provider: String,
        redirect_uri: String,
    ) -> Result<String, AppError> {
        let state = Uuid::new_v4().to_string();
        let now = Utc::now();
        let state_data = StateData {
            provider,
            redirect_uri,
            created_at: now,
            expires_at: now + ChronoDuration::seconds(OAUTH_STATE_TTL_SECONDS),
        };

        self.cache
            .store_state(&state, &state_data, OAUTH_STATE_TTL_SECONDS as u64)
            .await
            .map_err(|e| AppError::Internal(format!("Failed to store state: {}", e)))?;

        Ok(state)
    }

    async fn get_state_data_internal(&self, state: &str) -> Result<Option<StateData>, AppError> {
        self.cache
            .get_state(state)
            .await
            .map_err(|e| AppError::Internal(format!("Failed to get state: {}", e)))
    }

    async fn get_and_remove_state_internal(
        &self,
        state: &str,
    ) -> Result<Option<StateData>, AppError> {
        let state_data = self.get_state_data_internal(state).await?;
        if state_data.is_some() {
            self.cache
                .delete_state(state)
                .await
                .map_err(|e| AppError::Internal(format!("Failed to delete state: {}", e)))?;
        }
        Ok(state_data)
    }

    // Refresh token methods - removed unused internal methods
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::jwt::JwtService;
    use crate::config::{CacheConfig, JwtConfig, OAuthConfig, OAuthProvider};
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
            },
            ..Default::default()
        }
    }

    async fn create_test_components() -> (Arc<DatabaseManager>, Arc<CacheManager>) {
        let mut config = Config::default();
        config.storage.redis.enabled = false;
        config.storage.database.enabled = true;
        config.storage.database.url = "sqlite::memory:".to_string();

        let database = Arc::new(DatabaseManager::new_from_config(&config).await.unwrap());
        let cache = Arc::new(CacheManager::new_memory());

        (database, cache)
    }

    #[tokio::test]
    async fn test_oauth_service_creation() {
        let config = create_test_config();
        let (database, cache) = create_test_components().await;
        let jwt_service = JwtService::new("test-secret".to_string(), Algorithm::HS256).unwrap();

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
        let jwt_service = JwtService::new("test-secret".to_string(), Algorithm::HS256).unwrap();
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
        let jwt_service = JwtService::new("test-secret".to_string(), Algorithm::HS256).unwrap();
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
        let jwt_service = JwtService::new("test-secret".to_string(), Algorithm::HS256).unwrap();
        let oauth_service = OAuthService::new(config, jwt_service, database, cache).unwrap();

        let providers = oauth_service.list_providers();
        assert_eq!(providers.providers.len(), 1);

        let google_provider = &providers.providers[0];
        assert_eq!(google_provider.name, "google");
        assert_eq!(google_provider.display_name, "Google");
        assert_eq!(google_provider.scopes, vec!["openid", "email"]);
    }

    #[tokio::test]
    async fn test_display_names() {
        let config = create_test_config();
        let (database, cache) = create_test_components().await;
        let jwt_service = JwtService::new("test-secret".to_string(), Algorithm::HS256).unwrap();
        let oauth_service = OAuthService::new(config, jwt_service, database, cache).unwrap();

        assert_eq!(oauth_service.get_display_name("google"), "Google");
        assert_eq!(oauth_service.get_display_name("github"), "GitHub");
        assert_eq!(oauth_service.get_display_name("microsoft"), "Microsoft");
        assert_eq!(oauth_service.get_display_name("gitlab"), "GitLab");
        assert_eq!(oauth_service.get_display_name("auth0"), "Auth0");
        assert_eq!(oauth_service.get_display_name("okta"), "Okta");
        assert_eq!(oauth_service.get_display_name("custom"), "custom");
    }
}
