use crate::{
    auth::{OAuthClaims, jwt::JwtService, oauth::state::StateData},
    cache::CacheManager,
    config::Config,
    database::{
        DatabaseManager,
        entities::{AuditEventType, AuditLogEntry, RefreshTokenData, UserRecord},
    },
    error::AppError,
    utils::request_context::RequestContext,
};
use chrono::Utc;
use oauth2::{
    AuthorizationCode, CsrfToken, RedirectUrl, Scope, TokenResponse as OAuth2TokenResponse,
};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{collections::HashMap, sync::Arc};
use utoipa::ToSchema;
use uuid::Uuid;

use super::providers::Oauth2Client;

#[derive(Debug, Serialize, ToSchema)]
pub struct AuthorizeResponse {
    pub authorization_url: String,
    pub state: String,
    pub provider: String,
}

#[derive(Debug, Deserialize, Clone, ToSchema)]
pub struct TokenRequest {
    pub provider: String,
    pub authorization_code: String,
    pub redirect_uri: String,
    pub state: String,
}

#[derive(Debug, Deserialize, Clone, ToSchema)]
pub struct RefreshRequest {
    pub refresh_token: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: u64,
    pub refresh_token: String,
    pub scope: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ProviderInfo {
    pub name: String,
    pub display_name: String,
    pub scopes: Vec<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ProvidersResponse {
    pub providers: Vec<ProviderInfo>,
}

/// OAuth flow handlers
pub struct OAuthFlows {
    config: Config,
    jwt_service: Arc<dyn JwtService>,
    http_client: Client,
    database: Arc<dyn DatabaseManager>,
    cache: Arc<CacheManager>,
    oauth_clients: HashMap<String, Arc<Oauth2Client>>,
}

impl OAuthFlows {
    pub fn new(
        config: Config,
        jwt_service: Arc<dyn JwtService>,
        database: Arc<dyn DatabaseManager>,
        cache: Arc<CacheManager>,
        oauth_clients: HashMap<String, Arc<Oauth2Client>>,
    ) -> Self {
        Self {
            config,
            jwt_service,
            http_client: Client::new(),
            database,
            cache,
            oauth_clients,
        }
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
                AppError::BadRequest(format!("Unknown OAuth provider: {provider_name}"))
            })?;

        // Use the configured redirect URI if available, otherwise use the provided one
        let actual_redirect_uri = provider.redirect_uri.as_deref().unwrap_or(redirect_uri);
        tracing::debug!("using redirect_uri {}", actual_redirect_uri);

        let client = self.get_oauth_client(provider_name)?;

        // Create CSRF state token - store the actual redirect URI being used
        let state = self
            .create_state_internal(provider_name.to_string(), actual_redirect_uri.to_string())
            .await?;

        let (authorization_url, _csrf_token) = (*client)
            .clone()
            .set_redirect_uri(RedirectUrl::from_url(
                actual_redirect_uri.try_into().unwrap(),
            ))
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
        context: RequestContext,
    ) -> Result<TokenResponse, AppError> {
        // Perform the authentication flow and log the result
        match self
            .exchange_code_for_token_internal(request.clone(), context.clone())
            .await
        {
            Ok(response) => Ok(response),
            Err(e) => {
                // Log authentication failure if database is available
                {
                    let audit_entry = AuditLogEntry {
                        id: 0, // Will be set by database
                        user_id: None,
                        event_type: AuditEventType::OAuthLoginFailed,
                        provider: Some(request.provider.clone()),
                        ip_address: context.ip_address.clone(),
                        user_agent: context.user_agent.clone(),
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
        context: RequestContext,
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
        let client = (*client).clone().set_redirect_uri(RedirectUrl::from_url(
            state_data.redirect_uri.as_str().try_into().unwrap(),
        ));
        let http_client = reqwest::ClientBuilder::new()
            // Following redirects opens the client up to SSRF vulnerabilities.
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| AppError::Internal(format!("reqwest build error: {e}")))?;

        // Exchange authorization code for access token
        let token_result = client
            .exchange_code(AuthorizationCode::new(request.authorization_code))
            .request_async(&http_client)
            .await
            .map_err(|e| AppError::BadRequest(format!("Token exchange failed: {e}")))?;

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
        let (db_user_id, is_admin) = {
            let user_record =
                UserRecord::new(&request.provider, user_id, email).with_display_name(display_name);

            let db_user_id = self
                .database
                .users()
                .upsert(&user_record)
                .await
                .map_err(|e| AppError::Internal(format!("Failed to store user: {e}")))?;

            let is_admin = self.config.is_admin(email);

            // Log successful authentication
            let audit_entry = AuditLogEntry {
                id: 0, // Will be set by database
                user_id: Some(db_user_id),
                event_type: AuditEventType::OAuthLogin,
                provider: Some(request.provider.clone()),
                ip_address: context.ip_address.clone(),
                user_agent: context.user_agent.clone(),
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

            (db_user_id, is_admin)
        };

        // Create OAuth JWT token with proper refresh token support
        let mut oauth_claims = OAuthClaims::new(
            db_user_id, // Use database user ID as subject
            self.config.jwt.access_token_ttl,
        );
        oauth_claims.set_admin(is_admin);
        let access_token = self.jwt_service.create_oauth_token(&oauth_claims)?;

        // Create refresh token for proper OAuth flow
        let refresh_token = Uuid::new_v4().to_string();
        let refresh_token_hash = self.hash_token(&refresh_token);
        let refresh_token_data = RefreshTokenData {
            id: 0, // Will be set by database
            token_hash: refresh_token_hash,
            user_id: format!("{}:{}", request.provider, user_id), // Composite user ID
            provider: request.provider.clone(),
            email: email.to_string(),
            created_at: Utc::now(),
            expires_at: Utc::now()
                + chrono::Duration::seconds(self.config.jwt.refresh_token_ttl as i64),
            rotation_count: 0,
            revoked_at: None,
        };

        // Store refresh token
        self.database
            .refresh_tokens()
            .store(&refresh_token_data)
            .await
            .map_err(|e| AppError::Internal(format!("Failed to store refresh token: {e}")))?;

        Ok(TokenResponse {
            access_token,
            token_type: "Bearer".to_string(),
            expires_in: self.config.jwt.access_token_ttl,
            refresh_token,
            scope: provider.scopes.join(" "),
        })
    }

    pub async fn refresh_token(
        &self,
        request: RefreshRequest,
        context: RequestContext,
    ) -> Result<TokenResponse, AppError> {
        // Perform token refresh and log the result
        match self
            .refresh_token_internal(request.clone(), context.clone())
            .await
        {
            Ok(response) => Ok(response),
            Err(e) => {
                // Log refresh token failure if database is available
                {
                    let audit_entry = AuditLogEntry {
                        id: 0, // Will be set by database
                        user_id: None,
                        event_type: AuditEventType::AuthFailure,
                        provider: None, // Provider unknown at this point
                        ip_address: context.ip_address.clone(),
                        user_agent: context.user_agent.clone(),
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
        context: RequestContext,
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
                .map_err(|e| AppError::Internal(format!("Database error: {e}")))?
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
                .revoke(token_data.clone())
                .await
                .map_err(|e| AppError::Internal(format!("Failed to revoke token: {e}")))?;

            // Create new refresh token
            let new_token = Uuid::new_v4().to_string();
            let new_token_hash = self.hash_token(&new_token);
            let new_token_data = RefreshTokenData {
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
                .map_err(|e| AppError::Internal(format!("Failed to store new token: {e}")))?;

            // Log successful token refresh
            let audit_entry = AuditLogEntry {
                id: 0,         // Will be set by database
                user_id: None, // Would need user lookup by composite ID
                event_type: AuditEventType::TokenRefresh,
                provider: Some(token_data.provider.clone()),
                ip_address: context.ip_address,
                user_agent: context.user_agent,
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
        let email = if token_data.email.is_empty() {
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
            .map_err(|e| AppError::Internal(format!("Failed to lookup user: {e}")))?
            .map(|user| user.id)
            .ok_or_else(|| AppError::NotFound("User not found in database".to_string()))?;

        let is_admin = self.config.is_admin(&email);

        // Create new OAuth JWT token
        let mut oauth_claims = OAuthClaims::new(
            db_user_id, // Use database user ID as subject
            self.config.jwt.access_token_ttl,
        );

        oauth_claims.set_admin(is_admin);
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
                        display_name: super::providers::get_display_name(&name),
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
            .ok_or_else(|| AppError::BadRequest(format!("Unknown OAuth provider: {provider_name}")))
    }

    async fn get_user_info(
        &self,
        provider: &crate::auth::config::OAuthProvider,
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
            .map_err(|e| AppError::BadRequest(format!("Failed to fetch user info: {e}")))?;

        if !response.status().is_success() {
            return Err(AppError::BadRequest(format!(
                "User info request failed with status: {}",
                response.status()
            )));
        }

        let user_info: HashMap<String, Value> = response
            .json()
            .await
            .map_err(|e| AppError::BadRequest(format!("Failed to parse user info: {e}")))?;

        Ok(user_info)
    }

    /// Hash a token for secure storage
    fn hash_token(&self, token: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(token.as_bytes());
        format!("{:x}", hasher.finalize())
    }

    // State management methods using typed cache
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
            expires_at: now
                + chrono::Duration::seconds(crate::auth::oauth::state::OAUTH_STATE_TTL_SECONDS),
        };

        // Use typed cache for state data
        let state_cache = self.cache.cache::<StateData>();
        state_cache
            .set(&state, &state_data)
            .await
            .map_err(|e| AppError::Internal(format!("Failed to store state: {e}")))?;

        Ok(state)
    }

    async fn get_state_data_internal(&self, state: &str) -> Result<Option<StateData>, AppError> {
        let state_cache = self.cache.cache::<StateData>();
        state_cache
            .get(state)
            .await
            .map_err(|e| AppError::Internal(format!("Failed to get state: {e}")))
    }

    async fn get_and_remove_state_internal(
        &self,
        state: &str,
    ) -> Result<Option<StateData>, AppError> {
        let state_cache = self.cache.cache::<StateData>();
        let state_data = state_cache
            .get(state)
            .await
            .map_err(|e| AppError::Internal(format!("Failed to get state: {e}")))?;

        if state_data.is_some() {
            state_cache
                .delete(state)
                .await
                .map_err(|e| AppError::Internal(format!("Failed to delete state: {e}")))?;
        }
        Ok(state_data)
    }
}
