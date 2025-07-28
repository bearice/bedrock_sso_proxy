use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtConfig {
    pub secret: String,
    #[serde(default = "default_jwt_algorithm")]
    pub algorithm: String,
    #[serde(default = "default_access_token_ttl")]
    pub access_token_ttl: u64,
    #[serde(default = "default_refresh_token_ttl")]
    pub refresh_token_ttl: u64,
}

fn default_jwt_algorithm() -> String {
    "HS256".to_string()
}

fn default_access_token_ttl() -> u64 {
    3600 // 1 hour
}

fn default_refresh_token_ttl() -> u64 {
    7776000 // 90 days
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct OAuthConfig {
    #[serde(default)]
    pub providers: HashMap<String, OAuthProvider>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthProvider {
    pub client_id: String,
    pub client_secret: String,
    #[serde(default)]
    pub redirect_uri: Option<String>,
    #[serde(default)]
    pub scopes: Vec<String>,
    #[serde(default)]
    pub authorization_url: Option<String>,
    #[serde(default)]
    pub token_url: Option<String>,
    #[serde(default)]
    pub user_info_url: Option<String>,
    #[serde(default = "default_user_id_field")]
    pub user_id_field: String,
    #[serde(default = "default_email_field")]
    pub email_field: String,
    // For providers like Microsoft with tenant support
    #[serde(default)]
    pub tenant_id: Option<String>,
    // For providers like GitLab with instance support
    #[serde(default)]
    pub instance_url: Option<String>,
    // For providers like Auth0 with domain support
    #[serde(default)]
    pub domain: Option<String>,
}

fn default_user_id_field() -> String {
    "id".to_string()
}

fn default_email_field() -> String {
    "email".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AdminConfig {
    /// List of admin email addresses
    /// Users with these emails will have admin privileges
    #[serde(default)]
    pub emails: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKeyConfig {
    #[serde(default = "default_api_key_enabled")]
    pub enabled: bool,
    #[serde(default = "default_api_key_default_expiry_days")]
    pub default_expiry_days: Option<u32>,
    #[serde(default = "default_api_key_max_keys_per_user")]
    pub max_keys_per_user: u32,
}

fn default_api_key_enabled() -> bool {
    true
}

fn default_api_key_default_expiry_days() -> Option<u32> {
    None // No expiry by default
}

fn default_api_key_max_keys_per_user() -> u32 {
    10
}

impl Default for ApiKeyConfig {
    fn default() -> Self {
        Self {
            enabled: default_api_key_enabled(),
            default_expiry_days: default_api_key_default_expiry_days(),
            max_keys_per_user: default_api_key_max_keys_per_user(),
        }
    }
}

/// Apply predefined OAuth provider defaults based on provider name
pub fn apply_predefined_provider_defaults(provider_name: &str, provider: &mut OAuthProvider) {
    match provider_name {
        "google" => apply_google_defaults(provider),
        "github" => apply_github_defaults(provider),
        "microsoft" => apply_microsoft_defaults(provider),
        "gitlab" => apply_gitlab_defaults(provider),
        "auth0" => apply_auth0_defaults(provider),
        "okta" => apply_okta_defaults(provider),
        _ => {} // Custom provider, no defaults to apply
    }
}

fn apply_google_defaults(provider: &mut OAuthProvider) {
    if provider.authorization_url.is_none() {
        provider.authorization_url =
            Some("https://accounts.google.com/o/oauth2/v2/auth".to_string());
    }
    if provider.token_url.is_none() {
        provider.token_url = Some("https://oauth2.googleapis.com/token".to_string());
    }
    if provider.user_info_url.is_none() {
        provider.user_info_url = Some("https://www.googleapis.com/oauth2/v2/userinfo".to_string());
    }
    if provider.scopes.is_empty() {
        provider.scopes = vec![
            "openid".to_string(),
            "email".to_string(),
            "profile".to_string(),
        ];
    }
    if provider.user_id_field == "id" {
        // default wasn't overridden
        provider.user_id_field = "id".to_string();
    }
    if provider.email_field == "email" {
        // default wasn't overridden
        provider.email_field = "email".to_string();
    }
}

fn apply_github_defaults(provider: &mut OAuthProvider) {
    if provider.authorization_url.is_none() {
        provider.authorization_url = Some("https://github.com/login/oauth/authorize".to_string());
    }
    if provider.token_url.is_none() {
        provider.token_url = Some("https://github.com/login/oauth/access_token".to_string());
    }
    if provider.user_info_url.is_none() {
        provider.user_info_url = Some("https://api.github.com/user".to_string());
    }
    if provider.scopes.is_empty() {
        provider.scopes = vec!["user:email".to_string()];
    }
}

fn apply_microsoft_defaults(provider: &mut OAuthProvider) {
    let tenant = provider.tenant_id.as_deref().unwrap_or("common");
    if provider.authorization_url.is_none() {
        provider.authorization_url = Some(format!(
            "https://login.microsoftonline.com/{}/oauth2/v2.0/authorize",
            tenant
        ));
    }
    if provider.token_url.is_none() {
        provider.token_url = Some(format!(
            "https://login.microsoftonline.com/{}/oauth2/v2.0/token",
            tenant
        ));
    }
    if provider.user_info_url.is_none() {
        provider.user_info_url = Some("https://graph.microsoft.com/v1.0/me".to_string());
    }
    if provider.scopes.is_empty() {
        provider.scopes = vec![
            "openid".to_string(),
            "profile".to_string(),
            "email".to_string(),
        ];
    }
    if provider.email_field == "email" {
        // default wasn't overridden
        provider.email_field = "mail".to_string();
    }
}

fn apply_gitlab_defaults(provider: &mut OAuthProvider) {
    let instance = provider
        .instance_url
        .as_deref()
        .unwrap_or("https://gitlab.com");
    if provider.authorization_url.is_none() {
        provider.authorization_url = Some(format!("{}/oauth/authorize", instance));
    }
    if provider.token_url.is_none() {
        provider.token_url = Some(format!("{}/oauth/token", instance));
    }
    if provider.user_info_url.is_none() {
        provider.user_info_url = Some(format!("{}/api/v4/user", instance));
    }
    if provider.scopes.is_empty() {
        provider.scopes = vec!["read_user".to_string()];
    }
}

fn apply_auth0_defaults(provider: &mut OAuthProvider) {
    if let Some(domain) = &provider.domain {
        if provider.authorization_url.is_none() {
            provider.authorization_url = Some(format!("https://{}/authorize", domain));
        }
        if provider.token_url.is_none() {
            provider.token_url = Some(format!("https://{}/oauth/token", domain));
        }
        if provider.user_info_url.is_none() {
            provider.user_info_url = Some(format!("https://{}/userinfo", domain));
        }
    }
    if provider.scopes.is_empty() {
        provider.scopes = vec![
            "openid".to_string(),
            "profile".to_string(),
            "email".to_string(),
        ];
    }
    if provider.user_id_field == "id" {
        // default wasn't overridden
        provider.user_id_field = "sub".to_string();
    }
}

fn apply_okta_defaults(provider: &mut OAuthProvider) {
    if let Some(domain) = &provider.domain {
        if provider.authorization_url.is_none() {
            provider.authorization_url =
                Some(format!("https://{}/oauth2/default/v1/authorize", domain));
        }
        if provider.token_url.is_none() {
            provider.token_url = Some(format!("https://{}/oauth2/default/v1/token", domain));
        }
        if provider.user_info_url.is_none() {
            provider.user_info_url = Some(format!("https://{}/oauth2/default/v1/userinfo", domain));
        }
    }
    if provider.scopes.is_empty() {
        provider.scopes = vec![
            "openid".to_string(),
            "profile".to_string(),
            "email".to_string(),
        ];
    }
    if provider.user_id_field == "id" {
        // default wasn't overridden
        provider.user_id_field = "sub".to_string();
    }
}