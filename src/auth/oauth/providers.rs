use crate::{auth::config::OAuthProvider, config::Config, error::AppError};
use oauth2::{
    AuthUrl, ClientId, ClientSecret, EndpointNotSet, EndpointSet, RedirectUrl, TokenUrl,
    basic::BasicClient,
};
use std::{collections::HashMap, sync::Arc};

// Avoid oauth2 type madness
pub type Oauth2Client =
    BasicClient<EndpointSet, EndpointNotSet, EndpointNotSet, EndpointNotSet, EndpointSet>;

/// Provider display name mapping
pub fn get_display_name(provider_name: &str) -> String {
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

/// Initialize OAuth clients for all configured providers
pub fn initialize_oauth_clients(
    config: &Config,
) -> Result<HashMap<String, Arc<Oauth2Client>>, AppError> {
    let mut clients = HashMap::new();

    for provider_name in config.list_oauth_providers() {
        if let Some(provider) = config.get_oauth_provider(&provider_name) {
            let client = Arc::new(create_oauth_client(&provider, &provider_name)?);
            clients.insert(provider_name, client);
        }
    }

    Ok(clients)
}

/// Create OAuth client for a single provider
pub fn create_oauth_client(
    provider: &OAuthProvider,
    provider_name: &str,
) -> Result<Oauth2Client, AppError> {
    let auth_url = AuthUrl::new(
        provider
            .authorization_url
            .as_ref()
            .ok_or_else(|| {
                AppError::BadRequest(format!(
                    "Authorization URL not configured for OAuth provider '{}'. Please check your configuration. \
                     For known providers (google, github, microsoft, gitlab), URLs should be auto-configured. \
                     For custom providers or providers requiring domain/tenant configuration (auth0, okta), \
                     you must specify the authorization_url explicitly.",
                    provider_name
                ))
            })?
            .clone(),
    )
    .map_err(|e| AppError::BadRequest(format!("Invalid authorization URL for provider '{}': {}", provider_name, e)))?;

    let token_url = TokenUrl::new(
        provider
            .token_url
            .as_ref()
            .ok_or_else(|| {
                AppError::BadRequest(format!(
                    "Token URL not configured for OAuth provider '{}'. Please check your configuration. \
                     For known providers (google, github, microsoft, gitlab), URLs should be auto-configured. \
                     For custom providers or providers requiring domain/tenant configuration (auth0, okta), \
                     you must specify the token_url explicitly.",
                    provider_name
                ))
            })?
            .clone(),
    )
    .map_err(|e| AppError::BadRequest(format!("Invalid token URL for provider '{}': {}", provider_name, e)))?;

    let redirect_url = provider
        .redirect_uri
        .as_ref()
        .map(|uri| RedirectUrl::new(uri.clone()))
        .transpose()
        .map_err(|e| {
            AppError::BadRequest(format!(
                "Invalid redirect URI for provider '{}': {}",
                provider_name, e
            ))
        })?;

    let mut client = BasicClient::new(ClientId::new(provider.client_id.clone()))
        .set_client_secret(ClientSecret::new(provider.client_secret.clone()))
        .set_auth_uri(auth_url)
        .set_token_uri(token_url);

    if let Some(redirect_url) = redirect_url {
        client = client.set_redirect_uri(redirect_url);
    }

    Ok(client)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::config::OAuthProvider;

    fn create_test_provider() -> OAuthProvider {
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
        }
    }

    #[test]
    fn test_display_names() {
        assert_eq!(get_display_name("google"), "Google");
        assert_eq!(get_display_name("github"), "GitHub");
        assert_eq!(get_display_name("microsoft"), "Microsoft");
        assert_eq!(get_display_name("gitlab"), "GitLab");
        assert_eq!(get_display_name("auth0"), "Auth0");
        assert_eq!(get_display_name("okta"), "Okta");
        assert_eq!(get_display_name("custom"), "custom");
    }

    #[test]
    fn test_create_oauth_client() {
        let provider = create_test_provider();
        let result = create_oauth_client(&provider, "google");
        assert!(result.is_ok());
    }

    #[test]
    fn test_create_oauth_client_missing_auth_url() {
        let mut provider = create_test_provider();
        provider.authorization_url = None;

        let result = create_oauth_client(&provider, "test");
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Authorization URL not configured")
        );
    }

    #[test]
    fn test_create_oauth_client_missing_token_url() {
        let mut provider = create_test_provider();
        provider.token_url = None;

        let result = create_oauth_client(&provider, "test");
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Token URL not configured")
        );
    }
}
