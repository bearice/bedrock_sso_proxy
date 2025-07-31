use crate::{
    config::Config,
    health::{HealthCheckResult, HealthChecker},
};
use std::sync::Arc;

/// Health checker implementation for OAuth service
pub struct OAuthHealthChecker {
    config: Arc<Config>,
}

impl OAuthHealthChecker {
    pub fn new(config: Arc<Config>) -> Self {
        Self { config }
    }
}

#[async_trait::async_trait]
impl HealthChecker for OAuthHealthChecker {
    fn name(&self) -> &str {
        "oauth"
    }

    async fn check(&self) -> HealthCheckResult {
        let provider_names = self.config.list_oauth_providers();
        let provider_count = provider_names.len();

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

            for provider_name in &provider_names {
                if let Some(provider) = self.config.get_oauth_provider(provider_name) {
                    if provider.client_id.is_empty() || provider.client_secret.is_empty() {
                        misconfigured_providers.push(provider_name);
                    } else {
                        configured_providers.push(provider_name);
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
        let provider_names = self.config.list_oauth_providers();
        let providers: Vec<serde_json::Value> = provider_names
            .iter()
            .filter_map(|name| {
                self.config.get_oauth_provider(name).map(|provider| {
                    serde_json::json!({
                        "name": name,
                        "display_name": super::providers::get_display_name(name),
                        "scopes": provider.scopes
                    })
                })
            })
            .collect();

        Some(serde_json::json!({
            "service": "OAuth Authentication",
            "providers": providers
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        auth::config::{OAuthConfig, OAuthProvider},
        config::Config,
    };
    use std::collections::HashMap;

    fn create_test_config_with_providers() -> Config {
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
            ..Default::default()
        }
    }

    fn create_test_config_empty() -> Config {
        Config {
            oauth: OAuthConfig {
                providers: HashMap::new(),
            },
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn test_health_check_with_providers() {
        let config = Arc::new(create_test_config_with_providers());
        let health_checker = OAuthHealthChecker::new(config);

        let result = health_checker.check().await;
        assert!(matches!(
            result.status,
            crate::health::HealthStatus::Healthy
        ));

        let details = result.details.unwrap();
        assert_eq!(details["provider_count"], 1);
        assert_eq!(details["configured_providers"][0], "google");
    }

    #[tokio::test]
    async fn test_health_check_no_providers() {
        let config = Arc::new(create_test_config_empty());
        let health_checker = OAuthHealthChecker::new(config);

        let result = health_checker.check().await;
        assert!(matches!(
            result.status,
            crate::health::HealthStatus::Degraded
        ));

        let details = result.details.unwrap();
        assert_eq!(details["provider_count"], 0);
    }

    #[tokio::test]
    async fn test_health_check_misconfigured_provider() {
        let mut config = create_test_config_with_providers();
        // Make provider misconfigured by removing client_secret
        if let Some(provider) = config.oauth.providers.get_mut("google") {
            provider.client_secret = "".to_string();
        }

        let config = Arc::new(config);
        let health_checker = OAuthHealthChecker::new(config);

        let result = health_checker.check().await;
        assert!(matches!(
            result.status,
            crate::health::HealthStatus::Degraded
        ));

        let details = result.details.unwrap();
        assert_eq!(details["provider_count"], 1);
        assert_eq!(details["misconfigured_providers"][0], "google");
    }

    #[test]
    fn test_info() {
        let config = Arc::new(create_test_config_with_providers());
        let health_checker = OAuthHealthChecker::new(config);

        let info = health_checker.info().unwrap();
        assert_eq!(info["service"], "OAuth Authentication");
        assert_eq!(info["providers"][0]["name"], "google");
        assert_eq!(info["providers"][0]["display_name"], "Google");
    }
}
