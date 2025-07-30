use aws_config::{BehaviorVersion, Region, SdkConfig};
use aws_credential_types::Credentials;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AwsConfig {
    pub region: String,
    pub access_key_id: Option<String>,
    pub secret_access_key: Option<String>,
    pub profile: Option<String>,
    pub bearer_token: Option<String>,
    /// Custom prefix-to-region mappings for model ID routing
    /// Example: {"custom": "us-west-2", "eu": "eu-central-1"}
    #[serde(default)]
    pub region_prefix_mappings: HashMap<String, String>,
}

impl AwsConfig {
    /// Build AWS SDK config using credential chain if explicit credentials not provided
    pub async fn build_sdk_config(
        &self,
    ) -> Result<SdkConfig, Box<dyn std::error::Error + Send + Sync>> {
        let mut config_builder = aws_config::defaults(BehaviorVersion::latest())
            .region(Region::new(self.region.clone()));

        // If explicit credentials are provided, use them
        if let (Some(access_key), Some(secret_key)) = (&self.access_key_id, &self.secret_access_key)
        {
            let credentials = Credentials::new(
                access_key,
                secret_key,
                None,
                None,
                "bedrock-sso-proxy-explicit",
            );
            config_builder = config_builder.credentials_provider(credentials);
        }
        // If profile is specified, set it
        else if let Some(profile) = &self.profile {
            config_builder = config_builder.profile_name(profile);
        }
        // Otherwise, use default credential chain (env vars, ~/.aws/credentials, IAM roles, etc.)

        Ok(config_builder.load().await)
    }

    /// Get explicit credentials if available, otherwise None (will use credential chain)
    pub fn get_explicit_credentials(&self) -> Option<Credentials> {
        if let (Some(access_key), Some(secret_key)) = (&self.access_key_id, &self.secret_access_key)
        {
            Some(Credentials::new(
                access_key,
                secret_key,
                None,
                None,
                "bedrock-sso-proxy-explicit",
            ))
        } else {
            None
        }
    }

    /// Get effective region prefix mappings (defaults + custom overrides)
    pub fn get_region_prefix_mappings(&self) -> HashMap<String, String> {
        let mut mappings = HashMap::new();

        // Start with built-in default mappings
        mappings.insert("us".to_string(), "us-east-1".to_string());
        mappings.insert("apac".to_string(), "ap-northeast-1".to_string());
        mappings.insert("eu".to_string(), "eu-west-1".to_string());

        // Override with custom mappings from configuration
        for (prefix, region) in &self.region_prefix_mappings {
            mappings.insert(prefix.clone(), region.clone());
        }

        mappings
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_build_sdk_config_with_explicit_credentials() {
        let config = AwsConfig {
            region: "us-east-1".to_string(),
            access_key_id: Some("test_key".to_string()),
            secret_access_key: Some("test_secret".to_string()),
            profile: None,
            bearer_token: None,
            region_prefix_mappings: HashMap::new(),
        };

        let sdk_config = config.build_sdk_config().await;
        assert!(sdk_config.is_ok());

        let config = sdk_config.unwrap();
        assert_eq!(config.region().unwrap().as_ref(), "us-east-1");
    }

    #[tokio::test]
    async fn test_build_sdk_config_with_profile() {
        let config = AwsConfig {
            region: "eu-west-1".to_string(),
            access_key_id: None,
            secret_access_key: None,
            profile: Some("test-profile".to_string()),
            bearer_token: None,
            region_prefix_mappings: HashMap::new(),
        };

        let sdk_config = config.build_sdk_config().await;
        assert!(sdk_config.is_ok());

        let config = sdk_config.unwrap();
        assert_eq!(config.region().unwrap().as_ref(), "eu-west-1");
    }

    #[tokio::test]
    async fn test_build_sdk_config_credential_chain() {
        let config = AwsConfig {
            region: "ap-southeast-1".to_string(),
            access_key_id: None,
            secret_access_key: None,
            profile: None,
            bearer_token: None,
            region_prefix_mappings: HashMap::new(),
        };

        let sdk_config = config.build_sdk_config().await;
        assert!(sdk_config.is_ok());

        let config = sdk_config.unwrap();
        assert_eq!(config.region().unwrap().as_ref(), "ap-southeast-1");
    }

    #[test]
    fn test_get_explicit_credentials_available() {
        let config = AwsConfig {
            region: "us-east-1".to_string(),
            access_key_id: Some("access_key".to_string()),
            secret_access_key: Some("secret_key".to_string()),
            profile: None,
            bearer_token: None,
            region_prefix_mappings: HashMap::new(),
        };

        let creds = config.get_explicit_credentials();
        assert!(creds.is_some());

        let credentials = creds.unwrap();
        assert_eq!(credentials.access_key_id(), "access_key");
        assert_eq!(credentials.secret_access_key(), "secret_key");
    }

    #[test]
    fn test_get_explicit_credentials_partial() {
        let config = AwsConfig {
            region: "us-east-1".to_string(),
            access_key_id: Some("access_key".to_string()),
            secret_access_key: None,
            profile: None,
            bearer_token: None,
            region_prefix_mappings: HashMap::new(),
        };

        let creds = config.get_explicit_credentials();
        assert!(creds.is_none());
    }

    #[test]
    fn test_get_explicit_credentials_none() {
        let config = AwsConfig {
            region: "us-east-1".to_string(),
            access_key_id: None,
            secret_access_key: None,
            profile: Some("default".to_string()),
            bearer_token: None,
            region_prefix_mappings: HashMap::new(),
        };

        let creds = config.get_explicit_credentials();
        assert!(creds.is_none());
    }

    #[test]
    fn test_get_region_prefix_mappings_defaults() {
        let config = AwsConfig {
            region: "us-east-1".to_string(),
            access_key_id: None,
            secret_access_key: None,
            profile: None,
            bearer_token: None,
            region_prefix_mappings: HashMap::new(),
        };

        let mappings = config.get_region_prefix_mappings();
        assert_eq!(mappings.get("us"), Some(&"us-east-1".to_string()));
        assert_eq!(mappings.get("eu"), Some(&"eu-west-1".to_string()));
        assert_eq!(mappings.get("apac"), Some(&"ap-northeast-1".to_string()));
    }

    #[test]
    fn test_get_region_prefix_mappings_with_custom_overrides() {
        let mut custom_mappings = HashMap::new();
        custom_mappings.insert("eu".to_string(), "eu-central-1".to_string());
        custom_mappings.insert("custom".to_string(), "us-west-2".to_string());

        let config = AwsConfig {
            region: "us-east-1".to_string(),
            access_key_id: None,
            secret_access_key: None,
            profile: None,
            bearer_token: None,
            region_prefix_mappings: custom_mappings,
        };

        let mappings = config.get_region_prefix_mappings();
        assert_eq!(mappings.get("us"), Some(&"us-east-1".to_string())); // Default
        assert_eq!(mappings.get("eu"), Some(&"eu-central-1".to_string())); // Override
        assert_eq!(mappings.get("apac"), Some(&"ap-northeast-1".to_string())); // Default
        assert_eq!(mappings.get("custom"), Some(&"us-west-2".to_string())); // Custom
    }
}
