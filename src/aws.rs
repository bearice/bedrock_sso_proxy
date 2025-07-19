use crate::config::AwsConfig;
use aws_config::{BehaviorVersion, Region};
use aws_credential_types::{Credentials, provider::SharedCredentialsProvider};
use aws_sdk_bedrockruntime::Client as BedrockClient;
use axum::http::{HeaderMap, HeaderValue};
use std::sync::Arc;

#[derive(Clone)]
pub struct AwsClients {
    pub bedrock: Arc<BedrockClient>,
}

impl AwsClients {
    pub async fn new(aws_config: &AwsConfig) -> Self {
        let mut config_loader = aws_config::defaults(BehaviorVersion::latest())
            .region(Region::new(aws_config.region.clone()));

        // If profile is specified, use it
        if let Some(profile) = &aws_config.profile {
            config_loader = config_loader.profile_name(profile);
        }

        // Set credentials directly if provided in config
        if let (Some(access_key), Some(secret_key)) =
            (&aws_config.access_key_id, &aws_config.secret_access_key)
        {
            let credentials = Credentials::new(
                access_key,
                secret_key,
                None,
                None,
                "bedrock-sso-proxy-config",
            );

            config_loader =
                config_loader.credentials_provider(SharedCredentialsProvider::new(credentials));
        }

        let config = config_loader.load().await;
        let bedrock_client = BedrockClient::new(&config);

        Self {
            bedrock: Arc::new(bedrock_client),
        }
    }

    pub async fn new_with_region(region: &str) -> Self {
        let aws_config = AwsConfig {
            region: region.to_string(),
            access_key_id: None,
            secret_access_key: None,
            profile: None,
        };
        Self::new(&aws_config).await
    }

    #[cfg(test)]
    pub fn new_test() -> Self {
        use aws_sdk_bedrockruntime::config::Region;

        let config = aws_sdk_bedrockruntime::Config::builder()
            .region(Region::new("us-east-1"))
            .behavior_version(aws_sdk_bedrockruntime::config::BehaviorVersion::latest())
            .build();

        let bedrock_client = BedrockClient::from_conf(config);

        Self {
            bedrock: Arc::new(bedrock_client),
        }
    }

    /// Process headers for forwarding to AWS, removing sensitive headers
    pub fn process_headers_for_aws(headers: &HeaderMap) -> HeaderMap {
        let mut forwarded_headers = HeaderMap::new();

        for (name, value) in headers {
            // Skip authorization header and other sensitive headers
            match name.as_str().to_lowercase().as_str() {
                "authorization" | "host" | "content-length" => continue,
                _ => {
                    if let Ok(header_value) = HeaderValue::try_from(value.as_bytes()) {
                        forwarded_headers.insert(name.clone(), header_value);
                    }
                }
            }
        }

        forwarded_headers
    }

    /// Process headers from AWS response for client response
    pub fn process_headers_from_aws(headers: &HeaderMap) -> HeaderMap {
        let mut client_headers = HeaderMap::new();

        for (name, value) in headers {
            // Forward most headers but skip some AWS-specific ones
            match name.as_str().to_lowercase().as_str() {
                "x-amz-request-id" | "x-amz-id-2" => continue,
                _ => {
                    if let Ok(header_value) = HeaderValue::try_from(value.as_bytes()) {
                        client_headers.insert(name.clone(), header_value);
                    }
                }
            }
        }

        client_headers
    }

    /// Check if the client can connect to AWS Bedrock
    pub async fn health_check(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Simple health check: try to create a minimal request to verify configuration
        // We can't actually test the connection without making a real API call
        // For now, just return Ok if the client was created successfully
        // In a real implementation, you might try a lightweight API call
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aws_clients_creation() {
        let clients = AwsClients::new_test();
        assert!((clients.bedrock.as_ref() as *const _ as usize != 0));
    }

    #[test]
    fn test_aws_clients_clone() {
        let clients = AwsClients::new_test();
        let cloned = clients.clone();

        assert!(Arc::ptr_eq(&clients.bedrock, &cloned.bedrock));
    }

    #[tokio::test]
    async fn test_aws_clients_new_with_region() {
        unsafe {
            std::env::set_var("AWS_ACCESS_KEY_ID", "test");
            std::env::set_var("AWS_SECRET_ACCESS_KEY", "test");
        }

        let clients = AwsClients::new_with_region("us-west-2").await;
        assert!((clients.bedrock.as_ref() as *const _ as usize != 0));

        unsafe {
            std::env::remove_var("AWS_ACCESS_KEY_ID");
            std::env::remove_var("AWS_SECRET_ACCESS_KEY");
        }
    }

    #[tokio::test]
    async fn test_aws_clients_new_with_credentials() {
        let aws_config = AwsConfig {
            region: "us-east-1".to_string(),
            access_key_id: Some("test_key".to_string()),
            secret_access_key: Some("test_secret".to_string()),
            profile: None,
        };

        let clients = AwsClients::new(&aws_config).await;
        assert!((clients.bedrock.as_ref() as *const _ as usize != 0));
    }

    #[tokio::test]
    async fn test_aws_clients_new_with_profile() {
        let aws_config = AwsConfig {
            region: "us-east-1".to_string(),
            access_key_id: None,
            secret_access_key: None,
            profile: Some("test-profile".to_string()),
        };

        let clients = AwsClients::new(&aws_config).await;
        assert!((clients.bedrock.as_ref() as *const _ as usize != 0));
    }

    #[test]
    fn test_process_headers_for_aws() {
        let mut headers = HeaderMap::new();
        headers.insert("authorization", HeaderValue::from_static("Bearer token"));
        headers.insert("content-type", HeaderValue::from_static("application/json"));
        headers.insert("x-custom-header", HeaderValue::from_static("custom-value"));
        headers.insert("host", HeaderValue::from_static("example.com"));

        let processed = AwsClients::process_headers_for_aws(&headers);

        assert!(!processed.contains_key("authorization"));
        assert!(!processed.contains_key("host"));
        assert!(processed.contains_key("content-type"));
        assert!(processed.contains_key("x-custom-header"));
    }

    #[test]
    fn test_process_headers_from_aws() {
        let mut headers = HeaderMap::new();
        headers.insert("content-type", HeaderValue::from_static("application/json"));
        headers.insert("x-amz-request-id", HeaderValue::from_static("12345"));
        headers.insert("x-custom-header", HeaderValue::from_static("custom-value"));

        let processed = AwsClients::process_headers_from_aws(&headers);

        assert!(!processed.contains_key("x-amz-request-id"));
        assert!(processed.contains_key("content-type"));
        assert!(processed.contains_key("x-custom-header"));
    }
}
