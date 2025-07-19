use aws_config::BehaviorVersion;
use aws_sdk_bedrockruntime::Client as BedrockClient;
use std::sync::Arc;

#[derive(Clone)]
pub struct AwsClients {
    pub bedrock: Arc<BedrockClient>,
}

impl AwsClients {
    pub async fn new(region: &str) -> Self {
        let config = aws_config::defaults(BehaviorVersion::latest())
            .region(aws_config::Region::new(region.to_string()))
            .load()
            .await;

        let bedrock_client = BedrockClient::new(&config);

        Self {
            bedrock: Arc::new(bedrock_client),
        }
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

        let clients = AwsClients::new("us-west-2").await;
        assert!((clients.bedrock.as_ref() as *const _ as usize != 0));

        unsafe {
            std::env::remove_var("AWS_ACCESS_KEY_ID");
            std::env::remove_var("AWS_SECRET_ACCESS_KEY");
        }
    }
}
