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
}
