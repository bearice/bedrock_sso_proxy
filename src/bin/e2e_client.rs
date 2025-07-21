use base64::{Engine as _, engine::general_purpose};
use bedrock_sso_proxy::{aws_http::AwsHttpClient, config::Config};
use chrono::{Duration, Utc};
use clap::{Parser, Subcommand};
use futures_util::stream::StreamExt;
use jsonwebtoken::{EncodingKey, Header, encode};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::io::{self, Write};

#[derive(Parser)]
#[command(name = "bedrock-e2e-client")]
#[command(about = "End-to-end test client for Bedrock SSO Proxy")]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    #[arg(short, long, default_value = "config.yaml")]
    config: String,

    #[arg(short, long, default_value = "http://localhost:3000")]
    server_url: String,

    #[arg(
        short,
        long,
        help = "Connect directly to AWS Bedrock instead of through proxy"
    )]
    direct: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Interactive chat with a model
    Chat {
        #[arg(
            short,
            long,
            default_value = "apac.anthropic.claude-3-sonnet-20240229-v1:0"
        )]
        model: String,

        #[arg(short, long)]
        streaming: bool,
    },
    /// Send a single message to a model
    Message {
        #[arg(
            short,
            long,
            default_value = "apac.anthropic.claude-3-sonnet-20240229-v1:0"
        )]
        model: String,

        #[arg(short, long)]
        text: String,

        #[arg(short, long)]
        streaming: bool,
    },
    /// Test server health
    Health,
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    exp: i64,
}

#[derive(Debug, Deserialize)]
struct BedrockResponse {
    #[serde(rename = "type")]
    #[allow(dead_code)]
    response_type: Option<String>,
    completion: Option<String>,
    content: Option<Vec<ContentBlock>>,
}

#[derive(Debug, Deserialize)]
struct ContentBlock {
    #[serde(rename = "type")]
    #[allow(dead_code)]
    content_type: String,
    text: Option<String>,
}

struct E2EClient {
    client: Client,
    server_url: String,
    jwt_token: String,
    aws_client: Option<AwsHttpClient>,
    direct_mode: bool,
}

impl E2EClient {
    fn new(
        server_url: String,
        jwt_secret: &str,
        config: &Config,
        direct_mode: bool,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let jwt_token = Self::generate_jwt_token(jwt_secret)?;
        let client = Client::new();

        let aws_client = if direct_mode {
            Some(AwsHttpClient::new(config.aws.clone()))
        } else {
            None
        };

        Ok(Self {
            client,
            server_url,
            jwt_token,
            aws_client,
            direct_mode,
        })
    }

    fn generate_jwt_token(secret: &str) -> Result<String, Box<dyn std::error::Error>> {
        let claims = Claims {
            sub: "e2e-test-user".to_string(),
            exp: (Utc::now() + Duration::hours(1)).timestamp(),
        };

        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(secret.as_ref()),
        )?;

        Ok(token)
    }

    // Shared payload creation
    fn create_bedrock_payload(message: &str) -> Value {
        json!({
            "anthropic_version": "bedrock-2023-05-31",
            "max_tokens": 1000,
            "messages": [
                {
                    "role": "user",
                    "content": message
                }
            ]
        })
    }

    // Shared response parsing for standard responses
    fn parse_standard_response(
        &self,
        response_text: &str,
        connection_type: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        if let Ok(json_value) = serde_json::from_str::<Value>(response_text) {
            if let Ok(bedrock_response) =
                serde_json::from_value::<BedrockResponse>(json_value.clone())
            {
                // Handle Anthropic Claude response format
                if let Some(content) = bedrock_response.content {
                    for block in content {
                        if let Some(text) = block.text {
                            println!("\n🤖 Model Response ({}):\n{}\n", connection_type, text);
                        }
                    }
                } else if let Some(completion) = bedrock_response.completion {
                    println!(
                        "\n🤖 Model Response ({}):\n{}\n",
                        connection_type, completion
                    );
                } else {
                    println!(
                        "\n📋 Raw Response ({}):\n{}\n",
                        connection_type,
                        serde_json::to_string_pretty(&json_value)?
                    );
                }
            } else {
                println!(
                    "\n📋 Raw Response ({}):\n{}\n",
                    connection_type,
                    serde_json::to_string_pretty(&json_value)?
                );
            }
        } else {
            println!(
                "\n📋 Raw Response ({}):\n{}\n",
                connection_type, response_text
            );
        }
        Ok(())
    }

    // Shared streaming chunk parsing
    fn parse_streaming_chunk(&self, chunk_str: &str) -> Option<String> {
        if let Some(start) = chunk_str.find("{\"bytes\":\"") {
            if let Some(end) = chunk_str[start..].find("\"}") {
                let json_str = &chunk_str[start..start + end + 2];

                if let Ok(event_data) = serde_json::from_str::<Value>(json_str) {
                    if let Some(base64_bytes) = event_data.get("bytes").and_then(|b| b.as_str()) {
                        if let Ok(decoded_bytes) = general_purpose::STANDARD.decode(base64_bytes) {
                            if let Ok(decoded_str) = String::from_utf8(decoded_bytes) {
                                if let Ok(decoded_json) =
                                    serde_json::from_str::<Value>(&decoded_str)
                                {
                                    // Check for content_block_delta with text
                                    if decoded_json.get("type").and_then(|t| t.as_str())
                                        == Some("content_block_delta")
                                    {
                                        if let Some(delta) = decoded_json.get("delta") {
                                            if let Some(text) =
                                                delta.get("text").and_then(|t| t.as_str())
                                            {
                                                return Some(text.to_string());
                                            }
                                        }
                                    }
                                    // Check for message_stop to end stream
                                    else if decoded_json.get("type").and_then(|t| t.as_str())
                                        == Some("message_stop")
                                    {
                                        return Some("__STREAM_END__".to_string());
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        None
    }

    async fn health_check(&self) -> Result<(), Box<dyn std::error::Error>> {
        if self.direct_mode {
            if let Some(aws_client) = &self.aws_client {
                match aws_client.health_check().await {
                    Ok(_) => println!("✅ Direct AWS connection: healthy"),
                    Err(e) => println!("❌ Direct AWS connection: {}", e),
                }
            }
        } else {
            let url = format!("{}/health", self.server_url);
            let response = self.client.get(&url).send().await?;
            println!("Health check status: {}", response.status());
            let body = response.text().await?;
            println!("Response: {}", body);
        }
        Ok(())
    }

    async fn send_message(
        &self,
        model: &str,
        message: &str,
        streaming: bool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        if streaming {
            self.send_streaming_message(model, message).await
        } else {
            self.send_standard_message(model, message).await
        }
    }

    async fn send_standard_message(
        &self,
        model: &str,
        message: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        if self.direct_mode {
            self.send_direct_standard(model, message).await
        } else {
            self.send_proxy_standard(model, message).await
        }
    }

    async fn send_proxy_standard(
        &self,
        model: &str,
        message: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let url = format!("{}/model/{}/invoke", self.server_url, model);
        let payload = Self::create_bedrock_payload(message);

        let response = self
            .client
            .post(&url)
            .header("Authorization", format!("Bearer {}", self.jwt_token))
            .header("Content-Type", "application/json")
            .json(&payload)
            .send()
            .await?;

        println!("Response status: {}", response.status());

        if response.status().is_success() {
            let response_text = response.text().await?;
            self.parse_standard_response(&response_text, "Via Proxy")?;
        } else {
            let error_text = response.text().await?;
            println!("❌ Proxy Error: {}", error_text);
        }

        Ok(())
    }

    async fn send_direct_standard(
        &self,
        model: &str,
        message: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let aws_client = self
            .aws_client
            .as_ref()
            .ok_or("Direct mode requires AWS client to be initialized")?;

        let payload = Self::create_bedrock_payload(message);
        let payload_bytes = serde_json::to_vec(&payload)?;

        println!("🔗 Connecting directly to AWS Bedrock...");
        let response = aws_client
            .invoke_model(
                model,
                Some("application/json"),
                Some("application/json"),
                payload_bytes,
            )
            .await?;

        println!("Response status: {}", response.status);

        if response.status.is_success() {
            let response_text = String::from_utf8_lossy(&response.body);
            self.parse_standard_response(&response_text, "Direct AWS")?;
        } else {
            let error_text = String::from_utf8_lossy(&response.body);
            println!("❌ Direct AWS Error: {}", error_text);
        }

        Ok(())
    }

    async fn send_streaming_message(
        &self,
        model: &str,
        message: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        if self.direct_mode {
            self.send_direct_streaming(model, message).await
        } else {
            self.send_proxy_streaming(model, message).await
        }
    }

    async fn send_proxy_streaming(
        &self,
        model: &str,
        message: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let url = format!(
            "{}/model/{}/invoke-with-response-stream",
            self.server_url, model
        );
        let payload = Self::create_bedrock_payload(message);

        let response = self
            .client
            .post(&url)
            .header("Authorization", format!("Bearer {}", self.jwt_token))
            .header("Content-Type", "application/json")
            .json(&payload)
            .send()
            .await?;

        println!("Streaming response status: {}", response.status());

        if response.status().is_success() {
            println!("\n🤖 Model Response (Via Proxy streaming):");
            self.handle_proxy_streaming_response(response.bytes_stream())
                .await?;
        } else {
            let error_text = response.text().await?;
            println!("❌ Proxy Streaming Error: {}", error_text);
        }

        Ok(())
    }

    async fn send_direct_streaming(
        &self,
        model: &str,
        message: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let aws_client = self
            .aws_client
            .as_ref()
            .ok_or("Direct mode requires AWS client to be initialized")?;

        let payload = Self::create_bedrock_payload(message);
        let payload_bytes = serde_json::to_vec(&payload)?;
        let headers = axum::http::HeaderMap::new();

        println!("🔗 Connecting directly to AWS Bedrock (streaming)...");
        let response = aws_client
            .invoke_model_with_response_stream(
                model,
                &headers,
                Some("application/json"),
                Some("application/vnd.amazon.eventstream"),
                payload_bytes,
            )
            .await?;

        println!("Streaming response status: {}", response.status);

        if response.status.is_success() {
            println!("\n🤖 Model Response (Direct AWS streaming):");
            self.handle_direct_streaming_response(response.stream)
                .await?;
        } else {
            println!("❌ Direct AWS Streaming Error: Status {}", response.status);
        }

        Ok(())
    }

    // Proxy streaming response handler
    async fn handle_proxy_streaming_response(
        &self,
        mut stream: impl futures_util::Stream<Item = Result<bytes::Bytes, reqwest::Error>> + Unpin,
    ) -> Result<(), Box<dyn std::error::Error>> {
        while let Some(chunk_result) = stream.next().await {
            let chunk = chunk_result?;
            let chunk_str = String::from_utf8_lossy(&chunk);

            if let Some(result) = self.parse_streaming_chunk(&chunk_str) {
                if result == "__STREAM_END__" {
                    println!("\n✅ Stream completed");
                    break;
                } else {
                    print!("{}", result);
                    io::stdout().flush().unwrap();
                }
            }
        }
        println!();
        Ok(())
    }

    // Direct AWS streaming response handler
    async fn handle_direct_streaming_response(
        &self,
        mut stream: Box<
            dyn futures_util::Stream<Item = Result<bytes::Bytes, reqwest::Error>> + Send + Unpin,
        >,
    ) -> Result<(), Box<dyn std::error::Error>> {
        while let Some(chunk_result) = stream.next().await {
            let chunk = chunk_result?;
            let chunk_str = String::from_utf8_lossy(&chunk);

            if let Some(result) = self.parse_streaming_chunk(&chunk_str) {
                if result == "__STREAM_END__" {
                    println!("\n✅ Stream completed");
                    break;
                } else {
                    print!("{}", result);
                    io::stdout().flush().unwrap();
                }
            }
        }
        println!();
        Ok(())
    }

    async fn interactive_chat(
        &self,
        model: &str,
        streaming: bool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        println!("🚀 Starting interactive chat with model: {}", model);
        println!(
            "💡 Connection mode: {}",
            if self.direct_mode {
                "Direct AWS"
            } else {
                "Via Proxy"
            }
        );
        println!("💡 Type 'quit', 'exit', or press Ctrl-D to end the chat");
        println!(
            "💡 Streaming mode: {}",
            if streaming { "enabled" } else { "disabled" }
        );
        println!("{}", "=".repeat(60));

        loop {
            print!("\n👤 You: ");
            io::stdout().flush()?;

            let mut input = String::new();
            let bytes_read = io::stdin().read_line(&mut input)?;

            // Check for EOF (Ctrl-D)
            if bytes_read == 0 {
                println!("\n👋 Goodbye!");
                break;
            }

            let input = input.trim();

            if input.is_empty() {
                continue;
            }

            if input.eq_ignore_ascii_case("quit") || input.eq_ignore_ascii_case("exit") {
                println!("👋 Goodbye!");
                break;
            }

            if let Err(e) = self.send_message(model, input, streaming).await {
                println!("❌ Error sending message: {}", e);
            }
        }

        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    // Load configuration
    let config = Config::load_from_file(&cli.config)
        .map_err(|e| format!("Failed to load config from {}: {}", cli.config, e))?;

    // Create E2E client
    let client = E2EClient::new(cli.server_url, &config.jwt.secret, &config, cli.direct)?;

    match cli.command {
        Commands::Health => {
            client.health_check().await?;
        }
        Commands::Message {
            model,
            text,
            streaming,
        } => {
            client.send_message(&model, &text, streaming).await?;
        }
        Commands::Chat { model, streaming } => {
            client.interactive_chat(&model, streaming).await?;
        }
    }

    Ok(())
}
