use bedrock_sso_proxy::config::Config;
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
}

#[derive(Subcommand)]
enum Commands {
    /// Interactive chat with a model
    Chat {
        #[arg(short, long, default_value = "anthropic.claude-3-sonnet-20240229-v1:0")]
        model: String,

        #[arg(short, long)]
        streaming: bool,
    },
    /// Send a single message to a model
    Message {
        #[arg(short, long, default_value = "anthropic.claude-3-sonnet-20240229-v1:0")]
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
}

impl E2EClient {
    fn new(server_url: String, jwt_secret: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let jwt_token = Self::generate_jwt_token(jwt_secret)?;
        let client = Client::new();

        Ok(Self {
            client,
            server_url,
            jwt_token,
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

    async fn health_check(&self) -> Result<(), Box<dyn std::error::Error>> {
        let url = format!("{}/health", self.server_url);
        let response = self.client.get(&url).send().await?;

        println!("Health check status: {}", response.status());
        let body = response.text().await?;
        println!("Response: {}", body);

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
        let url = format!("{}/model/{}/invoke", self.server_url, model);

        let payload = json!({
            "anthropic_version": "bedrock-2023-05-31",
            "max_tokens": 1000,
            "messages": [
                {
                    "role": "user",
                    "content": message
                }
            ]
        });

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

            // Try to parse as JSON to format nicely
            if let Ok(json_value) = serde_json::from_str::<Value>(&response_text) {
                if let Ok(bedrock_response) =
                    serde_json::from_value::<BedrockResponse>(json_value.clone())
                {
                    // Handle Anthropic Claude response format
                    if let Some(content) = bedrock_response.content {
                        for block in content {
                            if let Some(text) = block.text {
                                println!("\n🤖 Model Response:\n{}\n", text);
                            }
                        }
                    } else if let Some(completion) = bedrock_response.completion {
                        println!("\n🤖 Model Response:\n{}\n", completion);
                    } else {
                        println!(
                            "\n📋 Raw Response:\n{}\n",
                            serde_json::to_string_pretty(&json_value)?
                        );
                    }
                } else {
                    println!(
                        "\n📋 Raw Response:\n{}\n",
                        serde_json::to_string_pretty(&json_value)?
                    );
                }
            } else {
                println!("\n📋 Raw Response:\n{}\n", response_text);
            }
        } else {
            let error_text = response.text().await?;
            println!("❌ Error: {}", error_text);
        }

        Ok(())
    }

    async fn send_streaming_message(
        &self,
        model: &str,
        message: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let url = format!(
            "{}/model/{}/invoke-with-response-stream",
            self.server_url, model
        );

        let payload = json!({
            "anthropic_version": "bedrock-2023-05-31",
            "max_tokens": 1000,
            "messages": [
                {
                    "role": "user",
                    "content": message
                }
            ]
        });

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
            println!("\n🤖 Model Response (streaming):");
            let mut stream = response.bytes_stream();

            while let Some(chunk_result) = stream.next().await {
                let chunk = chunk_result?;
                let chunk_str = String::from_utf8_lossy(&chunk);

                // Parse SSE format
                for line in chunk_str.lines() {
                    if let Some(data) = line.strip_prefix("data: ") {
                        if data == "[DONE]" {
                            println!("\n✅ Stream completed");
                            break;
                        }

                        if let Ok(json_data) = serde_json::from_str::<Value>(data) {
                            if let Some(delta) = json_data.get("delta") {
                                if let Some(text) = delta.get("text") {
                                    print!("{}", text.as_str().unwrap_or(""));
                                    io::stdout().flush().unwrap();
                                }
                            }
                        }
                    }
                }
            }
            println!();
        } else {
            let error_text = response.text().await?;
            println!("❌ Streaming Error: {}", error_text);
        }

        Ok(())
    }

    async fn interactive_chat(
        &self,
        model: &str,
        streaming: bool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        println!("🚀 Starting interactive chat with model: {}", model);
        println!("💡 Type 'quit' or 'exit' to end the chat");
        println!(
            "💡 Streaming mode: {}",
            if streaming { "enabled" } else { "disabled" }
        );
        println!("{}", "=".repeat(60));

        loop {
            print!("\n👤 You: ");
            io::stdout().flush()?;

            let mut input = String::new();
            io::stdin().read_line(&mut input)?;
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
    let client = E2EClient::new(cli.server_url, &config.jwt.secret)?;

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
