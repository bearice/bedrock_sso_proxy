use bedrock_sso_proxy::cost_tracking::PricingClient;
use env_logger;
use std::env;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    let args: Vec<String> = env::args().collect();
    let model_id = args
        .get(1)
        .unwrap_or(&"anthropic.claude-opus-4-20250514-v1:0".to_string())
        .clone();

    let pricing_client = PricingClient::new("us-east-1".to_string());

    println!("Fetching pricing data from AWS API...");
    match pricing_client.fetch_all_models_from_aws().await {
        Ok(models) => {
            if models.is_empty() {
                println!("No models found in AWS API response");
            } else {
                println!("Found {} models from AWS API", models.len());

                if let Some(model) = models.iter().find(|m| m.model_id.contains(&model_id)) {
                    println!("Model: {}", model.model_id);
                    println!(
                        "Input:  ${:.6} per 1K tokens",
                        model.input_cost_per_1k_tokens
                    );
                    println!(
                        "Output: ${:.6} per 1K tokens",
                        model.output_cost_per_1k_tokens
                    );
                    println!(
                        "Updated: {}",
                        model.updated_at.format("%Y-%m-%d %H:%M:%S UTC")
                    );
                } else {
                    println!(
                        "Model containing '{}' not found. Available models:",
                        model_id
                    );
                    for (i, model) in models.iter().take(5).enumerate() {
                        println!("  {}: {}", i + 1, model.model_id);
                    }
                    if models.len() > 5 {
                        println!("  ... and {} more", models.len() - 5);
                    }
                }
            }
        }
        Err(e) => {
            eprintln!("Error fetching pricing: {}", e);
            std::process::exit(1);
        }
    }

    Ok(())
}
