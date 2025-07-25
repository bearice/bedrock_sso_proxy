use axum::http::HeaderMap;
/// Cost Tracking Demonstration
///
/// This example shows how the cost tracking system works:
/// 1. Initialize model costs with fallback pricing
/// 2. Simulate model usage and automatic cost calculation
/// 3. Demonstrate cost update from AWS Price List API
/// 4. Show cost summary and management
use bedrock_sso_proxy::{
    config::{AwsConfig, Config},
    cost_tracking::CostTrackingService,
    model_service::{ModelRequest, ModelService, UsageMetadata},
    storage::{Storage},
};
use chrono::Utc;
use rust_decimal::Decimal;
use std::sync::Arc;
use tracing::{Level, info};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    tracing_subscriber::fmt().with_max_level(Level::INFO).init();

    info!("🚀 Cost Tracking Demonstration Starting");

    // 1. Setup test storage and config
    let config = Config {
        aws: AwsConfig {
            region: "us-east-1".to_string(),
            access_key_id: Some("demo".to_string()),
            secret_access_key: Some("demo".to_string()),
            profile: None,
            bearer_token: None,
        },
        ..Default::default()
    };

    let storage = Arc::new(Storage::new(
        Box::new(bedrock_sso_proxy::storage::memory::MemoryCacheStorage::new(
            3600,
        )),
        Box::new(bedrock_sso_proxy::storage::database::SqliteStorage::new("sqlite::memory:").await.unwrap()),
    ));
    
    // Run database migrations
    storage.migrate().await?;

    // 2. Initialize ModelService with cost tracking
    let model_service = Arc::new(ModelService::new(storage.clone(), config.clone()));

    info!("📊 Initializing model costs...");
    model_service.initialize_model_costs().await?;

    // 3. Demonstrate cost tracking service
    let cost_service = CostTrackingService::new(storage.clone(), "us-east-1".to_string());

    // Show supported models from embedded pricing
    info!("🤖 Available Models from Embedded Pricing:");
    match cost_service.get_cost_summary().await {
        Ok(summary) => {
            for (i, model) in summary.models.iter().take(5).enumerate() {
                info!("  {}. {}", i + 1, model.model_id);
                info!(
                    "     📈 Pricing: Input=${:.4}/1k, Output=${:.4}/1k",
                    model.input_cost_per_1k_tokens, model.output_cost_per_1k_tokens
                );
            }
            if summary.models.len() > 5 {
                info!("     ... and {} more models", summary.models.len() - 5);
            }
        }
        Err(e) => info!("❌ Could not load models: {}", e),
    }

    // 4. Simulate model usage with automatic cost tracking
    info!("🔄 Simulating model usage...");

    let demo_user_id = 12345;
    let model_request = ModelRequest {
        model_id: "anthropic.claude-sonnet-4-20250514-v1:0".to_string(),
        body: b"Hello, world!".to_vec(),
        headers: HeaderMap::new(),
        user_id: demo_user_id,
        endpoint_type: "anthropic".to_string(),
    };

    // Simulate usage with mock AWS response headers
    let usage_metadata = UsageMetadata {
        input_tokens: 100,
        output_tokens: 250,
        region: "us-east-1".to_string(),
        response_time_ms: 1250,
    };

    // Manually store some model costs for demonstration
    let claude_sonnet_cost = bedrock_sso_proxy::storage::StoredModelCost {
        id: None,
        model_id: "anthropic.claude-sonnet-4-20250514-v1:0".to_string(),
        input_cost_per_1k_tokens: Decimal::from_f64_retain(0.003).unwrap(),  // $3 per million tokens
        output_cost_per_1k_tokens: Decimal::from_f64_retain(0.015).unwrap(), // $15 per million tokens
        updated_at: Utc::now(),
    };
    storage
        .database
        .upsert_model_cost(&claude_sonnet_cost)
        .await?;

    info!("💰 Cost Calculation Demo:");
    if let Some(cost) = model_service
        .storage()
        .database
        .get_model_cost(&model_request.model_id)
        .await?
    {
        let input_cost = Decimal::from_f64_retain(usage_metadata.input_tokens as f64 / 1000.0).unwrap() * cost.input_cost_per_1k_tokens;
        let output_cost = Decimal::from_f64_retain(usage_metadata.output_tokens as f64 / 1000.0).unwrap() * cost.output_cost_per_1k_tokens;
        let total_cost = input_cost + output_cost;

        info!(
            "  📝 Usage: {} input + {} output tokens",
            usage_metadata.input_tokens, usage_metadata.output_tokens
        );
        info!(
            "  💵 Input cost: ${:.6} ({} tokens × ${:.4}/1k)",
            input_cost, usage_metadata.input_tokens, cost.input_cost_per_1k_tokens
        );
        info!(
            "  💵 Output cost: ${:.6} ({} tokens × ${:.4}/1k)",
            output_cost, usage_metadata.output_tokens, cost.output_cost_per_1k_tokens
        );
        info!("  💎 Total cost: ${:.6}", total_cost);
    }

    // 5. Demonstrate cost summary
    info!("📈 Getting cost summary...");
    let summary = cost_service.get_cost_summary().await?;
    info!("  📊 Total models with pricing: {}", summary.total_models);
    info!(
        "  🕐 Last updated: {}",
        summary.last_updated.map_or("Never".to_string(), |dt| dt
            .format("%Y-%m-%d %H:%M:%S UTC")
            .to_string())
    );

    if !summary.models.is_empty() {
        info!("  💰 Sample model costs:");
        for model in summary.models.iter().take(3) {
            info!(
                "    • {}: Input=${:.4}/1k, Output=${:.4}/1k",
                model.model_id, model.input_cost_per_1k_tokens, model.output_cost_per_1k_tokens
            );
        }
    }

    // 6. Demonstrate periodic cost updates (simulated)
    info!("🔄 Demonstrating cost update capability...");
    info!("  ℹ️  In production, you would call:");
    info!("     POST /admin/costs/update");
    info!("  📝 This endpoint fetches latest pricing from AWS Price List API");
    info!("  ⚡ Falls back to configured default prices if API is unavailable");
    info!("  🔁 Can be called periodically (daily/weekly) to keep prices current");

    // 7. Available API endpoints
    info!("🛠️  Available Cost Tracking API Endpoints:");
    info!("  📊 GET  /admin/costs/summary          - Get cost summary for all models");
    info!("  🔄 POST /admin/costs/update           - Update all model costs from AWS API");
    info!("  📝 GET  /admin/model-costs            - Get all model costs");
    info!("  ➕ POST /admin/model-costs            - Create new model cost");
    info!("  ✏️  PUT  /admin/model-costs/{{model}} - Update specific model cost");
    info!("  🗑️  DEL  /admin/model-costs/{{model}} - Delete model cost");

    info!("✅ Cost Tracking Demonstration Complete!");
    info!("🚀 The system automatically tracks usage costs for all API calls");
    info!("📈 Costs are calculated using real AWS Bedrock pricing when available");
    info!("💡 Fallback pricing ensures cost tracking works even without AWS API access");

    Ok(())
}
