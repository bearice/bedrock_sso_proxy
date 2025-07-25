use crate::error::AppError;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use reqwest::Client;
use rust_embed::RustEmbed;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use once_cell::sync::Lazy;
use tracing::{debug, info};

#[derive(RustEmbed)]
#[folder = "."]
#[include = "aws_pricing.json"]
struct PricingAssets;

/// Cached embedded pricing data parsed from JSON
static EMBEDDED_PRICING: Lazy<HashMap<String, (f64, f64)>> = Lazy::new(|| {
    let mut pricing = HashMap::new();
    
    if let Some(pricing_file) = PricingAssets::get("aws_pricing.json") {
        if let Ok(pricing_data) = serde_json::from_slice::<Value>(&pricing_file.data) {
            parse_pricing_data(&pricing_data, &mut pricing);
        }
    }
    
    pricing
});

/// Parse pricing data from JSON (handles both AWS format and simplified format)
fn parse_pricing_data(pricing_data: &Value, pricing: &mut HashMap<String, (f64, f64)>) {
    if let Some(models) = pricing_data.get("models") {
        // Our simplified format
        if let Some(models_obj) = models.as_object() {
            for (model_id, model_data) in models_obj {
                if let (Some(input_cost), Some(output_cost)) = (
                    model_data.get("input_cost_per_1k").and_then(|v| v.as_f64()),
                    model_data.get("output_cost_per_1k").and_then(|v| v.as_f64())
                ) {
                    pricing.insert(model_id.clone(), (input_cost, output_cost));
                }
            }
        }
    } else if let Some(price_list) = pricing_data.get("PriceList") {
        // AWS format
        if let Some(price_array) = price_list.as_array() {
            for item in price_array {
                if let (Some(product), Some(terms)) = (
                    item.get("product"),
                    item.get("terms").and_then(|t| t.get("OnDemand"))
                ) {
                    if let Some(model_id) = product
                        .get("attributes")
                        .and_then(|a| a.get("modelId"))
                        .and_then(|m| m.as_str())
                    {
                        if let Some((input_cost, output_cost)) = extract_pricing_from_terms(terms) {
                            pricing.insert(model_id.to_string(), (input_cost, output_cost));
                        }
                    }
                }
            }
        }
    }
}

/// Extract pricing from AWS terms object
fn extract_pricing_from_terms(terms: &Value) -> Option<(f64, f64)> {
    let mut input_cost = None;
    let mut output_cost = None;
    
    if let Some(terms_obj) = terms.as_object() {
        for term_value in terms_obj.values() {
            if let Some(price_dimensions) = term_value.get("priceDimensions").and_then(|p| p.as_object()) {
                for dimension in price_dimensions.values() {
                    if let (Some(description), Some(price_per_unit)) = (
                        dimension.get("description").and_then(|d| d.as_str()),
                        dimension.get("pricePerUnit").and_then(|p| p.get("USD")).and_then(|u| u.as_str())
                    ) {
                        if let Ok(price) = price_per_unit.parse::<f64>() {
                            let price_per_1k = price * 1000.0; // Convert to per-1K tokens
                            
                            let desc_lower = description.to_lowercase();
                            if desc_lower.contains("input") || desc_lower.contains("prompt") {
                                input_cost = Some(price_per_1k);
                            } else if desc_lower.contains("output") || desc_lower.contains("completion") {
                                output_cost = Some(price_per_1k);
                            }
                        }
                    }
                }
            }
        }
    }
    
    match (input_cost, output_cost) {
        (Some(input), Some(output)) => Some((input, output)),
        _ => None,
    }
}

/// Unified pricing information for a Bedrock model
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelPricing {
    pub model_id: String,
    pub input_cost_per_1k_tokens: f64,
    pub output_cost_per_1k_tokens: f64,
    pub provider: String,
    pub updated_at: DateTime<Utc>,
}

/// Trait for pricing data sources
#[async_trait]
pub trait PricingDataSource {
    async fn get_all_models(&self) -> Result<Vec<ModelPricing>, AppError>;
    async fn get_model(&self, model_id: &str) -> Result<ModelPricing, AppError>;
}

/// AWS API pricing data source
pub struct AwsApiPricingSource {
    client: Client,
    #[allow(dead_code)]
    region: String,
}

/// Embedded pricing data source
pub struct EmbeddedPricingSource;

/// AWS Pricing API response structure
#[derive(Debug, Deserialize)]
struct PricingResponse {
    #[serde(rename = "PriceList")]
    price_list: Vec<PriceListItem>,
}

#[derive(Debug, Deserialize)]
struct PriceListItem {
    #[serde(rename = "terms")]
    terms: Terms,
    #[serde(rename = "product")]
    product: Product,
}

#[derive(Debug, Deserialize)]
struct Terms {
    #[serde(rename = "OnDemand")]
    on_demand: HashMap<String, OnDemandTerm>,
}

#[derive(Debug, Deserialize)]
struct OnDemandTerm {
    #[serde(rename = "priceDimensions")]
    price_dimensions: HashMap<String, PriceDimension>,
}

#[derive(Debug, Deserialize)]
struct PriceDimension {
    #[serde(rename = "pricePerUnit")]
    price_per_unit: HashMap<String, String>,
    #[serde(rename = "description")]
    description: String,
}

#[derive(Debug, Deserialize)]
struct Product {
    #[serde(rename = "attributes")]
    attributes: ProductAttributes,
}

#[derive(Debug, Deserialize)]
struct ProductAttributes {
    #[serde(rename = "modelId")]
    model_id: Option<String>,
    #[serde(rename = "usagetype")]
    #[allow(dead_code)]
    usage_type: Option<String>,
}

impl AwsApiPricingSource {
    pub fn new(region: String) -> Self {
        Self {
            client: Client::new(),
            region,
        }
    }

    /// Fetch raw pricing data from AWS API
    async fn fetch_aws_pricing_data(&self) -> Result<PricingResponse, AppError> {
        let url = "https://pricing.us-east-1.amazonaws.com/offers/v1.0/aws/AmazonBedrock/current/index.json";
        
        debug!("Requesting pricing data from AWS API: {}", url);

        let response = self.client
            .get(url)
            .header("Accept", "application/json")
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("AWS Pricing API request failed: {}", e)))?;

        if !response.status().is_success() {
            return Err(AppError::Internal(format!(
                "AWS Pricing API returned status: {}",
                response.status()
            )));
        }

        let pricing_data: PricingResponse = response.json().await
            .map_err(|e| AppError::Internal(format!("Failed to parse AWS API response: {}", e)))?;

        info!("Successfully fetched pricing data from AWS API");
        Ok(pricing_data)
    }

    /// Parse AWS pricing data into unified format
    fn parse_aws_pricing_data(&self, pricing_data: &PricingResponse) -> Result<Vec<ModelPricing>, AppError> {
        let mut all_pricing = Vec::new();
        let now = Utc::now();

        for item in &pricing_data.price_list {
            // Check if this item has model information
            if let Some(model_id) = &item.product.attributes.model_id {
                // Extract pricing from terms
                if let Some((input_cost, output_cost)) = self.extract_pricing_from_aws_terms(&item.terms) {
                    all_pricing.push(ModelPricing {
                        model_id: model_id.clone(),
                        provider: "AWS".to_string(),
                        input_cost_per_1k_tokens: input_cost,
                        output_cost_per_1k_tokens: output_cost,
                        updated_at: now,
                    });
                    debug!("Parsed pricing for {}: input=${:.4}/1k, output=${:.4}/1k", 
                          model_id, input_cost, output_cost);
                }
            }
        }

        if all_pricing.is_empty() {
            return Err(AppError::Internal("No valid pricing data found in AWS API response".to_string()));
        }

        info!("Successfully parsed pricing for {} models from AWS API", all_pricing.len());
        Ok(all_pricing)
    }

    /// Extract pricing from AWS terms structure
    fn extract_pricing_from_aws_terms(&self, terms: &Terms) -> Option<(f64, f64)> {
        let mut input_cost = None;
        let mut output_cost = None;
        
        for term in terms.on_demand.values() {
            for dimension in term.price_dimensions.values() {
                if let Some(usd_price) = dimension.price_per_unit.get("USD") {
                    if let Ok(price) = usd_price.parse::<f64>() {
                        let price_per_1k = price * 1000.0; // Convert to per-1K tokens
                        
                        let description = dimension.description.to_lowercase();
                        if description.contains("input") || description.contains("prompt") {
                            input_cost = Some(price_per_1k);
                        } else if description.contains("output") || description.contains("completion") {
                            output_cost = Some(price_per_1k);
                        }
                    }
                }
            }
        }
        
        match (input_cost, output_cost) {
            (Some(input), Some(output)) => Some((input, output)),
            _ => None,
        }
    }
}

#[async_trait]
impl PricingDataSource for AwsApiPricingSource {
    async fn get_all_models(&self) -> Result<Vec<ModelPricing>, AppError> {
        info!("Fetching all Bedrock pricing from AWS API");
        
        // 1. Fetch raw data from AWS API
        let raw_pricing_data = self.fetch_aws_pricing_data().await?;
        
        // 2. Parse the raw data into unified format
        self.parse_aws_pricing_data(&raw_pricing_data)
    }

    async fn get_model(&self, model_id: &str) -> Result<ModelPricing, AppError> {
        info!("Fetching pricing for Bedrock model: {} from AWS API", model_id);
        
        // Get all pricing data (more efficient than single model calls)
        let all_pricing = self.get_all_models().await?;
        
        // Find the specific model in the dataset
        all_pricing.into_iter()
            .find(|p| p.model_id == model_id)
            .ok_or_else(|| AppError::NotFound(format!("Model {} not found in AWS API pricing data", model_id)))
    }
}

impl EmbeddedPricingSource {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl PricingDataSource for EmbeddedPricingSource {
    async fn get_all_models(&self) -> Result<Vec<ModelPricing>, AppError> {
        let mut all_pricing = Vec::new();
        let now = Utc::now();

        for (model_id, (input_cost, output_cost)) in EMBEDDED_PRICING.iter() {
            all_pricing.push(ModelPricing {
                model_id: model_id.to_string(),
                provider: "AWS (embedded)".to_string(),
                input_cost_per_1k_tokens: *input_cost,
                output_cost_per_1k_tokens: *output_cost,
                updated_at: now,
            });
        }

        debug!("Loaded {} models from embedded pricing data", all_pricing.len());
        Ok(all_pricing)
    }

    async fn get_model(&self, model_id: &str) -> Result<ModelPricing, AppError> {
        if let Some((input_cost, output_cost)) = EMBEDDED_PRICING.get(model_id) {
            debug!("Using embedded pricing for {}: input=${:.4}/1k, output=${:.4}/1k", 
                   model_id, input_cost, output_cost);
            Ok(ModelPricing {
                model_id: model_id.to_string(),
                provider: "AWS (embedded)".to_string(),
                input_cost_per_1k_tokens: *input_cost,
                output_cost_per_1k_tokens: *output_cost,
                updated_at: Utc::now(),
            })
        } else {
            Err(AppError::NotFound(format!(
                "No pricing data available for model: {}",
                model_id
            )))
        }
    }
}

/// Unified pricing client that coordinates multiple data sources
pub struct PricingClient {
    aws_source: AwsApiPricingSource,
    embedded_source: EmbeddedPricingSource,
}

impl PricingClient {
    pub fn new(region: String) -> Self {
        Self {
            aws_source: AwsApiPricingSource::new(region),
            embedded_source: EmbeddedPricingSource::new(),
        }
    }

    /// Get all model pricing from AWS API (fails if API unavailable)
    pub async fn fetch_all_models_from_aws(&self) -> Result<Vec<ModelPricing>, AppError> {
        self.aws_source.get_all_models().await
    }

    /// Get specific model pricing from AWS API (fails if API unavailable)
    pub async fn fetch_model_from_aws(&self, model_id: &str) -> Result<ModelPricing, AppError> {
        self.aws_source.get_model(model_id).await
    }

    /// Get all model pricing from embedded data
    pub async fn load_all_models_from_embedded(&self) -> Result<Vec<ModelPricing>, AppError> {
        self.embedded_source.get_all_models().await
    }

    /// Get specific model pricing from embedded data
    pub async fn load_model_from_embedded(&self, model_id: &str) -> Result<ModelPricing, AppError> {
        self.embedded_source.get_model(model_id).await
    }
}

impl Default for EmbeddedPricingSource {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_pricing_client_creation() {
        let client = PricingClient::new("us-east-1".to_string());
        assert_eq!(client.aws_source.region, "us-east-1");
    }

    #[test]
    fn test_model_pricing_creation() {
        let pricing = ModelPricing {
            model_id: "test-model".to_string(),
            input_cost_per_1k_tokens: 0.003,
            output_cost_per_1k_tokens: 0.015,
            provider: "AWS".to_string(),
            updated_at: Utc::now(),
        };
        
        assert_eq!(pricing.input_cost_per_1k_tokens, 0.003);
        assert_eq!(pricing.output_cost_per_1k_tokens, 0.015);
        assert_eq!(pricing.model_id, "test-model");
    }

    #[tokio::test]
    async fn test_embedded_pricing_source() {
        let source = EmbeddedPricingSource::new();
        let models = source.get_all_models().await.unwrap();
        
        // Should return models from embedded data
        println!("Loaded {} models from embedded data", models.len());
    }
}