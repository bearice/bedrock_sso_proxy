use crate::error::AppError;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use once_cell::sync::Lazy;
use rust_embed::RustEmbed;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{debug, info};

#[derive(RustEmbed)]
#[folder = "."]
#[include = "bedrock_pricing.csv"]
struct PricingAssets;

/// CSV record structure for pricing data
#[derive(Debug, Deserialize)]
struct PricingRecord {
    region_id: String,
    model_id: String,
    model_name: String,
    provider: String,
    input_price: f64,
    output_price: f64,
    #[allow(dead_code)]
    batch_input_price: Option<f64>,
    #[allow(dead_code)]
    batch_output_price: Option<f64>,
    cache_write_price: Option<f64>,
    cache_read_price: Option<f64>,
}

/// Type alias for pricing data structure
/// Structure: region_id -> model_id -> (input_price, output_price, cache_write_price, cache_read_price, model_name, provider)
type PricingData =
    HashMap<String, HashMap<String, (f64, f64, Option<f64>, Option<f64>, String, String)>>;

/// Cached embedded pricing data parsed from CSV
/// Structure: region_id -> model_id -> (input_price, output_price, cache_write_price, cache_read_price, model_name, provider)
static EMBEDDED_PRICING: Lazy<PricingData> = Lazy::new(|| {
    let mut pricing = HashMap::new();

    if let Some(pricing_file) = PricingAssets::get("bedrock_pricing.csv") {
        if let Ok(csv_content) = std::str::from_utf8(&pricing_file.data) {
            parse_csv_pricing_data(csv_content, &mut pricing);
        }
    }

    pricing
});

/// Parse CSV pricing data into region -> model -> (input_price, output_price, cache_write_price, cache_read_price, model_name, provider) structure
fn parse_csv_pricing_data(csv_content: &str, pricing: &mut PricingData) {
    let mut reader = csv::Reader::from_reader(csv_content.as_bytes());

    for record in reader.deserialize().flatten() {
        let record: PricingRecord = record;

        // CSV already has per-1K pricing
        let input_price_per_1k = record.input_price;
        let output_price_per_1k = record.output_price;
        let cache_write_price = record.cache_write_price;
        let cache_read_price = record.cache_read_price;

        pricing.entry(record.region_id).or_default().insert(
            record.model_id,
            (
                input_price_per_1k,
                output_price_per_1k,
                cache_write_price,
                cache_read_price,
                record.model_name,
                record.provider,
            ),
        );
    }

    info!("Loaded pricing data for {} regions from CSV", pricing.len());
}

/// Unified pricing information for a Bedrock model
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelPricing {
    pub model_id: String,
    pub input_cost_per_1k_tokens: f64,
    pub output_cost_per_1k_tokens: f64,
    pub cache_write_cost_per_1k_tokens: Option<f64>,
    pub cache_read_cost_per_1k_tokens: Option<f64>,
    pub provider: String,
    pub region: String,
    pub updated_at: DateTime<Utc>,
}

/// Trait for pricing data sources
#[async_trait]
pub trait PricingDataSource {
    async fn get_all_models(&self) -> Result<Vec<ModelPricing>, AppError>;
    async fn get_model(&self, model_id: &str) -> Result<ModelPricing, AppError>;
    async fn get_models_for_region(&self, region: &str) -> Result<Vec<ModelPricing>, AppError>;
}

/// CSV-based pricing data source with region awareness
pub struct CsvPricingSource {
    region: String,
}

impl CsvPricingSource {
    pub fn new(region: String) -> Self {
        Self { region }
    }

    /// Get all available regions from the CSV data
    pub fn get_available_regions() -> Vec<String> {
        EMBEDDED_PRICING.keys().cloned().collect()
    }

    /// Parse pricing data from CSV content string
    pub fn parse_csv_content(csv_content: &str) -> Result<Vec<ModelPricing>, AppError> {
        let mut models = Vec::new();
        let mut reader = csv::Reader::from_reader(csv_content.as_bytes());
        let now = Utc::now();

        for record in reader.deserialize().flatten() {
            let record: PricingRecord = record;

            models.push(ModelPricing {
                model_id: record.model_id,
                input_cost_per_1k_tokens: record.input_price,
                output_cost_per_1k_tokens: record.output_price,
                cache_write_cost_per_1k_tokens: record.cache_write_price,
                cache_read_cost_per_1k_tokens: record.cache_read_price,
                provider: record.provider,
                region: record.region_id,
                updated_at: now,
            });
        }

        if models.is_empty() {
            return Err(AppError::BadRequest(
                "No valid pricing data found in CSV".to_string(),
            ));
        }

        info!("Parsed {} models from CSV content", models.len());
        Ok(models)
    }

    /// Get embedded CSV file's last modified date from compile-time constant
    pub fn get_embedded_csv_modified_date() -> DateTime<Utc> {
        // Use compile-time embedded timestamp from build.rs
        if let Some(timestamp_str) = option_env!("BEDROCK_CSV_MODIFIED_TIME") {
            if let Ok(timestamp) = timestamp_str.parse::<i64>() {
                if let Some(datetime) = DateTime::from_timestamp(timestamp, 0) {
                    return datetime;
                }
            }
        }

        // Fallback to current time if we can't get the embedded timestamp
        Utc::now()
    }

    /// Get all models across all regions
    pub async fn get_all_models_all_regions() -> Result<Vec<ModelPricing>, AppError> {
        let mut all_models = Vec::new();
        let csv_modified_date = Self::get_embedded_csv_modified_date();

        for (region, region_models) in EMBEDDED_PRICING.iter() {
            for (
                model_id,
                (input_cost, output_cost, cache_write_cost, cache_read_cost, _model_name, provider),
            ) in region_models.iter()
            {
                all_models.push(ModelPricing {
                    model_id: model_id.clone(),
                    input_cost_per_1k_tokens: *input_cost,
                    output_cost_per_1k_tokens: *output_cost,
                    cache_write_cost_per_1k_tokens: *cache_write_cost,
                    cache_read_cost_per_1k_tokens: *cache_read_cost,
                    provider: provider.clone(),
                    region: region.clone(),
                    updated_at: csv_modified_date,
                });
            }
        }

        debug!(
            "Loaded {} models from CSV across all regions with updated_at={}",
            all_models.len(),
            csv_modified_date
        );
        Ok(all_models)
    }

    /// Batch update: get all models for batch processing
    pub async fn get_batch_update_data() -> Result<Vec<ModelPricing>, AppError> {
        Self::get_all_models_all_regions().await
    }
}

#[async_trait]
impl PricingDataSource for CsvPricingSource {
    async fn get_all_models(&self) -> Result<Vec<ModelPricing>, AppError> {
        let mut models = Vec::new();
        let csv_modified_date = Self::get_embedded_csv_modified_date();

        if let Some(region_models) = EMBEDDED_PRICING.get(&self.region) {
            for (
                model_id,
                (input_cost, output_cost, cache_write_cost, cache_read_cost, _model_name, provider),
            ) in region_models.iter()
            {
                models.push(ModelPricing {
                    model_id: model_id.clone(),
                    input_cost_per_1k_tokens: *input_cost,
                    output_cost_per_1k_tokens: *output_cost,
                    cache_write_cost_per_1k_tokens: *cache_write_cost,
                    cache_read_cost_per_1k_tokens: *cache_read_cost,
                    provider: provider.clone(),
                    region: self.region.clone(),
                    updated_at: csv_modified_date,
                });
            }
        }

        debug!(
            "Loaded {} models from CSV for region {} with updated_at={}",
            models.len(),
            self.region,
            csv_modified_date
        );
        Ok(models)
    }

    async fn get_model(&self, model_id: &str) -> Result<ModelPricing, AppError> {
        if let Some(region_models) = EMBEDDED_PRICING.get(&self.region) {
            if let Some((
                input_cost,
                output_cost,
                cache_write_cost,
                cache_read_cost,
                _model_name,
                provider,
            )) = region_models.get(model_id)
            {
                let csv_modified_date = Self::get_embedded_csv_modified_date();
                debug!(
                    "Using CSV pricing for {} in region {}: input=${:.4}/1k, output=${:.4}/1k, cache_write=${:?}/1k, cache_read=${:?}/1k, updated_at={}",
                    model_id,
                    self.region,
                    input_cost,
                    output_cost,
                    cache_write_cost,
                    cache_read_cost,
                    csv_modified_date
                );
                return Ok(ModelPricing {
                    model_id: model_id.to_string(),
                    input_cost_per_1k_tokens: *input_cost,
                    output_cost_per_1k_tokens: *output_cost,
                    cache_write_cost_per_1k_tokens: *cache_write_cost,
                    cache_read_cost_per_1k_tokens: *cache_read_cost,
                    provider: provider.clone(),
                    region: self.region.clone(),
                    updated_at: csv_modified_date,
                });
            }
        }

        Err(AppError::NotFound(format!(
            "No pricing data available for model: {} in region: {}",
            model_id, self.region
        )))
    }

    async fn get_models_for_region(&self, region: &str) -> Result<Vec<ModelPricing>, AppError> {
        let mut models = Vec::new();
        let csv_modified_date = Self::get_embedded_csv_modified_date();

        if let Some(region_models) = EMBEDDED_PRICING.get(region) {
            for (
                model_id,
                (input_cost, output_cost, cache_write_cost, cache_read_cost, _model_name, provider),
            ) in region_models.iter()
            {
                models.push(ModelPricing {
                    model_id: model_id.clone(),
                    input_cost_per_1k_tokens: *input_cost,
                    output_cost_per_1k_tokens: *output_cost,
                    cache_write_cost_per_1k_tokens: *cache_write_cost,
                    cache_read_cost_per_1k_tokens: *cache_read_cost,
                    provider: provider.clone(),
                    region: region.to_string(),
                    updated_at: csv_modified_date,
                });
            }
        }

        debug!(
            "Loaded {} models from CSV for region {} with updated_at={}",
            models.len(),
            region,
            csv_modified_date
        );
        Ok(models)
    }
}

/// Unified pricing client that uses CSV data
pub struct PricingClient {
    csv_source: CsvPricingSource,
}

impl PricingClient {
    pub fn new(region: String) -> Self {
        Self {
            csv_source: CsvPricingSource::new(region),
        }
    }

    /// Get all model pricing from CSV data for the configured region
    pub async fn get_all_models(&self) -> Result<Vec<ModelPricing>, AppError> {
        self.csv_source.get_all_models().await
    }

    /// Get specific model pricing from CSV data for the configured region
    pub async fn get_model(&self, model_id: &str) -> Result<ModelPricing, AppError> {
        self.csv_source.get_model(model_id).await
    }

    /// Get all models for a specific region
    pub async fn get_models_for_region(&self, region: &str) -> Result<Vec<ModelPricing>, AppError> {
        self.csv_source.get_models_for_region(region).await
    }

    /// Get all models across all regions (for batch updates)
    pub async fn get_all_models_all_regions() -> Result<Vec<ModelPricing>, AppError> {
        CsvPricingSource::get_all_models_all_regions().await
    }

    /// Get all available regions
    pub fn get_available_regions() -> Vec<String> {
        CsvPricingSource::get_available_regions()
    }

    /// Get batch update data for all models
    pub async fn get_batch_update_data() -> Result<Vec<ModelPricing>, AppError> {
        CsvPricingSource::get_batch_update_data().await
    }

    /// Parse CSV content and return pricing data
    pub fn parse_csv_content(csv_content: &str) -> Result<Vec<ModelPricing>, AppError> {
        CsvPricingSource::parse_csv_content(csv_content)
    }
}

impl Default for CsvPricingSource {
    fn default() -> Self {
        Self::new("us-east-1".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_pricing_client_creation() {
        let client = PricingClient::new("us-east-1".to_string());
        assert_eq!(client.csv_source.region, "us-east-1");
    }

    #[test]
    fn test_model_pricing_creation() {
        let pricing = ModelPricing {
            model_id: "test-model".to_string(),
            input_cost_per_1k_tokens: 0.003,
            output_cost_per_1k_tokens: 0.015,
            cache_write_cost_per_1k_tokens: Some(0.00375),
            cache_read_cost_per_1k_tokens: Some(0.0003),
            provider: "AWS".to_string(),
            region: "us-east-1".to_string(),
            updated_at: Utc::now(),
        };

        assert_eq!(pricing.input_cost_per_1k_tokens, 0.003);
        assert_eq!(pricing.output_cost_per_1k_tokens, 0.015);
        assert_eq!(pricing.cache_write_cost_per_1k_tokens, Some(0.00375));
        assert_eq!(pricing.cache_read_cost_per_1k_tokens, Some(0.0003));
        assert_eq!(pricing.model_id, "test-model");
        assert_eq!(pricing.region, "us-east-1");
    }

    #[tokio::test]
    async fn test_csv_pricing_source() {
        let source = CsvPricingSource::new("us-east-1".to_string());
        let models = source.get_all_models().await.unwrap();

        // Should return models from CSV data for us-east-1
        debug!("Loaded {} models from CSV for us-east-1", models.len());
        assert!(!models.is_empty());
    }

    #[tokio::test]
    async fn test_batch_update_data() {
        let batch_data = CsvPricingSource::get_batch_update_data().await.unwrap();
        debug!("Loaded {} models for batch update", batch_data.len());
        assert!(!batch_data.is_empty());
    }

    #[test]
    fn test_available_regions() {
        let regions = CsvPricingSource::get_available_regions();
        debug!("Available regions: {:?}", regions);
        assert!(!regions.is_empty());
        assert!(regions.contains(&"us-east-1".to_string()));
    }

    #[test]
    fn test_parse_csv_content() {
        let csv_content = r#"region_id,model_id,model_name,provider,input_price,output_price,batch_input_price,batch_output_price,cache_write_price,cache_read_price
us-east-1,anthropic.claude-3-haiku-20240307-v1:0,Claude 3 Haiku,Anthropic,0.00025,0.00125,0.000125,0.000625,,
us-west-2,anthropic.claude-3-sonnet-20240229-v1:0,Claude 3 Sonnet,Anthropic,0.003,0.015,0.0015,0.0075,0.00375,0.0003"#;

        let models = CsvPricingSource::parse_csv_content(csv_content).unwrap();

        assert_eq!(models.len(), 2);

        let haiku_model = &models[0];
        assert_eq!(
            haiku_model.model_id,
            "anthropic.claude-3-haiku-20240307-v1:0"
        );
        assert_eq!(haiku_model.region, "us-east-1");
        assert_eq!(haiku_model.provider, "Anthropic");
        assert_eq!(haiku_model.input_cost_per_1k_tokens, 0.00025);
        assert_eq!(haiku_model.output_cost_per_1k_tokens, 0.00125);
        assert_eq!(haiku_model.cache_write_cost_per_1k_tokens, None);
        assert_eq!(haiku_model.cache_read_cost_per_1k_tokens, None);

        let sonnet_model = &models[1];
        assert_eq!(
            sonnet_model.model_id,
            "anthropic.claude-3-sonnet-20240229-v1:0"
        );
        assert_eq!(sonnet_model.region, "us-west-2");
        assert_eq!(sonnet_model.provider, "Anthropic");
        assert_eq!(sonnet_model.input_cost_per_1k_tokens, 0.003);
        assert_eq!(sonnet_model.output_cost_per_1k_tokens, 0.015);
        assert_eq!(sonnet_model.cache_write_cost_per_1k_tokens, Some(0.00375));
        assert_eq!(sonnet_model.cache_read_cost_per_1k_tokens, Some(0.0003));
    }

    #[test]
    fn test_parse_empty_csv_content() {
        let csv_content = "region_id,model_id,model_name,provider,input_price,output_price,batch_input_price,batch_output_price,cache_write_price,cache_read_price";

        let result = CsvPricingSource::parse_csv_content(csv_content);
        assert!(result.is_err());

        if let Err(AppError::BadRequest(msg)) = result {
            assert_eq!(msg, "No valid pricing data found in CSV");
        } else {
            panic!("Expected BadRequest error");
        }
    }
}
