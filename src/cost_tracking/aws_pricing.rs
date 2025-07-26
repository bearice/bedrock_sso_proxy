use crate::error::AppError;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use once_cell::sync::Lazy;
use reqwest::Client;
use rust_embed::RustEmbed;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::time::Duration;
use tracing::{debug, info, warn};

// AWS Price List API endpoints
const AWS_PRICING_INDEX_URL: &str = "https://pricing.us-east-1.amazonaws.com/offers/v1.0/aws/index.json";
const AWS_PRICING_BASE_HOST: &str = "https://pricing.us-east-1.amazonaws.com";

// API request configuration
const API_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_RETRIES: u32 = 3;
const RETRY_DELAY: Duration = Duration::from_secs(1);

/// AWS Price List API index structure
#[derive(Debug, Deserialize)]
struct AwsPricingIndex {
    offers: HashMap<String, AwsPricingOffer>,
}

/// AWS Price List API offer structure
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct AwsPricingOffer {
    #[serde(rename = "offerCode")]
    offer_code: String,
    #[serde(rename = "versionIndexUrl")]
    version_index_url: String,
    #[serde(rename = "currentVersionUrl")]
    current_version_url: String,
}

/// AWS Price List API version index structure
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct AwsPricingVersionIndex {
    #[serde(rename = "offerCode")]
    offer_code: String,
    #[serde(rename = "currentVersion")]
    current_version: String,
    versions: HashMap<String, AwsPricingVersion>,
}

/// AWS Price List API version structure
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct AwsPricingVersion {
    #[serde(rename = "offerVersionUrl")]
    offer_version_url: String,
    #[serde(rename = "versionEffectiveBeginDate")]
    version_effective_begin_date: String,
    #[serde(rename = "versionEffectiveEndDate")]
    version_effective_end_date: Option<String>,
}

/// AWS Price List API region index structure
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct AwsPricingRegionIndex {
    regions: HashMap<String, AwsPricingRegion>,
}

/// AWS Price List API region structure
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct AwsPricingRegion {
    #[serde(rename = "regionCode")]
    region_code: String,
    #[serde(rename = "currentVersionUrl")]
    current_version_url: String,
}

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
                    model_data
                        .get("output_cost_per_1k")
                        .and_then(|v| v.as_f64()),
                ) {
                    pricing.insert(model_id.clone(), (input_cost, output_cost));
                }
            }
        }
    } else if let (Some(products), Some(terms)) = (
        pricing_data.get("products"),
        pricing_data.get("terms").and_then(|t| t.get("OnDemand")),
    ) {
        // AWS pricing format (products + terms structure)
        if let Some(products_obj) = products.as_object() {
            for (sku, product) in products_obj {
                if let Some(model_id) = product
                    .get("attributes")
                    .and_then(|a| a.get("modelId"))
                    .and_then(|m| m.as_str())
                {
                    if let Some(product_terms) = terms.get(sku) {
                        if let Some((input_cost, output_cost)) = extract_pricing_from_terms(product_terms) {
                            pricing.insert(model_id.to_string(), (input_cost, output_cost));
                        }
                    }
                }
            }
        }
    } else if let Some(price_list) = pricing_data.get("PriceList") {
        // AWS format (legacy structure)
        if let Some(price_array) = price_list.as_array() {
            for item in price_array {
                if let (Some(product), Some(terms)) = (
                    item.get("product"),
                    item.get("terms").and_then(|t| t.get("OnDemand")),
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
            if let Some(price_dimensions) = term_value
                .get("priceDimensions")
                .and_then(|p| p.as_object())
            {
                for dimension in price_dimensions.values() {
                    if let (Some(description), Some(price_per_unit), Some(unit)) = (
                        dimension.get("description").and_then(|d| d.as_str()),
                        dimension
                            .get("pricePerUnit")
                            .and_then(|p| p.get("USD"))
                            .and_then(|u| u.as_str()),
                        dimension.get("unit").and_then(|u| u.as_str()),
                    ) {
                        if let Ok(price) = price_per_unit.parse::<f64>() {
                            // Convert price to per-1K tokens based on unit
                            let price_per_1k = match unit {
                                "1K tokens" => price,
                                "tokens" => price * 1000.0,
                                _ => {
                                    debug!("Unknown pricing unit '{}', ignoring", unit);
                                    continue;
                                }
                            };

                            let desc_lower = description.to_lowercase();
                            if desc_lower.contains("input") || desc_lower.contains("prompt") {
                                input_cost = Some(price_per_1k);
                            } else if desc_lower.contains("output")
                                || desc_lower.contains("completion")
                            {
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
#[allow(dead_code)]
struct PricingResponse {
    #[serde(rename = "PriceList", default)]
    price_list: Vec<PriceListItem>,
    #[serde(default)]
    products: Option<HashMap<String, AwsProduct>>,
    #[serde(default)]
    terms: Option<AwsTerms>,
    #[serde(rename = "formatVersion")]
    format_version: Option<String>,
    #[serde(rename = "disclaimer")]
    disclaimer: Option<String>,
    #[serde(rename = "offerCode")]
    offer_code: Option<String>,
}

/// AWS Product structure in the new format
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct AwsProduct {
    #[serde(rename = "sku")]
    sku: String,
    #[serde(rename = "productFamily")]
    product_family: String,
    #[serde(rename = "attributes")]
    attributes: AwsProductAttributes,
}

/// AWS Product attributes
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct AwsProductAttributes {
    #[serde(rename = "model")]
    model: Option<String>,
    #[serde(rename = "modelId")]
    model_id: Option<String>,
    #[serde(rename = "location")]
    location: Option<String>,
    #[serde(rename = "locationType")]
    location_type: Option<String>,
    #[serde(rename = "operation")]
    operation: Option<String>,
    #[serde(rename = "servicecode")]
    service_code: Option<String>,
    #[serde(rename = "servicename")]
    service_name: Option<String>,
    #[serde(rename = "usagetype")]
    usage_type: Option<String>,
    #[serde(rename = "inferenceType")]
    inference_type: Option<String>,
    #[serde(rename = "provider")]
    provider: Option<String>,
}

/// AWS Terms structure in the new format
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct AwsTerms {
    #[serde(rename = "OnDemand")]
    on_demand: HashMap<String, HashMap<String, AwsOnDemandTerm>>,
}

/// AWS OnDemand term structure
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct AwsOnDemandTerm {
    #[serde(rename = "priceDimensions")]
    price_dimensions: HashMap<String, AwsPriceDimension>,
    #[serde(rename = "sku")]
    sku: String,
    #[serde(rename = "effectiveDate")]
    effective_date: Option<String>,
    #[serde(rename = "offerTermCode")]
    offer_term_code: String,
    #[serde(rename = "termAttributes")]
    term_attributes: HashMap<String, String>,
}

/// AWS Price dimension structure
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct AwsPriceDimension {
    #[serde(rename = "unit")]
    unit: String,
    #[serde(rename = "endRange")]
    end_range: Option<String>,
    #[serde(rename = "description")]
    description: String,
    #[serde(rename = "appliesTo")]
    applies_to: Option<Vec<String>>,
    #[serde(rename = "rateCode")]
    rate_code: String,
    #[serde(rename = "beginRange")]
    begin_range: Option<String>,
    #[serde(rename = "pricePerUnit")]
    price_per_unit: HashMap<String, String>,
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
        let client = Client::builder()
            .timeout(API_TIMEOUT)
            .redirect(reqwest::redirect::Policy::limited(10))
            .user_agent("bedrock-sso-proxy/1.0")
            .build()
            .unwrap_or_else(|e| {
                panic!("Failed to create HTTP client: {}", e);
            });

        Self {
            client,
            region,
        }
    }

    /// Convert relative URL to full URL
    fn to_full_url(&self, relative_url: &str) -> String {
        if relative_url.starts_with("http") {
            relative_url.to_string()
        } else if relative_url.starts_with('/') {
            format!("{}{}", AWS_PRICING_BASE_HOST, relative_url)
        } else {
            format!("{}/{}", AWS_PRICING_BASE_HOST, relative_url)
        }
    }

    /// Normalize model name to Bedrock model ID format
    fn normalize_model_name(&self, model_name: &str) -> String {
        match model_name {
            // Legacy Claude models
            "Claude 2.0" | "Claude" => "anthropic.claude-v2".to_string(),
            "Claude 2.1" => "anthropic.claude-v2:1".to_string(),
            "Claude Instant" => "anthropic.claude-instant-v1".to_string(),

            // Claude 3 models
            "Claude 3 Haiku" => "anthropic.claude-3-haiku-20240307-v1:0".to_string(),
            "Claude 3 Sonnet" => "anthropic.claude-3-sonnet-20240229-v1:0".to_string(),
            "Claude 3 Opus" => "anthropic.claude-3-opus-20240229-v1:0".to_string(),

            // Claude 3.5 models
            "Claude 3.5 Sonnet" => "anthropic.claude-3-5-sonnet-20240620-v1:0".to_string(),
            "Claude 3.5 Sonnet v2" => "anthropic.claude-3-5-sonnet-20241022-v2:0".to_string(),
            "Claude 3.5 Haiku" => "anthropic.claude-3-5-haiku-20241022-v1:0".to_string(),

            // Claude 3.7 models
            "Claude 3.7 Sonnet" => "anthropic.claude-3-7-sonnet-20250219-v1:0".to_string(),

            // Claude 4 models
            "Claude Opus 4" => "anthropic.claude-opus-4-20250514-v1:0".to_string(),
            "Claude Sonnet 4" => "anthropic.claude-sonnet-4-20250514-v1:0".to_string(),

            // Amazon Nova models
            "Nova Premier" => "amazon.nova-premier-v1:0".to_string(),
            "Nova Pro" => "amazon.nova-pro-v1:0".to_string(),
            "Nova Lite" => "amazon.nova-lite-v1:0".to_string(),
            "Nova Micro" => "amazon.nova-micro-v1:0".to_string(),
            "Nova Canvas" => "amazon.nova-canvas-v1:0".to_string(),
            "Nova Reel" => "amazon.nova-reel-v1:0".to_string(),
            "Nova Sonic" => "amazon.nova-sonic-v1:0".to_string(),

            // Titan models
            "Titan Text Large" => "amazon.titan-tg1-large".to_string(),
            "Titan Text G1 - Premier" => "amazon.titan-text-premier-v1:0".to_string(),
            "Titan Text G1 - Express" => "amazon.titan-text-express-v1".to_string(),
            "Titan Text G1 - Lite" => "amazon.titan-text-lite-v1".to_string(),
            "Titan Image Generator G1" => "amazon.titan-image-generator-v1".to_string(),
            "Titan Image Generator G1 v2" => "amazon.titan-image-generator-v2:0".to_string(),
            "Titan Text Embeddings v2" | "Titan Text Embeddings V2" => "amazon.titan-embed-g1-text-02".to_string(),
            "Titan Embeddings G1 - Text" => "amazon.titan-embed-text-v1".to_string(),
            "Titan Multimodal Embeddings G1" => "amazon.titan-embed-image-v1".to_string(),

            // Other provider models
            "Jamba-Instruct" => "ai21.jamba-instruct-v1:0".to_string(),
            "Jamba 1.5 Large" => "ai21.jamba-1-5-large-v1:0".to_string(),
            "Jamba 1.5 Mini" => "ai21.jamba-1-5-mini-v1:0".to_string(),
            "Command" => "cohere.command-text-v14".to_string(),
            "Command R" => "cohere.command-r-v1:0".to_string(),
            "Command R+" => "cohere.command-r-plus-v1:0".to_string(),
            "Command Light" => "cohere.command-light-text-v14".to_string(),
            "Embed English" => "cohere.embed-english-v3".to_string(),
            "Embed Multilingual" => "cohere.embed-multilingual-v3".to_string(),
            "DeepSeek-R1" => "deepseek.r1-v1:0".to_string(),
            "SDXL 1.0" => "stability.stable-diffusion-xl-v1".to_string(),
            "Marengo Embed v2.7" => "twelvelabs.marengo-embed-2-7-v1:0".to_string(),

            // Meta Llama models
            name if name.starts_with("Llama ") => {
                match name {
                    "Llama 3 8B Instruct" => "meta.llama3-8b-instruct-v1:0".to_string(),
                    "Llama 3 70B Instruct" => "meta.llama3-70b-instruct-v1:0".to_string(),
                    "Llama 3.1 8B Instruct" => "meta.llama3-1-8b-instruct-v1:0".to_string(),
                    "Llama 3.1 70B Instruct" => "meta.llama3-1-70b-instruct-v1:0".to_string(),
                    "Llama 3.2 1B Instruct" => "meta.llama3-2-1b-instruct-v1:0".to_string(),
                    "Llama 3.2 3B Instruct" => "meta.llama3-2-3b-instruct-v1:0".to_string(),
                    "Llama 3.2 11B Instruct" => "meta.llama3-2-11b-instruct-v1:0".to_string(),
                    "Llama 3.2 90B Instruct" => "meta.llama3-2-90b-instruct-v1:0".to_string(),
                    "Llama 3.3 70B Instruct" => "meta.llama3-3-70b-instruct-v1:0".to_string(),
                    "Llama 4 Scout 17B Instruct" => "meta.llama4-scout-17b-instruct-v1:0".to_string(),
                    "Llama 4 Maverick 17B Instruct" => "meta.llama4-maverick-17b-instruct-v1:0".to_string(),
                    _ => format!("meta.{}", name.to_lowercase().replace(" ", "-"))
                }
            }

            // Mistral models
            name if name.starts_with("Mistral") || name.starts_with("Mixtral") || name.starts_with("Pixtral") => {
                match name {
                    "Mistral 7B Instruct" => "mistral.mistral-7b-instruct-v0:2".to_string(),
                    "Mixtral 8x7B Instruct" => "mistral.mixtral-8x7b-instruct-v0:1".to_string(),
                    "Mistral Large (24.02)" => "mistral.mistral-large-2402-v1:0".to_string(),
                    "Mistral Small (24.02)" => "mistral.mistral-small-2402-v1:0".to_string(),
                    "Pixtral Large (25.02)" => "mistral.pixtral-large-2502-v1:0".to_string(),
                    _ => format!("mistral.{}", name.to_lowercase().replace(" ", "-"))
                }
            }

            name if name.contains("Claude") => {
                // Handle any remaining Claude models not explicitly mapped
                format!("anthropic.{}", name.to_lowercase().replace(" ", "-"))
            }
            name => {
                // For unknown models, use as-is with aws prefix
                format!("aws.{}", name.to_lowercase().replace(" ", "-"))
            }
        }
    }

    /// Make a HTTP request with retry logic
    async fn make_request(&self, url: &str) -> Result<reqwest::Response, AppError> {
        for attempt in 1..=MAX_RETRIES {
            debug!("Making request to {} (attempt {}/{})", url, attempt, MAX_RETRIES);

            match self.client.get(url).header("Accept", "application/json").send().await {
                Ok(response) => {
                    if response.status().is_success() {
                        return Ok(response);
                    } else if response.status().is_server_error() && attempt < MAX_RETRIES {
                        warn!("Server error {} for {}, retrying in {:?}", response.status(), url, RETRY_DELAY);
                        tokio::time::sleep(RETRY_DELAY).await;
                        continue;
                    } else {
                        return Err(AppError::Internal(format!(
                            "HTTP request failed with status: {} for URL: {}",
                            response.status(),
                            url
                        )));
                    }
                }
                Err(e) => {
                    if attempt < MAX_RETRIES {
                        warn!("Request failed for {}: {}, retrying in {:?}", url, e, RETRY_DELAY);
                        tokio::time::sleep(RETRY_DELAY).await;
                        continue;
                    } else {
                        return Err(AppError::Internal(format!(
                            "HTTP request failed after {} attempts for URL {}: {}",
                            MAX_RETRIES,
                            url,
                            e
                        )));
                    }
                }
            }
        }

        unreachable!("Should have returned from retry loop")
    }

    /// Fetch the latest pricing data URL from AWS Price List API
    async fn fetch_latest_pricing_url(&self) -> Result<String, AppError> {
        debug!("Fetching AWS pricing index from: {}", AWS_PRICING_INDEX_URL);

        // Step 1: Get the main index
        let index_response = self.make_request(AWS_PRICING_INDEX_URL).await?;

        let index: AwsPricingIndex = index_response
            .json()
            .await
            .map_err(|e| AppError::Internal(format!("Failed to parse AWS pricing index: {}", e)))?;

        // Step 2: Get the AmazonBedrock offer info
        let bedrock_offer = index.offers.get("AmazonBedrock").ok_or_else(|| {
            AppError::Internal("AmazonBedrock offer not found in pricing index".to_string())
        })?;

        let version_url = self.to_full_url(&bedrock_offer.version_index_url);
        debug!("Found AmazonBedrock offer, fetching version index from: {}", version_url);

        // Step 3: Get the version index
        let version_response = self.make_request(&version_url).await?;

        let version_index: AwsPricingVersionIndex = version_response
            .json()
            .await
            .map_err(|e| AppError::Internal(format!("Failed to parse AWS version index: {}", e)))?;

        // Step 4: Get the current version info
        let current_version = version_index.versions.get(&version_index.current_version).ok_or_else(|| {
            AppError::Internal(format!("Current version {} not found in version index", version_index.current_version))
        })?;

        let final_url = self.to_full_url(&current_version.offer_version_url);
        debug!("Found current version {}, using pricing URL: {}", version_index.current_version, final_url);

        info!("Successfully resolved latest AWS pricing URL for version: {}", version_index.current_version);
        Ok(final_url)
    }

    /// Fetch raw pricing data from AWS API using the latest URL
    async fn fetch_aws_pricing_data(&self) -> Result<PricingResponse, AppError> {
        let url = self.fetch_latest_pricing_url().await?;

        debug!("Requesting latest pricing data from AWS API: {}", url);

        let response = self.make_request(&url).await?;

        let pricing_data: PricingResponse = response
            .json()
            .await
            .map_err(|e| AppError::Internal(format!("Failed to parse AWS API response: {}", e)))?;

        info!("Successfully fetched latest pricing data from AWS API");
        Ok(pricing_data)
    }

    /// Parse AWS pricing data into unified format
    fn parse_aws_pricing_data(
        &self,
        pricing_data: &PricingResponse,
    ) -> Result<Vec<ModelPricing>, AppError> {
        let mut all_pricing = Vec::new();
        let now = Utc::now();

        if let (Some(products), Some(terms)) = (&pricing_data.products, &pricing_data.terms) {
            debug!("Parsing AWS pricing with {} products", products.len());

            for (sku, product) in products {
                // Try both modelId and model fields
                if let Some(model_name) = product.attributes.model_id.as_ref()
                    .or(product.attributes.model.as_ref()) {
                    // Find the corresponding terms for this SKU
                    if let Some(sku_terms) = terms.on_demand.get(sku) {
                        if let Some((input_cost, output_cost)) = self.extract_pricing_from_new_terms(sku_terms) {
                            // Convert model name to proper model ID format
                            let model_id = self.normalize_model_name(model_name);

                            all_pricing.push(ModelPricing {
                                model_id: model_id.clone(),
                                provider: "AWS".to_string(),
                                input_cost_per_1k_tokens: input_cost,
                                output_cost_per_1k_tokens: output_cost,
                                updated_at: now,
                            });
                            debug!(
                                "Parsed pricing for {} ({}): input=${:.4}/1k, output=${:.4}/1k",
                                model_id, model_name, input_cost, output_cost
                            );
                        }else{
                            //debug!("can not extract pricing: {:?}", sku_terms)
                        }
                    }else {
                        debug!("SKU not found: {}", model_name)
                    }
                }else{
                    debug!("No model_id in product: {}", product.sku)
                }
            }
        } else {
            warn!("Unknown AWS pricing format - no PriceList or products/terms found");
        }

        if all_pricing.is_empty() {
            return Err(AppError::Internal(
                "No valid pricing data found in AWS API response".to_string(),
            ));
        }

        info!(
            "Successfully parsed pricing for {} models from AWS API",
            all_pricing.len()
        );
        Ok(all_pricing)
    }

    /// Extract pricing from new AWS terms structure
    fn extract_pricing_from_new_terms(&self, sku_terms: &HashMap<String, AwsOnDemandTerm>) -> Option<(f64, f64)> {
        let mut input_cost = None;
        let mut output_cost = None;

        for term in sku_terms.values() {
            for dimension in term.price_dimensions.values() {
                if let Some(usd_price) = dimension.price_per_unit.get("USD") {
                    if let Ok(price) = usd_price.parse::<f64>() {
                        // Convert price to per-1K tokens based on unit
                        let price_per_1k = match dimension.unit.as_str() {
                            "1K tokens" => price,
                            "tokens" => price * 1000.0,
                            _ => {
                                debug!("Unknown pricing unit '{}', ignoring", dimension.unit);
                                continue;
                            }
                        };

                        let description = dimension.description.to_lowercase();
                        if description.contains("input") || description.contains("prompt") {
                            input_cost = Some(price_per_1k);
                        } else if description.contains("output")
                            || description.contains("completion")
                        {
                            output_cost = Some(price_per_1k);
                        }
                    }
                }
            }
        }
        //debug!("input: {:?} output: {:?}", input_cost, output_cost);
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
        info!(
            "Fetching pricing for Bedrock model: {} from AWS API",
            model_id
        );

        // Get all pricing data (more efficient than single model calls)
        let all_pricing = self.get_all_models().await?;

        // Find the specific model in the dataset
        all_pricing
            .into_iter()
            .find(|p| p.model_id == model_id)
            .ok_or_else(|| {
                AppError::NotFound(format!(
                    "Model {} not found in AWS API pricing data",
                    model_id
                ))
            })
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

        debug!(
            "Loaded {} models from embedded pricing data",
            all_pricing.len()
        );
        Ok(all_pricing)
    }

    async fn get_model(&self, model_id: &str) -> Result<ModelPricing, AppError> {
        if let Some((input_cost, output_cost)) = EMBEDDED_PRICING.get(model_id) {
            debug!(
                "Using embedded pricing for {}: input=${:.4}/1k, output=${:.4}/1k",
                model_id, input_cost, output_cost
            );
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
