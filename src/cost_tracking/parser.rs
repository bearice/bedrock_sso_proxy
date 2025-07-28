use serde::{Deserialize};
use tracing::{debug};


/// CSV record structure for pricing data
#[derive(Debug, Deserialize)]
pub struct PricingRecord {
    pub region_id: String,
    pub model_id: String,
    pub model_name: String,
    pub provider: String,
    pub input_price: f64,
    pub output_price: f64,
    #[allow(dead_code)]
    pub batch_input_price: Option<f64>,
    #[allow(dead_code)]
    pub batch_output_price: Option<f64>,
    pub cache_write_price: Option<f64>,
    pub cache_read_price: Option<f64>,
}

/// Type alias for pricing data structure
pub type PricingData = Vec<PricingRecord>;

/// Parse CSV pricing data
pub fn parse_csv_pricing_data(csv_content: &str) -> PricingData {
    let mut reader = csv::Reader::from_reader(csv_content.as_bytes());
    let pricing: Vec<_> = reader.deserialize().flatten().collect();
    debug!("Loaded pricing data for {} regions from CSV", pricing.len());
    pricing
}
