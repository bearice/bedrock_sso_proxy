use chrono::{DateTime, Utc};
use serde::{Deserialize, Deserializer};
use tracing::{debug, error, warn};

/// CSV record structure for pricing data
///
/// # CSV Format Requirements
/// This parser expects a **strict CSV format** with the following constraints:
///
/// ## Required:
/// - **Header row**: Must be present with exact field names
/// - **Column order**: Must match the struct field order exactly
/// - **Field names**: Must match exactly (case-sensitive)
/// - **Required fields**: All non-Optional fields must have values
///
/// ## Expected CSV structure:
/// ```csv
/// region_id,model_id,model_name,provider,input_price,output_price,batch_input_price,batch_output_price,cache_write_price,cache_read_price,timestamp
/// us-east-1,claude-3-sonnet,Claude 3 Sonnet,Anthropic,0.003,0.015,,,0.0018,0.00036,2024-01-15T10:30:00Z
/// ```
///
/// ## Flexibility:
/// - **Optional fields**: Can be empty (batch_input_price, batch_output_price, cache_write_price, cache_read_price, timestamp)
/// - **Timestamp formats**: Supports RFC3339, Unix timestamps, ISO8601 with/without timezone (parsing fails if invalid)
/// - **Type conversion**: Basic string-to-number conversion
///
/// ## Limitations:
/// - **No column reordering**: Changing column order will cause parsing failures
/// - **No missing headers**: Header row is mandatory
/// - **No field aliases**: Field names must match exactly
/// - **No graceful degradation**: Missing required fields will cause parsing to fail
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct PricingRecord {
    pub region_id: String,
    pub model_id: String,
    pub model_name: String,
    pub provider: String,
    pub input_price: f64,
    pub output_price: f64,
    pub batch_input_price: Option<f64>,
    pub batch_output_price: Option<f64>,
    pub cache_write_price: Option<f64>,
    pub cache_read_price: Option<f64>,
    #[serde(deserialize_with = "deserialize_optional_flexible_timestamp")]
    pub timestamp: Option<DateTime<Utc>>,
}

/// Type alias for pricing data structure
pub type PricingData = Vec<PricingRecord>;

/// Detailed error information for CSV parsing failures
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CsvParseError {
    pub line_number: usize,
    pub error_type: String,
    pub message: String,
    pub raw_line: Option<String>,
    pub column_position: Option<usize>,
}

/// Comprehensive CSV parsing error with all failure details
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct CsvParsingError {
    pub total_lines: usize,
    pub successful_lines: usize,
    pub failed_lines: usize,
    pub header_errors: Vec<String>,
    pub parse_errors: Vec<CsvParseError>,
    pub summary: String,
}

impl std::fmt::Display for CsvParsingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.summary)
    }
}

impl std::error::Error for CsvParsingError {}

/// Parse CSV pricing data with comprehensive error reporting
///
/// # Important
/// This function expects a **strict CSV format** as documented in [`PricingRecord`].
/// The parser will either succeed completely or fail with detailed error information.
///
/// # Parameters
/// - `csv_content`: CSV content as string with headers and data rows
///
/// # Returns
/// - `Ok(PricingData)`: All records parsed successfully
/// - `Err(CsvParsingError)`: Detailed error information for all failures
///
/// # Error Details
/// When parsing fails, the error includes:
/// - Line numbers and raw content for failed rows
/// - Header validation errors
/// - Specific parse error messages
/// - Summary statistics
///
/// # Example
/// ```rust
/// use bedrock_sso_proxy::cost::parse_csv_pricing_data;
/// let csv_data = "region_id,model_id,model_name,provider,input_price,output_price,batch_input_price,batch_output_price,cache_write_price,cache_read_price,timestamp\nus-east-1,claude-3-sonnet,Claude 3 Sonnet,Anthropic,0.003,0.015,,,0.0018,0.00036,2024-01-15T10:30:00";
/// match parse_csv_pricing_data(csv_data) {
///     Ok(pricing) => println!("Successfully parsed {} records", pricing.len()),
///     Err(e) => println!("Parse failed: {}", e),
/// }
/// ```
pub fn parse_csv_pricing_data(csv_content: &str) -> Result<PricingData, CsvParsingError> {
    let mut reader = csv::Reader::from_reader(csv_content.as_bytes());
    let mut pricing = Vec::new();
    let mut successful_count = 0;
    let mut error_count = 0;
    let mut header_errors = Vec::new();
    let mut parse_errors = Vec::new();

    // Get headers for validation
    let _headers = match reader.headers() {
        Ok(headers) => {
            debug!("CSV headers: {:?}", headers);
            header_errors.extend(validate_headers(headers));
            headers.clone()
        }
        Err(e) => {
            let error_msg = format!("Failed to read CSV headers: {e}");
            error!("{}", error_msg);
            header_errors.push(error_msg);
            return Err(CsvParsingError {
                total_lines: 0,
                successful_lines: 0,
                failed_lines: 1,
                header_errors,
                parse_errors,
                summary: "Failed to read CSV headers".to_string(),
            });
        }
    };

    // Process records one by one with detailed error reporting
    for (line_number, result) in reader.deserialize::<PricingRecord>().enumerate() {
        let actual_line_number = line_number + 2; // +1 for 0-based, +1 for header row

        match result {
            Ok(record) => {
                // Validate the parsed record
                if let Err(validation_error) = validate_record(&record) {
                    let parse_error = CsvParseError {
                        line_number: actual_line_number,
                        error_type: "ValidationError".to_string(),
                        message: validation_error,
                        raw_line: get_raw_line(csv_content, actual_line_number)
                            .map(|s| s.to_string()),
                        column_position: None,
                    };
                    error!(
                        "Validation failed for line {}: {}",
                        actual_line_number, parse_error.message
                    );
                    parse_errors.push(parse_error);
                    error_count += 1;
                } else {
                    pricing.push(record);
                    successful_count += 1;
                }
            }
            Err(e) => {
                let raw_line = get_raw_line(csv_content, actual_line_number);
                let mut parse_error = CsvParseError {
                    line_number: actual_line_number,
                    error_type: "ParseError".to_string(),
                    message: e.to_string(),
                    raw_line: raw_line.map(|s| s.to_string()),
                    column_position: None,
                };

                // Provide specific error context
                match e.kind() {
                    csv::ErrorKind::Deserialize {
                        pos: Some(pos),
                        err,
                    } => {
                        parse_error.error_type = "DeserializationError".to_string();
                        parse_error.message = format!("Deserialization error: {err}");
                        parse_error.column_position = Some(pos.byte().try_into().unwrap());
                    }
                    csv::ErrorKind::Utf8 {
                        pos: Some(pos),
                        err,
                    } => {
                        parse_error.error_type = "Utf8Error".to_string();
                        parse_error.message = format!("UTF-8 encoding error: {err}");
                        parse_error.column_position = Some(pos.byte().try_into().unwrap());
                    }
                    _ => {
                        parse_error.message = format!("Parse error: {e}");
                    }
                }

                error!(
                    "CSV parsing error at line {}: {}",
                    actual_line_number, parse_error.message
                );
                parse_errors.push(parse_error);
                error_count += 1;
            }
        }
    }

    let total_lines = successful_count + error_count;

    // If there are any errors, return them
    if error_count > 0 || !header_errors.is_empty() {
        let summary = if !header_errors.is_empty() {
            format!(
                "CSV parsing failed with {} header errors and {} line errors out of {} total lines",
                header_errors.len(),
                error_count,
                total_lines
            )
        } else {
            format!("CSV parsing failed with {error_count} errors out of {total_lines} total lines")
        };

        warn!("{}", summary);

        return Err(CsvParsingError {
            total_lines,
            successful_lines: successful_count,
            failed_lines: error_count,
            header_errors,
            parse_errors,
            summary,
        });
    }

    debug!(
        "Successfully loaded {} pricing records from CSV",
        successful_count
    );
    Ok(pricing)
}

/// Validate CSV headers match expected format
fn validate_headers(headers: &csv::StringRecord) -> Vec<String> {
    let expected_headers = [
        "region_id",
        "model_id",
        "model_name",
        "provider",
        "input_price",
        "output_price",
        "batch_input_price",
        "batch_output_price",
        "cache_write_price",
        "cache_read_price",
        "timestamp",
    ];

    let actual_headers: Vec<&str> = headers.iter().collect();
    let mut errors = Vec::new();

    if actual_headers.len() != expected_headers.len() {
        let error_msg = format!(
            "Header count mismatch: expected {} columns, found {}. Expected: {:?}, Actual: {:?}",
            expected_headers.len(),
            actual_headers.len(),
            expected_headers,
            actual_headers
        );
        warn!("{}", error_msg);
        errors.push(error_msg);
    }

    for (i, (expected, actual)) in expected_headers
        .iter()
        .zip(actual_headers.iter())
        .enumerate()
    {
        if expected != actual {
            let error_msg = format!(
                "Header mismatch at column {}: expected '{}', found '{}'",
                i + 1,
                expected,
                actual
            );
            warn!("{}", error_msg);
            errors.push(error_msg);
        }
    }

    errors
}

/// Validate a parsed record for business logic constraints
fn validate_record(record: &PricingRecord) -> Result<(), String> {
    // Check required fields are not empty
    if record.region_id.trim().is_empty() {
        return Err("region_id cannot be empty".to_string());
    }

    if record.model_id.trim().is_empty() {
        return Err("model_id cannot be empty".to_string());
    }

    if record.model_name.trim().is_empty() {
        return Err("model_name cannot be empty".to_string());
    }

    if record.provider.trim().is_empty() {
        return Err("provider cannot be empty".to_string());
    }

    // Check prices are non-negative
    if record.input_price < 0.0 {
        return Err(format!(
            "input_price cannot be negative: {}",
            record.input_price
        ));
    }

    if record.output_price < 0.0 {
        return Err(format!(
            "output_price cannot be negative: {}",
            record.output_price
        ));
    }

    // Validate optional prices if present
    if let Some(price) = record.batch_input_price {
        if price < 0.0 {
            return Err(format!("batch_input_price cannot be negative: {price}"));
        }
    }

    if let Some(price) = record.batch_output_price {
        if price < 0.0 {
            return Err(format!("batch_output_price cannot be negative: {price}"));
        }
    }

    if let Some(price) = record.cache_write_price {
        if price < 0.0 {
            return Err(format!("cache_write_price cannot be negative: {price}"));
        }
    }

    if let Some(price) = record.cache_read_price {
        if price < 0.0 {
            return Err(format!("cache_read_price cannot be negative: {price}"));
        }
    }

    // Timestamp is now parsed automatically during deserialization

    Ok(())
}

/// Custom deserializer for optional flexible timestamp formats
fn deserialize_optional_flexible_timestamp<'de, D>(
    deserializer: D,
) -> Result<Option<DateTime<Utc>>, D::Error>
where
    D: Deserializer<'de>,
{
    let timestamp_str = String::deserialize(deserializer)?;

    // Handle empty strings
    if timestamp_str.trim().is_empty() {
        return Ok(None);
    }

    // Try RFC 3339 format first
    if let Ok(dt) = DateTime::parse_from_rfc3339(&timestamp_str) {
        return Ok(Some(dt.with_timezone(&Utc)));
    }

    // Try RFC 3339 format with Z appended (for naive timestamps)
    let timestamp_with_z = if timestamp_str.ends_with('Z') {
        timestamp_str.clone()
    } else {
        format!("{timestamp_str}Z")
    };

    if let Ok(dt) = DateTime::parse_from_rfc3339(&timestamp_with_z) {
        return Ok(Some(dt.with_timezone(&Utc)));
    }

    // Try Unix timestamp (integer seconds)
    if let Ok(timestamp) = timestamp_str.parse::<i64>() {
        if let Some(dt) = DateTime::from_timestamp(timestamp, 0) {
            return Ok(Some(dt));
        }
    }

    // Try Unix timestamp (float seconds)
    if let Ok(timestamp) = timestamp_str.parse::<f64>() {
        let secs = timestamp.floor() as i64;
        let nanos = ((timestamp - timestamp.floor()) * 1_000_000_000.0) as u32;
        if let Some(dt) = DateTime::from_timestamp(secs, nanos) {
            return Ok(Some(dt));
        }
    }

    // Try ISO 8601 format without timezone (assume UTC)
    if let Ok(naive_dt) = chrono::NaiveDateTime::parse_from_str(&timestamp_str, "%Y-%m-%dT%H:%M:%S")
    {
        return Ok(Some(naive_dt.and_utc()));
    }

    // Try ISO 8601 format with microseconds without timezone (assume UTC)
    if let Ok(naive_dt) =
        chrono::NaiveDateTime::parse_from_str(&timestamp_str, "%Y-%m-%dT%H:%M:%S%.f")
    {
        return Ok(Some(naive_dt.and_utc()));
    }

    // If all parsing fails, return error
    Err(serde::de::Error::custom(format!(
        "invalid timestamp format '{timestamp_str}': expected RFC3339, Unix timestamp, or ISO8601"
    )))
}

/// Get raw line content for error reporting
fn get_raw_line(csv_content: &str, line_number: usize) -> Option<&str> {
    csv_content.lines().nth(line_number - 1)
}
