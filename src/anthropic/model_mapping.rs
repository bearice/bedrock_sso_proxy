use super::AnthropicError;
use std::collections::HashMap;
use std::sync::LazyLock;

/// Default model mapping from Anthropic API model names to AWS Bedrock model IDs
/// This provides the latest Claude model mappings as of January 2025
static DEFAULT_MODEL_MAPPING: LazyLock<HashMap<&'static str, &'static str>> = LazyLock::new(|| {
    let mut map = HashMap::new();

    // Claude 4 Models (Latest)
    map.insert(
        "claude-opus-4-20250514",
        "anthropic.claude-opus-4-20250514-v1:0",
    );
    map.insert("claude-opus-4-0", "anthropic.claude-opus-4-20250514-v1:0");
    map.insert(
        "claude-sonnet-4-20250514",
        "anthropic.claude-sonnet-4-20250514-v1:0",
    );
    map.insert(
        "claude-sonnet-4-0",
        "anthropic.claude-sonnet-4-20250514-v1:0",
    );

    // Claude 3.7 Models
    map.insert(
        "claude-3-7-sonnet-20250219",
        "anthropic.claude-3-7-sonnet-20250219-v1:0",
    );
    map.insert(
        "claude-3-7-sonnet-latest",
        "anthropic.claude-3-7-sonnet-20250219-v1:0",
    );

    // Claude 3.5 Models
    map.insert(
        "claude-3-5-sonnet-20241022",
        "anthropic.claude-3-5-sonnet-20241022-v2:0",
    );
    map.insert(
        "claude-3-5-sonnet-latest",
        "anthropic.claude-3-5-sonnet-20241022-v2:0",
    );
    map.insert(
        "claude-3-5-sonnet-20240620",
        "anthropic.claude-3-5-sonnet-20240620-v1:0",
    );
    map.insert(
        "claude-3-5-haiku-20241022",
        "anthropic.claude-3-5-haiku-20241022-v1:0",
    );
    map.insert(
        "claude-3-5-haiku-latest",
        "anthropic.claude-3-5-haiku-20241022-v1:0",
    );

    // Claude 3 Models (Original)
    map.insert(
        "claude-3-opus-20240229",
        "anthropic.claude-3-opus-20240229-v1:0",
    );
    map.insert(
        "claude-3-sonnet-20240229",
        "anthropic.claude-3-sonnet-20240229-v1:0",
    );
    map.insert(
        "claude-3-haiku-20240307",
        "anthropic.claude-3-haiku-20240307-v1:0",
    );

    // Backward compatibility aliases
    map.insert("claude-3-sonnet", "anthropic.claude-3-sonnet-20240229-v1:0");
    map.insert("claude-3-haiku", "anthropic.claude-3-haiku-20240307-v1:0");
    map.insert("claude-3-opus", "anthropic.claude-3-opus-20240229-v1:0");
    map.insert(
        "claude-3-5-sonnet",
        "anthropic.claude-3-5-sonnet-20241022-v2:0",
    );
    map.insert(
        "claude-3-5-haiku",
        "anthropic.claude-3-5-haiku-20241022-v1:0",
    );

    map
});

/// Maps Anthropic model names to AWS Bedrock model IDs with support for custom overrides
pub struct ModelMapper {
    /// User-defined model mappings that override defaults
    custom_mappings: HashMap<String, String>,
    /// Cached reverse mapping for performance
    reverse_mapping: HashMap<String, String>,
    /// AWS region for automatic region prefix
    aws_region: String,
}

impl ModelMapper {
    /// Create a new model mapper with optional custom mappings and AWS region
    pub fn new(custom_mappings: HashMap<String, String>, aws_region: String) -> Self {
        // Build reverse mapping from both default and custom mappings
        let mut reverse_mapping = HashMap::new();

        // Add default mappings to reverse lookup, prioritizing canonical names over aliases
        // Process in order: canonical names first, then aliases
        let canonical_models = [
            "claude-opus-4-20250514",
            "claude-sonnet-4-20250514",
            "claude-3-7-sonnet-20250219",
            "claude-3-5-sonnet-20241022",
            "claude-3-5-sonnet-20240620",
            "claude-3-5-haiku-20241022",
            "claude-3-opus-20240229",
            "claude-3-sonnet-20240229",
            "claude-3-haiku-20240307",
        ];

        // First, add canonical models
        for anthropic in canonical_models {
            if let Some(bedrock) = DEFAULT_MODEL_MAPPING.get(anthropic) {
                reverse_mapping.insert(bedrock.to_string(), anthropic.to_string());
            }
        }

        // Then add aliases only if no canonical mapping exists
        for (anthropic, bedrock) in DEFAULT_MODEL_MAPPING.iter() {
            if !reverse_mapping.contains_key(*bedrock) {
                reverse_mapping.insert(bedrock.to_string(), anthropic.to_string());
            }
        }

        // Override with custom mappings in reverse lookup
        for (anthropic, bedrock) in &custom_mappings {
            reverse_mapping.insert(bedrock.clone(), anthropic.clone());
        }

        Self {
            custom_mappings,
            reverse_mapping,
            aws_region,
        }
    }

    /// Get region prefix based on AWS region
    fn get_region_prefix(&self) -> String {
        // Extract region prefix from AWS region (e.g., "us-east-1" -> "us")
        if let Some(region_prefix) = self.aws_region.split('-').next() {
            format!("{region_prefix}.")
        } else {
            // Fallback to "us." if region parsing fails
            "us.".to_string()
        }
    }

    /// Convert Anthropic model name to Bedrock model ID
    pub fn anthropic_to_bedrock(&self, anthropic_model: &str) -> Result<String, AnthropicError> {
        // First check custom mappings (user overrides)
        if let Some(bedrock_model) = self.custom_mappings.get(anthropic_model) {
            return Ok(bedrock_model.clone());
        }

        // Then check default mappings and add region prefix
        if let Some(bedrock_model) = DEFAULT_MODEL_MAPPING.get(anthropic_model) {
            let region_prefix = self.get_region_prefix();
            return Ok(format!("{region_prefix}{bedrock_model}"));
        }

        Err(AnthropicError::UnsupportedModel(
            anthropic_model.to_string(),
        ))
    }

    /// Convert Bedrock model ID to Anthropic model name
    pub fn bedrock_to_anthropic(&self, bedrock_model: &str) -> Result<String, AnthropicError> {
        self.reverse_mapping
            .get(bedrock_model)
            .cloned()
            .ok_or_else(|| AnthropicError::UnsupportedModel(bedrock_model.to_string()))
    }

    /// Check if an Anthropic model name is supported
    pub fn is_anthropic_model_supported(&self, model: &str) -> bool {
        self.custom_mappings.contains_key(model) || DEFAULT_MODEL_MAPPING.contains_key(model)
    }

    /// Check if a Bedrock model ID is supported for Anthropic API
    pub fn is_bedrock_model_supported(&self, model: &str) -> bool {
        self.reverse_mapping.contains_key(model)
    }

    /// Get all supported Anthropic model names
    pub fn get_supported_anthropic_models(&self) -> Vec<String> {
        let mut models = Vec::new();

        // Add default models
        models.extend(DEFAULT_MODEL_MAPPING.keys().map(|s| s.to_string()));

        // Add custom models (avoiding duplicates)
        for model in self.custom_mappings.keys() {
            if !models.contains(model) {
                models.push(model.clone());
            }
        }

        models.sort();
        models
    }

    /// Get all supported Bedrock model IDs
    pub fn get_supported_bedrock_models(&self) -> Vec<String> {
        let mut models: Vec<String> = self.reverse_mapping.keys().cloned().collect();
        models.sort();
        models
    }

    /// Validate and normalize an Anthropic model name
    /// This handles aliases and ensures the model is supported
    pub fn validate_anthropic_model(&self, model: &str) -> Result<String, AnthropicError> {
        // Check if the model is directly supported
        if self.is_anthropic_model_supported(model) {
            return Ok(model.to_string());
        }

        // Handle case variations - try to find a case-insensitive match
        let lower_model = model.to_lowercase();

        // Check custom mappings first (case-insensitive)
        for supported_model in self.custom_mappings.keys() {
            if supported_model.to_lowercase() == lower_model {
                return Ok(supported_model.clone());
            }
        }

        // Check default mappings (case-insensitive)
        for supported_model in DEFAULT_MODEL_MAPPING.keys() {
            if supported_model.to_lowercase() == lower_model {
                return Ok(supported_model.to_string());
            }
        }

        Err(AnthropicError::UnsupportedModel(model.to_string()))
    }

    /// Get the effective mapping (custom overrides default)
    pub fn get_effective_mapping(&self) -> HashMap<String, String> {
        let mut effective = HashMap::new();

        // Start with default mappings
        for (anthropic, bedrock) in DEFAULT_MODEL_MAPPING.iter() {
            effective.insert(anthropic.to_string(), bedrock.to_string());
        }

        // Override with custom mappings
        for (anthropic, bedrock) in &self.custom_mappings {
            effective.insert(anthropic.clone(), bedrock.clone());
        }

        effective
    }

    /// Check if a model mapping exists (either default or custom)
    pub fn has_mapping(&self, anthropic_model: &str) -> bool {
        self.is_anthropic_model_supported(anthropic_model)
    }
}

impl Default for ModelMapper {
    fn default() -> Self {
        Self::new(HashMap::new(), "us-east-1".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_anthropic_to_bedrock_mapping() {
        let mapper = ModelMapper::default();

        // Test Claude 4 models
        let result = mapper
            .anthropic_to_bedrock("claude-opus-4-20250514")
            .unwrap();
        assert_eq!(result, "us.anthropic.claude-opus-4-20250514-v1:0");

        let result = mapper.anthropic_to_bedrock("claude-opus-4-0").unwrap();
        assert_eq!(result, "us.anthropic.claude-opus-4-20250514-v1:0");

        // Test Claude 3.5 models
        let result = mapper
            .anthropic_to_bedrock("claude-3-5-sonnet-latest")
            .unwrap();
        assert_eq!(result, "us.anthropic.claude-3-5-sonnet-20241022-v2:0");

        // Test Claude 3 models
        let result = mapper
            .anthropic_to_bedrock("claude-3-sonnet-20240229")
            .unwrap();
        assert_eq!(result, "us.anthropic.claude-3-sonnet-20240229-v1:0");

        let result = mapper
            .anthropic_to_bedrock("claude-3-haiku-20240307")
            .unwrap();
        assert_eq!(result, "us.anthropic.claude-3-haiku-20240307-v1:0");

        let result = mapper
            .anthropic_to_bedrock("claude-3-opus-20240229")
            .unwrap();
        assert_eq!(result, "us.anthropic.claude-3-opus-20240229-v1:0");
    }

    #[test]
    fn test_bedrock_to_anthropic_mapping() {
        let mapper = ModelMapper::default();

        let result = mapper
            .bedrock_to_anthropic("anthropic.claude-opus-4-20250514-v1:0")
            .unwrap();
        assert_eq!(result, "claude-opus-4-20250514");

        let result = mapper
            .bedrock_to_anthropic("anthropic.claude-3-sonnet-20240229-v1:0")
            .unwrap();
        assert_eq!(result, "claude-3-sonnet-20240229");

        let result = mapper
            .bedrock_to_anthropic("anthropic.claude-3-5-sonnet-20240620-v1:0")
            .unwrap();
        assert_eq!(result, "claude-3-5-sonnet-20240620");
    }

    #[test]
    fn test_unsupported_model() {
        let mapper = ModelMapper::default();

        let result = mapper.anthropic_to_bedrock("unsupported-model");
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            AnthropicError::UnsupportedModel(_)
        ));
    }

    #[test]
    fn test_custom_model_mapping() {
        let mut custom_mappings = HashMap::new();
        custom_mappings.insert(
            "custom-claude-model".to_string(),
            "us.anthropic.custom-claude-model-v1:0".to_string(),
        );

        let mapper = ModelMapper::new(custom_mappings, "us-east-1".to_string());

        // Test custom mapping
        assert_eq!(
            mapper.anthropic_to_bedrock("custom-claude-model").unwrap(),
            "us.anthropic.custom-claude-model-v1:0"
        );

        // Test default mapping still works
        assert_eq!(
            mapper
                .anthropic_to_bedrock("claude-3-haiku-20240307")
                .unwrap(),
            "us.anthropic.claude-3-haiku-20240307-v1:0"
        );
    }

    #[test]
    fn test_custom_override_default() {
        let mut custom_mappings = HashMap::new();
        custom_mappings.insert(
            "claude-3-haiku-20240307".to_string(),
            "anthropic.custom-haiku-override-v1:0".to_string(),
        );

        let mapper = ModelMapper::new(custom_mappings, "us-east-1".to_string());

        // Test that custom mapping overrides default
        assert_eq!(
            mapper
                .anthropic_to_bedrock("claude-3-haiku-20240307")
                .unwrap(),
            "anthropic.custom-haiku-override-v1:0"
        );
    }

    #[test]
    fn test_model_validation_with_aliases() {
        let mapper = ModelMapper::default();

        // Test direct model names
        assert_eq!(
            mapper
                .validate_anthropic_model("claude-3-sonnet-20240229")
                .unwrap(),
            "claude-3-sonnet-20240229"
        );

        // Test aliases (built into default mapping)
        assert_eq!(
            mapper.validate_anthropic_model("claude-3-sonnet").unwrap(),
            "claude-3-sonnet"
        );

        assert_eq!(
            mapper
                .validate_anthropic_model("claude-3-5-sonnet-latest")
                .unwrap(),
            "claude-3-5-sonnet-latest"
        );

        assert_eq!(
            mapper.validate_anthropic_model("claude-opus-4-0").unwrap(),
            "claude-opus-4-0"
        );
    }

    #[test]
    fn test_case_insensitive_validation() {
        let mapper = ModelMapper::default();

        // Test case variations
        assert_eq!(
            mapper
                .validate_anthropic_model("CLAUDE-3-SONNET-20240229")
                .unwrap(),
            "claude-3-sonnet-20240229"
        );

        assert_eq!(
            mapper
                .validate_anthropic_model("Claude-3-Haiku-20240307")
                .unwrap(),
            "claude-3-haiku-20240307"
        );
    }

    #[test]
    fn test_model_support_checks() {
        let mapper = ModelMapper::default();

        assert!(mapper.is_anthropic_model_supported("claude-3-sonnet-20240229"));
        assert!(mapper.is_anthropic_model_supported("claude-opus-4-20250514"));
        assert!(mapper.is_bedrock_model_supported("anthropic.claude-3-sonnet-20240229-v1:0"));

        assert!(!mapper.is_anthropic_model_supported("unsupported-model"));
        assert!(!mapper.is_bedrock_model_supported("unsupported.model"));
    }

    #[test]
    fn test_get_supported_models() {
        let mapper = ModelMapper::default();

        let anthropic_models = mapper.get_supported_anthropic_models();
        assert!(!anthropic_models.is_empty());
        assert!(anthropic_models.contains(&"claude-3-sonnet-20240229".to_string()));
        assert!(anthropic_models.contains(&"claude-opus-4-20250514".to_string()));

        let bedrock_models = mapper.get_supported_bedrock_models();
        assert!(!bedrock_models.is_empty());
        assert!(bedrock_models.contains(&"anthropic.claude-3-sonnet-20240229-v1:0".to_string()));
        assert!(bedrock_models.contains(&"anthropic.claude-opus-4-20250514-v1:0".to_string()));
    }

    #[test]
    fn test_latest_model_aliases() {
        let mapper = ModelMapper::default();

        // Test that latest aliases resolve to actual models
        let result = mapper
            .validate_anthropic_model("claude-3-5-sonnet-latest")
            .unwrap();
        assert_eq!(result, "claude-3-5-sonnet-latest");
        assert!(mapper.is_anthropic_model_supported(&result));

        // Verify the mapping works
        let bedrock_id = mapper.anthropic_to_bedrock(&result).unwrap();
        assert_eq!(bedrock_id, "us.anthropic.claude-3-5-sonnet-20241022-v2:0");
    }

    #[test]
    fn test_bidirectional_mapping_consistency() {
        let mapper = ModelMapper::default();

        // Test that mapping is bidirectional and consistent for core models
        let test_models = vec![
            "claude-opus-4-20250514",
            "claude-sonnet-4-20250514",
            "claude-3-5-sonnet-20241022",
            "claude-3-sonnet-20240229",
            "claude-3-haiku-20240307",
        ];

        for anthropic_model in test_models {
            let bedrock_model = mapper.anthropic_to_bedrock(anthropic_model).unwrap();
            // Strip region prefix for reverse mapping test
            let bedrock_without_prefix =
                bedrock_model.strip_prefix("us.").unwrap_or(&bedrock_model);
            let back_to_anthropic = mapper.bedrock_to_anthropic(bedrock_without_prefix).unwrap();
            assert_eq!(anthropic_model, back_to_anthropic);
        }
    }

    #[test]
    fn test_effective_mapping() {
        let mut custom_mappings = HashMap::new();
        custom_mappings.insert(
            "claude-3-haiku-20240307".to_string(),
            "anthropic.custom-haiku-v1:0".to_string(),
        );
        custom_mappings.insert(
            "custom-model".to_string(),
            "anthropic.custom-model-v1:0".to_string(),
        );

        let mapper = ModelMapper::new(custom_mappings, "us-east-1".to_string());
        let effective = mapper.get_effective_mapping();

        // Should have custom override
        assert_eq!(
            effective.get("claude-3-haiku-20240307"),
            Some(&"anthropic.custom-haiku-v1:0".to_string())
        );

        // Should have custom addition
        assert_eq!(
            effective.get("custom-model"),
            Some(&"anthropic.custom-model-v1:0".to_string())
        );

        // Should have default mappings
        assert_eq!(
            effective.get("claude-opus-4-20250514"),
            Some(&"anthropic.claude-opus-4-20250514-v1:0".to_string())
        );
    }
}
