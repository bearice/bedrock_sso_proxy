use super::AnthropicError;
use std::collections::HashMap;

/// Maps Anthropic model names to AWS Bedrock model IDs
pub struct ModelMapper {
    /// Anthropic model name -> Bedrock model ID
    anthropic_to_bedrock: HashMap<String, String>,
    /// Bedrock model ID -> Anthropic model name
    bedrock_to_anthropic: HashMap<String, String>,
}

impl ModelMapper {
    /// Create a new model mapper with predefined mappings
    pub fn new() -> Self {
        let mut anthropic_to_bedrock = HashMap::new();
        let mut bedrock_to_anthropic = HashMap::new();

        // Claude 3 models (as per DESIGN.md)
        let mappings = vec![
            (
                "claude-3-sonnet-20240229",
                "anthropic.claude-3-sonnet-20240229-v1:0",
            ),
            (
                "claude-3-haiku-20240307",
                "anthropic.claude-3-haiku-20240307-v1:0",
            ),
            (
                "claude-3-opus-20240229",
                "anthropic.claude-3-opus-20240229-v1:0",
            ),
            (
                "claude-3-5-sonnet-20240620",
                "anthropic.claude-3-5-sonnet-20240620-v1:0",
            ),
            (
                "claude-3-5-haiku-20241022",
                "anthropic.claude-3-5-haiku-20241022-v1:0",
            ),
            // Add more recent models as they become available
            (
                "claude-3-5-sonnet-20241022",
                "anthropic.claude-3-5-sonnet-20241022-v1:0",
            ),
        ];

        for (anthropic, bedrock) in mappings {
            anthropic_to_bedrock.insert(anthropic.to_string(), bedrock.to_string());
            bedrock_to_anthropic.insert(bedrock.to_string(), anthropic.to_string());
        }

        Self {
            anthropic_to_bedrock,
            bedrock_to_anthropic,
        }
    }

    /// Convert Anthropic model name to Bedrock model ID
    pub fn anthropic_to_bedrock(&self, anthropic_model: &str) -> Result<String, AnthropicError> {
        self.anthropic_to_bedrock
            .get(anthropic_model)
            .cloned()
            .ok_or_else(|| AnthropicError::UnsupportedModel(anthropic_model.to_string()))
    }

    /// Convert Bedrock model ID to Anthropic model name
    pub fn bedrock_to_anthropic(&self, bedrock_model: &str) -> Result<String, AnthropicError> {
        self.bedrock_to_anthropic
            .get(bedrock_model)
            .cloned()
            .ok_or_else(|| AnthropicError::UnsupportedModel(bedrock_model.to_string()))
    }

    /// Check if an Anthropic model name is supported
    pub fn is_anthropic_model_supported(&self, model: &str) -> bool {
        self.anthropic_to_bedrock.contains_key(model)
    }

    /// Check if a Bedrock model ID is supported for Anthropic API
    pub fn is_bedrock_model_supported(&self, model: &str) -> bool {
        self.bedrock_to_anthropic.contains_key(model)
    }

    /// Get all supported Anthropic model names
    pub fn get_supported_anthropic_models(&self) -> Vec<String> {
        self.anthropic_to_bedrock.keys().cloned().collect()
    }

    /// Get all supported Bedrock model IDs
    pub fn get_supported_bedrock_models(&self) -> Vec<String> {
        self.bedrock_to_anthropic.keys().cloned().collect()
    }

    /// Validate and normalize an Anthropic model name
    /// This handles aliases and ensures the model is supported
    pub fn validate_anthropic_model(&self, model: &str) -> Result<String, AnthropicError> {
        // Check if the model is directly supported
        if self.is_anthropic_model_supported(model) {
            return Ok(model.to_string());
        }

        // Handle common aliases or variations
        let normalized = match model {
            // Handle version aliases
            "claude-3-sonnet" | "claude-3-sonnet-latest" => "claude-3-sonnet-20240229",
            "claude-3-haiku" | "claude-3-haiku-latest" => "claude-3-haiku-20240307",
            "claude-3-opus" | "claude-3-opus-latest" => "claude-3-opus-20240229",
            "claude-3-5-sonnet" | "claude-3-5-sonnet-latest" => "claude-3-5-sonnet-20241022", // Latest version
            "claude-3-5-haiku" | "claude-3-5-haiku-latest" => "claude-3-5-haiku-20241022",
            // Handle case variations
            _ => {
                let lower_model = model.to_lowercase();
                // Try to find a case-insensitive match
                for supported_model in self.anthropic_to_bedrock.keys() {
                    if supported_model.to_lowercase() == lower_model {
                        return Ok(supported_model.clone());
                    }
                }
                model // Return original if no alias found
            }
        };

        // Check if the normalized model is supported
        if self.is_anthropic_model_supported(normalized) {
            Ok(normalized.to_string())
        } else {
            Err(AnthropicError::UnsupportedModel(model.to_string()))
        }
    }
}

impl Default for ModelMapper {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_anthropic_to_bedrock_mapping() {
        let mapper = ModelMapper::new();

        let result = mapper
            .anthropic_to_bedrock("claude-3-sonnet-20240229")
            .unwrap();
        assert_eq!(result, "anthropic.claude-3-sonnet-20240229-v1:0");

        let result = mapper
            .anthropic_to_bedrock("claude-3-haiku-20240307")
            .unwrap();
        assert_eq!(result, "anthropic.claude-3-haiku-20240307-v1:0");

        let result = mapper
            .anthropic_to_bedrock("claude-3-opus-20240229")
            .unwrap();
        assert_eq!(result, "anthropic.claude-3-opus-20240229-v1:0");
    }

    #[test]
    fn test_bedrock_to_anthropic_mapping() {
        let mapper = ModelMapper::new();

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
        let mapper = ModelMapper::new();

        let result = mapper.anthropic_to_bedrock("unsupported-model");
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            AnthropicError::UnsupportedModel(_)
        ));
    }

    #[test]
    fn test_model_validation_with_aliases() {
        let mapper = ModelMapper::new();

        // Test direct model names
        assert_eq!(
            mapper
                .validate_anthropic_model("claude-3-sonnet-20240229")
                .unwrap(),
            "claude-3-sonnet-20240229"
        );

        // Test aliases
        assert_eq!(
            mapper.validate_anthropic_model("claude-3-sonnet").unwrap(),
            "claude-3-sonnet-20240229"
        );

        assert_eq!(
            mapper
                .validate_anthropic_model("claude-3-sonnet-latest")
                .unwrap(),
            "claude-3-sonnet-20240229"
        );

        assert_eq!(
            mapper
                .validate_anthropic_model("claude-3-5-sonnet")
                .unwrap(),
            "claude-3-5-sonnet-20241022"
        );
    }

    #[test]
    fn test_case_insensitive_validation() {
        let mapper = ModelMapper::new();

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
        let mapper = ModelMapper::new();

        assert!(mapper.is_anthropic_model_supported("claude-3-sonnet-20240229"));
        assert!(mapper.is_bedrock_model_supported("anthropic.claude-3-sonnet-20240229-v1:0"));

        assert!(!mapper.is_anthropic_model_supported("unsupported-model"));
        assert!(!mapper.is_bedrock_model_supported("unsupported.model"));
    }

    #[test]
    fn test_get_supported_models() {
        let mapper = ModelMapper::new();

        let anthropic_models = mapper.get_supported_anthropic_models();
        assert!(!anthropic_models.is_empty());
        assert!(anthropic_models.contains(&"claude-3-sonnet-20240229".to_string()));

        let bedrock_models = mapper.get_supported_bedrock_models();
        assert!(!bedrock_models.is_empty());
        assert!(bedrock_models.contains(&"anthropic.claude-3-sonnet-20240229-v1:0".to_string()));
    }

    #[test]
    fn test_latest_model_aliases() {
        let mapper = ModelMapper::new();

        // Test that latest aliases resolve to actual models
        let result = mapper
            .validate_anthropic_model("claude-3-5-sonnet-latest")
            .unwrap();
        assert_eq!(result, "claude-3-5-sonnet-20241022");
        assert!(mapper.is_anthropic_model_supported(&result));

        // Verify the mapping works
        let bedrock_id = mapper.anthropic_to_bedrock(&result).unwrap();
        assert_eq!(bedrock_id, "anthropic.claude-3-5-sonnet-20241022-v1:0");
    }

    #[test]
    fn test_bidirectional_mapping_consistency() {
        let mapper = ModelMapper::new();

        // Test that mapping is bidirectional and consistent
        for anthropic_model in mapper.get_supported_anthropic_models() {
            let bedrock_model = mapper.anthropic_to_bedrock(&anthropic_model).unwrap();
            let back_to_anthropic = mapper.bedrock_to_anthropic(&bedrock_model).unwrap();
            assert_eq!(anthropic_model, back_to_anthropic);
        }
    }
}
