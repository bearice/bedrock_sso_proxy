use std::collections::HashMap;

/// Regional prefix mapping for AWS Bedrock model IDs
/// Maps AWS region codes to their corresponding model ID prefixes
#[derive(Clone)]
pub struct RegionalModelMapping {
    region_to_prefix: HashMap<String, String>,
    prefix_to_region: HashMap<String, String>,
}

impl RegionalModelMapping {
    /// Create a new regional model mapping with default mappings
    pub fn new() -> Self {
        let mut prefix_to_region = HashMap::new();

        // Built-in default mappings for prefix to primary region
        prefix_to_region.insert("us".to_string(), "us-east-1".to_string());
        prefix_to_region.insert("apac".to_string(), "ap-northeast-1".to_string());
        prefix_to_region.insert("eu".to_string(), "eu-west-1".to_string());

        Self {
            region_to_prefix: HashMap::new(),
            prefix_to_region,
        }
    }

    /// Create a new regional model mapping with custom prefix mappings
    pub fn new_with_custom_mappings(custom_mappings: HashMap<String, String>) -> Self {
        let mut prefix_to_region = HashMap::new();

        // Start with built-in default mappings
        prefix_to_region.insert("us".to_string(), "us-east-1".to_string());
        prefix_to_region.insert("apac".to_string(), "ap-northeast-1".to_string());
        prefix_to_region.insert("eu".to_string(), "eu-west-1".to_string());

        // Override with custom mappings
        for (prefix, region) in custom_mappings {
            prefix_to_region.insert(prefix, region);
        }

        Self {
            region_to_prefix: HashMap::new(),
            prefix_to_region,
        }
    }

    /// Add or update a region-to-prefix mapping
    pub fn add_mapping(&mut self, region: String, prefix: String) {
        self.region_to_prefix.insert(region, prefix);
    }

    /// Add or update a prefix-to-region mapping (configurable)
    pub fn add_prefix_mapping(&mut self, prefix: String, region: String) {
        self.prefix_to_region.insert(prefix, region);
    }

    /// Get the prefix for a given region using pattern matching
    pub fn get_prefix(&self, region: &str) -> Option<String> {
        // Check explicit mappings first
        if let Some(prefix) = self.region_to_prefix.get(region) {
            return Some(prefix.clone());
        }

        // Use pattern matching for standard AWS regions
        if region.starts_with("us-") {
            Some("us".to_string())
        } else if region.starts_with("ap-") {
            Some("apac".to_string())
        } else if region.starts_with("eu-") {
            Some("eu".to_string())
        } else {
            None
        }
    }

    /// Add regional prefix to a model ID if not already present
    /// Returns the model ID with regional prefix added
    pub fn add_regional_prefix(&self, model_id: &str, region: &str) -> String {
        // Check if the model ID already has a regional prefix
        if self.has_regional_prefix(model_id) {
            return model_id.to_string();
        }

        // Get the prefix for the region
        if let Some(prefix) = self.get_prefix(region) {
            format!("{prefix}.{model_id}")
        } else {
            // If we don't have a mapping for this region, return the model ID as-is
            // This maintains backwards compatibility
            tracing::warn!("No regional prefix mapping found for region: {}", region);
            model_id.to_string()
        }
    }

    /// Strip regional prefix from a model ID
    /// Returns the model ID without regional prefix for cost tracking
    pub fn strip_regional_prefix(&self, model_id: &str) -> String {
        // Check if the model ID has a regional prefix pattern
        if let Some(dot_index) = model_id.find('.') {
            let potential_prefix = &model_id[..dot_index];

            // Check if this prefix is one of our known regional prefixes
            let known_prefixes = ["us", "apac", "eu"];
            if known_prefixes.contains(&potential_prefix) {
                return model_id[dot_index + 1..].to_string();
            }
        }

        // If no regional prefix found, return as-is
        model_id.to_string()
    }

    /// Check if a model ID already has a regional prefix
    pub fn has_regional_prefix(&self, model_id: &str) -> bool {
        if let Some(dot_index) = model_id.find('.') {
            let potential_prefix = &model_id[..dot_index];
            let known_prefixes = ["us", "apac", "eu"];
            return known_prefixes.contains(&potential_prefix);
        }
        false
    }

    /// Get the region for a given prefix using configurable mapping
    pub fn get_region_for_prefix(&self, prefix: &str) -> Option<String> {
        self.prefix_to_region.get(prefix).cloned()
    }

    /// Parse region from a model ID that has a regional prefix
    /// Returns the region if the prefix is recognized, None otherwise
    pub fn parse_region_from_model_id(&self, model_id: &str) -> Option<String> {
        if let Some(dot_index) = model_id.find('.') {
            let prefix = &model_id[..dot_index];

            // Check explicit region-to-prefix mappings first
            for (region, region_prefix) in &self.region_to_prefix {
                if region_prefix == prefix {
                    return Some(region.clone());
                }
            }

            // Use configurable prefix-to-region mapping (with built-in defaults)
            if let Some(region) = self.prefix_to_region.get(prefix) {
                return Some(region.clone());
            }
        }
        None
    }
}

impl Default for RegionalModelMapping {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_regional_mapping() {
        let mapping = RegionalModelMapping::new();

        // Test some basic mappings
        assert_eq!(mapping.get_prefix("us-east-1"), Some("us".to_string()));
        assert_eq!(mapping.get_prefix("eu-west-1"), Some("eu".to_string()));
        assert_eq!(
            mapping.get_prefix("ap-southeast-1"),
            Some("apac".to_string())
        );
        assert_eq!(mapping.get_prefix("unknown-region"), None);
    }

    #[test]
    fn test_add_mapping() {
        let mut mapping = RegionalModelMapping::new();
        mapping.add_mapping("custom-region".to_string(), "custom".to_string());

        assert_eq!(
            mapping.get_prefix("custom-region"),
            Some("custom".to_string())
        );
    }

    #[test]
    fn test_add_regional_prefix() {
        let mapping = RegionalModelMapping::new();

        // Test adding prefix to model without prefix
        let result =
            mapping.add_regional_prefix("anthropic.claude-sonnet-4-20250514-v1:0", "us-east-1");
        assert_eq!(result, "us.anthropic.claude-sonnet-4-20250514-v1:0");

        // Test AP region gets apac prefix
        let result = mapping
            .add_regional_prefix("anthropic.claude-sonnet-4-20250514-v1:0", "ap-southeast-1");
        assert_eq!(result, "apac.anthropic.claude-sonnet-4-20250514-v1:0");

        // Test model that already has prefix - should not double-prefix
        let result =
            mapping.add_regional_prefix("us.anthropic.claude-sonnet-4-20250514-v1:0", "us-east-1");
        assert_eq!(result, "us.anthropic.claude-sonnet-4-20250514-v1:0");

        // Test unknown region - should return original
        let result = mapping
            .add_regional_prefix("anthropic.claude-sonnet-4-20250514-v1:0", "unknown-region");
        assert_eq!(result, "anthropic.claude-sonnet-4-20250514-v1:0");
    }

    #[test]
    fn test_strip_regional_prefix() {
        let mapping = RegionalModelMapping::new();

        // Test stripping known prefix
        let result = mapping.strip_regional_prefix("us.anthropic.claude-sonnet-4-20250514-v1:0");
        assert_eq!(result, "anthropic.claude-sonnet-4-20250514-v1:0");

        // Test stripping EU prefix
        let result = mapping.strip_regional_prefix("eu.anthropic.claude-sonnet-4-20250514-v1:0");
        assert_eq!(result, "anthropic.claude-sonnet-4-20250514-v1:0");

        // Test stripping APAC prefix
        let result = mapping.strip_regional_prefix("apac.anthropic.claude-sonnet-4-20250514-v1:0");
        assert_eq!(result, "anthropic.claude-sonnet-4-20250514-v1:0");

        // Test model without regional prefix - should return as-is
        let result = mapping.strip_regional_prefix("anthropic.claude-sonnet-4-20250514-v1:0");
        assert_eq!(result, "anthropic.claude-sonnet-4-20250514-v1:0");

        // Test model with unknown prefix - should return as-is
        let result =
            mapping.strip_regional_prefix("unknown.anthropic.claude-sonnet-4-20250514-v1:0");
        assert_eq!(result, "unknown.anthropic.claude-sonnet-4-20250514-v1:0");
    }

    #[test]
    fn test_has_regional_prefix() {
        let mapping = RegionalModelMapping::new();

        // Test model with known prefix
        assert!(mapping.has_regional_prefix("us.anthropic.claude-sonnet-4-20250514-v1:0"));
        assert!(mapping.has_regional_prefix("eu.anthropic.claude-sonnet-4-20250514-v1:0"));
        assert!(mapping.has_regional_prefix("apac.anthropic.claude-sonnet-4-20250514-v1:0"));

        // Test model without prefix
        assert!(!mapping.has_regional_prefix("anthropic.claude-sonnet-4-20250514-v1:0"));

        // Test model with unknown prefix
        assert!(!mapping.has_regional_prefix("unknown.anthropic.claude-sonnet-4-20250514-v1:0"));
    }

    #[test]
    fn test_parse_region_from_model_id() {
        let mapping = RegionalModelMapping::new();

        // Test parsing region from model ID with known prefix (uses built-in defaults)
        let region =
            mapping.parse_region_from_model_id("us.anthropic.claude-sonnet-4-20250514-v1:0");
        assert_eq!(region, Some("us-east-1".to_string()));

        let region =
            mapping.parse_region_from_model_id("apac.anthropic.claude-sonnet-4-20250514-v1:0");
        assert_eq!(region, Some("ap-northeast-1".to_string()));

        let region =
            mapping.parse_region_from_model_id("eu.anthropic.claude-sonnet-4-20250514-v1:0");
        assert_eq!(region, Some("eu-west-1".to_string()));

        // Test parsing region from model ID without prefix
        let region = mapping.parse_region_from_model_id("anthropic.claude-sonnet-4-20250514-v1:0");
        assert!(region.is_none());

        // Test parsing region from model ID with unknown prefix
        let region =
            mapping.parse_region_from_model_id("unknown.anthropic.claude-sonnet-4-20250514-v1:0");
        assert!(region.is_none());
    }

    #[test]
    fn test_configurable_prefix_mapping() {
        let mut mapping = RegionalModelMapping::new();

        // Test built-in defaults
        assert_eq!(
            mapping.get_region_for_prefix("us"),
            Some("us-east-1".to_string())
        );
        assert_eq!(
            mapping.get_region_for_prefix("apac"),
            Some("ap-northeast-1".to_string())
        );
        assert_eq!(
            mapping.get_region_for_prefix("eu"),
            Some("eu-west-1".to_string())
        );

        // Test configurable mapping
        mapping.add_prefix_mapping("us".to_string(), "us-west-2".to_string());
        assert_eq!(
            mapping.get_region_for_prefix("us"),
            Some("us-west-2".to_string())
        );

        // Test custom prefix
        mapping.add_prefix_mapping("custom".to_string(), "custom-region-1".to_string());
        assert_eq!(
            mapping.get_region_for_prefix("custom"),
            Some("custom-region-1".to_string())
        );
    }

    #[test]
    fn test_round_trip_prefix_operations() {
        let mapping = RegionalModelMapping::new();
        let original_model_id = "anthropic.claude-sonnet-4-20250514-v1:0";

        // Add prefix, then strip it - should get back original
        let with_prefix = mapping.add_regional_prefix(original_model_id, "us-east-1");
        let stripped = mapping.strip_regional_prefix(&with_prefix);

        assert_eq!(stripped, original_model_id);
    }

    #[test]
    fn test_new_with_custom_mappings() {
        let mut custom_mappings = HashMap::new();
        custom_mappings.insert("eu".to_string(), "eu-central-1".to_string());
        custom_mappings.insert("custom".to_string(), "us-west-2".to_string());

        let mapping = RegionalModelMapping::new_with_custom_mappings(custom_mappings);

        // Test that defaults are still present
        assert_eq!(
            mapping.get_region_for_prefix("us"),
            Some("us-east-1".to_string())
        );
        assert_eq!(
            mapping.get_region_for_prefix("apac"),
            Some("ap-northeast-1".to_string())
        );

        // Test that custom override works
        assert_eq!(
            mapping.get_region_for_prefix("eu"),
            Some("eu-central-1".to_string())
        );

        // Test that custom addition works
        assert_eq!(
            mapping.get_region_for_prefix("custom"),
            Some("us-west-2".to_string())
        );
    }
}
