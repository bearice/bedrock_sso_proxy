use super::{
    AnthropicError, AnthropicRequest, AnthropicResponse, ContentBlock, Usage,
    model_mapping::ModelMapper,
};

#[cfg(test)]
use super::Message;
use serde_json::{Value, json};

/// Transforms an Anthropic API request to Bedrock format
pub fn transform_anthropic_to_bedrock(
    request: AnthropicRequest,
    model_mapper: &ModelMapper,
) -> Result<(Value, String), AnthropicError> {
    // Validate and normalize the model name
    let normalized_model = model_mapper.validate_anthropic_model(&request.model)?;

    // Convert to Bedrock model ID
    let bedrock_model_id = model_mapper.anthropic_to_bedrock(&normalized_model)?;

    // Build the Bedrock request format
    let mut bedrock_request = json!({
        "anthropic_version": "bedrock-2023-05-31",
        "max_tokens": request.max_tokens,
        "messages": request.messages
    });

    // Add optional parameters if present
    if let Some(temperature) = request.temperature {
        bedrock_request["temperature"] = json!(temperature);
    }

    if let Some(top_p) = request.top_p {
        bedrock_request["top_p"] = json!(top_p);
    }

    if let Some(top_k) = request.top_k {
        bedrock_request["top_k"] = json!(top_k);
    }

    if let Some(stop_sequences) = request.stop_sequences {
        bedrock_request["stop_sequences"] = json!(stop_sequences);
    }

    if let Some(system) = request.system {
        // Handle system field - convert to string if it's an array of content blocks
        let system_string = match system {
            serde_json::Value::String(s) => s,
            serde_json::Value::Array(content_blocks) => {
                // Extract text from content blocks and concatenate
                let mut system_text = String::new();
                for block in content_blocks {
                    if let Some(text) = block.get("text").and_then(|t| t.as_str()) {
                        if !system_text.is_empty() {
                            system_text.push('\n');
                        }
                        system_text.push_str(text);
                    }
                }
                system_text
            }
            _ => {
                // For any other format, try to convert to string
                system.as_str().unwrap_or("").to_string()
            }
        };

        if !system_string.is_empty() {
            bedrock_request["system"] = json!(system_string);
        }
    }

    // Note: 'stream' parameter is handled at the HTTP level, not in the request body

    Ok((bedrock_request, bedrock_model_id))
}

/// Transforms a Bedrock API response to Anthropic format
pub fn transform_bedrock_to_anthropic(
    bedrock_response: Value,
    original_model: &str,
    model_mapper: &ModelMapper,
) -> Result<AnthropicResponse, AnthropicError> {
    // Extract required fields from Bedrock response
    let id = bedrock_response["id"]
        .as_str()
        .unwrap_or("msg_unknown")
        .to_string();

    let type_ = bedrock_response["type"]
        .as_str()
        .unwrap_or("message")
        .to_string();

    let role = bedrock_response["role"]
        .as_str()
        .unwrap_or("assistant")
        .to_string();

    let stop_reason = bedrock_response["stop_reason"]
        .as_str()
        .unwrap_or("end_turn")
        .to_string();

    let stop_sequence = bedrock_response["stop_sequence"]
        .as_str()
        .map(|s| s.to_string());

    // Transform content blocks
    let content = transform_content_blocks(&bedrock_response["content"])?;

    // Transform usage information
    let usage = transform_usage(&bedrock_response["usage"])?;

    // Determine the model name to return
    // Try to use the original model name from the request, but validate it
    let response_model = if model_mapper.is_anthropic_model_supported(original_model) {
        original_model.to_string()
    } else {
        // Fall back to the model from the response if available
        bedrock_response["model"]
            .as_str()
            .and_then(|bedrock_model| model_mapper.bedrock_to_anthropic(bedrock_model).ok())
            .unwrap_or_else(|| original_model.to_string())
    };

    Ok(AnthropicResponse {
        id,
        type_,
        role,
        content,
        model: response_model,
        stop_reason,
        stop_sequence,
        usage,
    })
}

/// Transforms content blocks from Bedrock to Anthropic format
fn transform_content_blocks(content_value: &Value) -> Result<Vec<ContentBlock>, AnthropicError> {
    let content_array = content_value.as_array().ok_or_else(|| {
        AnthropicError::TransformationError("Content must be an array".to_string())
    })?;

    let mut content_blocks = Vec::new();

    for block in content_array {
        let type_ = block["type"].as_str().unwrap_or("text").to_string();

        let text = block["text"].as_str().map(|s| s.to_string());

        // Extract any additional fields
        let mut extra = serde_json::Map::new();
        if let Some(obj) = block.as_object() {
            for (key, value) in obj {
                if key != "type" && key != "text" {
                    extra.insert(key.clone(), value.clone());
                }
            }
        }

        content_blocks.push(ContentBlock { type_, text, extra });
    }

    Ok(content_blocks)
}

/// Transforms usage information from Bedrock to Anthropic format
fn transform_usage(usage_value: &Value) -> Result<Usage, AnthropicError> {
    let input_tokens = usage_value["input_tokens"].as_u64().unwrap_or(0) as u32;

    let output_tokens = usage_value["output_tokens"].as_u64().unwrap_or(0) as u32;

    Ok(Usage {
        input_tokens,
        output_tokens,
    })
}

/// Transforms streaming event data from Bedrock to Anthropic format
pub fn transform_streaming_event(
    bedrock_chunk: &[u8],
    _model_mapper: &ModelMapper,
    original_model: &str,
) -> Result<Option<String>, AnthropicError> {
    // Parse the chunk as a string first
    let chunk_str = std::str::from_utf8(bedrock_chunk)
        .map_err(|e| AnthropicError::TransformationError(format!("Invalid UTF-8: {}", e)))?;

    // Handle Server-Sent Events format
    if let Some(data_part) = chunk_str.strip_prefix("data: ") {
        // Handle special cases
        if data_part.trim() == "[DONE]" {
            return Ok(Some("data: [DONE]\n\n".to_string()));
        }

        // Try to parse as JSON
        if let Ok(bedrock_data) = serde_json::from_str::<Value>(data_part) {
            // Transform the event data to Anthropic format
            let anthropic_event =
                transform_bedrock_event_to_anthropic(bedrock_data, original_model)?;
            let event_json = serde_json::to_string(&anthropic_event).map_err(|e| {
                AnthropicError::TransformationError(format!("JSON serialization failed: {}", e))
            })?;

            return Ok(Some(format!("data: {}\n\n", event_json)));
        }
    }

    // If we can't parse or transform the chunk, pass it through as-is
    // This ensures compatibility with various streaming formats
    Ok(Some(chunk_str.to_string()))
}

/// Transforms a Bedrock streaming event to Anthropic streaming format
fn transform_bedrock_event_to_anthropic(
    bedrock_event: Value,
    original_model: &str,
) -> Result<Value, AnthropicError> {
    // This is a simplified transformation for streaming events
    // In practice, you would need to handle different event types:
    // - message_start
    // - content_block_start
    // - content_block_delta
    // - content_block_stop
    // - message_delta
    // - message_stop

    // For now, we'll pass through most fields and ensure model consistency
    let mut anthropic_event = bedrock_event.clone();

    // Ensure the model field uses the original Anthropic model name
    if let Some(event_obj) = anthropic_event.as_object_mut() {
        if event_obj.contains_key("model") {
            event_obj.insert("model".to_string(), json!(original_model));
        }

        // Handle message events that might contain model information
        if let Some(message) = event_obj.get_mut("message") {
            if let Some(message_obj) = message.as_object_mut() {
                message_obj.insert("model".to_string(), json!(original_model));
            }
        }
    }

    Ok(anthropic_event)
}

/// Helper function to validate Anthropic request format
pub fn validate_anthropic_request(request: &AnthropicRequest) -> Result<(), AnthropicError> {
    // Check required fields
    if request.model.is_empty() {
        return Err(AnthropicError::MissingField("model".to_string()));
    }

    if request.messages.is_empty() {
        return Err(AnthropicError::MissingField("messages".to_string()));
    }

    if request.max_tokens == 0 {
        return Err(AnthropicError::InvalidRequest(
            "max_tokens must be greater than 0".to_string(),
        ));
    }

    // Validate temperature range
    if let Some(temp) = request.temperature {
        if !(0.0..=1.0).contains(&temp) {
            return Err(AnthropicError::InvalidRequest(
                "temperature must be between 0.0 and 1.0".to_string(),
            ));
        }
    }

    // Validate top_p range
    if let Some(top_p) = request.top_p {
        if !(0.0..=1.0).contains(&top_p) {
            return Err(AnthropicError::InvalidRequest(
                "top_p must be between 0.0 and 1.0".to_string(),
            ));
        }
    }

    // Validate top_k range
    if let Some(top_k) = request.top_k {
        if top_k == 0 {
            return Err(AnthropicError::InvalidRequest(
                "top_k must be greater than 0".to_string(),
            ));
        }
    }

    // Validate messages
    for (i, message) in request.messages.iter().enumerate() {
        if message.role.is_empty() {
            return Err(AnthropicError::InvalidRequest(format!(
                "message[{}] role cannot be empty",
                i
            )));
        }

        if !["user", "assistant", "system"].contains(&message.role.as_str()) {
            return Err(AnthropicError::InvalidRequest(format!(
                "message[{}] role must be 'user', 'assistant', or 'system'",
                i
            )));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_mapper() -> ModelMapper {
        ModelMapper::default()
    }

    fn create_test_anthropic_request() -> AnthropicRequest {
        AnthropicRequest {
            model: "claude-sonnet-4-20250514".to_string(),
            messages: vec![Message {
                role: "user".to_string(),
                content: json!("Hello, how can you help me today?"),
            }],
            max_tokens: 1000,
            temperature: Some(0.7),
            top_p: None,
            top_k: None,
            stop_sequences: None,
            stream: Some(false),
            system: None,
        }
    }

    fn create_test_bedrock_response() -> Value {
        json!({
            "id": "msg_01ABC123",
            "type": "message",
            "role": "assistant",
            "content": [
                {
                    "type": "text",
                    "text": "Hello! I'm Claude, an AI assistant."
                }
            ],
            "model": "anthropic.claude-sonnet-4-20250514-v1:0",
            "stop_reason": "end_turn",
            "stop_sequence": null,
            "usage": {
                "input_tokens": 12,
                "output_tokens": 35
            }
        })
    }

    #[test]
    fn test_anthropic_to_bedrock_transformation() {
        let mapper = create_test_mapper();
        let anthropic_request = create_test_anthropic_request();

        let (bedrock_request, model_id) =
            transform_anthropic_to_bedrock(anthropic_request, &mapper).unwrap();

        assert_eq!(model_id, "us.anthropic.claude-sonnet-4-20250514-v1:0");
        assert_eq!(bedrock_request["anthropic_version"], "bedrock-2023-05-31");
        assert_eq!(bedrock_request["max_tokens"], 1000);
        // Use approximate comparison for floating point values
        assert!((bedrock_request["temperature"].as_f64().unwrap() - 0.7).abs() < 0.001);
        assert!(bedrock_request["messages"].is_array());
    }

    #[test]
    fn test_bedrock_to_anthropic_transformation() {
        let mapper = create_test_mapper();
        let bedrock_response = create_test_bedrock_response();

        let anthropic_response =
            transform_bedrock_to_anthropic(bedrock_response, "claude-sonnet-4-20250514", &mapper)
                .unwrap();

        assert_eq!(anthropic_response.id, "msg_01ABC123");
        assert_eq!(anthropic_response.type_, "message");
        assert_eq!(anthropic_response.role, "assistant");
        assert_eq!(anthropic_response.model, "claude-sonnet-4-20250514");
        assert_eq!(anthropic_response.stop_reason, "end_turn");
        assert_eq!(anthropic_response.content.len(), 1);
        assert_eq!(anthropic_response.content[0].type_, "text");
        assert_eq!(
            anthropic_response.content[0].text,
            Some("Hello! I'm Claude, an AI assistant.".to_string())
        );
        assert_eq!(anthropic_response.usage.input_tokens, 12);
        assert_eq!(anthropic_response.usage.output_tokens, 35);
    }

    #[test]
    fn test_request_validation() {
        let mut request = create_test_anthropic_request();

        // Valid request should pass
        assert!(validate_anthropic_request(&request).is_ok());

        // Empty model should fail
        request.model = "".to_string();
        assert!(validate_anthropic_request(&request).is_err());
        request.model = "claude-sonnet-4-20250514".to_string();

        // Empty messages should fail
        request.messages = vec![];
        assert!(validate_anthropic_request(&request).is_err());
        request.messages = vec![Message {
            role: "user".to_string(),
            content: json!("Hello"),
        }];

        // Zero max_tokens should fail
        request.max_tokens = 0;
        assert!(validate_anthropic_request(&request).is_err());
        request.max_tokens = 1000;

        // Invalid temperature should fail
        request.temperature = Some(1.5);
        assert!(validate_anthropic_request(&request).is_err());
        request.temperature = Some(0.7);

        // Invalid top_p should fail
        request.top_p = Some(-0.1);
        assert!(validate_anthropic_request(&request).is_err());
    }

    #[test]
    fn test_unsupported_model_transformation() {
        let mapper = create_test_mapper();
        let mut request = create_test_anthropic_request();
        request.model = "unsupported-model".to_string();

        let result = transform_anthropic_to_bedrock(request, &mapper);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            AnthropicError::UnsupportedModel(_)
        ));
    }

    #[test]
    fn test_streaming_event_transformation() {
        let mapper = create_test_mapper();
        let chunk = b"data: {\"type\": \"content_block_delta\", \"delta\": {\"text\": \"Hello\"}}";

        let result = transform_streaming_event(chunk, &mapper, "claude-sonnet-4-20250514");
        assert!(result.is_ok());

        let transformed = result.unwrap();
        assert!(transformed.is_some());
        assert!(transformed.unwrap().starts_with("data: "));
    }

    #[test]
    fn test_done_event_passthrough() {
        let mapper = create_test_mapper();
        let chunk = b"data: [DONE]";

        let result = transform_streaming_event(chunk, &mapper, "claude-sonnet-4-20250514");
        assert!(result.is_ok());

        let transformed = result.unwrap();
        assert_eq!(transformed, Some("data: [DONE]\n\n".to_string()));
    }

    #[test]
    fn test_content_block_transformation() {
        let content_json = json!([
            {
                "type": "text",
                "text": "Hello world"
            },
            {
                "type": "image",
                "source": {
                    "type": "base64",
                    "data": "iVBORw0KGgo..."
                }
            }
        ]);

        let content_blocks = transform_content_blocks(&content_json).unwrap();
        assert_eq!(content_blocks.len(), 2);

        assert_eq!(content_blocks[0].type_, "text");
        assert_eq!(content_blocks[0].text, Some("Hello world".to_string()));

        assert_eq!(content_blocks[1].type_, "image");
        assert!(content_blocks[1].extra.contains_key("source"));
    }

    #[test]
    fn test_usage_transformation() {
        let usage_json = json!({
            "input_tokens": 50,
            "output_tokens": 100
        });

        let usage = transform_usage(&usage_json).unwrap();
        assert_eq!(usage.input_tokens, 50);
        assert_eq!(usage.output_tokens, 100);
    }

    #[test]
    fn test_model_alias_in_transformation() {
        let mapper = create_test_mapper();
        let mut request = create_test_anthropic_request();
        request.model = "claude-3-sonnet".to_string(); // Using alias

        let (_bedrock_request, model_id) =
            transform_anthropic_to_bedrock(request, &mapper).unwrap();

        // Should resolve to the actual model ID that the alias points to
        assert_eq!(model_id, "us.anthropic.claude-3-sonnet-20240229-v1:0");
    }

    #[test]
    fn test_system_field_as_array() {
        let mapper = create_test_mapper();
        let mut request = create_test_anthropic_request();

        // Set system field as array of content blocks (like the failing request)
        request.system = Some(json!([{
            "type": "text",
            "text": "You are a helpful assistant."
        }]));

        let (bedrock_request, _model_id) =
            transform_anthropic_to_bedrock(request, &mapper).unwrap();

        // Should convert array to string
        assert_eq!(bedrock_request["system"], "You are a helpful assistant.");
    }

    #[test]
    fn test_system_field_as_string() {
        let mapper = create_test_mapper();
        let mut request = create_test_anthropic_request();

        // Set system field as simple string
        request.system = Some(json!("You are a helpful assistant."));

        let (bedrock_request, _model_id) =
            transform_anthropic_to_bedrock(request, &mapper).unwrap();

        // Should pass through as string
        assert_eq!(bedrock_request["system"], "You are a helpful assistant.");
    }
}
