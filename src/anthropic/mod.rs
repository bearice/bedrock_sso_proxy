pub mod model_mapping;
pub mod transform;

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Error types specific to Anthropic API format handling
#[derive(Error, Debug)]
pub enum AnthropicError {
    #[error("Unsupported model: {0}")]
    UnsupportedModel(String),

    #[error("Invalid request format: {0}")]
    InvalidRequest(String),

    #[error("Transformation failed: {0}")]
    TransformationError(String),

    #[error("Missing required field: {0}")]
    MissingField(String),
}

/// Anthropic API request format
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnthropicRequest {
    /// The model ID in Anthropic format (e.g., "claude-sonnet-4-20250514")
    pub model: String,

    /// Array of message objects
    pub messages: Vec<Message>,

    /// Maximum number of tokens to generate
    pub max_tokens: u32,

    /// Controls randomness: 0.0 is deterministic, 1.0 is maximum randomness
    #[serde(skip_serializing_if = "Option::is_none")]
    pub temperature: Option<f32>,

    /// Alternative to temperature for nucleus sampling
    #[serde(skip_serializing_if = "Option::is_none")]
    pub top_p: Option<f32>,

    /// Only sample from top K options
    #[serde(skip_serializing_if = "Option::is_none")]
    pub top_k: Option<u32>,

    /// Sequences where the API will stop generating
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stop_sequences: Option<Vec<String>>,

    /// Whether to stream the response
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stream: Option<bool>,

    /// System prompt to provide context (can be string or array of content blocks)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub system: Option<serde_json::Value>,
}

/// Anthropic API response format
#[derive(Debug, Serialize, Deserialize)]
pub struct AnthropicResponse {
    /// Unique identifier for this particular message
    pub id: String,

    /// Object type, will be "message"
    #[serde(rename = "type")]
    pub type_: String,

    /// Role of the message sender (should be "assistant")
    pub role: String,

    /// Array of content blocks
    pub content: Vec<ContentBlock>,

    /// The model that generated this response
    pub model: String,

    /// Reason why the model stopped generating
    pub stop_reason: String,

    /// The stop sequence that caused generation to stop, if any
    pub stop_sequence: Option<String>,

    /// Token usage information
    pub usage: Usage,
}

/// Message object in the conversation
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Message {
    /// Role of the message sender ("user", "assistant", or "system")
    pub role: String,

    /// Content of the message (can be string or array of content blocks)
    pub content: serde_json::Value,
}

/// Content block in a message or response
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ContentBlock {
    /// Type of content block ("text", "image", etc.)
    #[serde(rename = "type")]
    pub type_: String,

    /// Text content (present when type is "text")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,

    /// Additional fields for other content types can be added here
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

/// Token usage information
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Usage {
    /// Number of input tokens
    pub input_tokens: u32,

    /// Number of output tokens
    pub output_tokens: u32,
}

/// Streaming event for Server-Sent Events
#[derive(Debug, Serialize, Deserialize)]
pub struct StreamEvent {
    /// Type of event ("message_start", "content_block_delta", "message_delta", "message_stop")
    #[serde(rename = "type")]
    pub event_type: String,

    /// Event data (varies by event type)
    #[serde(flatten)]
    pub data: serde_json::Value,
}

impl From<AnthropicError> for crate::error::AppError {
    fn from(err: AnthropicError) -> Self {
        match err {
            AnthropicError::UnsupportedModel(msg) => {
                crate::error::AppError::BadRequest(format!("Unsupported model: {}", msg))
            }
            AnthropicError::InvalidRequest(msg) => {
                crate::error::AppError::BadRequest(format!("Invalid request: {}", msg))
            }
            AnthropicError::TransformationError(msg) => {
                crate::error::AppError::Internal(format!("Transformation error: {}", msg))
            }
            AnthropicError::MissingField(field) => {
                crate::error::AppError::BadRequest(format!("Missing required field: {}", field))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_anthropic_request_deserialization() {
        let json = r#"{
            "model": "claude-sonnet-4-20250514",
            "messages": [
                {
                    "role": "user",
                    "content": "Hello, how can you help me today?"
                }
            ],
            "max_tokens": 1000,
            "temperature": 0.7
        }"#;

        let request: AnthropicRequest = serde_json::from_str(json).unwrap();
        assert_eq!(request.model, "claude-sonnet-4-20250514");
        assert_eq!(request.max_tokens, 1000);
        assert_eq!(request.temperature, Some(0.7));
        assert_eq!(request.messages.len(), 1);
        assert_eq!(request.messages[0].role, "user");
    }

    #[test]
    fn test_anthropic_response_serialization() {
        let response = AnthropicResponse {
            id: "msg_01ABC123".to_string(),
            type_: "message".to_string(),
            role: "assistant".to_string(),
            content: vec![ContentBlock {
                type_: "text".to_string(),
                text: Some("Hello! I'm Claude, an AI assistant.".to_string()),
                extra: serde_json::Map::new(),
            }],
            model: "claude-sonnet-4-20250514".to_string(),
            stop_reason: "end_turn".to_string(),
            stop_sequence: None,
            usage: Usage {
                input_tokens: 12,
                output_tokens: 35,
            },
        };

        let json = serde_json::to_string_pretty(&response).unwrap();
        assert!(json.contains("msg_01ABC123"));
        assert!(json.contains("Hello! I'm Claude"));
        assert!(json.contains("input_tokens"));
    }

    #[test]
    fn test_anthropic_error_conversion() {
        let anthropic_err = AnthropicError::UnsupportedModel("invalid-model".to_string());
        let app_err: crate::error::AppError = anthropic_err.into();

        match app_err {
            crate::error::AppError::BadRequest(msg) => {
                assert!(msg.contains("Unsupported model: invalid-model"));
            }
            _ => panic!("Expected BadRequest error"),
        }
    }

    #[test]
    fn test_message_with_complex_content() {
        let json = r#"{
            "role": "user",
            "content": [
                {
                    "type": "text",
                    "text": "What's in this image?"
                },
                {
                    "type": "image",
                    "source": {
                        "type": "base64",
                        "media_type": "image/jpeg",
                        "data": "iVBORw0KGgoAAAANSUhEUgAA..."
                    }
                }
            ]
        }"#;

        let message: Message = serde_json::from_str(json).unwrap();
        assert_eq!(message.role, "user");
        assert!(message.content.is_array());

        let content_array = message.content.as_array().unwrap();
        assert_eq!(content_array.len(), 2);
        assert_eq!(content_array[0]["type"], "text");
        assert_eq!(content_array[1]["type"], "image");
    }
}
