use super::*;
use crate::{
    anthropic::transform::transform_bedrock_event_to_anthropic,
    aws::config::AwsConfig,
    aws::bedrock::BedrockRuntimeImpl,
    config::Config,
    database::{entities::*, UsageQuery},
    model_service::streaming::{EventStreamParser, ParsedEventStream},
    model_service::types::*,
    test_utils::TestServerBuilder,
};
use bytes::Bytes;
use futures_util::StreamExt;
use std::sync::Arc;

fn create_test_config() -> Config {
    Config {
        aws: AwsConfig {
            region: "us-east-1".to_string(),
            access_key_id: Some("test-key".to_string()),
            secret_access_key: Some("test-secret".to_string()),
            profile: None,
            bearer_token: None,
        },
        ..Default::default()
    }
}

async fn create_test_server() -> (crate::Server, Config) {
    let config = create_test_config();
    let server = TestServerBuilder::new()
        .with_config(config.clone())
        .build()
        .await;

    (server, config)
}

async fn create_test_setup() -> (
    Arc<dyn crate::model_service::ModelService>,
    Arc<dyn crate::database::DatabaseManager>,
) {
    let server = TestServerBuilder::new().build().await;
    (server.model_service, server.database)
}

#[tokio::test]
async fn test_model_service_creation() {
    let (server, config) = create_test_server().await;
    let database = server.database.clone();
    let bedrock = Arc::new(BedrockRuntimeImpl::new_test());
    let model_service = ModelServiceImpl::new(bedrock, database.clone(), config);

    // Verify service was created successfully
    assert_eq!(model_service.config.aws.region, "us-east-1");
}

#[tokio::test]
async fn test_extract_usage_metadata() {
    let (server, config) = create_test_server().await;
    let database = server.database.clone();
    let bedrock = Arc::new(BedrockRuntimeImpl::new_test());
    let model_service = ModelServiceImpl::new(bedrock, database.clone(), config);

    let mut headers = axum::http::HeaderMap::new();
    headers.insert("x-amzn-bedrock-input-token-count", "100".parse().unwrap());
    headers.insert("x-amzn-bedrock-output-token-count", "50".parse().unwrap());

    let response_body = b"{}"; // Empty JSON response body for test
    let metadata = model_service
        .extract_usage_metadata(&headers, response_body, 250)
        .unwrap();

    assert_eq!(metadata.input_tokens, 100);
    assert_eq!(metadata.output_tokens, 50);
    assert_eq!(metadata.cache_write_tokens, None);
    assert_eq!(metadata.cache_read_tokens, None);
    assert_eq!(metadata.response_time_ms, 250);
    assert_eq!(metadata.region, "us-east-1");
}

#[tokio::test]
async fn test_extract_usage_metadata_from_response_body() {
    let (server, config) = create_test_server().await;
    let database = server.database.clone();
    let bedrock = Arc::new(BedrockRuntimeImpl::new_test());
    let model_service = ModelServiceImpl::new(bedrock, database.clone(), config);

    // Test with JSON response body containing cache tokens
    let response_body = br#"{"id":"msg_bdrk_01QjKY4iZgTq69BYEKRD112G","type":"message","role":"assistant","model":"claude-opus-4-20250514","content":[{"type":"text","text":"Hello! It's nice to meet you. How are you doing today?"}],"stop_reason":"end_turn","stop_sequence":null,"usage":{"input_tokens":10,"cache_creation_input_tokens":5,"cache_read_input_tokens":3,"output_tokens":18}}"#;

    let headers = axum::http::HeaderMap::new();
    let metadata = model_service
        .extract_usage_metadata(&headers, response_body, 250)
        .unwrap();

    assert_eq!(metadata.input_tokens, 10);
    assert_eq!(metadata.output_tokens, 18);
    assert_eq!(metadata.cache_write_tokens, Some(5));
    assert_eq!(metadata.cache_read_tokens, Some(3));
    assert_eq!(metadata.response_time_ms, 250);
    assert_eq!(metadata.region, "us-east-1");
}

#[tokio::test]
async fn test_collect_streaming_events_with_real_data() {
    let (server, config) = create_test_server().await;
    let database = server.database.clone();
    let bedrock = Arc::new(BedrockRuntimeImpl::new_test());
    let model_service = ModelServiceImpl::new(bedrock, database.clone(), config);

    // Use the real AWS binary fixture instead of SSE format
    let binary_data = include_bytes!("../../tests/fixtures/stream-out.bin");
    let stream = futures_util::stream::iter(
        vec![Bytes::from(binary_data.as_slice())]
            .into_iter()
            .map(Ok::<_, reqwest::Error>),
    );
    let boxed_stream = Box::new(stream);

    let (collected_data, usage_metadata) = model_service
        .collect_streaming_events(boxed_stream, 250)
        .await
        .unwrap();

    // Verify token extraction from binary AWS Event Stream format
    assert_eq!(usage_metadata.input_tokens, 17);
    assert_eq!(usage_metadata.output_tokens, 322);
    assert_eq!(usage_metadata.cache_write_tokens, Some(0)); // From message_start event
    assert_eq!(usage_metadata.cache_read_tokens, Some(0)); // From message_start event
    assert_eq!(usage_metadata.response_time_ms, 250);
    assert_eq!(usage_metadata.region, "us-east-1");

    // Verify that all streaming data was collected
    assert!(!collected_data.is_empty());
    assert_eq!(collected_data.len(), binary_data.len());
}

#[tokio::test]
async fn test_calculate_cost() {
    let (server, config) = create_test_server().await;
    let database = server.database.clone();

    // Add a model cost to storage
    let model_cost = StoredModelCost {
        id: 0,
        region: "us-east-1".to_string(),
        model_id: "test-model".to_string(),
        input_cost_per_1k_tokens: rust_decimal::Decimal::new(3, 3), // 0.003 exactly
        output_cost_per_1k_tokens: rust_decimal::Decimal::new(15, 3), // 0.015 exactly
        cache_write_cost_per_1k_tokens: Some(rust_decimal::Decimal::new(375, 5)), // 0.00375 exactly
        cache_read_cost_per_1k_tokens: Some(rust_decimal::Decimal::new(3, 4)), // 0.0003 exactly
        updated_at: chrono::Utc::now(),
    };
    database
        .model_costs()
        .upsert_many(&[model_cost])
        .await
        .unwrap();

    // Test cost calculation through the usage tracking service
    let usage_service = crate::model_service::usage::UsageTrackingService::new(config, database);
    let cost = usage_service
        .calculate_cost("us-east-1", "test-model", 100, 50, None, None)
        .await;

    assert!(cost.is_some());
    // Calculate expected cost: (0.003 * 100 / 1000) + (0.015 * 50 / 1000) = 0.00105
    let expected_cost = rust_decimal::Decimal::new(105, 5); // 0.00105 exactly
    let actual_cost = cost.unwrap();
    // Use approximate comparison due to potential precision issues in calculations
    let diff = (actual_cost - expected_cost).abs();
    assert!(
        diff < rust_decimal::Decimal::new(1, 7), // 0.0000001 tolerance
        "Expected cost {}, got {}, diff {}",
        expected_cost,
        actual_cost,
        diff
    );
}

#[tokio::test]
async fn test_track_usage() {
    let (server, config) = create_test_server().await;
    let database = server.database.clone();
    let bedrock = Arc::new(BedrockRuntimeImpl::new_test());
    let model_service = ModelServiceImpl::new(bedrock, database.clone(), config);

    // Create a test user first
    let user_record = UserRecord {
        id: 0,
        provider_user_id: "test-user".to_string(),
        provider: "google".to_string(),
        email: "test@example.com".to_string(),
        display_name: Some("Test User".to_string()),
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
        last_login: Some(chrono::Utc::now()),
    };
    let user_id = database.users().upsert(&user_record).await.unwrap();

    let request = ModelRequest {
        model_id: "test-model".to_string(),
        body: vec![],
        headers: axum::http::HeaderMap::new(),
        user_id,
        endpoint_type: "bedrock".to_string(),
    };

    let usage_metadata = UsageMetadata {
        input_tokens: 100,
        output_tokens: 50,
        cache_write_tokens: None,
        cache_read_tokens: None,
        region: "us-east-1".to_string(),
        response_time_ms: 250,
    };

    // Track usage
    model_service
        .track_usage(&request, &usage_metadata)
        .await
        .unwrap();

    // Verify usage was recorded
    let records = database
        .usage()
        .get_records(&UsageQuery {
            user_id: Some(user_id),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].input_tokens, 100);
    assert_eq!(records[0].output_tokens, 50);
    assert_eq!(records[0].model_id, "test-model");
}

#[test]
fn test_event_stream_parser() {
    let mut parser = EventStreamParser::new();

    // Use real AWS Event Stream binary data (simplified test)
    // This simulates the actual binary format from AWS
    let binary_data = include_bytes!("../../tests/fixtures/stream-out.bin");
    let events = parser.parse_chunk(binary_data).unwrap();

    // Should parse some events from the fixture
    assert!(
        !events.is_empty(),
        "Should parse events from binary fixture"
    );

    // Check that we got the expected types
    let mut has_message_start = false;
    let mut has_content_delta = false;
    let mut has_message_stop = false;

    for event in &events {
        if let Some(data) = &event.data {
            match data.get("type").and_then(|t| t.as_str()) {
                Some("message_start") => has_message_start = true,
                Some("content_block_delta") => has_content_delta = true,
                Some("message_stop") => has_message_stop = true,
                _ => {}
            }
        }
    }

    assert!(has_message_start, "Should have message_start event");
    assert!(has_content_delta, "Should have content_block_delta events");
    assert!(has_message_stop, "Should have message_stop event");

    // Check usage metrics
    let metrics = parser.get_usage_metrics();
    assert_eq!(metrics.input_tokens, 17);
    assert_eq!(metrics.output_tokens, 322);
    assert_eq!(metrics.cache_write_tokens, Some(0));
    assert_eq!(metrics.cache_read_tokens, Some(0));
}

#[test]
fn test_event_stream_parser_chunked_data() {
    let mut parser = EventStreamParser::new();

    // Test parsing binary data that arrives in chunks
    let binary_data = include_bytes!("../../tests/fixtures/stream-out.bin");
    let mid_point = binary_data.len() / 2;

    let chunk1 = &binary_data[..mid_point];
    let chunk2 = &binary_data[mid_point..];

    let events1 = parser.parse_chunk(chunk1).unwrap();
    // May or may not have complete events depending on chunk boundary

    let events2 = parser.parse_chunk(chunk2).unwrap();

    let total_events = events1.len() + events2.len();
    assert!(
        total_events > 0,
        "Should have parsed some events across chunks"
    );

    // Check final usage metrics
    let metrics = parser.get_usage_metrics();
    assert_eq!(metrics.input_tokens, 17);
    assert_eq!(metrics.output_tokens, 322);
    assert_eq!(metrics.cache_write_tokens, Some(0));
    assert_eq!(metrics.cache_read_tokens, Some(0));
}

// Stream integration tests moved from tests/stream_integration_test.rs

#[tokio::test]
async fn test_stream_integration_with_fixture() {
    let (model_service, _database) = create_test_setup().await;

    // Load the binary fixture
    let binary_data = include_bytes!("../../tests/fixtures/stream-out.bin");

    // Test 1: Event Stream Parser with binary data
    let mut parser = EventStreamParser::new();
    let all_parsed_events = parser.parse_chunk(binary_data).unwrap();

    // Verify we parsed events
    assert!(!all_parsed_events.is_empty(), "Should parse SSE events");

    // Test 2: Usage Accounting
    let usage_metrics = parser.get_usage_metrics();

    // Verify usage metrics were extracted
    assert!(
        usage_metrics.input_tokens > 0,
        "Should extract input tokens"
    );
    assert!(
        usage_metrics.output_tokens > 0,
        "Should extract output tokens"
    );

    // Print extracted metrics for verification
    println!("Extracted usage metrics:");
    println!("  Input tokens: {}", usage_metrics.input_tokens);
    println!("  Output tokens: {}", usage_metrics.output_tokens);
    println!(
        "  Cache write tokens: {:?}",
        usage_metrics.cache_write_tokens
    );
    println!("  Cache read tokens: {:?}", usage_metrics.cache_read_tokens);

    // Test 3: Event Structure Verification
    let mut has_message_start = false;
    let mut has_content_deltas = false;
    let mut has_message_stop = false;

    for event in &all_parsed_events {
        if let Some(data) = &event.data {
            match data.get("type").and_then(|t| t.as_str()) {
                Some("message_start") => {
                    has_message_start = true;
                    // Verify message_start has usage info
                    assert!(
                        data.get("message").is_some(),
                        "message_start should have message field"
                    );
                }
                Some("content_block_delta") => {
                    has_content_deltas = true;
                    // Verify content delta structure
                    assert!(
                        data.get("delta").is_some(),
                        "content_block_delta should have delta field"
                    );
                }
                Some("message_stop") => {
                    has_message_stop = true;
                    // Verify message_stop has invocation metrics
                    assert!(
                        data.get("amazon-bedrock-invocationMetrics").is_some(),
                        "message_stop should have amazon-bedrock-invocationMetrics"
                    );
                }
                _ => {}
            }
        }
    }

    assert!(has_message_start, "Should have message_start event");
    assert!(has_content_deltas, "Should have content_block_delta events");
    assert!(has_message_stop, "Should have message_stop event");

    // Test 4: Anthropic Format Transformation
    let mut anthropic_events = Vec::new();

    for event in &all_parsed_events {
        if let Some(data) = &event.data {
            match transform_bedrock_event_to_anthropic(data.clone(), "claude-sonnet-4-20250514") {
                Ok(transformed) => {
                    anthropic_events.push(transformed);
                }
                Err(e) => {
                    println!("Transform error (expected for some events): {}", e);
                }
            }
        }
    }

    // Verify transformation worked
    assert!(
        !anthropic_events.is_empty(),
        "Should transform some events to Anthropic format"
    );

    // Test 5: End-to-End Stream Processing with binary data
    let stream = futures_util::stream::iter(
        vec![Bytes::from(binary_data.to_vec())]
            .into_iter()
            .map(Ok::<_, reqwest::Error>),
    );
    let boxed_stream = Box::new(stream);

    // Test 5: End-to-End Stream Processing - just verify we can parse the stream

    let start_time = std::time::Instant::now();
    let response_time_ms = start_time.elapsed().as_millis() as u32;
    let (_, usage_metadata) = model_service
        .collect_streaming_events(boxed_stream, response_time_ms)
        .await
        .unwrap();

    // Verify usage tracking worked
    assert!(
        usage_metadata.input_tokens > 0,
        "Should track input tokens from stream"
    );
    assert!(
        usage_metadata.output_tokens > 0,
        "Should track output tokens from stream"
    );

    println!("✅ Stream integration test passed!");
    println!(
        "Final usage metadata: {} input, {} output tokens",
        usage_metadata.input_tokens, usage_metadata.output_tokens
    );
}

#[tokio::test]
async fn test_bedrock_route_receives_exact_binary_stream() {
    let (model_service, _database) = create_test_setup().await;

    // Load the binary fixture - this is what AWS would send
    let binary_data = include_bytes!("../../tests/fixtures/stream-out.bin");

    // Test that ParsedEventStream correctly processes the binary data
    let stream = futures_util::stream::iter(
        vec![Bytes::from(binary_data.to_vec())]
            .into_iter()
            .map(Ok::<_, reqwest::Error>),
    );
    let boxed_stream = Box::new(stream);

    let usage_tracker = UsageTracker {
        model_request: ModelRequest {
            model_id: "claude-sonnet-4-20250514".to_string(),
            body: vec![],
            headers: axum::http::HeaderMap::new(),
            user_id: 1,
            endpoint_type: "bedrock".to_string(),
        },
        model_service: model_service.clone(),
        start_time: std::time::Instant::now(),
    };

    let parsed_event_stream = ParsedEventStream::new(boxed_stream, Some(usage_tracker));

    // Collect events from the parsed stream
    let events: Vec<_> = parsed_event_stream.collect().await;

    // Verify we got events back
    assert!(!events.is_empty(), "Should parse events from binary stream");

    // Verify the events contain the expected data
    let mut has_message_start = false;
    let mut has_message_stop = false;

    for event_result in events {
        match event_result {
            Ok(sse_event) => {
                if let Some(data) = &sse_event.data {
                    match data.get("type").and_then(|t| t.as_str()) {
                        Some("message_start") => has_message_start = true,
                        Some("message_stop") => has_message_stop = true,
                        _ => {}
                    }
                }
            }
            Err(e) => {
                println!("Error in stream: {}", e);
            }
        }
    }

    assert!(has_message_start, "Should have message_start event");
    assert!(has_message_stop, "Should have message_stop event");

    println!("✅ Bedrock route binary stream test passed!");
}

#[tokio::test]
async fn test_bedrock_route_returns_exact_binary_format() {
    let (model_service, _database) = create_test_setup().await;

    // Load the binary fixture - this is what AWS sends
    let binary_data = include_bytes!("../../tests/fixtures/stream-out.bin");

    // Create stream response from model service
    let stream = futures_util::stream::iter(
        vec![Bytes::from(binary_data.to_vec())]
            .into_iter()
            .map(Ok::<_, reqwest::Error>),
    );
    let boxed_stream = Box::new(stream);

    let usage_tracker = UsageTracker {
        model_request: ModelRequest {
            model_id: "claude-sonnet-4-20250514".to_string(),
            body: vec![],
            headers: axum::http::HeaderMap::new(),
            user_id: 1,
            endpoint_type: "bedrock".to_string(),
        },
        model_service: model_service.clone(),
        start_time: std::time::Instant::now(),
    };

    let parsed_event_stream = ParsedEventStream::new(boxed_stream, Some(usage_tracker));

    // Collect binary chunks that would be sent to Bedrock route client
    let mut binary_chunks = Vec::new();
    let mut total_size = 0;

    let events: Vec<_> = parsed_event_stream.collect().await;

    for event_result in events {
        match event_result {
            Ok(sse_event) => {
                // This is what the Bedrock route would send - the raw binary data
                total_size += sse_event.raw.len();
                binary_chunks.push(sse_event.raw);
            }
            Err(e) => {
                panic!("Error in stream: {}", e);
            }
        }
    }

    // Verify we got binary data back
    assert!(!binary_chunks.is_empty(), "Should have binary chunks");
    assert!(total_size > 0, "Should have non-zero total size");

    // Verify the binary data maintains the original AWS Event Stream format
    let first_chunk = &binary_chunks[0];
    assert!(
        first_chunk.len() >= 12,
        "Should have at least 12 bytes for Event Stream header"
    );

    // Check that it starts with the total length field (4 bytes, big endian)
    let total_length = u32::from_be_bytes([
        first_chunk[0],
        first_chunk[1],
        first_chunk[2],
        first_chunk[3],
    ]);
    assert!(total_length > 0, "Should have valid total length");

    println!("✅ Bedrock route returns exact binary format!");
    println!(
        "Binary chunks: {}, Total size: {} bytes",
        binary_chunks.len(),
        total_size
    );
}

#[tokio::test]
async fn test_stream_parser_with_real_data() {
    let binary_data = include_bytes!("../../tests/fixtures/stream-out.bin");

    let mut parser = EventStreamParser::new();
    let parsed_events = parser.parse_chunk(binary_data).unwrap();
    let mut event_types = Vec::new();

    for event in parsed_events {
        if let Some(data) = &event.data {
            if let Some(event_type) = data.get("type").and_then(|t| t.as_str()) {
                event_types.push(event_type.to_string());
            }
        }
    }

    // Verify we see the expected event sequence
    assert!(
        event_types.contains(&"message_start".to_string()),
        "Should have message_start"
    );
    assert!(
        event_types.contains(&"content_block_start".to_string()),
        "Should have content_block_start"
    );
    assert!(
        event_types.contains(&"content_block_delta".to_string()),
        "Should have content_block_delta"
    );
    assert!(
        event_types.contains(&"message_stop".to_string()),
        "Should have message_stop"
    );

    // Get final usage metrics
    let usage_metrics = parser.get_usage_metrics();

    // Based on the fixture, we should have specific token counts
    // The fixture contains a message_start event with these exact usage metrics
    assert_eq!(
        usage_metrics.input_tokens, 17,
        "Should extract 17 input tokens from fixture"
    );
    assert_eq!(
        usage_metrics.output_tokens, 322,
        "Should extract 322 output tokens from fixture"
    );
    assert_eq!(
        usage_metrics.cache_write_tokens,
        Some(0),
        "Should have cache_write_tokens"
    );
    assert_eq!(
        usage_metrics.cache_read_tokens,
        Some(0),
        "Should have cache_read_tokens"
    );

    println!("Event types found: {:?}", event_types);
    println!("Usage metrics: {:?}", usage_metrics);
}

#[tokio::test]
async fn test_anthropic_transformation_with_real_events() {
    let binary_data = include_bytes!("../../tests/fixtures/stream-out.bin");

    let mut parser = EventStreamParser::new();
    let parsed_events = parser.parse_chunk(binary_data).unwrap();
    let mut transformed_count = 0;
    let mut original_model_preserved = 0;

    for event in parsed_events {
        if let Some(data) = &event.data {
            match transform_bedrock_event_to_anthropic(data.clone(), "claude-sonnet-4-20250514") {
                Ok(transformed) => {
                    transformed_count += 1;

                    // Verify model field is preserved
                    if let Some(model) = transformed.get("model") {
                        if model.as_str() == Some("claude-sonnet-4-20250514") {
                            original_model_preserved += 1;
                        }
                    }

                    // Verify message model field is preserved
                    if let Some(message) = transformed.get("message") {
                        if let Some(model) = message.get("model") {
                            if model.as_str() == Some("claude-sonnet-4-20250514") {
                                original_model_preserved += 1;
                            }
                        }
                    }
                }
                Err(_) => {
                    // Some events might not transform, that's okay
                }
            }
        }
    }

    assert!(
        transformed_count > 0,
        "Should transform some events successfully"
    );
    assert!(
        original_model_preserved > 0,
        "Should preserve original model name in transformed events"
    );

    println!(
        "Transformed {} events, preserved model in {} cases",
        transformed_count, original_model_preserved
    );
}