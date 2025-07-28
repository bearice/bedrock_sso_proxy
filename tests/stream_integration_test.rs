use bedrock_sso_proxy::{
    anthropic::transform::transform_bedrock_event_to_anthropic, model_service::EventStreamParser,
    test_utils::TestServerBuilder,
};
use bytes::Bytes;
use futures_util::StreamExt;
use std::sync::Arc;

async fn create_test_setup() -> (
    Arc<dyn bedrock_sso_proxy::model_service::ModelService>,
    Arc<dyn bedrock_sso_proxy::database::DatabaseManager>,
) {
    let server = TestServerBuilder::new().build().await;
    (server.model_service, server.database)
}

#[tokio::test]
async fn test_stream_integration_with_fixture() {
    let (model_service, _database) = create_test_setup().await;

    // Load the binary fixture
    let binary_data = include_bytes!("fixtures/stream-out.bin");

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
    let binary_data = include_bytes!("fixtures/stream-out.bin");

    // Test that ParsedEventStream correctly processes the binary data
    let stream = futures_util::stream::iter(
        vec![Bytes::from(binary_data.to_vec())]
            .into_iter()
            .map(Ok::<_, reqwest::Error>),
    );
    let boxed_stream = Box::new(stream);

    let usage_tracker = bedrock_sso_proxy::model_service::UsageTracker {
        model_request: bedrock_sso_proxy::model_service::ModelRequest {
            model_id: "claude-sonnet-4-20250514".to_string(),
            body: vec![],
            headers: axum::http::HeaderMap::new(),
            user_id: 1,
            endpoint_type: "bedrock".to_string(),
        },
        model_service: model_service.clone(),
        start_time: std::time::Instant::now(),
    };

    let parsed_event_stream =
        bedrock_sso_proxy::model_service::ParsedEventStream::new(boxed_stream, Some(usage_tracker));

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
    let binary_data = include_bytes!("fixtures/stream-out.bin");

    // Create stream response from model service
    let stream = futures_util::stream::iter(
        vec![Bytes::from(binary_data.to_vec())]
            .into_iter()
            .map(Ok::<_, reqwest::Error>),
    );
    let boxed_stream = Box::new(stream);

    let usage_tracker = bedrock_sso_proxy::model_service::UsageTracker {
        model_request: bedrock_sso_proxy::model_service::ModelRequest {
            model_id: "claude-sonnet-4-20250514".to_string(),
            body: vec![],
            headers: axum::http::HeaderMap::new(),
            user_id: 1,
            endpoint_type: "bedrock".to_string(),
        },
        model_service: model_service.clone(),
        start_time: std::time::Instant::now(),
    };

    let parsed_event_stream =
        bedrock_sso_proxy::model_service::ParsedEventStream::new(boxed_stream, Some(usage_tracker));

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
    let binary_data = include_bytes!("fixtures/stream-out.bin");

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
    let binary_data = include_bytes!("fixtures/stream-out.bin");

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
