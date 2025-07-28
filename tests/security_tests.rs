use axum::{
    body::Body,
    http::{Method, Request, StatusCode},
};
use base64::Engine;
use bedrock_sso_proxy::auth::jwt::OAuthClaims;
use std::sync::Arc;

mod common;
use common::{RequestBuilder, TestHarness, helpers};

#[tokio::test]
async fn test_security_sql_injection_attempts() {
    let harness = TestHarness::new_for_security_tests().await;
    let created_user_id = harness.create_test_user("test1@example.com").await;
    let token = harness.create_integration_token(created_user_id);

    // Test SQL injection attempts in model ID
    let malicious_model_ids = vec![
        "'; DROP TABLE users; --",
        "1' OR '1'='1",
        "'; SELECT * FROM secrets; --",
        "../../../etc/passwd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    ];

    for model_id in malicious_model_ids {
        let encoded_model_id = urlencoding::encode(model_id);
        let request = Request::builder()
            .uri(format!("/bedrock/model/{}/invoke", encoded_model_id))
            .method("POST")
            .header("Authorization", format!("Bearer {}", token))
            .header("Content-Type", "application/json")
            .body(Body::from(r#"{"messages": []}"#))
            .unwrap();

        let response = harness.make_request(request).await;
        
        // With mock AWS: Authentication must succeed first
        assert_ne!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "SQL injection should not bypass authentication for model ID: {}",
            model_id
        );

        // Mock AWS should detect and reject malicious model IDs
        // This tests that our proxy correctly forwards the malicious input to AWS
        // AWS (mock) should reject SQL injection patterns in model IDs
        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "Mock AWS should reject SQL injection in model ID: {}",
            model_id
        );
    }
}

#[tokio::test]
async fn test_security_xss_attempts() {
    let harness = TestHarness::new_for_security_tests().await;
    let created_user_id = harness.create_test_user("test2@example.com").await;
    let token = harness.create_security_token(created_user_id, 3600);

    // Test XSS payloads in request body
    let xss_payloads = vec![
        r#"{"messages": [{"role": "user", "content": "<script>alert('xss')</script>"}]}"#,
        r#"{"messages": [{"role": "user", "content": "javascript:alert('xss')"}]}"#,
        r#"{"messages": [{"role": "user", "content": "<img src=x onerror=alert('xss')>"}]}"#,
    ];

    for payload in xss_payloads {
        let request = RequestBuilder::invoke_model_with_auth("test-model", &token, payload);

        let response = harness.make_request(request).await;
        
        // Authentication must succeed first
        assert_ne!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "XSS payload should not bypass authentication: {}",
            payload
        );

        // Mock AWS should detect and reject XSS patterns in request body
        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "Mock AWS should reject XSS payload: {}",
            payload
        );
    }
}

#[tokio::test]
async fn test_security_oversized_requests() {
    let harness = TestHarness::new_for_security_tests().await;
    let created_user_id = harness.create_test_user("test3@example.com").await;
    let token = harness.create_security_token(created_user_id, 3600);

    // Create extremely large payload (1MB)
    let large_content = "A".repeat(1024 * 1024);
    let large_payload = format!(
        r#"{{"messages": [{{"role": "user", "content": "{}"}}]}}"#,
        large_content
    );

    let request = RequestBuilder::invoke_model_with_auth("test-model", &token, &large_payload);

    let response = harness.make_request(request).await;
    // The key security test: Large payloads should NOT cause authentication bypass
    // Authentication should succeed, then AWS processes the request
    assert_ne!(
        response.status(),
        StatusCode::UNAUTHORIZED,
        "Large payload should not bypass authentication"
    );

    // AWS may process large payloads normally or reject them
    let acceptable_statuses = [
        StatusCode::OK,                    // AWS processes normally
        StatusCode::BAD_REQUEST,           // AWS rejects large payload
        StatusCode::FORBIDDEN,             // AWS access denied
        StatusCode::PAYLOAD_TOO_LARGE,     // AWS payload size limit
        StatusCode::INTERNAL_SERVER_ERROR, // AWS service error
    ];

    helpers::assert_status_in(&response, &acceptable_statuses, "oversized request");
}

#[tokio::test]
async fn test_security_header_injection() {
    let harness = TestHarness::new_for_security_tests().await;
    let created_user_id = harness.create_test_user("test4@example.com").await;
    let token = harness.create_security_token(created_user_id, 3600);

    // Test header injection attempts
    let malicious_headers = vec![
        ("X-Forwarded-For", "127.0.0.1\r\nX-Injected: malicious"),
        ("User-Agent", "Mozilla/5.0\r\nX-Injected: malicious"),
        ("Referer", "http://example.com\r\nX-Injected: malicious"),
    ];

    for (header_name, header_value) in malicious_headers {
        // Note: Most HTTP libraries will reject headers with CRLF, but we test anyway
        let request_result = Request::builder()
            .uri("/bedrock/model/test-model/invoke")
            .method("POST")
            .header("Authorization", format!("Bearer {}", token))
            .header("Content-Type", "application/json")
            .header(header_name, header_value)
            .body(Body::from(r#"{"messages": []}"#));

        // Some malicious headers might be rejected at the HTTP layer
        if let Ok(request) = request_result {
            let response = harness.make_request(request).await;
            // The key security test: Header injection should NOT cause authentication bypass
            assert_ne!(
                response.status(),
                StatusCode::UNAUTHORIZED,
                "Header injection should not bypass authentication: {} = {}",
                header_name,
                header_value
            );

            // AWS may process header injection normally or reject it
            let acceptable_statuses = [
                StatusCode::OK,                    // AWS processes normally
                StatusCode::BAD_REQUEST,           // AWS rejects malformed headers
                StatusCode::FORBIDDEN,             // AWS access denied
                StatusCode::INTERNAL_SERVER_ERROR, // AWS service error
            ];

            helpers::assert_status_in(
                &response,
                &acceptable_statuses,
                &format!("header injection: {} = {}", header_name, header_value),
            );
        }
    }
}

#[tokio::test]
async fn test_security_invalid_content_types() {
    let harness = TestHarness::new_for_security_tests().await;
    let created_user_id = harness.create_test_user("test5@example.com").await;
    let token = harness.create_security_token(created_user_id, 3600);

    // Test various invalid or unusual content types
    let invalid_content_types = vec![
        "application/x-evil",
        "text/html",
        "application/javascript",
        "image/jpeg",
        "../../../etc/passwd",
        "application/json; charset=utf-8\r\nX-Injected: malicious",
    ];

    for content_type in invalid_content_types {
        let request_result = RequestBuilder::with_content_type(
            "/bedrock/model/test-model/invoke",
            Method::POST,
            &token,
            content_type,
            r#"{"messages": []}"#,
        );

        match request_result {
            Ok(request) => {
                let response = harness.make_request(request).await;
                // The key security test: Invalid content types should NOT cause authentication bypass
                assert_ne!(
                    response.status(),
                    StatusCode::UNAUTHORIZED,
                    "Invalid content type should not bypass authentication: {}",
                    content_type
                );

                // AWS may process invalid content types normally or reject them
                let acceptable_statuses = [
                    StatusCode::OK,                     // AWS processes normally
                    StatusCode::BAD_REQUEST,            // AWS rejects invalid content type
                    StatusCode::FORBIDDEN,              // AWS access denied
                    StatusCode::UNSUPPORTED_MEDIA_TYPE, // AWS unsupported media type
                    StatusCode::INTERNAL_SERVER_ERROR,  // AWS service error
                ];

                helpers::assert_status_in(
                    &response,
                    &acceptable_statuses,
                    &format!("content type: {}", content_type),
                );
            }
            Err(_) => {
                // Some invalid headers are rejected at the HTTP layer, which is expected
                // This is actually good security behavior
            }
        }
    }
}

#[tokio::test]
async fn test_security_path_traversal() {
    let harness = TestHarness::new_for_security_tests().await;
    let created_user_id = harness.create_test_user("test6@example.com").await;
    let token = harness.create_security_token(created_user_id, 3600);

    // Test path traversal attempts
    let path_traversal_attempts = vec![
        "../../etc/passwd",
        "../../../windows/system32/config/sam",
        "..%2F..%2F..%2Fetc%2Fpasswd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "....//....//....//etc/passwd",
    ];

    for path in path_traversal_attempts {
        let request = RequestBuilder::invoke_model_with_auth(path, &token, r#"{"messages": []}"#);

        let response = harness.make_request(request).await;
        // Path traversal attempts: The proxy forwards requests to AWS, so 200 OK is possible
        // if AWS processes the malicious model ID normally. We mainly want to ensure
        // no file system access or information disclosure occurs at the proxy level.
        let acceptable_statuses = [
            StatusCode::OK, // AWS might process it normally
            StatusCode::BAD_REQUEST,
            StatusCode::NOT_FOUND,
            StatusCode::METHOD_NOT_ALLOWED, // Invalid method/route combination
            StatusCode::INTERNAL_SERVER_ERROR,
        ];

        helpers::assert_status_in(
            &response,
            &acceptable_statuses,
            &format!("path traversal: {}", path),
        );
    }
}

#[tokio::test]
async fn test_security_malformed_json_bodies() {
    let harness = TestHarness::new_for_security_tests().await;
    let created_user_id = harness.create_test_user("test7@example.com").await;
    let token = harness.create_security_token(created_user_id, 3600);

    // Test various malformed JSON bodies
    let malformed_json = vec![
        r#"{"messages": [}"#,                                  // Syntax error
        r#"{"messages": ["#,                                   // Incomplete
        r#"{"messages": [{"role": "user", "content": "test""#, // Missing closing braces
        r#"invalid json"#,                                     // Not JSON at all
        r#"{"messages": null}"#,                               // Null messages
        r#"{"messages": [{"role": null, "content": null}]}"#,  // Null fields
        r#"{}"#,                                               // Empty object
        r#"[]"#,                                               // Array instead of object
        r#"null"#,                                             // Just null
        r#""""#,                                               // Just string
        r#"123"#,                                              // Just number
    ];

    for json_body in malformed_json {
        let request = RequestBuilder::invoke_model_with_auth("test-model", &token, json_body);

        let response = harness.make_request(request).await;
        // Malformed JSON should be rejected with client error or handled gracefully
        helpers::assert_status_in(
            &response,
            &[
                StatusCode::BAD_REQUEST,
                StatusCode::FORBIDDEN,
                StatusCode::UNPROCESSABLE_ENTITY,
                StatusCode::INTERNAL_SERVER_ERROR,
                StatusCode::OK, // Some might be forwarded to AWS
            ],
            &format!("malformed JSON: {}", json_body),
        );
    }
}

#[tokio::test]
async fn test_security_http_method_tampering() {
    let harness = TestHarness::new_for_security_tests().await;
    let created_user_id = harness.create_test_user("test8@example.com").await;
    let token = harness.create_security_token(created_user_id, 3600);

    // Test various HTTP methods on protected endpoints
    let methods = vec![
        Method::GET,
        Method::PUT,
        Method::DELETE,
        Method::PATCH,
        Method::HEAD,
        Method::OPTIONS,
        Method::TRACE,
    ];

    for method in methods {
        let request = RequestBuilder::custom_request(
            "/bedrock/model/test-model/invoke",
            method.clone(),
            &token,
            &[],
            r#"{"messages": []}"#,
        );

        let response = harness.make_request(request).await;

        // Only POST should be allowed for invoke endpoints
        if method == Method::POST {
            // POST might succeed or fail with business logic errors, but not method errors
            assert_ne!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
        } else {
            // Other methods should be rejected
            helpers::assert_status_with_context(
                &response,
                StatusCode::METHOD_NOT_ALLOWED,
                &format!("{} method", method),
            );
        }
    }
}

#[tokio::test]
async fn test_security_jwt_algorithm_confusion() {
    let harness = TestHarness::new_for_security_tests().await;
    let created_user_id = harness.create_test_user("test9@example.com").await;

    let claims = OAuthClaims::new(created_user_id, 3600);

    // Test 1: Create a manually crafted "none" algorithm token
    // This simulates the classic algorithm confusion attack
    let none_payload = format!(
        r#"{{"alg":"none","typ":"JWT"}}.{}.{}"#,
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_string(&claims).unwrap()),
        "" // No signature for "none" algorithm
    );

    let request =
        RequestBuilder::invoke_model_with_auth("test-model", &none_payload, r#"{"messages": []}"#);

    let response = harness.make_request(request).await;
    // Should reject "none" algorithm tokens
    helpers::assert_status_with_context(
        &response,
        StatusCode::UNAUTHORIZED,
        "none algorithm token",
    );

    // Test 2: Try different algorithms that might be accepted by mistake
    let malicious_algorithms = vec!["HS384", "HS512", "RS256", "ES256"];

    for alg in malicious_algorithms {
        // Create manually crafted header with different algorithm
        let malicious_header = format!(r#"{{"alg":"{}","typ":"JWT"}}"#, alg);
        let malicious_token = format!(
            "{}.{}.invalid_signature",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&malicious_header),
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(serde_json::to_string(&claims).unwrap())
        );

        let request = RequestBuilder::invoke_model_with_auth(
            "test-model",
            &malicious_token,
            r#"{"messages": []}"#,
        );

        let response = harness.make_request(request).await;
        // Should reject tokens with wrong algorithms
        helpers::assert_status_with_context(
            &response,
            StatusCode::UNAUTHORIZED,
            &format!("{} algorithm token", alg),
        );
    }

    // Test 3: Verify that valid HS256 token still works (positive control)
    let valid_token = harness.create_security_token(created_user_id, 3600);

    let request =
        RequestBuilder::invoke_model_with_auth("test-model", &valid_token, r#"{"messages": []}"#);

    let response = harness.make_request(request).await;
    // Valid HS256 token should not be rejected for auth reasons
    assert_ne!(
        response.status(),
        StatusCode::UNAUTHORIZED,
        "Valid HS256 token should be accepted"
    );

    // AWS may process the request normally or reject with service errors
    let acceptable_statuses = [
        StatusCode::OK,                    // AWS processes normally
        StatusCode::BAD_REQUEST,           // AWS rejects request
        StatusCode::FORBIDDEN,             // AWS access denied
        StatusCode::INTERNAL_SERVER_ERROR, // AWS service error
    ];

    helpers::assert_status_in(&response, &acceptable_statuses, "valid HS256 token");
}

#[tokio::test]
async fn test_security_rate_limiting_simulation() {
    let harness = Arc::new(TestHarness::new_for_security_tests().await);
    let created_user_id = harness.create_test_user("test10@example.com").await;
    let token = harness.create_security_token(created_user_id, 3600);

    // Simulate rapid fire requests (potential DoS attempt)
    let mut handles = vec![];

    for i in 0..50 {
        let harness_clone = harness.clone();
        let token_clone = token.clone();

        let handle = tokio::spawn(async move {
            let request = RequestBuilder::health_with_auth(&token_clone);

            let response = harness_clone.make_request(request).await;
            (i, response.status())
        });

        handles.push(handle);
    }

    // Execute all requests concurrently
    let results = futures_util::future::join_all(handles).await;

    // Verify server doesn't crash under load
    for result in results {
        let (i, status) = result.unwrap();
        // Should handle load gracefully - all requests should succeed since no rate limiting is implemented
        assert_eq!(
            status,
            StatusCode::OK,
            "Request {} failed with status {}: rate limiting simulation should not cause failures",
            i,
            status
        );
    }
}

#[tokio::test]
async fn test_security_api_key_sql_injection() {
    let harness = TestHarness::new_for_security_tests().await;
    let created_user_id = harness.create_test_user("apikey@example.com").await;
    let api_key = harness.create_test_api_key(created_user_id, "Security Test Key").await;

    // Test SQL injection attempts in model ID with API key authentication
    let malicious_model_ids = vec![
        "'; DROP TABLE api_keys; --",
        "1' OR '1'='1",
        "'; SELECT * FROM users; --",
    ];

    for model_id in malicious_model_ids {
        let encoded_model_id = urlencoding::encode(model_id);
        
        // Test with X-API-Key header
        let request = RequestBuilder::invoke_model_with_api_key_header(
            &encoded_model_id, 
            &api_key, 
            r#"{"messages": []}"#
        );

        let response = harness.make_request(request).await;
        
        // API key authentication must succeed first
        assert_ne!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "SQL injection should not bypass API key authentication for model ID: {}",
            model_id
        );

        // Mock AWS should reject malicious model IDs
        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "Mock AWS should reject SQL injection in model ID with API key: {}",
            model_id
        );
    }
}

#[tokio::test]
async fn test_security_api_key_bearer_auth() {
    let harness = TestHarness::new_for_security_tests().await;
    let created_user_id = harness.create_test_user("bearer@example.com").await;
    let api_key = harness.create_test_api_key(created_user_id, "Bearer Test Key").await;

    // Test malicious payloads with Bearer token format for API keys
    let xss_payloads = vec![
        r#"{"messages": [{"role": "user", "content": "<script>alert('xss')</script>"}]}"#,
        r#"{"messages": [{"role": "user", "content": "javascript:alert('xss')"}]}"#,
    ];

    for payload in xss_payloads {
        // Test with Authorization Bearer header (API key in Bearer format)
        let request = RequestBuilder::invoke_model_with_api_key_bearer(
            "test-model",
            &api_key,
            payload
        );

        let response = harness.make_request(request).await;
        
        // API key authentication must succeed first
        assert_ne!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "XSS payload should not bypass API key bearer authentication: {}",
            payload
        );

        // Mock AWS should reject XSS payloads
        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "Mock AWS should reject XSS payload with API key bearer: {}",
            payload
        );
    }
}

#[tokio::test]
async fn test_security_invalid_api_key() {
    let harness = TestHarness::new_for_security_tests().await;

    let malicious_api_keys = vec![
        "SSOK_'; DROP TABLE api_keys; --",
        "SSOK_<script>alert('xss')</script>",
        "SSOK_../../etc/passwd",
        "not_an_api_key",
        "Bearer invalid_jwt_token",
    ];

    for fake_key in malicious_api_keys {
        let request = RequestBuilder::invoke_model_with_api_key_header(
            "test-model",
            fake_key,
            r#"{"messages": []}"#
        );

        let response = harness.make_request(request).await;
        
        // Invalid API keys should be rejected at authentication layer
        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "Invalid API key should be rejected: {}",
            fake_key
        );
    }
}
