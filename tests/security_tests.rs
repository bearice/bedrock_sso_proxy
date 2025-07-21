use axum::{
    body::Body,
    http::{Method, Request, StatusCode},
};
use base64::Engine;
use bedrock_sso_proxy::{Config, Server, auth::{AuthConfig, jwt::{JwtService, parse_algorithm}}, aws_http::AwsHttpClient};
use jsonwebtoken::{EncodingKey, Header, encode};
use serde::{Deserialize, Serialize};
use std::{
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use tower::ServiceExt;

#[derive(Debug, Serialize, Deserialize)]
struct SecurityClaims {
    sub: String,
    exp: usize,
    malicious_field: Option<String>,
}

fn create_security_token(secret: &str, sub: &str, exp_offset: i64) -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let exp = (now + exp_offset) as usize;

    let claims = SecurityClaims {
        sub: sub.to_string(),
        exp,
        malicious_field: Some("malicious_payload".to_string()),
    };

    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_ref()),
    )
    .unwrap()
}

#[tokio::test]
async fn test_security_sql_injection_attempts() {
    let config = Config::default();
    let jwt_service = JwtService::new(config.jwt.secret.clone(), parse_algorithm(&config.jwt.algorithm).unwrap());
    let auth_config = Arc::new(AuthConfig::new(jwt_service));
    let aws_http_client = AwsHttpClient::new_test();

    let server = Server::new(config.clone());
    let app = server.create_app(auth_config, aws_http_client);

    let token = create_security_token(&config.jwt.secret, "user123", 3600);

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
            .uri(format!("/model/{}/invoke", encoded_model_id))
            .method("POST")
            .header("Authorization", format!("Bearer {}", token))
            .header("Content-Type", "application/json")
            .body(Body::from(r#"{"messages": []}"#))
            .unwrap();

        let response = app.clone().oneshot(request).await.unwrap();
        // Should not expose internal server errors for malicious model IDs
        // Expecting either 400 Bad Request or 500 Internal Server Error, but not exposing system details
        assert_ne!(
            response.status(),
            StatusCode::OK,
            "Malicious model ID '{}' should not succeed",
            model_id
        );
        assert_ne!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "Should not be an auth issue for model ID: {}",
            model_id
        );
    }
}

#[tokio::test]
async fn test_security_xss_attempts() {
    let config = Config::default();
    let jwt_service = JwtService::new(config.jwt.secret.clone(), parse_algorithm(&config.jwt.algorithm).unwrap());
    let auth_config = Arc::new(AuthConfig::new(jwt_service));
    let aws_http_client = AwsHttpClient::new_test();

    let server = Server::new(config.clone());
    let app = server.create_app(auth_config, aws_http_client);

    let token = create_security_token(&config.jwt.secret, "user123", 3600);

    // Test XSS payloads in request body
    let xss_payloads = vec![
        r#"{"messages": [{"role": "user", "content": "<script>alert('xss')</script>"}]}"#,
        r#"{"messages": [{"role": "user", "content": "javascript:alert('xss')"}]}"#,
        r#"{"messages": [{"role": "user", "content": "<img src=x onerror=alert('xss')>"}]}"#,
    ];

    for payload in xss_payloads {
        let request = Request::builder()
            .uri("/model/test-model/invoke")
            .method("POST")
            .header("Authorization", format!("Bearer {}", token))
            .header("Content-Type", "application/json")
            .body(Body::from(payload))
            .unwrap();

        let response = app.clone().oneshot(request).await.unwrap();
        // XSS payloads should be processed normally by the proxy (AWS will handle content filtering)
        // We expect either success (proxy forwards) or server error (AWS rejects)
        assert!(
            response.status() == StatusCode::OK
                || response.status() == StatusCode::INTERNAL_SERVER_ERROR
                || response.status() == StatusCode::BAD_REQUEST,
            "Unexpected status {} for XSS payload",
            response.status()
        );
    }
}

#[tokio::test]
async fn test_security_oversized_requests() {
    let config = Config::default();
    let jwt_service = JwtService::new(config.jwt.secret.clone(), parse_algorithm(&config.jwt.algorithm).unwrap());
    let auth_config = Arc::new(AuthConfig::new(jwt_service));
    let aws_http_client = AwsHttpClient::new_test();

    let server = Server::new(config.clone());
    let app = server.create_app(auth_config, aws_http_client);

    let token = create_security_token(&config.jwt.secret, "user123", 3600);

    // Create extremely large payload (1MB)
    let large_content = "A".repeat(1024 * 1024);
    let large_payload = format!(
        r#"{{"messages": [{{"role": "user", "content": "{}"}}]}}"#,
        large_content
    );

    let request = Request::builder()
        .uri("/model/test-model/invoke")
        .method("POST")
        .header("Authorization", format!("Bearer {}", token))
        .header("Content-Type", "application/json")
        .body(Body::from(large_payload))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    // Large payloads should either be accepted by proxy or rejected with appropriate error
    // 413 Payload Too Large, 400 Bad Request, or 500 Internal Server Error are acceptable
    assert!(
        response.status() == StatusCode::PAYLOAD_TOO_LARGE
            || response.status() == StatusCode::BAD_REQUEST
            || response.status() == StatusCode::INTERNAL_SERVER_ERROR
            || response.status() == StatusCode::OK,
        "Unexpected status {} for oversized request",
        response.status()
    );
}

#[tokio::test]
async fn test_security_header_injection() {
    let config = Config::default();
    let jwt_service = JwtService::new(config.jwt.secret.clone(), parse_algorithm(&config.jwt.algorithm).unwrap());
    let auth_config = Arc::new(AuthConfig::new(jwt_service));
    let aws_http_client = AwsHttpClient::new_test();

    let server = Server::new(config.clone());
    let app = server.create_app(auth_config, aws_http_client);

    let token = create_security_token(&config.jwt.secret, "user123", 3600);

    // Test header injection attempts
    let malicious_headers = vec![
        ("X-Forwarded-For", "127.0.0.1\r\nX-Injected: malicious"),
        ("User-Agent", "Mozilla/5.0\r\nX-Injected: malicious"),
        ("Referer", "http://example.com\r\nX-Injected: malicious"),
    ];

    for (header_name, header_value) in malicious_headers {
        // Note: Most HTTP libraries will reject headers with CRLF, but we test anyway
        let request_result = Request::builder()
            .uri("/model/test-model/invoke")
            .method("POST")
            .header("Authorization", format!("Bearer {}", token))
            .header("Content-Type", "application/json")
            .header(header_name, header_value)
            .body(Body::from(r#"{"messages": []}"#));

        // Some malicious headers might be rejected at the HTTP layer
        if let Ok(request) = request_result {
            let response = app.clone().oneshot(request).await.unwrap();
            // Malicious headers should either be stripped/ignored or cause request rejection
            assert!(
                response.status() == StatusCode::OK
                    || response.status() == StatusCode::BAD_REQUEST
                    || response.status() == StatusCode::INTERNAL_SERVER_ERROR,
                "Unexpected status {} for header injection attempt",
                response.status()
            );
        }
    }
}

#[tokio::test]
async fn test_security_invalid_content_types() {
    let config = Config::default();
    let jwt_service = JwtService::new(config.jwt.secret.clone(), parse_algorithm(&config.jwt.algorithm).unwrap());
    let auth_config = Arc::new(AuthConfig::new(jwt_service));
    let aws_http_client = AwsHttpClient::new_test();

    let server = Server::new(config.clone());
    let app = server.create_app(auth_config, aws_http_client);

    let token = create_security_token(&config.jwt.secret, "user123", 3600);

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
        let request_result = Request::builder()
            .uri("/model/test-model/invoke")
            .method("POST")
            .header("Authorization", format!("Bearer {}", token))
            .header("Content-Type", content_type)
            .body(Body::from(r#"{"messages": []}"#));

        match request_result {
            Ok(request) => {
                let response = app.clone().oneshot(request).await.unwrap();
                // Invalid content types should be either accepted (proxy forwards) or rejected
                assert!(
                    response.status() == StatusCode::OK
                        || response.status() == StatusCode::BAD_REQUEST
                        || response.status() == StatusCode::UNSUPPORTED_MEDIA_TYPE
                        || response.status() == StatusCode::INTERNAL_SERVER_ERROR,
                    "Unexpected status {} for content type: {}",
                    response.status(),
                    content_type
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
    let config = Config::default();
    let jwt_service = JwtService::new(config.jwt.secret.clone(), parse_algorithm(&config.jwt.algorithm).unwrap());
    let auth_config = Arc::new(AuthConfig::new(jwt_service));
    let aws_http_client = AwsHttpClient::new_test();

    let server = Server::new(config.clone());
    let app = server.create_app(auth_config, aws_http_client);

    let token = create_security_token(&config.jwt.secret, "user123", 3600);

    // Test path traversal attempts
    let path_traversal_attempts = vec![
        "../../etc/passwd",
        "../../../windows/system32/config/sam",
        "..%2F..%2F..%2Fetc%2Fpasswd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "....//....//....//etc/passwd",
    ];

    for path in path_traversal_attempts {
        let request = Request::builder()
            .uri(format!("/model/{}/invoke", path))
            .method("POST")
            .header("Authorization", format!("Bearer {}", token))
            .header("Content-Type", "application/json")
            .body(Body::from(r#"{"messages": []}"#))
            .unwrap();

        let response = app.clone().oneshot(request).await.unwrap();
        // Path traversal attempts should not succeed or expose file system info
        assert_ne!(
            response.status(),
            StatusCode::OK,
            "Path traversal '{}' should not succeed",
            path
        );
        // Should get client error (400) or server error, but not expose filesystem
        assert!(
            response.status() == StatusCode::BAD_REQUEST
                || response.status() == StatusCode::NOT_FOUND
                || response.status() == StatusCode::INTERNAL_SERVER_ERROR,
            "Unexpected status {} for path traversal: {}",
            response.status(),
            path
        );
    }
}

#[tokio::test]
async fn test_security_malformed_json_bodies() {
    let config = Config::default();
    let jwt_service = JwtService::new(config.jwt.secret.clone(), parse_algorithm(&config.jwt.algorithm).unwrap());
    let auth_config = Arc::new(AuthConfig::new(jwt_service));
    let aws_http_client = AwsHttpClient::new_test();

    let server = Server::new(config.clone());
    let app = server.create_app(auth_config, aws_http_client);

    let token = create_security_token(&config.jwt.secret, "user123", 3600);

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
        let request = Request::builder()
            .uri("/model/test-model/invoke")
            .method("POST")
            .header("Authorization", format!("Bearer {}", token))
            .header("Content-Type", "application/json")
            .body(Body::from(json_body))
            .unwrap();

        let response = app.clone().oneshot(request).await.unwrap();
        // Malformed JSON should be rejected with client error or handled gracefully
        assert!(
            response.status() == StatusCode::BAD_REQUEST
                || response.status() == StatusCode::UNPROCESSABLE_ENTITY
                || response.status() == StatusCode::INTERNAL_SERVER_ERROR
                || response.status() == StatusCode::OK, // Some might be forwarded to AWS
            "Unexpected status {} for malformed JSON",
            response.status()
        );
    }
}

#[tokio::test]
async fn test_security_http_method_tampering() {
    let config = Config::default();
    let jwt_service = JwtService::new(config.jwt.secret.clone(), parse_algorithm(&config.jwt.algorithm).unwrap());
    let auth_config = Arc::new(AuthConfig::new(jwt_service));
    let aws_http_client = AwsHttpClient::new_test();

    let server = Server::new(config.clone());
    let app = server.create_app(auth_config, aws_http_client);

    let token = create_security_token(&config.jwt.secret, "user123", 3600);

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
        let request = Request::builder()
            .uri("/model/test-model/invoke")
            .method(method.clone())
            .header("Authorization", format!("Bearer {}", token))
            .header("Content-Type", "application/json")
            .body(Body::from(r#"{"messages": []}"#))
            .unwrap();

        let response = app.clone().oneshot(request).await.unwrap();

        // Only POST should be allowed for invoke endpoints
        if method == Method::POST {
            // POST might succeed or fail with business logic errors, but not method errors
            assert_ne!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
        } else {
            // Other methods should be rejected
            assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
        }
    }
}

#[tokio::test]
async fn test_security_jwt_algorithm_confusion() {
    let config = Config::default();
    let jwt_service = JwtService::new(config.jwt.secret.clone(), parse_algorithm(&config.jwt.algorithm).unwrap());
    let auth_config = Arc::new(AuthConfig::new(jwt_service));
    let aws_http_client = AwsHttpClient::new_test();

    let server = Server::new(config.clone());
    let app = server.create_app(auth_config, aws_http_client);

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as usize;

    let claims = SecurityClaims {
        sub: "malicious_user".to_string(),
        exp: now + 3600,
        malicious_field: Some("algorithm_confusion".to_string()),
    };

    // Test 1: Create a manually crafted "none" algorithm token
    // This simulates the classic algorithm confusion attack
    let none_payload = format!(
        r#"{{"alg":"none","typ":"JWT"}}.{}.{}"#,
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_string(&claims).unwrap()),
        "" // No signature for "none" algorithm
    );

    let request = Request::builder()
        .uri("/model/test-model/invoke")
        .method("POST")
        .header("Authorization", format!("Bearer {}", none_payload))
        .header("Content-Type", "application/json")
        .body(Body::from(r#"{"messages": []}"#))
        .unwrap();

    let response = app.clone().oneshot(request).await.unwrap();
    // Should reject "none" algorithm tokens
    assert_eq!(
        response.status(),
        StatusCode::UNAUTHORIZED,
        "Server should reject 'none' algorithm tokens"
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

        let request = Request::builder()
            .uri("/model/test-model/invoke")
            .method("POST")
            .header("Authorization", format!("Bearer {}", malicious_token))
            .header("Content-Type", "application/json")
            .body(Body::from(r#"{"messages": []}"#))
            .unwrap();

        let response = app.clone().oneshot(request).await.unwrap();
        // Should reject tokens with wrong algorithms
        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "Server should reject '{}' algorithm tokens",
            alg
        );
    }

    // Test 3: Verify that valid HS256 token still works (positive control)
    let valid_header = Header::default(); // HS256 is the default algorithm

    let valid_token = encode(
        &valid_header,
        &claims,
        &EncodingKey::from_secret(config.jwt.secret.as_ref()),
    )
    .unwrap();

    let request = Request::builder()
        .uri("/model/test-model/invoke")
        .method("POST")
        .header("Authorization", format!("Bearer {}", valid_token))
        .header("Content-Type", "application/json")
        .body(Body::from(r#"{"messages": []}"#))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    // Valid HS256 token should not be rejected for auth reasons
    assert_ne!(
        response.status(),
        StatusCode::UNAUTHORIZED,
        "Valid HS256 token should be accepted"
    );
}

#[tokio::test]
async fn test_security_rate_limiting_simulation() {
    let config = Config::default();
    let jwt_service = JwtService::new(config.jwt.secret.clone(), parse_algorithm(&config.jwt.algorithm).unwrap());
    let auth_config = Arc::new(AuthConfig::new(jwt_service));
    let aws_http_client = AwsHttpClient::new_test();

    let server = Server::new(config.clone());
    let app = Arc::new(server.create_app(auth_config, aws_http_client));

    let token = create_security_token(&config.jwt.secret, "rate_limit_user", 3600);

    // Simulate rapid fire requests (potential DoS attempt)
    let mut handles = vec![];

    for i in 0..50 {
        let app_clone = app.clone();
        let token_clone = token.clone();

        let handle = tokio::spawn(async move {
            let request = Request::builder()
                .uri("/health")
                .header("Authorization", format!("Bearer {}", token_clone))
                .body(Body::empty())
                .unwrap();

            let response = (*app_clone).clone().oneshot(request).await.unwrap();
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
