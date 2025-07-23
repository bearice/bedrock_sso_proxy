use axum::{
    body::Body,
    extract::MatchedPath,
    http::{Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use metrics::{counter, histogram, gauge};
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use std::time::Instant;
use tracing::info;

/// Initialize Prometheus metrics exporter
pub fn init_metrics() -> Result<PrometheusHandle, Box<dyn std::error::Error + Send + Sync>> {
    let builder = PrometheusBuilder::new()
        .with_http_listener(([0, 0, 0, 0], 9090))
        .add_global_label("service", "bedrock_sso_proxy");

    let handle = builder.install_recorder()?;
    
    info!("Metrics server started on :9090/metrics");
    Ok(handle)
}

/// Middleware to collect HTTP request metrics
pub async fn metrics_middleware(
    req: Request<Body>,
    next: Next,
) -> Response {
    let start = Instant::now();
    let method = req.method().clone();
    let path = req
        .extensions()
        .get::<MatchedPath>()
        .map(|mp| mp.as_str())
        .unwrap_or("unknown");

    // Track active requests
    let active_requests_key = format!("active_requests_total{{method=\"{}\",path=\"{}\"}}", method, path);
    gauge!("http_requests_active").increment(1.0);

    let response = next.run(req).await;
    
    let duration = start.elapsed();
    let status = response.status();

    // Record metrics
    let labels = [
        ("method", method.as_str()),
        ("path", path),
        ("status", status.as_str()),
    ];

    counter!("http_requests_total", &labels).increment(1);
    histogram!("http_request_duration_seconds", &labels).record(duration.as_secs_f64());
    
    // Track active requests
    gauge!("http_requests_active").decrement(1.0);

    // Track error rates
    if status.is_server_error() {
        counter!("http_errors_total", &labels[..2]).increment(1);
    }

    response
}

/// Track JWT validation metrics
pub fn track_jwt_validation(success: bool, source: String) {
    let result = if success { "success" } else { "failure" };
    counter!("jwt_validations_total", "source" => source, "result" => result).increment(1);
}

/// Track OAuth operations
pub fn track_oauth_operation(operation: String, provider: String, success: bool) {
    let result = if success { "success" } else { "failure" };
    counter!("oauth_operations_total", 
        "operation" => operation, 
        "provider" => provider, 
        "result" => result
    ).increment(1);
}

/// Track AWS Bedrock API calls
pub fn track_bedrock_call(model_id: String, endpoint: String, status: StatusCode, duration: std::time::Duration) {
    let status_str = status.as_str().to_string();
    
    counter!("bedrock_requests_total", 
        "model" => model_id.clone(), 
        "endpoint" => endpoint.clone(), 
        "status" => status_str.clone()
    ).increment(1);
    
    histogram!("bedrock_request_duration_seconds", 
        "model" => model_id.clone(), 
        "endpoint" => endpoint.clone(), 
        "status" => status_str
    ).record(duration.as_secs_f64());
    
    if status.is_server_error() {
        counter!("bedrock_errors_total", 
            "model" => model_id, 
            "endpoint" => endpoint
        ).increment(1);
    }
}

/// Track cache operations
pub fn track_cache_operation(operation: String, cache_type: String, hit: bool) {
    let result = if hit { "hit" } else { "miss" };
    counter!("cache_operations_total", 
        "operation" => operation, 
        "cache_type" => cache_type, 
        "result" => result
    ).increment(1);
}

/// Update cache size metrics
pub fn update_cache_size(cache_type: String, size: usize) {
    gauge!("cache_size_entries", "cache_type" => cache_type).set(size as f64);
}

/// Metrics endpoint handler
pub async fn metrics_handler(handle: axum::extract::State<PrometheusHandle>) -> impl IntoResponse {
    handle.render()
}

/// Health check with metrics
pub async fn health_metrics() -> impl IntoResponse {
    // Update system metrics
    gauge!("system_uptime_seconds").set(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as f64
    );

    // System metrics (basic implementation without external dependencies)
    gauge!("system_health").set(1.0);

    (StatusCode::OK, "OK")
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http::Method};
    use std::time::Duration;

    #[test]
    fn test_track_jwt_validation() {
        track_jwt_validation(true, "legacy".to_string());
        track_jwt_validation(false, "oauth".to_string());
        // No panics, metrics recorded
    }

    #[test]
    fn test_track_oauth_operation() {
        track_oauth_operation("authorize".to_string(), "google".to_string(), true);
        track_oauth_operation("token".to_string(), "github".to_string(), false);
        // No panics, metrics recorded
    }

    #[test]
    fn test_track_bedrock_call() {
        track_bedrock_call(
            "claude-3-sonnet".to_string(),
            "invoke".to_string(),
            StatusCode::OK,
            Duration::from_millis(500)
        );
        track_bedrock_call(
            "claude-3-haiku".to_string(),
            "invoke-stream".to_string(),
            StatusCode::INTERNAL_SERVER_ERROR,
            Duration::from_millis(1000)
        );
        // No panics, metrics recorded
    }

    #[test]
    fn test_track_cache_operation() {
        track_cache_operation("get".to_string(), "validation".to_string(), true);
        track_cache_operation("set".to_string(), "refresh_token".to_string(), false);
        // No panics, metrics recorded
    }

    #[test]
    fn test_update_cache_size() {
        update_cache_size("validation".to_string(), 100);
        update_cache_size("refresh_token".to_string(), 50);
        // No panics, metrics recorded
    }
}