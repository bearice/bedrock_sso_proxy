use axum::{
    extract::Request,
    http::{HeaderName, HeaderValue},
    middleware::Next,
    response::Response,
};
use std::str::FromStr;
use uuid::Uuid;

pub const REQUEST_ID_HEADER: &str = "X-Request-ID";

#[derive(Clone, Copy, Debug)]
pub struct RequestId(pub Uuid);

impl RequestId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    pub fn as_str(&self) -> String {
        self.0.to_string()
    }

    pub fn uuid(&self) -> Uuid {
        self.0
    }
}

impl Default for RequestId {
    fn default() -> Self {
        Self(Uuid::nil())
    }
}

impl std::fmt::Display for RequestId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Middleware that generates a unique request ID for each incoming request.
/// The request ID is:
/// 1. Generated as a UUID v4
/// 2. Added to request extensions for use in handlers and other middleware
/// 3. Added to response headers for client debugging
/// 4. Available for logging throughout the request lifecycle
pub async fn request_id_middleware(mut request: Request, next: Next) -> Response {
    // Check if request already has an X-Request-ID header (e.g., from load balancer)
    let request_id = if let Some(existing_id) = request
        .headers()
        .get(REQUEST_ID_HEADER)
        .and_then(|h| h.to_str().ok())
        .and_then(|s| Uuid::from_str(s).ok())
    {
        RequestId(existing_id)
    } else {
        RequestId::new()
    };

    // Insert request ID into request extensions
    request.extensions_mut().insert(request_id);

    // Process the request
    let mut response = next.run(request).await;

    // Add request ID to response headers
    if let Ok(header_value) = HeaderValue::from_str(&request_id.as_str()) {
        response
            .headers_mut()
            .insert(HeaderName::from_static("x-request-id"), header_value);
    }

    response
}

/// Extension trait to easily extract request ID from axum extractors
pub trait RequestIdExt {
    fn request_id(&self) -> RequestId;
}

impl RequestIdExt for axum::http::Extensions {
    fn request_id(&self) -> RequestId {
        self.get::<RequestId>().copied().unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        Router,
        body::Body,
        extract::Extension,
        http::{Method, Request as HttpRequest, StatusCode},
        response::Json,
        routing::get,
    };
    use serde_json::json;
    use tower::ServiceExt;

    async fn test_handler(Extension(request_id): Extension<RequestId>) -> Json<serde_json::Value> {
        Json(json!({
            "request_id": request_id.as_str(),
            "message": "Hello World"
        }))
    }

    #[tokio::test]
    async fn test_request_id_middleware_generates_id() {
        let app = Router::new()
            .route("/test", get(test_handler))
            .layer(axum::middleware::from_fn(request_id_middleware));

        let request = HttpRequest::builder()
            .method(Method::GET)
            .uri("/test")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        // Check that response has X-Request-ID header
        let request_id_header = response.headers().get("x-request-id");
        assert!(request_id_header.is_some());

        let request_id_str = request_id_header.unwrap().to_str().unwrap();
        assert!(Uuid::from_str(request_id_str).is_ok());
    }

    #[tokio::test]
    async fn test_request_id_middleware_preserves_existing_id() {
        let existing_id = Uuid::new_v4();

        let app = Router::new()
            .route("/test", get(test_handler))
            .layer(axum::middleware::from_fn(request_id_middleware));

        let request = HttpRequest::builder()
            .method(Method::GET)
            .uri("/test")
            .header(REQUEST_ID_HEADER, existing_id.to_string())
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        // Check that response has the same X-Request-ID header
        let request_id_header = response.headers().get("x-request-id").unwrap();
        let returned_id = request_id_header.to_str().unwrap();

        assert_eq!(returned_id, existing_id.to_string());
    }

    #[tokio::test]
    async fn test_request_id_new() {
        let id1 = RequestId::new();
        let id2 = RequestId::new();

        assert_ne!(id1.uuid(), id2.uuid());
    }

    #[tokio::test]
    async fn test_request_id_display() {
        let request_id = RequestId::new();
        let as_string = request_id.as_str();
        let display_string = format!("{request_id}");

        assert_eq!(as_string, display_string);
        assert!(Uuid::from_str(&as_string).is_ok());
    }
}
