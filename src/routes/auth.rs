use crate::{
    auth::oauth::{RefreshRequest, TokenRequest},
    database::entities::UserRecord,
    error::AppError,
    server::Server,
    utils::request_context::RequestContext,
};
use axum::{
    Extension, Router,
    extract::{Path, Query, State},
    http::HeaderMap,
    response::{Json, Redirect},
    routing::{get, post},
};
use serde::Deserialize;
use url::Url;

#[derive(Deserialize)]
pub struct AuthorizeQuery {
    pub redirect_uri: Option<String>,
    pub state: Option<String>,
}

pub fn create_auth_routes() -> Router<Server> {
    Router::new()
        .route("/authorize/{provider}", get(authorize_handler))
        .route("/token", post(token_handler))
        .route("/refresh", post(refresh_handler))
        .route("/providers", get(providers_handler))
        .route("/callback/{provider}", get(callback_handler))
}

pub fn create_protected_auth_routes() -> Router<Server> {
    Router::new().route("/me", get(me_handler))
}

pub async fn authorize_handler(
    State(server): State<Server>,
    Path(provider): Path<String>,
    Query(params): Query<AuthorizeQuery>,
    headers: HeaderMap,
) -> Result<Json<crate::auth::oauth::AuthorizeResponse>, AppError> {
    let redirect_uri = params.redirect_uri.unwrap_or_else(|| {
        // Build redirect URI from request headers to avoid hardcoded URLs
        build_redirect_uri_from_request(&headers, &provider)
    });

    let response = server
        .oauth_service
        .get_authorization_url(&provider, &redirect_uri)
        .await?;
    Ok(Json(response))
}

pub async fn token_handler(
    State(server): State<Server>,
    headers: HeaderMap,
    Json(request): Json<TokenRequest>,
) -> Result<Json<crate::auth::oauth::TokenResponse>, AppError> {
    let context = RequestContext::extract_from_headers(&headers);
    let response = server
        .oauth_service
        .exchange_code_for_token(request, context)
        .await?;
    Ok(Json(response))
}

pub async fn refresh_handler(
    State(server): State<Server>,
    headers: HeaderMap,
    Json(request): Json<RefreshRequest>,
) -> Result<Json<crate::auth::oauth::TokenResponse>, AppError> {
    let context = RequestContext::extract_from_headers(&headers);
    let response = server.oauth_service.refresh_token(request, context).await?;
    Ok(Json(response))
}

pub async fn providers_handler(
    State(server): State<Server>,
) -> Result<Json<crate::auth::oauth::ProvidersResponse>, AppError> {
    let response = server.oauth_service.list_providers();
    Ok(Json(response))
}

pub async fn callback_handler(
    State(server): State<Server>,
    Path(provider): Path<String>,
    Query(params): Query<CallbackQuery>,
    headers: HeaderMap,
) -> Result<Redirect, AppError> {
    // Handle OAuth errors first
    if let Some(error) = params.error {
        let error_description = params
            .error_description
            .unwrap_or_else(|| "OAuth authentication failed".to_string());
        let error_url =
            build_callback_url(&[("error", &error), ("error_description", &error_description)])?;
        return Ok(Redirect::to(&error_url));
    }

    let code = params
        .code
        .ok_or_else(|| AppError::BadRequest("Missing authorization code".to_string()))?;

    let state = params
        .state
        .ok_or_else(|| AppError::BadRequest("Missing state parameter".to_string()))?;

    // Get the redirect URI from the state data (stored when authorization URL was generated)
    let redirect_uri = server
        .oauth_service
        .get_redirect_uri_for_state(&state)
        .await
        .ok_or_else(|| AppError::BadRequest("Invalid or expired state parameter".to_string()))?;

    let token_request = TokenRequest {
        provider: provider.clone(),
        authorization_code: code,
        redirect_uri,
        state,
    };

    let context = RequestContext::extract_from_headers(&headers);
    match server
        .oauth_service
        .exchange_code_for_token(token_request, context)
        .await
    {
        Ok(token_response) => {
            // Redirect to frontend callback page with success parameters
            let success_url = build_callback_url(&[
                ("success", "true"),
                ("provider", &provider),
                ("access_token", &token_response.access_token),
                ("expires_in", &token_response.expires_in.to_string()),
                ("scope", &token_response.scope),
            ])?;
            Ok(Redirect::to(&success_url))
        }
        Err(e) => {
            // Redirect to frontend callback page with error parameters
            let error_url = build_callback_url(&[
                ("error", "token_exchange_failed"),
                ("error_description", &e.to_string()),
                ("provider", &provider),
            ])?;
            Ok(Redirect::to(&error_url))
        }
    }
}

/// Get current user information (requires authentication)
pub async fn me_handler(
    Extension(user): Extension<UserRecord>,
) -> Result<Json<UserRecord>, AppError> {
    // Get user ID from subject
    Ok(Json(user))
}

#[derive(Deserialize)]
pub struct CallbackQuery {
    pub code: Option<String>,
    pub state: Option<String>,
    pub error: Option<String>,
    pub error_description: Option<String>,
}

/// Build a redirect URI from request headers, supporting reverse proxies and sub-paths
fn build_redirect_uri_from_request(headers: &HeaderMap, provider: &str) -> String {
    // 1. Determine the scheme (http/https)
    let scheme = determine_scheme_from_headers(headers);

    // 2. Get the host (with port if non-standard)
    let host = determine_host_from_headers(headers);

    // 3. Determine the base path (for sub-path deployments)
    let base_path = determine_base_path_from_headers(headers);

    // 4. Build the complete redirect URI
    format!("{scheme}://{host}{base_path}/auth/callback/{provider}")
}

/// Determine the scheme from various proxy headers
fn determine_scheme_from_headers(headers: &HeaderMap) -> &'static str {
    // Check X-Forwarded-Proto (most common)
    if let Some(proto) = headers
        .get("x-forwarded-proto")
        .and_then(|h| h.to_str().ok())
    {
        if proto.contains("https") {
            return "https";
        }
    }

    // Check X-Forwarded-SSL (Apache/nginx)
    if headers.get("x-forwarded-ssl").is_some() {
        return "https";
    }

    // Check Front-End-Https (Microsoft IIS)
    if let Some(fe_https) = headers.get("front-end-https").and_then(|h| h.to_str().ok()) {
        if fe_https.eq_ignore_ascii_case("on") {
            return "https";
        }
    }

    // Check X-Url-Scheme (some load balancers)
    if let Some(scheme) = headers.get("x-url-scheme").and_then(|h| h.to_str().ok()) {
        if scheme.eq_ignore_ascii_case("https") {
            return "https";
        }
    }

    "http" // default to http for development
}

/// Determine the host from various headers, handling proxied requests
fn determine_host_from_headers(headers: &HeaderMap) -> String {
    // Check X-Forwarded-Host (most common for proxied requests)
    if let Some(host) = headers
        .get("x-forwarded-host")
        .and_then(|h| h.to_str().ok())
    {
        // Take the first host if there are multiple (comma-separated)
        return host.split(',').next().unwrap().trim().to_string();
    }

    // Check X-Original-Host (some proxies)
    if let Some(host) = headers.get("x-original-host").and_then(|h| h.to_str().ok()) {
        return host.to_string();
    }

    // Fallback to standard Host header
    headers
        .get("host")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("localhost:3000") // development fallback
        .to_string()
}

/// Determine the base path for sub-path deployments
fn determine_base_path_from_headers(headers: &HeaderMap) -> String {
    // Check X-Forwarded-Prefix (nginx, Traefik)
    if let Some(prefix) = headers
        .get("x-forwarded-prefix")
        .and_then(|h| h.to_str().ok())
    {
        return ensure_leading_slash(prefix.trim_end_matches('/'));
    }

    // Check X-Forwarded-Path (some load balancers)
    if let Some(path) = headers
        .get("x-forwarded-path")
        .and_then(|h| h.to_str().ok())
    {
        return ensure_leading_slash(path.trim_end_matches('/'));
    }

    // Check X-Script-Name (WSGI-style)
    if let Some(script_name) = headers.get("x-script-name").and_then(|h| h.to_str().ok()) {
        return ensure_leading_slash(script_name.trim_end_matches('/'));
    }

    // Check X-Original-URI and extract path prefix
    if let Some(original_uri) = headers.get("x-original-uri").and_then(|h| h.to_str().ok()) {
        if let Some(path_end) = original_uri.find("/auth/") {
            let base_path = &original_uri[..path_end];
            if !base_path.is_empty() {
                return ensure_leading_slash(base_path);
            }
        }
    }

    // No sub-path detected
    String::new()
}

/// Ensure a path has a leading slash but no trailing slash
fn ensure_leading_slash(path: &str) -> String {
    if path.is_empty() {
        String::new()
    } else if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{path}")
    }
}

/// Helper function to build callback URLs with proper query parameter encoding.
///
/// This is much safer than manual string formatting because:
/// - Automatic URL encoding of special characters
/// - Prevents injection attacks through malicious parameters
/// - Handles edge cases like empty values, special characters
/// - More maintainable and readable than format! macros
/// - Deployment path agnostic (returns relative URL)
fn build_callback_url(params: &[(&str, &str)]) -> Result<String, AppError> {
    // Use a temporary base URL just for query parameter building
    let mut url = Url::parse("http://temp/callback")
        .map_err(|e| AppError::Internal(format!("Failed to parse base URL: {e}")))?;

    {
        let mut query_pairs = url.query_pairs_mut();
        for (key, value) in params {
            query_pairs.append_pair(key, value);
        }
    }

    // Return just the relative path and query, no assumptions about deployment domain/path
    Ok(format!("/callback?{}", url.query().unwrap_or("")))
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use crate::{
        Config,
        auth::config::{OAuthConfig, OAuthProvider},
    };

    use super::*;

    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };

    use tower::ServiceExt;

    fn create_test_config() -> Config {
        let mut providers = HashMap::new();
        providers.insert(
            "google".to_string(),
            OAuthProvider {
                client_id: "test-client-id".to_string(),
                client_secret: "test-client-secret".to_string(),
                ..Default::default()
            },
        );
        Config {
            oauth: OAuthConfig { providers },
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn test_authorize_handler() {
        let server = crate::test_utils::TestServerBuilder::new()
            .with_config(create_test_config())
            .build()
            .await;
        let app = create_auth_routes().with_state(server);

        let request = Request::builder()
            .uri("/authorize/google")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_authorize_handler_unknown_provider() {
        let server = crate::test_utils::TestServerBuilder::new().build().await;
        let app = create_auth_routes().with_state(server);

        let request = Request::builder()
            .uri("/authorize/unknown")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_providers_handler() {
        let server = crate::test_utils::TestServerBuilder::new().build().await;
        let app = create_auth_routes().with_state(server);

        let request = Request::builder()
            .uri("/providers")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[test]
    fn test_build_callback_url() {
        // Test success URL
        let success_url = build_callback_url(&[
            ("success", "true"),
            ("provider", "google"),
            ("access_token", "token123"),
            ("expires_in", "3600"),
            ("scope", "email profile"),
        ])
        .unwrap();

        assert!(success_url.starts_with("/callback?"));
        assert!(success_url.contains("success=true"));
        assert!(success_url.contains("provider=google"));
        assert!(success_url.contains("access_token=token123"));
        assert!(success_url.contains("expires_in=3600"));
        // URL crate uses + for spaces in query parameters instead of %20
        assert!(success_url.contains("scope=email+profile"));

        // Test error URL with special characters
        let error_url = build_callback_url(&[
            ("error", "invalid_request"),
            ("error_description", "Missing required parameter"),
            ("provider", "github"),
        ])
        .unwrap();

        assert!(error_url.starts_with("/callback?"));
        assert!(error_url.contains("error=invalid_request"));
        assert!(error_url.contains("error_description=Missing+required+parameter"));
        assert!(error_url.contains("provider=github"));
    }

    #[test]
    fn test_build_redirect_uri_from_request() {
        // Test basic HTTP with standard host
        let mut headers = HeaderMap::new();
        headers.insert("host", "example.com".parse().unwrap());
        let uri = build_redirect_uri_from_request(&headers, "google");
        assert_eq!(uri, "http://example.com/auth/callback/google");

        // Test HTTPS with x-forwarded-proto
        headers.insert("x-forwarded-proto", "https".parse().unwrap());
        let uri = build_redirect_uri_from_request(&headers, "github");
        assert_eq!(uri, "https://example.com/auth/callback/github");

        // Test HTTPS with x-forwarded-ssl
        headers.remove("x-forwarded-proto");
        headers.insert("x-forwarded-ssl", "on".parse().unwrap());
        let uri = build_redirect_uri_from_request(&headers, "microsoft");
        assert_eq!(uri, "https://example.com/auth/callback/microsoft");

        // Test sub-path deployment with X-Forwarded-Prefix
        headers.clear();
        headers.insert("host", "api.example.com".parse().unwrap());
        headers.insert("x-forwarded-proto", "https".parse().unwrap());
        headers.insert("x-forwarded-prefix", "/my-app".parse().unwrap());
        let uri = build_redirect_uri_from_request(&headers, "google");
        assert_eq!(uri, "https://api.example.com/my-app/auth/callback/google");

        // Test X-Forwarded-Host with multiple hosts (should use first)
        headers.clear();
        headers.insert(
            "x-forwarded-host",
            "api.example.com, internal.example.com".parse().unwrap(),
        );
        headers.insert("x-forwarded-proto", "https".parse().unwrap());
        let uri = build_redirect_uri_from_request(&headers, "github");
        assert_eq!(uri, "https://api.example.com/auth/callback/github");

        // Test X-Original-URI path extraction
        headers.clear();
        headers.insert("host", "example.com".parse().unwrap());
        headers.insert(
            "x-original-uri",
            "/my-service/auth/authorize/google".parse().unwrap(),
        );
        let uri = build_redirect_uri_from_request(&headers, "google");
        assert_eq!(uri, "http://example.com/my-service/auth/callback/google");

        // Test multiple proxy headers (should prioritize correctly)
        headers.clear();
        headers.insert("host", "localhost:3000".parse().unwrap());
        headers.insert("x-forwarded-host", "api.production.com".parse().unwrap());
        headers.insert("x-forwarded-proto", "https".parse().unwrap());
        headers.insert("x-forwarded-prefix", "/api/v1".parse().unwrap());
        let uri = build_redirect_uri_from_request(&headers, "microsoft");
        assert_eq!(
            uri,
            "https://api.production.com/api/v1/auth/callback/microsoft"
        );

        // Test fallback when no headers
        let empty_headers = HeaderMap::new();
        let uri = build_redirect_uri_from_request(&empty_headers, "google");
        assert_eq!(uri, "http://localhost:3000/auth/callback/google");
    }

    #[test]
    fn test_ensure_leading_slash() {
        assert_eq!(ensure_leading_slash(""), "");
        assert_eq!(ensure_leading_slash("api"), "/api");
        assert_eq!(ensure_leading_slash("/api"), "/api");
        assert_eq!(ensure_leading_slash("api/v1"), "/api/v1");
        assert_eq!(ensure_leading_slash("/api/v1"), "/api/v1");
    }
}
