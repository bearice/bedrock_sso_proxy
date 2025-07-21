use crate::{
    auth::oauth::{OAuthService, TokenRequest, RefreshRequest},
    error::AppError,
};
use axum::{
    extract::{Path, Query, State, Request},
    response::{Html, Json},
    routing::{get, post},
    Router,
};
use serde::Deserialize;
use std::sync::Arc;

#[derive(Deserialize)]
pub struct AuthorizeQuery {
    pub redirect_uri: Option<String>,
    pub state: Option<String>,
}

pub fn create_auth_routes() -> Router<Arc<OAuthService>> {
    Router::new()
        .route("/auth/authorize/{provider}", get(authorize_handler))
        .route("/auth/token", post(token_handler))
        .route("/auth/refresh", post(refresh_handler))
        .route("/auth/providers", get(providers_handler))
        .route("/auth/callback/{provider}", get(callback_handler))
        .route("/auth/validate", get(validate_handler))
}

pub async fn authorize_handler(
    State(oauth_service): State<Arc<OAuthService>>,
    Path(provider): Path<String>,
    Query(params): Query<AuthorizeQuery>,
) -> Result<Json<crate::auth::oauth::AuthorizeResponse>, AppError> {
    let redirect_uri = params.redirect_uri
        .unwrap_or_else(|| "http://localhost:3000/auth/callback".to_string());

    let response = oauth_service.get_authorization_url(&provider, &redirect_uri)?;
    Ok(Json(response))
}

pub async fn token_handler(
    State(oauth_service): State<Arc<OAuthService>>,
    Json(request): Json<TokenRequest>,
) -> Result<Json<crate::auth::oauth::TokenResponse>, AppError> {
    let response = oauth_service.exchange_code_for_token(request).await?;
    Ok(Json(response))
}

pub async fn refresh_handler(
    State(oauth_service): State<Arc<OAuthService>>,
    Json(request): Json<RefreshRequest>,
) -> Result<Json<crate::auth::oauth::TokenResponse>, AppError> {
    let response = oauth_service.refresh_token(request).await?;
    Ok(Json(response))
}

pub async fn providers_handler(
    State(oauth_service): State<Arc<OAuthService>>,
) -> Result<Json<crate::auth::oauth::ProvidersResponse>, AppError> {
    let response = oauth_service.list_providers();
    Ok(Json(response))
}

pub async fn callback_handler(
    State(oauth_service): State<Arc<OAuthService>>,
    Path(provider): Path<String>,
    Query(params): Query<CallbackQuery>,
) -> Result<Html<String>, AppError> {
    let code = params.code
        .ok_or_else(|| AppError::BadRequest("Missing authorization code".to_string()))?;
    
    let state = params.state
        .ok_or_else(|| AppError::BadRequest("Missing state parameter".to_string()))?;

    // For callback, we use a default redirect URI - in a real implementation,
    // this should be configured or stored with the state
    let redirect_uri = "http://localhost:3000/auth/callback".to_string();

    let token_request = TokenRequest {
        provider: provider.clone(),
        authorization_code: code,
        redirect_uri,
        state,
    };

    match oauth_service.exchange_code_for_token(token_request).await {
        Ok(token_response) => {
            let html = generate_success_html(&provider, &token_response);
            Ok(Html(html))
        }
        Err(e) => {
            let html = generate_error_html(&provider, &e.to_string());
            Ok(Html(html))
        }
    }
}

pub async fn validate_handler(
    State(oauth_service): State<Arc<OAuthService>>,
    request: Request,
) -> Result<Json<crate::auth::oauth::ValidationResponse>, AppError> {
    // Extract token from Authorization header
    let auth_header = request
        .headers()
        .get("authorization")
        .and_then(|header| header.to_str().ok())
        .ok_or_else(|| AppError::Unauthorized("Missing Authorization header".to_string()))?;

    if !auth_header.starts_with("Bearer ") {
        return Err(AppError::Unauthorized("Invalid Authorization format".to_string()));
    }

    let token = &auth_header[7..];
    let response = oauth_service.validate_token(token).await?;
    Ok(Json(response))
}

#[derive(Deserialize)]
pub struct CallbackQuery {
    pub code: Option<String>,
    pub state: Option<String>,
    pub error: Option<String>,
    pub error_description: Option<String>,
}

fn generate_success_html(provider: &str, token_response: &crate::auth::oauth::TokenResponse) -> String {
    let provider_display = match provider {
        "google" => "Google",
        "github" => "GitHub",
        "microsoft" => "Microsoft",
        "gitlab" => "GitLab",
        "auth0" => "Auth0",
        "okta" => "Okta",
        _ => provider,
    };

    format!(r#"
<!DOCTYPE html>
<html>
<head>
    <title>Authentication Success</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; background-color: #f5f5f5; }}
        .container {{ background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); max-width: 800px; }}
        .success {{ color: #28a745; }}
        .token-box {{ background: #f8f9fa; padding: 15px; border-radius: 4px; border-left: 4px solid #007bff; margin: 15px 0; }}
        .token-value {{ font-family: monospace; word-break: break-all; font-size: 12px; }}
        .copy-btn {{ background: #007bff; color: white; border: none; padding: 5px 10px; border-radius: 3px; cursor: pointer; margin-left: 10px; }}
        .setup-section {{ margin-top: 30px; padding: 20px; background: #e9f7ff; border-radius: 4px; }}
        pre {{ background: #f1f1f1; padding: 15px; border-radius: 4px; overflow-x: auto; }}
    </style>
</head>
<body>
    <div class="container">
        <h1 class="success">✅ Authentication Successful</h1>
        <p><strong>Provider:</strong> {}</p>
        
        <div class="token-box">
            <h3>Access Token</h3>
            <div class="token-value" id="access-token">{}</div>
            <button class="copy-btn" onclick="copyToClipboard('access-token')">Copy</button>
        </div>
        
        <div class="token-box">
            <h3>Refresh Token</h3>
            <div class="token-value" id="refresh-token">{}</div>
            <button class="copy-btn" onclick="copyToClipboard('refresh-token')">Copy</button>
        </div>
        
        <div class="setup-section">
            <h2>🔧 Claude Code Setup</h2>
            <p>To use this token with Claude Code, choose one of the following methods:</p>
            
            <h3>Method 1: Environment Variables</h3>
            <pre>export BEDROCK_TOKEN="{}"
export BEDROCK_ENDPOINT="https://your-proxy-domain.com"</pre>
            
            <h3>Method 2: Claude Code Configuration</h3>
            <pre>claude-code config set bedrock.token "{}"
claude-code config set bedrock.endpoint "https://your-proxy-domain.com"</pre>
            
            <h3>Method 3: Config File (~/.claude/config.json)</h3>
            <pre>{{
  "bedrock": {{
    "endpoint": "https://your-proxy-domain.com",
    "token": "{}",
    "refresh_token": "{}"
  }}
}}</pre>
            
            <h3>Testing Your Setup</h3>
            <pre>curl -X POST "https://your-proxy-domain.com/model/anthropic.claude-3-sonnet-20240229-v1:0/invoke" \\
  -H "Authorization: Bearer {}" \\
  -H "Content-Type: application/json" \\
  -d '{{
    "anthropic_version": "bedrock-2023-05-31",
    "max_tokens": 1000,
    "messages": [{{"role": "user", "content": "Hello"}}]
  }}'</pre>
            
            <p><strong>Token expires in:</strong> {} seconds ({} hours)</p>
            <p><strong>Scopes:</strong> {}</p>
        </div>
    </div>
    
    <script>
        function copyToClipboard(elementId) {{
            const element = document.getElementById(elementId);
            const text = element.textContent;
            
            if (navigator.clipboard) {{
                navigator.clipboard.writeText(text).then(() => {{
                    alert('Token copied to clipboard!');
                }});
            }} else {{
                // Fallback for older browsers
                const textArea = document.createElement('textarea');
                textArea.value = text;
                document.body.appendChild(textArea);
                textArea.select();
                document.execCommand('copy');
                document.body.removeChild(textArea);
                alert('Token copied to clipboard!');
            }}
        }}
    </script>
</body>
</html>
"#, 
        provider_display,
        token_response.access_token,
        token_response.refresh_token,
        token_response.access_token,
        token_response.access_token,
        token_response.access_token,
        token_response.refresh_token,
        token_response.access_token,
        token_response.expires_in,
        token_response.expires_in / 3600,
        token_response.scope
    )
}

fn generate_error_html(provider: &str, error: &str) -> String {
    let provider_display = match provider {
        "google" => "Google",
        "github" => "GitHub",
        "microsoft" => "Microsoft",
        "gitlab" => "GitLab",
        "auth0" => "Auth0",
        "okta" => "Okta",
        _ => provider,
    };

    format!(r#"
<!DOCTYPE html>
<html>
<head>
    <title>Authentication Error</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; background-color: #f5f5f5; }}
        .container {{ background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); max-width: 600px; }}
        .error {{ color: #dc3545; }}
        .error-box {{ background: #f8d7da; padding: 15px; border-radius: 4px; border-left: 4px solid #dc3545; margin: 15px 0; }}
        .retry-btn {{ background: #007bff; color: white; text-decoration: none; padding: 10px 20px; border-radius: 4px; display: inline-block; margin-top: 15px; }}
    </style>
</head>
<body>
    <div class="container">
        <h1 class="error">❌ Authentication Failed</h1>
        <p><strong>Provider:</strong> {}</p>
        
        <div class="error-box">
            <h3>Error Details</h3>
            <p>{}</p>
        </div>
        
        <p>Please check your OAuth configuration and try again.</p>
        <a href="javascript:history.back()" class="retry-btn">← Go Back</a>
    </div>
</body>
</html>
"#, provider_display, error)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::{Config, OAuthConfig, OAuthProvider, JwtConfig, CacheConfig},
        auth::{jwt::JwtService, cache::OAuthCache, oauth::OAuthService},
    };
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use jsonwebtoken::Algorithm;
    use std::collections::HashMap;
    use tower::ServiceExt;

    fn create_test_oauth_service() -> Arc<OAuthService> {
        let mut providers = HashMap::new();
        providers.insert("google".to_string(), OAuthProvider {
            client_id: "test-client-id".to_string(),
            client_secret: "test-client-secret".to_string(),
            redirect_uri: Some("http://localhost:3000/callback".to_string()),
            scopes: vec!["openid".to_string(), "email".to_string()],
            authorization_url: Some("https://accounts.google.com/o/oauth2/v2/auth".to_string()),
            token_url: Some("https://oauth2.googleapis.com/token".to_string()),
            user_info_url: Some("https://www.googleapis.com/oauth2/v2/userinfo".to_string()),
            user_id_field: "id".to_string(),
            email_field: "email".to_string(),
            tenant_id: None,
            instance_url: None,
            domain: None,
        });

        let mut config = Config::default();
        config.oauth = OAuthConfig { providers };
        config.jwt = JwtConfig {
            secret: "test-secret".to_string(),
            algorithm: "HS256".to_string(),
            access_token_ttl: 3600,
            refresh_token_ttl: 86400,
        };
        config.cache = CacheConfig {
            validation_ttl: 3600,
            max_entries: 1000,
            cleanup_interval: 300,
        };

        let cache = OAuthCache::new(3600, 600, 86400, 1000);
        let jwt_service = JwtService::new("test-secret".to_string(), Algorithm::HS256);
        Arc::new(OAuthService::new(config, cache, jwt_service))
    }

    #[tokio::test]
    async fn test_authorize_handler() {
        let oauth_service = create_test_oauth_service();
        let app = create_auth_routes().with_state(oauth_service);

        let request = Request::builder()
            .uri("/auth/authorize/google")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_authorize_handler_unknown_provider() {
        let oauth_service = create_test_oauth_service();
        let app = create_auth_routes().with_state(oauth_service);

        let request = Request::builder()
            .uri("/auth/authorize/unknown")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_providers_handler() {
        let oauth_service = create_test_oauth_service();
        let app = create_auth_routes().with_state(oauth_service);

        let request = Request::builder()
            .uri("/auth/providers")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_validate_handler_missing_header() {
        let oauth_service = create_test_oauth_service();
        let app = create_auth_routes().with_state(oauth_service);

        let request = Request::builder()
            .uri("/auth/validate")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_validate_handler_invalid_format() {
        let oauth_service = create_test_oauth_service();
        let app = create_auth_routes().with_state(oauth_service);

        let request = Request::builder()
            .uri("/auth/validate")
            .header("authorization", "Invalid token")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn test_generate_success_html() {
        let token_response = crate::auth::oauth::TokenResponse {
            access_token: "test_token".to_string(),
            token_type: "Bearer".to_string(),
            expires_in: 3600,
            refresh_token: "refresh_token".to_string(),
            scope: "email profile".to_string(),
        };

        let html = generate_success_html("google", &token_response);
        assert!(html.contains("Google"));
        assert!(html.contains("test_token"));
        assert!(html.contains("refresh_token"));
        assert!(html.contains("Claude Code Setup"));
    }

    #[test]
    fn test_generate_error_html() {
        let html = generate_error_html("google", "Invalid authorization code");
        assert!(html.contains("Google"));
        assert!(html.contains("Invalid authorization code"));
        assert!(html.contains("Authentication Failed"));
    }
}