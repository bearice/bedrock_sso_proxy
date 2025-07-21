use axum::{
    Router,
    extract::Path,
    http::{HeaderMap, StatusCode},
    response::{Html, IntoResponse, Response},
    routing::get,
};
use rust_embed::RustEmbed;
use std::path::PathBuf;
use tokio::fs;
use tracing::{debug, warn};

#[derive(RustEmbed)]
#[folder = "frontend/dist"]
struct FrontendAssets;

/// Create frontend router with static file serving
pub fn create_frontend_router(frontend_config: crate::config::FrontendConfig) -> Router {
    let handler_config = frontend_config.clone();
    Router::new()
        .route("/", get(move || serve_index(handler_config.clone())))
        .route(
            "/{*path}",
            get(move |path| serve_static_file(path, frontend_config.clone())),
        )
}

/// Serve the main index.html file
async fn serve_index(config: crate::config::FrontendConfig) -> impl IntoResponse {
    serve_static_file(Path("index.html".to_string()), config).await
}

/// Serve static files - either from filesystem or embedded
async fn serve_static_file(
    Path(path): Path<String>,
    config: crate::config::FrontendConfig,
) -> impl IntoResponse {
    debug!("Serving static file: {}", path);

    // Security: prevent path traversal attacks
    if path.contains("..") || path.contains("\\") || path.starts_with('/') {
        warn!("Path traversal attempt blocked: {}", path);
        return (StatusCode::BAD_REQUEST, "Invalid path").into_response();
    }

    if let Some(frontend_path) = config.path {
        // Serve from filesystem directory
        debug!("Serving from filesystem: {}", frontend_path);
        serve_from_filesystem(&path, &frontend_path).await
    } else {
        // Serve from embedded assets
        debug!("Serving from embedded assets");
        serve_from_embedded(&path).await
    }
}

/// Serve files from filesystem directory
async fn serve_from_filesystem(path: &str, frontend_path: &str) -> Response {
    let file_path = PathBuf::from(frontend_path).join(path);

    match fs::read(&file_path).await {
        Ok(content) => {
            debug!("Serving from filesystem: {}/{}", frontend_path, path);
            serve_file_content(path, content)
        }
        Err(_) => {
            // File not found - try index.html for SPA routing
            if !path.contains('.') {
                let index_path = PathBuf::from(frontend_path).join("index.html");
                match fs::read(&index_path).await {
                    Ok(content) => {
                        debug!(
                            "Serving SPA fallback from filesystem: {}/index.html",
                            frontend_path
                        );
                        Html(String::from_utf8_lossy(&content).to_string()).into_response()
                    }
                    Err(_) => (StatusCode::NOT_FOUND, "Frontend not found").into_response(),
                }
            } else {
                (StatusCode::NOT_FOUND, "File not found").into_response()
            }
        }
    }
}

/// Serve files from embedded assets
async fn serve_from_embedded(path: &str) -> Response {
    if let Some(embedded_file) = FrontendAssets::get(path) {
        debug!("Serving from embedded assets: {}", path);
        serve_file_content(path, embedded_file.data.into_owned())
    } else {
        // File not found - try index.html for SPA routing
        if !path.contains('.') {
            if let Some(index_file) = FrontendAssets::get("index.html") {
                debug!("Serving SPA fallback from embedded: index.html");
                Html(String::from_utf8_lossy(&index_file.data).to_string()).into_response()
            } else {
                (
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Frontend not available - please build the frontend first",
                )
                    .into_response()
            }
        } else {
            (StatusCode::NOT_FOUND, "File not found").into_response()
        }
    }
}

/// Serve file content with appropriate content type
fn serve_file_content(path: &str, content: Vec<u8>) -> Response {
    let mut headers = HeaderMap::new();

    // Set content type based on file extension
    let content_type = match path.split('.').next_back() {
        Some("html") => "text/html; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("js") => "application/javascript; charset=utf-8",
        Some("json") => "application/json; charset=utf-8",
        Some("png") => "image/png",
        Some("jpg") | Some("jpeg") => "image/jpeg",
        Some("svg") => "image/svg+xml",
        Some("ico") => "image/x-icon",
        Some("woff") => "font/woff",
        Some("woff2") => "font/woff2",
        _ => "application/octet-stream",
    };

    headers.insert("content-type", content_type.parse().unwrap());
    headers.insert("cache-control", "public, max-age=3600".parse().unwrap());

    (headers, content).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum_test::TestServer;
    use tempfile::TempDir;
    use tokio::fs;

    #[tokio::test]
    async fn test_serve_embedded_index() {
        use crate::config::FrontendConfig;

        let config = FrontendConfig::default(); // Use embedded assets
        let app = create_frontend_router(config);
        let server = TestServer::new(app).unwrap();

        let response = server.get("/").await;
        response.assert_status_ok();
        response.assert_text_contains("Bedrock SSO Proxy");
        response.assert_text_contains("OAuth Authentication"); // From our new embedded HTML
    }

    #[tokio::test]
    async fn test_filesystem_serving() {
        use crate::config::FrontendConfig;

        let temp_dir = TempDir::new().unwrap();
        let original_dir = std::env::current_dir().unwrap();
        std::env::set_current_dir(temp_dir.path()).unwrap();

        // Create a frontend directory
        fs::create_dir_all("frontend").await.unwrap();
        fs::write(
            "frontend/index.html",
            "<html><body>Test Frontend</body></html>",
        )
        .await
        .unwrap();
        fs::write("frontend/app.js", "console.log('test');")
            .await
            .unwrap();

        // Configure to serve from filesystem
        let mut config = FrontendConfig::default();
        config.path = Some("frontend".to_string());

        let app = create_frontend_router(config);
        let server = TestServer::new(app).unwrap();

        // Test index.html
        let response = server.get("/").await;
        response.assert_status_ok();
        response.assert_text_contains("Test Frontend");

        // Test JS file
        let response = server.get("/app.js").await;
        response.assert_status_ok();
        response.assert_text("console.log('test');");

        // Test 404
        let response = server.get("/nonexistent.txt").await;
        response.assert_status(StatusCode::NOT_FOUND);

        // Test SPA routing
        let response = server.get("/some/route").await;
        response.assert_status_ok();
        response.assert_text_contains("Test Frontend"); // Should serve index.html

        std::env::set_current_dir(original_dir).unwrap();
    }

    #[tokio::test]
    async fn test_path_traversal_protection() {
        use crate::config::FrontendConfig;

        // Test the serve_static_file function directly to bypass Axum's URI normalization
        let config = FrontendConfig::default(); // Use embedded assets
        let malicious_paths = vec![
            "../etc/passwd",
            "..\\windows\\system32",
            "/absolute/path",
            "subdir/../../../etc/passwd",
        ];

        for malicious_path in malicious_paths {
            let response =
                serve_static_file(Path(malicious_path.to_string()), config.clone()).await;
            match response.into_response().status() {
                StatusCode::BAD_REQUEST => {} // Expected
                other => panic!(
                    "Expected BAD_REQUEST for path '{}', got {}",
                    malicious_path, other
                ),
            }
        }

        // Test valid paths that should serve SPA fallback
        let valid_paths = vec!["about", "users/123", "settings"];
        for valid_path in valid_paths {
            let response = serve_static_file(Path(valid_path.to_string()), config.clone()).await;
            match response.into_response().status() {
                StatusCode::SERVICE_UNAVAILABLE | StatusCode::OK => {} // Either no frontend built or SPA fallback
                other => panic!(
                    "Expected OK or SERVICE_UNAVAILABLE for path '{}', got {}",
                    valid_path, other
                ),
            }
        }
    }

    #[tokio::test]
    async fn test_embedded_assets() {
        use crate::config::FrontendConfig;

        let config = FrontendConfig::default(); // Use embedded assets
        let app = create_frontend_router(config);
        let server = TestServer::new(app).unwrap();

        // Test embedded CSS (direct access)
        let response = server.get("/styles.css").await;
        response.assert_status_ok();
        response.assert_header("content-type", "text/css; charset=utf-8");
        response.assert_text_contains("Bedrock SSO Proxy Default Frontend Styles");

        // Test embedded SVG
        let response = server.get("/favicon.svg").await;
        response.assert_status_ok();
        response.assert_header("content-type", "image/svg+xml");
        response.assert_text_contains("<svg");
    }

    #[tokio::test]
    async fn test_content_types() {
        use crate::config::FrontendConfig;

        let temp_dir = TempDir::new().unwrap();
        let original_dir = std::env::current_dir().unwrap();
        std::env::set_current_dir(temp_dir.path()).unwrap();

        fs::create_dir_all("frontend").await.unwrap();
        fs::write("frontend/style.css", "body { color: red; }")
            .await
            .unwrap();
        fs::write("frontend/script.js", "console.log('test');")
            .await
            .unwrap();

        let mut config = FrontendConfig::default();
        config.path = Some("frontend".to_string());
        let app = create_frontend_router(config);
        let server = TestServer::new(app).unwrap();

        let response = server.get("/style.css").await;
        response.assert_status_ok();
        response.assert_header("content-type", "text/css; charset=utf-8");

        let response = server.get("/script.js").await;
        response.assert_status_ok();
        response.assert_header("content-type", "application/javascript; charset=utf-8");

        std::env::set_current_dir(original_dir).unwrap();
    }
}
