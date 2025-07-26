use crate::cache::CacheError;
use crate::database::DatabaseError;
use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde_json::json;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AppError {
    #[error("Configuration error: {0}")]
    Config(#[from] config::ConfigError),

    #[error("JWT authentication error: {0}")]
    Jwt(#[from] jsonwebtoken::errors::Error),

    #[error("Internal server error: {0}")]
    Internal(String),

    #[error("Unauthorized: {0}")]
    Unauthorized(String),

    #[error("Bad request: {0}")]
    BadRequest(String),

    #[error("AWS service error: {0}")]
    Aws(String),

    #[error("HTTP request error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("URL parsing error: {0}")]
    UrlParse(#[from] url::ParseError),

    #[error("HTTP header error: {0}")]
    HttpHeader(#[from] axum::http::header::InvalidHeaderValue),

    #[error("JSON serialization error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("HTTP status code error: {0}")]
    InvalidStatusCode(#[from] axum::http::status::InvalidStatusCode),

    #[error("Header value error: {0}")]
    ToStrError(#[from] axum::http::header::ToStrError),

    #[error("AWS signing error: {0}")]
    AwsSigning(#[from] aws_sigv4::http_request::SigningError),

    #[error("AWS signing params error: {0}")]
    AwsSigningParams(#[from] aws_sigv4::sign::v4::signing_params::BuildError),

    #[error("Database error: {0}")]
    Database(#[from] DatabaseError),

    #[error("Cache error: {0}")]
    Cache(#[from] CacheError),

    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Forbidden: {0}")]
    Forbidden(String),
}

impl AppError {
    fn status_code(&self) -> StatusCode {
        match self {
            AppError::Jwt(_) | AppError::Unauthorized(_) => StatusCode::UNAUTHORIZED,
            AppError::BadRequest(_)
            | AppError::UrlParse(_)
            | AppError::HttpHeader(_)
            | AppError::Json(_)
            | AppError::ToStrError(_) => StatusCode::BAD_REQUEST,
            AppError::Http(_) | AppError::Aws(_) => StatusCode::BAD_GATEWAY,
            AppError::NotFound(_) => StatusCode::NOT_FOUND,
            AppError::Forbidden(_) => StatusCode::FORBIDDEN,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let status = self.status_code();
        let message = self.to_string();

        let body = Json(json!({
            "error": status.canonical_reason().unwrap_or("Unknown error"),
            "message": message
        }));

        (status, body).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::StatusCode;
    use jsonwebtoken::errors::{Error as JwtError, ErrorKind};

    #[test]
    fn test_app_error_display() {
        let config_err = AppError::Config(config::ConfigError::NotFound("test".to_string()));
        assert!(config_err.to_string().contains("Configuration error"));

        let jwt_err = AppError::Jwt(JwtError::from(ErrorKind::InvalidToken));
        assert!(jwt_err.to_string().contains("JWT authentication error"));

        let internal_err = AppError::Internal("test message".to_string());
        assert_eq!(
            internal_err.to_string(),
            "Internal server error: test message"
        );

        let unauthorized_err = AppError::Unauthorized("access denied".to_string());
        assert_eq!(unauthorized_err.to_string(), "Unauthorized: access denied");

        let bad_request_err = AppError::BadRequest("invalid input".to_string());
        assert_eq!(bad_request_err.to_string(), "Bad request: invalid input");
    }

    #[test]
    fn test_app_error_from_config_error() {
        let config_err = config::ConfigError::NotFound("test".to_string());
        let app_err: AppError = config_err.into();
        matches!(app_err, AppError::Config(_));
    }

    #[test]
    fn test_app_error_from_jwt_error() {
        let jwt_err = JwtError::from(ErrorKind::InvalidToken);
        let app_err: AppError = jwt_err.into();
        matches!(app_err, AppError::Jwt(_));
    }

    #[test]
    fn test_app_error_into_response() {
        let config_err = AppError::Config(config::ConfigError::NotFound("test".to_string()));
        let response = config_err.into_response();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);

        let jwt_err = AppError::Jwt(JwtError::from(ErrorKind::InvalidToken));
        let response = jwt_err.into_response();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let internal_err = AppError::Internal("test".to_string());
        let response = internal_err.into_response();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);

        let unauthorized_err = AppError::Unauthorized("access denied".to_string());
        let response = unauthorized_err.into_response();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn test_error_response_body_format() {
        let internal_err = AppError::Internal("test message".to_string());
        let response = internal_err.into_response();

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }
}
