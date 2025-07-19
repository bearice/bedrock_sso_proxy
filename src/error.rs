use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde_json::json;
use std::fmt;

#[derive(Debug)]
pub enum AppError {
    Config(config::ConfigError),
    Jwt(jsonwebtoken::errors::Error),
    Aws(aws_sdk_bedrockruntime::Error),
    Internal(String),
    Unauthorized(String),
}

impl fmt::Display for AppError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AppError::Config(err) => write!(f, "Configuration error: {}", err),
            AppError::Jwt(err) => write!(f, "JWT error: {}", err),
            AppError::Aws(err) => write!(f, "AWS error: {}", err),
            AppError::Internal(msg) => write!(f, "Internal error: {}", msg),
            AppError::Unauthorized(msg) => write!(f, "Unauthorized: {}", msg),
        }
    }
}

impl From<config::ConfigError> for AppError {
    fn from(err: config::ConfigError) -> Self {
        AppError::Config(err)
    }
}

impl From<jsonwebtoken::errors::Error> for AppError {
    fn from(err: jsonwebtoken::errors::Error) -> Self {
        AppError::Jwt(err)
    }
}

impl From<aws_sdk_bedrockruntime::Error> for AppError {
    fn from(err: aws_sdk_bedrockruntime::Error) -> Self {
        AppError::Aws(err)
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            AppError::Config(_) => (StatusCode::INTERNAL_SERVER_ERROR, "Configuration error"),
            AppError::Jwt(_) => (StatusCode::UNAUTHORIZED, "Authentication failed"),
            AppError::Aws(_) => (StatusCode::BAD_GATEWAY, "AWS service error"),
            AppError::Internal(_) => (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error"),
            AppError::Unauthorized(_) => (StatusCode::UNAUTHORIZED, "Authentication failed"),
        };

        let body = Json(json!({
            "error": error_message,
            "message": self.to_string()
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
        assert!(jwt_err.to_string().contains("JWT error"));

        let internal_err = AppError::Internal("test message".to_string());
        assert_eq!(internal_err.to_string(), "Internal error: test message");

        let unauthorized_err = AppError::Unauthorized("access denied".to_string());
        assert_eq!(unauthorized_err.to_string(), "Unauthorized: access denied");
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
