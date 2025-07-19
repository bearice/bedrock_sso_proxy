use crate::error::AppError;
use axum::{
    extract::{Request, State},
    http::header::AUTHORIZATION,
    middleware::Next,
    response::Response,
};
use jsonwebtoken::{DecodingKey, Validation, decode};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub exp: usize,
}

#[derive(Clone)]
pub struct AuthConfig {
    pub jwt_secret: String,
}

pub async fn jwt_auth_middleware(
    State(auth_config): State<Arc<AuthConfig>>,
    mut request: Request,
    next: Next,
) -> Result<Response, AppError> {
    let auth_header = request
        .headers()
        .get(AUTHORIZATION)
        .and_then(|header| header.to_str().ok())
        .ok_or_else(|| AppError::Internal("Missing Authorization header".to_string()))?;

    if !auth_header.starts_with("Bearer ") {
        return Err(AppError::Internal(
            "Invalid Authorization format".to_string(),
        ));
    }

    let token = &auth_header[7..];

    let _claims = decode::<Claims>(
        token,
        &DecodingKey::from_secret(auth_config.jwt_secret.as_ref()),
        &Validation::default(),
    )?;

    request.headers_mut().remove(AUTHORIZATION);

    Ok(next.run(request).await)
}
