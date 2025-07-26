use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Cache validation data structure
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CachedValidation {
    pub user_id: String,
    pub provider: String,
    pub email: String,
    pub validated_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub scopes: Vec<String>,
}

/// CSRF state tokens for OAuth security
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StateData {
    pub provider: String,
    pub redirect_uri: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}
