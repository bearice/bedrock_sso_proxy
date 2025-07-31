use crate::cache::typed::typed_cache;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Default OAuth state token TTL (10 minutes)
pub const OAUTH_STATE_TTL_SECONDS: i64 = 600;

/// CSRF state tokens for OAuth security
#[derive(Clone, Debug, Serialize, Deserialize)]
#[typed_cache(ttl = 600)] // 10 minutes TTL
pub struct StateData {
    pub provider: String,
    pub redirect_uri: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    #[test]
    fn test_state_data_creation() {
        let now = Utc::now();
        let state_data = StateData {
            provider: "google".to_string(),
            redirect_uri: "http://localhost:3000/callback".to_string(),
            created_at: now,
            expires_at: now + Duration::seconds(OAUTH_STATE_TTL_SECONDS),
        };

        assert_eq!(state_data.provider, "google");
        assert_eq!(state_data.redirect_uri, "http://localhost:3000/callback");
        assert!(state_data.expires_at > state_data.created_at);
    }
}
