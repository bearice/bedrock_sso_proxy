use axum::{
    extract::{ConnectInfo, Request},
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use governor::{
    Quota, RateLimiter,
    clock::DefaultClock,
    state::keyed::DefaultKeyedStateStore,
    middleware::NoOpMiddleware,
};
use nonzero_ext::*;
use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::Arc,
};
use tokio::sync::RwLock;
use tracing::{debug, warn};

use crate::auth::jwt::Claims;
use metrics::counter;

/// Rate limiter configuration
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    /// Requests per minute for authenticated users
    pub authenticated_rpm: u32,
    /// Requests per minute for unauthenticated requests (health checks, etc.)
    pub unauthenticated_rpm: u32,
    /// Requests per minute for OAuth token creation
    pub oauth_token_rpm: u32,
    /// Requests per minute per IP address
    pub ip_rpm: u32,
    /// Enable rate limiting
    pub enabled: bool,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            authenticated_rpm: 600,    // 10 RPS for authenticated users
            unauthenticated_rpm: 60,   // 1 RPS for unauthenticated
            oauth_token_rpm: 10,       // Very low for token creation
            ip_rpm: 1200,              // 20 RPS per IP
            enabled: true,
        }
    }
}

/// Rate limiter key types
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum RateLimitKey {
    /// Rate limit by user ID from JWT
    User(String),
    /// Rate limit by IP address
    IpAddress(IpAddr),
    /// Rate limit OAuth token operations by email
    OAuthToken(String),
    /// Rate limit unauthenticated requests by IP
    Unauthenticated(IpAddr),
}

/// Rate limiter store
pub type RateLimiterStore = Arc<RwLock<HashMap<RateLimitKey, RateLimiter<
    RateLimitKey,
    DefaultKeyedStateStore<RateLimitKey>,
    DefaultClock,
    NoOpMiddleware
>>>>;

/// Rate limiting service
#[derive(Clone)]
pub struct RateLimitService {
    config: RateLimitConfig,
    limiters: RateLimiterStore,
}

impl RateLimitService {
    pub fn new(config: RateLimitConfig) -> Self {
        Self {
            config,
            limiters: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Get or create a rate limiter for the given key and quota
    async fn get_limiter(&self, key: RateLimitKey, requests_per_minute: u32) -> RateLimiter<
        RateLimitKey,
        DefaultKeyedStateStore<RateLimitKey>,
        DefaultClock,
        NoOpMiddleware
    > {
        let quota = match std::num::NonZeroU32::new(requests_per_minute) {
            Some(rpm) => Quota::per_minute(rpm),
            None => Quota::per_minute(std::num::NonZeroU32::new(1).unwrap()),
        };
        
        // Try to get existing limiter
        {
            let limiters = self.limiters.read().await;
            if let Some(limiter) = limiters.get(&key) {
                return limiter.clone();
            }
        }

        // Create new limiter
        let limiter = RateLimiter::keyed(quota);
        
        // Store the limiter
        {
            let mut limiters = self.limiters.write().await;
            limiters.insert(key.clone(), limiter.clone());
        }

        limiter
    }

    /// Check if request is within rate limits
    pub async fn check_rate_limit(
        &self,
        key: RateLimitKey,
        requests_per_minute: u32,
    ) -> Result<(), RateLimitError> {
        if !self.config.enabled {
            return Ok(());
        }

        let limiter = self.get_limiter(key.clone(), requests_per_minute).await;
        
        match limiter.check_key(&key) {
            Ok(_) => {
                debug!("Rate limit check passed for key: {:?}", key);
                Ok(())
            }
            Err(_) => {
                warn!("Rate limit exceeded for key: {:?}", key);
                counter!("rate_limit_exceeded_total", &[("key_type", key.type_name())]).increment(1);
                Err(RateLimitError::LimitExceeded)
            }
        }
    }

    /// Clean up old limiters (should be called periodically)
    pub async fn cleanup_old_limiters(&self) {
        let mut limiters = self.limiters.write().await;
        let before_count = limiters.len();
        
        // Keep only recent limiters to prevent memory leaks
        // In a production system, you might want more sophisticated cleanup
        if limiters.len() > 10000 {
            limiters.clear();
            warn!("Cleared {} rate limiters due to memory pressure", before_count);
        }
    }
}

impl RateLimitKey {
    fn type_name(&self) -> &'static str {
        match self {
            RateLimitKey::User(_) => "user",
            RateLimitKey::IpAddress(_) => "ip",
            RateLimitKey::OAuthToken(_) => "oauth_token",
            RateLimitKey::Unauthenticated(_) => "unauthenticated",
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RateLimitError {
    #[error("Rate limit exceeded")]
    LimitExceeded,
}

impl IntoResponse for RateLimitError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            RateLimitError::LimitExceeded => (
                StatusCode::TOO_MANY_REQUESTS,
                "Rate limit exceeded. Please try again later."
            ),
        };

        (status, message).into_response()
    }
}

/// Extract IP address from request
fn extract_ip(headers: &HeaderMap, connect_info: Option<&ConnectInfo<SocketAddr>>) -> Option<IpAddr> {
    // Check X-Real-IP header (nginx)
    if let Some(ip) = headers.get("X-Real-IP") {
        if let Ok(ip_str) = ip.to_str() {
            if let Ok(ip) = ip_str.parse() {
                return Some(ip);
            }
        }
    }

    // Check X-Forwarded-For header (load balancers)
    if let Some(forwarded) = headers.get("X-Forwarded-For") {
        if let Ok(forwarded_str) = forwarded.to_str() {
            // Take the first IP (original client)
            if let Some(first_ip) = forwarded_str.split(',').next() {
                if let Ok(ip) = first_ip.trim().parse() {
                    return Some(ip);
                }
            }
        }
    }

    // Fall back to connection IP
    connect_info.map(|info| info.0.ip())
}

/// Rate limiting middleware for general requests
pub async fn rate_limit_middleware(
    connect_info: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    mut req: Request,
    next: Next,
) -> Result<Response, RateLimitError> {
    let rate_limiter = req.extensions().get::<RateLimitService>().cloned();
    if rate_limiter.is_none() {
        // Rate limiting not configured, pass through
        return Ok(next.run(req).await);
    }
    let rate_limiter = rate_limiter.unwrap();

    let ip = extract_ip(&headers, connect_info.as_ref());
    
    // Check IP-based rate limiting first
    if let Some(ip) = ip {
        let ip_key = RateLimitKey::IpAddress(ip);
        rate_limiter.check_rate_limit(ip_key, rate_limiter.config.ip_rpm).await?;
    }

    // Check user-based rate limiting if authenticated
    if let Some(claims) = req.extensions().get::<Claims>() {
        let user_key = RateLimitKey::User(claims.sub.clone());
        rate_limiter.check_rate_limit(user_key, rate_limiter.config.authenticated_rpm).await?;
    } else if let Some(ip) = ip {
        // Rate limit unauthenticated requests more strictly
        let unauth_key = RateLimitKey::Unauthenticated(ip);
        rate_limiter.check_rate_limit(unauth_key, rate_limiter.config.unauthenticated_rpm).await?;
    }

    Ok(next.run(req).await)
}

/// Rate limiting middleware specifically for OAuth token endpoints
pub async fn oauth_rate_limit_middleware(
    connect_info: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    req: Request,
    next: Next,
) -> Result<Response, RateLimitError> {
    let rate_limiter = req.extensions().get::<RateLimitService>().cloned();
    if rate_limiter.is_none() {
        // Rate limiting not configured, pass through
        return Ok(next.run(req).await);
    }
    let rate_limiter = rate_limiter.unwrap();

    let ip = extract_ip(&headers, connect_info.as_ref());
    
    // Very strict rate limiting for OAuth token operations
    if let Some(ip) = ip {
        let oauth_key = RateLimitKey::OAuthToken(ip.to_string());
        rate_limiter.check_rate_limit(oauth_key, rate_limiter.config.oauth_token_rpm).await?;
    }

    Ok(next.run(req).await)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[tokio::test]
    async fn test_rate_limit_service() {
        let config = RateLimitConfig {
            authenticated_rpm: 60,
            unauthenticated_rpm: 30,
            oauth_token_rpm: 5,
            ip_rpm: 120,
            enabled: true,
        };
        
        let service = RateLimitService::new(config);
        let key = RateLimitKey::User("test_user".to_string());
        
        // First request should pass
        assert!(service.check_rate_limit(key.clone(), 60).await.is_ok());
        
        // Cleanup test
        service.cleanup_old_limiters().await;
    }

    #[tokio::test]
    async fn test_rate_limit_disabled() {
        let config = RateLimitConfig {
            enabled: false,
            ..Default::default()
        };
        
        let service = RateLimitService::new(config);
        let key = RateLimitKey::User("test_user".to_string());
        
        // Should always pass when disabled
        for _ in 0..1000 {
            assert!(service.check_rate_limit(key.clone(), 1).await.is_ok());
        }
    }

    #[test]
    fn test_extract_ip() {
        let mut headers = HeaderMap::new();
        headers.insert("X-Real-IP", "192.168.1.1".parse().unwrap());
        
        let connect_info = ConnectInfo(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            8080
        ));
        
        let ip = extract_ip(&headers, Some(&connect_info));
        assert_eq!(ip, Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
    }

    #[test]
    fn test_rate_limit_key_type_name() {
        assert_eq!(RateLimitKey::User("test".to_string()).type_name(), "user");
        assert_eq!(RateLimitKey::IpAddress(IpAddr::V4(Ipv4Addr::LOCALHOST)).type_name(), "ip");
        assert_eq!(RateLimitKey::OAuthToken("test".to_string()).type_name(), "oauth_token");
        assert_eq!(RateLimitKey::Unauthenticated(IpAddr::V4(Ipv4Addr::LOCALHOST)).type_name(), "unauthenticated");
    }
}