use axum::http::HeaderMap;
use std::net::IpAddr;

/// Request context containing client information for audit logging
#[derive(Debug, Clone)]
pub struct RequestContext {
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
}

impl RequestContext {
    /// Extract request context from HTTP headers
    pub fn extract_from_headers(headers: &HeaderMap) -> Self {
        Self {
            ip_address: extract_client_ip(headers),
            user_agent: extract_user_agent(headers),
        }
    }
}

/// Extract client IP address from request headers
///
/// Handles various proxy headers in order of priority:
/// 1. X-Forwarded-For (most common, comma-separated list)
/// 2. X-Real-IP (nginx)
/// 3. CF-Connecting-IP (Cloudflare)
/// 4. X-Forwarded (RFC 7239)
/// 5. Forwarded (RFC 7239)
/// 6. Remote-Addr (fallback)
fn extract_client_ip(headers: &HeaderMap) -> Option<String> {
    // Check X-Forwarded-For (most common)
    if let Some(forwarded_for) = headers.get("x-forwarded-for").and_then(|h| h.to_str().ok()) {
        // X-Forwarded-For can be comma-separated list: client, proxy1, proxy2
        // Take the first (leftmost) IP which should be the original client
        if let Some(client_ip) = forwarded_for.split(',').next() {
            let ip = client_ip.trim();
            if let Ok(parsed_ip) = ip.parse::<IpAddr>() {
                // Validate it's a valid IP and not a private/loopback address in production
                if is_valid_client_ip(&parsed_ip) {
                    return Some(ip.to_string());
                }
            }
        }
    }

    // Check X-Real-IP (nginx)
    if let Some(real_ip) = headers.get("x-real-ip").and_then(|h| h.to_str().ok()) {
        if let Ok(parsed_ip) = real_ip.parse::<IpAddr>() {
            if is_valid_client_ip(&parsed_ip) {
                return Some(real_ip.to_string());
            }
        }
    }

    // Check CF-Connecting-IP (Cloudflare)
    if let Some(cf_ip) = headers
        .get("cf-connecting-ip")
        .and_then(|h| h.to_str().ok())
    {
        if let Ok(parsed_ip) = cf_ip.parse::<IpAddr>() {
            if is_valid_client_ip(&parsed_ip) {
                return Some(cf_ip.to_string());
            }
        }
    }

    // Check X-Forwarded (RFC 7239 format)
    if let Some(x_forwarded) = headers.get("x-forwarded").and_then(|h| h.to_str().ok()) {
        // RFC 7239 format: for=192.0.2.60;proto=http;by=203.0.113.43
        if let Some(ip) = extract_rfc7239_ip(x_forwarded) {
            return Some(ip);
        }
    }

    // Check Forwarded (RFC 7239 standard)
    if let Some(forwarded) = headers.get("forwarded").and_then(|h| h.to_str().ok()) {
        if let Some(ip) = extract_rfc7239_ip(forwarded) {
            return Some(ip);
        }
    }

    // Fallback to Remote-Addr (direct connection)
    if let Some(remote_addr) = headers.get("remote-addr").and_then(|h| h.to_str().ok()) {
        if let Ok(parsed_ip) = remote_addr.parse::<IpAddr>() {
            if is_valid_client_ip(&parsed_ip) {
                return Some(remote_addr.to_string());
            }
        }
    }

    None
}

/// Extract RFC 7239 format IP from Forwarded header
/// Format: for=192.0.2.60;proto=http;by=203.0.113.43
fn extract_rfc7239_ip(forwarded_header: &str) -> Option<String> {
    // Look for for= parameter
    for part in forwarded_header.split(';') {
        let part = part.trim();
        if let Some(ip_part) = part.strip_prefix("for=") {
            // Handle quoted IPs: for="192.0.2.60"
            let ip = ip_part.trim_matches('"');
            // Handle IPv6 format: for="[2001:db8::1]:8080"
            let ip = if ip.starts_with('[') && ip.contains("]:") {
                ip.split("]:").next().unwrap_or(ip).trim_start_matches('[')
            } else if ip.contains(':') && !ip.contains("::") {
                // IPv4 with port: for=192.0.2.60:8080
                ip.split(':').next().unwrap_or(ip)
            } else {
                ip
            };

            if let Ok(parsed_ip) = ip.parse::<IpAddr>() {
                if is_valid_client_ip(&parsed_ip) {
                    return Some(ip.to_string());
                }
            }
        }
    }
    None
}

/// Validate if IP address is suitable for client identification
///
/// In production, you may want to exclude private/loopback addresses
/// For development, we allow all valid IPs
fn is_valid_client_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(ipv4) => {
            // Accept all IPv4 addresses for now
            // In production, consider excluding:
            // - Private ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
            // - Loopback (127.0.0.0/8)
            // - Link-local (169.254.0.0/16)
            !ipv4.is_unspecified()
        }
        IpAddr::V6(ipv6) => {
            // Accept all IPv6 addresses for now
            // In production, consider excluding:
            // - Loopback (::1)
            // - Link-local (fe80::/10)
            // - Unique local (fc00::/7)
            !ipv6.is_unspecified()
        }
    }
}

/// Extract User-Agent header value
fn extract_user_agent(headers: &HeaderMap) -> Option<String> {
    headers
        .get("user-agent")
        .and_then(|h| h.to_str().ok())
        .map(|ua| {
            // Truncate very long user agents to prevent abuse
            if ua.len() > 500 {
                format!("{}...", &ua[..497])
            } else {
                ua.to_string()
            }
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderMap;

    #[test]
    fn test_extract_client_ip_x_forwarded_for() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            "203.0.113.195, 70.41.3.18, 150.172.238.178"
                .parse()
                .unwrap(),
        );

        let ip = extract_client_ip(&headers);
        assert_eq!(ip, Some("203.0.113.195".to_string()));
    }

    #[test]
    fn test_extract_client_ip_x_real_ip() {
        let mut headers = HeaderMap::new();
        headers.insert("x-real-ip", "203.0.113.195".parse().unwrap());

        let ip = extract_client_ip(&headers);
        assert_eq!(ip, Some("203.0.113.195".to_string()));
    }

    #[test]
    fn test_extract_client_ip_cf_connecting_ip() {
        let mut headers = HeaderMap::new();
        headers.insert("cf-connecting-ip", "203.0.113.195".parse().unwrap());

        let ip = extract_client_ip(&headers);
        assert_eq!(ip, Some("203.0.113.195".to_string()));
    }

    #[test]
    fn test_extract_client_ip_forwarded_rfc7239() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "forwarded",
            "for=203.0.113.195;proto=https;by=198.51.100.17"
                .parse()
                .unwrap(),
        );

        let ip = extract_client_ip(&headers);
        assert_eq!(ip, Some("203.0.113.195".to_string()));
    }

    #[test]
    fn test_extract_client_ip_forwarded_quoted() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "forwarded",
            "for=\"203.0.113.195\";proto=https".parse().unwrap(),
        );

        let ip = extract_client_ip(&headers);
        assert_eq!(ip, Some("203.0.113.195".to_string()));
    }

    #[test]
    fn test_extract_client_ip_forwarded_ipv6() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "forwarded",
            "for=\"[2001:db8::1]:8080\";proto=https".parse().unwrap(),
        );

        let ip = extract_client_ip(&headers);
        assert_eq!(ip, Some("2001:db8::1".to_string()));
    }

    #[test]
    fn test_extract_client_ip_priority() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "203.0.113.195".parse().unwrap());
        headers.insert("x-real-ip", "198.51.100.17".parse().unwrap());
        headers.insert("cf-connecting-ip", "192.0.2.60".parse().unwrap());

        // Should prefer X-Forwarded-For
        let ip = extract_client_ip(&headers);
        assert_eq!(ip, Some("203.0.113.195".to_string()));
    }

    #[test]
    fn test_extract_client_ip_no_headers() {
        let headers = HeaderMap::new();
        let ip = extract_client_ip(&headers);
        assert_eq!(ip, None);
    }

    #[test]
    fn test_extract_client_ip_invalid_ip() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "not-an-ip".parse().unwrap());

        let ip = extract_client_ip(&headers);
        assert_eq!(ip, None);
    }

    #[test]
    fn test_extract_user_agent() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "user-agent",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
                .parse()
                .unwrap(),
        );

        let ua = extract_user_agent(&headers);
        assert_eq!(
            ua,
            Some("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36".to_string())
        );
    }

    #[test]
    fn test_extract_user_agent_truncated() {
        let mut headers = HeaderMap::new();
        let long_ua = "a".repeat(600);
        headers.insert("user-agent", long_ua.parse().unwrap());

        let ua = extract_user_agent(&headers);
        assert!(ua.is_some());
        let ua = ua.unwrap();
        assert_eq!(ua.len(), 500);
        assert!(ua.ends_with("..."));
    }

    #[test]
    fn test_extract_user_agent_none() {
        let headers = HeaderMap::new();
        let ua = extract_user_agent(&headers);
        assert_eq!(ua, None);
    }

    #[test]
    fn test_request_context_extraction() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "203.0.113.195".parse().unwrap());
        headers.insert("user-agent", "Mozilla/5.0 Test".parse().unwrap());

        let context = RequestContext::extract_from_headers(&headers);
        assert_eq!(context.ip_address, Some("203.0.113.195".to_string()));
        assert_eq!(context.user_agent, Some("Mozilla/5.0 Test".to_string()));
    }

    #[test]
    fn test_request_context_empty_headers() {
        let headers = HeaderMap::new();
        let context = RequestContext::extract_from_headers(&headers);
        assert_eq!(context.ip_address, None);
        assert_eq!(context.user_agent, None);
    }

    #[test]
    fn test_is_valid_client_ip() {
        // Test IPv4
        assert!(is_valid_client_ip(&"203.0.113.195".parse().unwrap()));
        assert!(is_valid_client_ip(&"192.168.1.1".parse().unwrap())); // Private IP allowed in dev
        assert!(is_valid_client_ip(&"127.0.0.1".parse().unwrap())); // Loopback allowed in dev
        assert!(!is_valid_client_ip(&"0.0.0.0".parse().unwrap())); // Unspecified not allowed

        // Test IPv6
        assert!(is_valid_client_ip(&"2001:db8::1".parse().unwrap()));
        assert!(is_valid_client_ip(&"::1".parse().unwrap())); // Loopback allowed in dev
        assert!(!is_valid_client_ip(&"::".parse().unwrap())); // Unspecified not allowed
    }

    #[test]
    fn test_rfc7239_ip_extraction() {
        // Test basic for= parameter
        assert_eq!(
            extract_rfc7239_ip("for=203.0.113.195;proto=https"),
            Some("203.0.113.195".to_string())
        );

        // Test quoted IP
        assert_eq!(
            extract_rfc7239_ip("for=\"203.0.113.195\";proto=https"),
            Some("203.0.113.195".to_string())
        );

        // Test IPv6 with brackets and port
        assert_eq!(
            extract_rfc7239_ip("for=\"[2001:db8::1]:8080\";proto=https"),
            Some("2001:db8::1".to_string())
        );

        // Test IPv4 with port
        assert_eq!(
            extract_rfc7239_ip("for=203.0.113.195:8080;proto=https"),
            Some("203.0.113.195".to_string())
        );

        // Test no for= parameter
        assert_eq!(extract_rfc7239_ip("proto=https;by=198.51.100.17"), None);

        // Test invalid IP
        assert_eq!(extract_rfc7239_ip("for=not-an-ip;proto=https"), None);
    }
}
