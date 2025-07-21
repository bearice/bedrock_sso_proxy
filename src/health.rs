use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::RwLock;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HealthStatus {
    Healthy,
    Degraded,
    Unhealthy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheckResult {
    pub status: HealthStatus,
    pub message: Option<String>,
    pub details: Option<serde_json::Value>,
    pub duration_ms: Option<u64>,
}

impl HealthCheckResult {
    pub fn healthy() -> Self {
        Self {
            status: HealthStatus::Healthy,
            message: None,
            details: None,
            duration_ms: None,
        }
    }

    pub fn healthy_with_details(details: serde_json::Value) -> Self {
        Self {
            status: HealthStatus::Healthy,
            message: None,
            details: Some(details),
            duration_ms: None,
        }
    }

    pub fn degraded(message: String) -> Self {
        Self {
            status: HealthStatus::Degraded,
            message: Some(message),
            details: None,
            duration_ms: None,
        }
    }

    pub fn degraded_with_details(message: String, details: serde_json::Value) -> Self {
        Self {
            status: HealthStatus::Degraded,
            message: Some(message),
            details: Some(details),
            duration_ms: None,
        }
    }

    pub fn unhealthy(message: String) -> Self {
        Self {
            status: HealthStatus::Unhealthy,
            message: Some(message),
            details: None,
            duration_ms: None,
        }
    }

    pub fn unhealthy_with_details(message: String, details: serde_json::Value) -> Self {
        Self {
            status: HealthStatus::Unhealthy,
            message: Some(message),
            details: Some(details),
            duration_ms: None,
        }
    }

    pub fn with_duration(mut self, duration_ms: u64) -> Self {
        self.duration_ms = Some(duration_ms);
        self
    }
}

#[async_trait]
pub trait HealthChecker: Send + Sync {
    /// The name of this health check component
    fn name(&self) -> &str;
    
    /// Perform the health check
    async fn check(&self) -> HealthCheckResult;
    
    /// Optional: return static information about this component
    fn info(&self) -> Option<serde_json::Value> {
        None
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OverallHealthResponse {
    pub status: HealthStatus,
    pub service: String,
    pub version: String,
    pub timestamp: String,
    pub checks: HashMap<String, HealthCheckResult>,
    pub summary: HealthSummary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthSummary {
    pub total_checks: usize,
    pub healthy_count: usize,
    pub degraded_count: usize,
    pub unhealthy_count: usize,
    pub total_duration_ms: u64,
}

pub struct HealthService {
    checkers: Arc<RwLock<HashMap<String, Arc<dyn HealthChecker>>>>,
}

impl HealthService {
    pub fn new() -> Self {
        Self {
            checkers: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Register a health checker for a specific component
    pub async fn register(&self, checker: Arc<dyn HealthChecker>) {
        let name = checker.name().to_string();
        let mut checkers = self.checkers.write().await;
        checkers.insert(name, checker);
    }

    /// Remove a health checker
    pub async fn unregister(&self, name: &str) {
        let mut checkers = self.checkers.write().await;
        checkers.remove(name);
    }

    /// Run all health checks or specific ones based on filter
    pub async fn check_health(&self, filter: Option<&str>) -> OverallHealthResponse {
        let checkers = self.checkers.read().await;
        let mut results = HashMap::new();
        let mut total_duration = 0u64;

        // Determine which checks to run
        let checks_to_run: Vec<_> = match filter {
            Some("all") => checkers.iter().collect(),
            Some(specific) => checkers
                .iter()
                .filter(|(name, _)| name.as_str() == specific)
                .collect(),
            None => vec![], // No specific checks requested, just basic health
        };

        // Run the selected health checks
        for (name, checker) in checks_to_run {
            let start = Instant::now();
            let mut result = checker.check().await;
            let duration = start.elapsed().as_millis() as u64;
            result = result.with_duration(duration);
            total_duration += duration;
            results.insert(name.clone(), result);
        }

        // Calculate summary
        let healthy_count = results
            .values()
            .filter(|r| matches!(r.status, HealthStatus::Healthy))
            .count();
        let degraded_count = results
            .values()
            .filter(|r| matches!(r.status, HealthStatus::Degraded))
            .count();
        let unhealthy_count = results
            .values()
            .filter(|r| matches!(r.status, HealthStatus::Unhealthy))
            .count();

        // Determine overall status
        let overall_status = if unhealthy_count > 0 {
            HealthStatus::Unhealthy
        } else if degraded_count > 0 {
            HealthStatus::Degraded
        } else {
            HealthStatus::Healthy
        };

        let summary = HealthSummary {
            total_checks: results.len(),
            healthy_count,
            degraded_count,
            unhealthy_count,
            total_duration_ms: total_duration,
        };

        OverallHealthResponse {
            status: overall_status,
            service: "bedrock-sso-proxy".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            checks: results,
            summary,
        }
    }

    /// Get information about all registered health checkers
    pub async fn get_registered_checkers(&self) -> Vec<String> {
        let checkers = self.checkers.read().await;
        checkers.keys().cloned().collect()
    }
}

impl Default for HealthService {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    struct MockHealthyChecker;

    #[async_trait]
    impl HealthChecker for MockHealthyChecker {
        fn name(&self) -> &str {
            "mock_healthy"
        }

        async fn check(&self) -> HealthCheckResult {
            HealthCheckResult::healthy_with_details(json!({"test": "passed"}))
        }

        fn info(&self) -> Option<serde_json::Value> {
            Some(json!({"type": "mock", "version": "1.0"}))
        }
    }

    struct MockDegradedChecker;

    #[async_trait]
    impl HealthChecker for MockDegradedChecker {
        fn name(&self) -> &str {
            "mock_degraded"
        }

        async fn check(&self) -> HealthCheckResult {
            HealthCheckResult::degraded("Some performance issues".to_string())
        }
    }

    struct MockUnhealthyChecker;

    #[async_trait]
    impl HealthChecker for MockUnhealthyChecker {
        fn name(&self) -> &str {
            "mock_unhealthy"
        }

        async fn check(&self) -> HealthCheckResult {
            HealthCheckResult::unhealthy("Critical failure".to_string())
        }
    }

    #[tokio::test]
    async fn test_health_service_creation() {
        let service = HealthService::new();
        let checkers = service.get_registered_checkers().await;
        assert!(checkers.is_empty());
    }

    #[tokio::test]
    async fn test_register_and_check_healthy() {
        let service = HealthService::new();
        let checker = Arc::new(MockHealthyChecker);
        
        service.register(checker).await;
        
        let checkers = service.get_registered_checkers().await;
        assert_eq!(checkers.len(), 1);
        assert!(checkers.contains(&"mock_healthy".to_string()));
        
        let response = service.check_health(Some("all")).await;
        assert!(matches!(response.status, HealthStatus::Healthy));
        assert_eq!(response.summary.total_checks, 1);
        assert_eq!(response.summary.healthy_count, 1);
        assert_eq!(response.summary.degraded_count, 0);
        assert_eq!(response.summary.unhealthy_count, 0);
    }

    #[tokio::test]
    async fn test_multiple_checkers_mixed_status() {
        let service = HealthService::new();
        
        service.register(Arc::new(MockHealthyChecker)).await;
        service.register(Arc::new(MockDegradedChecker)).await;
        service.register(Arc::new(MockUnhealthyChecker)).await;
        
        let response = service.check_health(Some("all")).await;
        assert!(matches!(response.status, HealthStatus::Unhealthy)); // Worst case wins
        assert_eq!(response.summary.total_checks, 3);
        assert_eq!(response.summary.healthy_count, 1);
        assert_eq!(response.summary.degraded_count, 1);
        assert_eq!(response.summary.unhealthy_count, 1);
    }

    #[tokio::test]
    async fn test_specific_health_check() {
        let service = HealthService::new();
        
        service.register(Arc::new(MockHealthyChecker)).await;
        service.register(Arc::new(MockDegradedChecker)).await;
        
        let response = service.check_health(Some("mock_healthy")).await;
        assert!(matches!(response.status, HealthStatus::Healthy));
        assert_eq!(response.summary.total_checks, 1);
        assert!(response.checks.contains_key("mock_healthy"));
        assert!(!response.checks.contains_key("mock_degraded"));
    }

    #[tokio::test]
    async fn test_no_checks_requested() {
        let service = HealthService::new();
        
        service.register(Arc::new(MockHealthyChecker)).await;
        
        let response = service.check_health(None).await;
        assert!(matches!(response.status, HealthStatus::Healthy));
        assert_eq!(response.summary.total_checks, 0); // No checks run
        assert!(response.checks.is_empty());
    }

    #[tokio::test]
    async fn test_unregister_checker() {
        let service = HealthService::new();
        
        service.register(Arc::new(MockHealthyChecker)).await;
        assert_eq!(service.get_registered_checkers().await.len(), 1);
        
        service.unregister("mock_healthy").await;
        assert_eq!(service.get_registered_checkers().await.len(), 0);
    }

    #[test]
    fn test_health_check_result_creation() {
        let healthy = HealthCheckResult::healthy();
        assert!(matches!(healthy.status, HealthStatus::Healthy));
        assert!(healthy.message.is_none());

        let degraded = HealthCheckResult::degraded("Warning".to_string());
        assert!(matches!(degraded.status, HealthStatus::Degraded));
        assert_eq!(degraded.message, Some("Warning".to_string()));

        let unhealthy = HealthCheckResult::unhealthy("Error".to_string());
        assert!(matches!(unhealthy.status, HealthStatus::Unhealthy));
        assert_eq!(unhealthy.message, Some("Error".to_string()));

        let with_duration = HealthCheckResult::healthy().with_duration(150);
        assert_eq!(with_duration.duration_ms, Some(150));
    }
}