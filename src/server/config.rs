use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    #[serde(default = "default_log_level")]
    pub level: String,
    #[serde(default = "default_log_request")]
    pub log_request: bool,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: default_log_level(),
            log_request: default_log_request(),
        }
    }
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_log_request() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FrontendConfig {
    /// Path to serve frontend files from filesystem
    /// If not specified, uses embedded assets
    pub path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsConfig {
    #[serde(default = "default_metrics_enabled")]
    pub enabled: bool,
    #[serde(default = "default_metrics_port")]
    pub port: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShutdownConfig {
    /// Timeout in seconds for graceful shutdown of components
    #[serde(default = "default_shutdown_timeout")]
    pub timeout_seconds: u64,
    /// Timeout in seconds for streaming connections to complete
    #[serde(default = "default_streaming_timeout")]
    pub streaming_timeout_seconds: u64,
    /// Timeout in seconds for token tracking tasks to complete
    #[serde(default = "default_token_tracking_timeout")]
    pub token_tracking_timeout_seconds: u64,
    /// Timeout in seconds for background tasks to complete
    #[serde(default = "default_background_task_timeout")]
    pub background_task_timeout_seconds: u64,
}

fn default_metrics_enabled() -> bool {
    false
}

fn default_metrics_port() -> u16 {
    9090
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            enabled: default_metrics_enabled(),
            port: default_metrics_port(),
        }
    }
}

fn default_shutdown_timeout() -> u64 {
    30
}

fn default_streaming_timeout() -> u64 {
    30
}

fn default_token_tracking_timeout() -> u64 {
    30
}

fn default_background_task_timeout() -> u64 {
    5
}

impl Default for ShutdownConfig {
    fn default() -> Self {
        Self {
            timeout_seconds: default_shutdown_timeout(),
            streaming_timeout_seconds: default_streaming_timeout(),
            token_tracking_timeout_seconds: default_token_tracking_timeout(),
            background_task_timeout_seconds: default_background_task_timeout(),
        }
    }
}
