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

fn default_metrics_enabled() -> bool {
    true
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