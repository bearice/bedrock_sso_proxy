use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheConfig {
    #[serde(default = "default_validation_ttl")]
    pub validation_ttl: u64,
    #[serde(default = "default_max_entries")]
    pub max_entries: usize,
    #[serde(default = "default_cleanup_interval")]
    pub cleanup_interval: u64,
    #[serde(default = "default_cache_backend")]
    pub backend: String,
    #[serde(default = "default_redis_url")]
    pub redis_url: String,
    #[serde(default = "default_redis_key_prefix")]
    pub redis_key_prefix: String,
}

fn default_validation_ttl() -> u64 {
    86400 // 24 hours
}

fn default_max_entries() -> usize {
    10000
}

fn default_cleanup_interval() -> u64 {
    3600 // 1 hour
}

fn default_cache_backend() -> String {
    "memory".to_string()
}

fn default_redis_url() -> String {
    "redis://localhost:6379".to_string()
}

fn default_redis_key_prefix() -> String {
    "bedrock_sso:".to_string()
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            validation_ttl: default_validation_ttl(),
            max_entries: default_max_entries(),
            cleanup_interval: default_cleanup_interval(),
            backend: default_cache_backend(),
            redis_url: default_redis_url(),
            redis_key_prefix: default_redis_key_prefix(),
        }
    }
}