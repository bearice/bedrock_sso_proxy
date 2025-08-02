pub mod cleanup;
pub mod scheduler;
pub mod summaries;

use crate::error::AppError;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

pub use cleanup::CleanupJob;
pub use scheduler::JobScheduler;
pub use summaries::SummariesJob;

/// Configuration for the job system
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobsConfig {
    /// Enable/disable internal job scheduler
    pub enabled: bool,

    /// Usage summaries job configuration
    pub usage_summaries: UsageSummariesConfig,

    /// Usage cleanup job configuration  
    pub usage_cleanup: UsageCleanupConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsageSummariesConfig {
    /// Cron schedule expression
    pub schedule: String,
    /// Which periods to generate (daily, weekly, monthly, etc.)
    pub periods: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsageCleanupConfig {
    /// Cron schedule expression
    pub schedule: String,
    /// Retention for raw records in days
    pub raw_records_days: u32,
    /// Retention for summaries in days
    pub summaries_days: u32,
}

impl Default for JobsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            usage_summaries: UsageSummariesConfig {
                schedule: "0 0 2 * * *".to_string(), // Daily at 2 AM
                periods: vec!["daily".to_string()],
            },
            usage_cleanup: UsageCleanupConfig {
                schedule: "0 0 3 * * *".to_string(), // Daily at 3 AM
                raw_records_days: 30,
                summaries_days: 365,
            },
        }
    }
}

/// Result of job execution
#[derive(Debug, Clone)]
pub struct JobResult {
    pub success: bool,
    pub message: String,
    pub items_processed: u64,
}

impl JobResult {
    pub fn success_with_count(count: u64) -> Self {
        Self {
            success: true,
            message: format!("Successfully processed {} items", count),
            items_processed: count,
        }
    }

    pub fn success() -> Self {
        Self {
            success: true,
            message: "Job completed successfully".to_string(),
            items_processed: 0,
        }
    }

    pub fn failure(message: String) -> Self {
        Self {
            success: false,
            message,
            items_processed: 0,
        }
    }
}

/// Trait for executable jobs
#[async_trait]
pub trait Job: Send + Sync {
    /// Get the job name for logging and identification
    fn name(&self) -> &str;

    /// Execute the job and return the result
    async fn execute(&self) -> Result<JobResult, AppError>;
}
