pub mod cleanup;
pub mod scheduler;
pub mod summaries;

use crate::{database::entities::PeriodType, error::AppError};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

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
    /// Retention for summaries by period type in days
    #[serde(default = "default_summaries_retention_days")]
    pub summaries_retention_days: HashMap<PeriodType, u32>,
}

/// Default values for summaries retention days by period type
pub fn default_summaries_retention_days() -> HashMap<PeriodType, u32> {
    let mut map = HashMap::new();
    map.insert(PeriodType::Hourly, 7); // Keep hourly summaries for 7 days
    map.insert(PeriodType::Daily, 90); // Keep daily summaries for 90 days
    map.insert(PeriodType::Weekly, 365); // Keep weekly summaries for 1 year
    map.insert(PeriodType::Monthly, 1095); // Keep monthly summaries for 3 years
    map
}

impl UsageCleanupConfig {
    /// Get the retention days for a specific period type
    pub fn get_retention_days(&self, period_type: PeriodType) -> u32 {
        self.summaries_retention_days
            .get(&period_type)
            .copied()
            .unwrap_or_else(|| {
                // Fallback to defaults if not specified
                let defaults = default_summaries_retention_days();
                defaults.get(&period_type).copied().unwrap_or(365)
            })
    }
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
                summaries_retention_days: default_summaries_retention_days(),
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
            message: format!("Successfully processed {count} items"),
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
