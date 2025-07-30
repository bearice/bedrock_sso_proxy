use serde::{Deserialize, Serialize};

/// Configuration for summarization service
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SummarizationConfig {
    /// Whether summarization is enabled
    pub enabled: bool,
    /// Batch size for processing records
    pub batch_size: u32,
    /// Maximum retries for failed jobs
    pub max_retries: u32,
    /// Retention configuration
    pub retention: RetentionConfig,
    /// Schedule configuration  
    pub schedules: ScheduleConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetentionConfig {
    /// Days to keep raw records
    pub raw_records_days: u32,
    /// Days to keep summaries
    pub summaries_days: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScheduleConfig {
    /// Cron expression for hourly jobs
    pub hourly: String,
    /// Cron expression for daily jobs
    pub daily: String,
    /// Cron expression for weekly jobs
    pub weekly: String,
    /// Cron expression for monthly jobs
    pub monthly: String,
}

impl Default for SummarizationConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            batch_size: 1000,
            max_retries: 3,
            retention: RetentionConfig {
                raw_records_days: 30,
                summaries_days: 365,
            },
            schedules: ScheduleConfig {
                hourly: "0 * * * *".to_string(),  // Every hour at minute 0
                daily: "0 2 * * *".to_string(),   // Daily at 2 AM
                weekly: "0 3 * * 0".to_string(),  // Weekly on Sunday at 3 AM
                monthly: "0 4 1 * *".to_string(), // Monthly on 1st at 4 AM
            },
        }
    }
}
