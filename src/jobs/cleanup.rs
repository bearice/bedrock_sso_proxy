use super::{Job, JobResult, UsageCleanupConfig};
use crate::{error::AppError, summarization::SummarizationService};
use async_trait::async_trait;
use std::sync::Arc;
use tracing::info;

/// Job for cleaning up old usage records and summaries
pub struct CleanupJob {
    service: Arc<SummarizationService>,
    config: UsageCleanupConfig,
}

impl CleanupJob {
    pub fn new(service: Arc<SummarizationService>, config: UsageCleanupConfig) -> Self {
        Self { service, config }
    }
}

#[async_trait]
impl Job for CleanupJob {
    fn name(&self) -> &str {
        "usage_cleanup"
    }

    async fn execute(&self) -> Result<JobResult, AppError> {
        let mut total_cleaned = 0;

        // Clean up old raw records
        info!(
            "Cleaning up raw usage records older than {} days",
            self.config.raw_records_days
        );

        let records_cleaned = self
            .service
            .cleanup_records(self.config.raw_records_days)
            .await?;

        total_cleaned += records_cleaned;
        info!("Cleaned up {} raw usage records", records_cleaned);

        // Clean up old summaries
        info!(
            "Cleaning up usage summaries older than {} days",
            self.config.summaries_days
        );

        let summaries_cleaned = self
            .service
            .cleanup_summaries(self.config.summaries_days)
            .await?;

        total_cleaned += summaries_cleaned;
        info!("Cleaned up {} usage summaries", summaries_cleaned);

        Ok(JobResult::success_with_count(total_cleaned))
    }
}
