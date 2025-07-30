use super::{Job, JobResult, UsageSummariesConfig};
use crate::{error::AppError, summarization::SummarizationService};
use async_trait::async_trait;
use std::sync::Arc;
use tracing::info;

/// Job for generating usage summaries
pub struct SummariesJob {
    service: Arc<SummarizationService>,
    config: UsageSummariesConfig,
}

impl SummariesJob {
    pub fn new(service: Arc<SummarizationService>, config: UsageSummariesConfig) -> Self {
        Self { service, config }
    }
}

#[async_trait]
impl Job for SummariesJob {
    fn name(&self) -> &str {
        "usage_summaries"
    }

    async fn execute(&self) -> Result<JobResult, AppError> {
        let mut total_summaries = 0;

        for period in &self.config.periods {
            info!("Generating {} summaries", period);

            let days_back = match period.as_str() {
                "hourly" => 1,   // Last 24 hours
                "daily" => 7,    // Last week
                "weekly" => 30,  // Last month
                "monthly" => 90, // Last 3 months
                _ => {
                    return Err(AppError::Internal(format!(
                        "Unsupported period type: {}",
                        period
                    )));
                }
            };

            let count = self
                .service
                .generate_summaries(period, days_back, None, None)
                .await?;

            total_summaries += count;
            info!("Generated {} {} summaries", count, period);
        }

        Ok(JobResult::success_with_count(total_summaries as u64))
    }
}
