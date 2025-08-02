use super::{Job, JobResult, UsageSummariesConfig};
use crate::{
    error::AppError,
    summarization::{PeriodType, SummarizationService},
};
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
            info!(
                "Generating {} summaries using hierarchical aggregation",
                period
            );

            let period_type = match period.as_str() {
                "hourly" => PeriodType::Hourly,
                "daily" => PeriodType::Daily,
                "weekly" => PeriodType::Weekly,
                "monthly" => PeriodType::Monthly,
                _ => {
                    return Err(AppError::Internal(format!(
                        "Unsupported period type: {period}"
                    )));
                }
            };

            // Use the new period-based summarization that respects completion constraints
            let count = self.service.generate_period_summaries(period_type).await?;

            total_summaries += count;
            info!(
                "Generated {} {} summaries using hierarchical approach",
                count, period
            );
        }

        Ok(JobResult::success_with_count(total_summaries as u64))
    }
}
