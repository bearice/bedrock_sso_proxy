use crate::{
    database::DatabaseManager, database::entities::PeriodType, error::AppError,
    summarization::aggregator::SummaryAggregator,
};
use chrono::{Duration, Utc};
use std::sync::Arc;
use tracing::info;

/// Core summarization service using hierarchical aggregation
pub struct SummarizationService {
    database: Arc<dyn DatabaseManager>,
    aggregator: SummaryAggregator,
}

impl SummarizationService {
    pub fn new(database: Arc<dyn DatabaseManager>) -> Self {
        let aggregator = SummaryAggregator::new(database.clone());
        Self {
            database,
            aggregator,
        }
    }

    /// Generate usage summaries for a specific period using hierarchical aggregation
    pub async fn generate_summaries(
        &self,
        period: &str,
        days_back: u32,
        user_id_filter: Option<i32>,
        model_id_filter: Option<&str>,
        backfill: bool,
    ) -> Result<usize, AppError> {
        let period_type = match period {
            "hourly" => {
                tracing::warn!(
                    "Hourly summaries are now updated in real-time after each usage record. \
                    Manual hourly generation is only needed for backfilling historical data."
                );
                PeriodType::Hourly
            }
            "daily" => PeriodType::Daily,
            "weekly" => PeriodType::Weekly,
            "monthly" => PeriodType::Monthly,
            _ => {
                return Err(AppError::Internal(format!("Invalid period type: {period}")));
            }
        };

        let end_date = Utc::now();
        let start_date = end_date - Duration::days(days_back as i64);
        let cutoff_date = period_type.round_start(start_date);

        let mode_description = if backfill { "backfill" } else { "incremental" };
        info!(
            "Generating {} summaries from {} to {} using hierarchical aggregation (mode: {})",
            period,
            start_date.format("%Y-%m-%d %H:%M:%S"),
            end_date.format("%Y-%m-%d %H:%M:%S"),
            mode_description
        );

        // Use the unified efficient approach for both modes
        self.generate_summaries_internal(
            period_type,
            Some(cutoff_date),
            Some(end_date),
            user_id_filter,
            model_id_filter,
            backfill,
        )
        .await
    }

    /// Generate summaries for specific periods (used by job system)
    pub async fn generate_period_summaries(
        &self,
        period_type: PeriodType,
    ) -> Result<usize, AppError> {
        info!(
            "Generating {} summaries using hierarchical aggregation",
            period_type.as_str()
        );

        // Use the unified efficient approach without date limits
        self.generate_summaries_internal(period_type, None, None, None, None, false)
            .await
    }

    /// Internal unified method for generating summaries with efficient high-water mark approach
    async fn generate_summaries_internal(
        &self,
        period_type: PeriodType,
        start_limit: Option<chrono::DateTime<Utc>>,
        end_limit: Option<chrono::DateTime<Utc>>,
        user_id_filter: Option<i32>,
        model_id_filter: Option<&str>,
        backfill: bool,
    ) -> Result<usize, AppError> {
        let mut total_summaries = 0;

        if backfill && start_limit.is_some() && end_limit.is_some() {
            // Backfill mode: Process all periods within the date range
            let mut current_period_start = start_limit.unwrap();
            let end_date = end_limit.unwrap();

            while current_period_start < end_date {
                let period_end = period_type.period_end(current_period_start);

                if current_period_start >= end_date {
                    break;
                }

                info!(
                    "Processing {} period (backfill): {} to {}",
                    period_type.as_str(),
                    current_period_start.format("%Y-%m-%d %H:%M:%S"),
                    period_end.format("%Y-%m-%d %H:%M:%S")
                );

                let summaries = self
                    .aggregator
                    .generate_summaries_with_mode(period_type, current_period_start, backfill)
                    .await
                    .map_err(|e| {
                        AppError::Internal(format!("Failed to generate summaries: {e}"))
                    })?;

                if !summaries.is_empty() {
                    let filtered_summaries =
                        Self::apply_filters(summaries, user_id_filter, model_id_filter);
                    let stored_count = self
                        .aggregator
                        .store_summaries(&filtered_summaries)
                        .await
                        .map_err(|e| {
                        AppError::Internal(format!("Failed to store summaries: {e}"))
                    })?;

                    total_summaries += stored_count;

                    if stored_count > 0 {
                        info!(
                            "Stored {} {} summaries for period {} to {} (backfill)",
                            stored_count,
                            period_type.as_str(),
                            current_period_start.format("%Y-%m-%d %H:%M:%S"),
                            period_end.format("%Y-%m-%d %H:%M:%S")
                        );
                    }
                }

                current_period_start = period_end;
            }
        } else {
            // Incremental mode: Use high-water mark approach (efficient)
            while let Some(period_start) = self
                .aggregator
                .get_next_period_to_process(period_type)
                .await
                .map_err(|e| AppError::Internal(format!("Failed to get next period: {e}")))?
            {
                // Apply date range limits if specified
                if let Some(cutoff_date) = start_limit {
                    if period_start < cutoff_date {
                        continue;
                    }
                }
                if let Some(end_date) = end_limit {
                    if period_start >= end_date {
                        break;
                    }
                }

                info!(
                    "Processing {} period (incremental): {}",
                    period_type.as_str(),
                    period_start.format("%Y-%m-%d %H:%M:%S")
                );

                let summaries = self
                    .aggregator
                    .generate_summaries(period_type, period_start)
                    .await
                    .map_err(|e| {
                        AppError::Internal(format!("Failed to generate summaries: {e}"))
                    })?;

                if !summaries.is_empty() {
                    let filtered_summaries =
                        Self::apply_filters(summaries, user_id_filter, model_id_filter);
                    let stored_count = self
                        .aggregator
                        .store_summaries(&filtered_summaries)
                        .await
                        .map_err(|e| {
                        AppError::Internal(format!("Failed to store summaries: {e}"))
                    })?;

                    total_summaries += stored_count;

                    if stored_count > 0 {
                        info!(
                            "Stored {} {} summaries for period {} (incremental)",
                            stored_count,
                            period_type.as_str(),
                            period_start.format("%Y-%m-%d %H:%M:%S")
                        );
                    }
                } else {
                    // No summaries generated, break to avoid infinite loop
                    break;
                }
            }
        }

        info!(
            "Successfully created/updated {} {} summaries using hierarchical aggregation",
            total_summaries,
            period_type.as_str()
        );
        Ok(total_summaries)
    }

    /// Helper method to apply user_id and model_id filters
    fn apply_filters(
        summaries: Vec<crate::database::entities::UsageSummary>,
        user_id_filter: Option<i32>,
        model_id_filter: Option<&str>,
    ) -> Vec<crate::database::entities::UsageSummary> {
        summaries
            .into_iter()
            .filter(|s| {
                if let Some(uid) = user_id_filter {
                    if s.user_id != uid {
                        return false;
                    }
                }
                if let Some(mid) = model_id_filter {
                    if s.model_id != mid {
                        return false;
                    }
                }
                true
            })
            .collect()
    }

    /// Clean up old usage records
    pub async fn cleanup_records(&self, retention_days: u32) -> Result<u64, AppError> {
        let deleted_count = self
            .database
            .usage()
            .cleanup_old_records(retention_days)
            .await
            .map_err(|e| AppError::Internal(format!("Failed to cleanup records: {e}")))?;

        info!("Cleaned up {} old usage records", deleted_count);
        Ok(deleted_count)
    }

    /// Clean up old usage summaries
    pub async fn cleanup_summaries(&self, retention_days: u32) -> Result<u64, AppError> {
        let deleted_count = self
            .database
            .usage()
            .cleanup_old_summaries(retention_days)
            .await
            .map_err(|e| AppError::Internal(format!("Failed to cleanup summaries: {e}")))?;

        info!("Cleaned up {} old usage summaries", deleted_count);
        Ok(deleted_count)
    }
}
