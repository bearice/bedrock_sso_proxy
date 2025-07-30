use crate::{
    database::{DatabaseManager, entities::UsageSummary},
    error::AppError,
};
use chrono::{DateTime, Datelike, Duration, Timelike, Utc};
use rust_decimal::Decimal;
use std::collections::HashMap;
use tracing::info;

/// Core summarization service extracted from maintenance CLI
pub struct SummarizationService {
    database: std::sync::Arc<dyn DatabaseManager>,
}

impl SummarizationService {
    pub fn new(database: std::sync::Arc<dyn DatabaseManager>) -> Self {
        Self { database }
    }

    /// Generate usage summaries for a specific period and time range
    pub async fn generate_summaries(
        &self,
        period: &str,
        days_back: u32,
        user_id_filter: Option<i32>,
        model_id_filter: Option<&str>,
    ) -> Result<usize, AppError> {
        use crate::database::dao::usage::UsageQuery;

        let end_date = Utc::now();
        let start_date = end_date - Duration::days(days_back as i64);

        info!(
            "Generating {} summaries from {} to {}",
            period,
            start_date.format("%Y-%m-%d %H:%M:%S"),
            end_date.format("%Y-%m-%d %H:%M:%S")
        );

        // Get all usage records within the specified time range
        let query = UsageQuery {
            user_id: user_id_filter,
            model_id: model_id_filter.map(|s| s.to_string()),
            start_date: Some(start_date),
            end_date: Some(end_date),
            success_only: None,
            limit: None,
            offset: None,
        };

        let records = self
            .database
            .usage()
            .get_records(&query)
            .await
            .map_err(|e| AppError::Internal(format!("Failed to get usage records: {}", e)))?;

        info!("Found {} usage records to process", records.len());

        if records.is_empty() {
            info!("No records found for the specified criteria");
            return Ok(0);
        }

        // Group records by (user_id, model_id, period)
        let mut summary_groups: HashMap<(i32, String, String, DateTime<Utc>), Vec<_>> =
            HashMap::new();

        for record in records {
            let period_start = self.calculate_period_start(period, record.request_time)?;
            let key = (
                record.user_id,
                record.model_id.clone(),
                period.to_string(),
                period_start,
            );
            summary_groups.entry(key).or_default().push(record);
        }

        info!("Created {} summary groups", summary_groups.len());

        // Generate and store summaries for each group
        let mut summaries_created = 0;
        for ((user_id, model_id, period_type, period_start), group_records) in summary_groups {
            let period_end = self.calculate_period_end(period, period_start)?;
            let summary = self.create_summary(
                user_id,
                model_id,
                period_type,
                period_start,
                period_end,
                group_records,
            )?;

            self.database
                .usage()
                .upsert_summary(&summary)
                .await
                .map_err(|e| AppError::Internal(format!("Failed to upsert summary: {}", e)))?;

            summaries_created += 1;

            if summaries_created % 100 == 0 {
                info!("Created {} summaries...", summaries_created);
            }
        }

        info!(
            "Successfully created/updated {} summaries",
            summaries_created
        );
        Ok(summaries_created)
    }

    /// Calculate the start of a period for a given timestamp
    fn calculate_period_start(
        &self,
        period: &str,
        timestamp: DateTime<Utc>,
    ) -> Result<DateTime<Utc>, AppError> {
        match period {
            "hourly" => Ok(timestamp
                .date_naive()
                .and_hms_opt(timestamp.hour(), 0, 0)
                .unwrap()
                .and_utc()),
            "daily" => Ok(timestamp
                .date_naive()
                .and_hms_opt(0, 0, 0)
                .unwrap()
                .and_utc()),
            "weekly" => {
                let days_since_monday = timestamp.weekday().num_days_from_monday();
                let start_of_week = timestamp - Duration::days(days_since_monday as i64);
                Ok(start_of_week
                    .date_naive()
                    .and_hms_opt(0, 0, 0)
                    .unwrap()
                    .and_utc())
            }
            "monthly" => Ok(timestamp
                .date_naive()
                .with_day(1)
                .unwrap()
                .and_hms_opt(0, 0, 0)
                .unwrap()
                .and_utc()),
            _ => Err(AppError::Internal(format!(
                "Invalid period type: {}",
                period
            ))),
        }
    }

    /// Calculate the end of a period for a given start time
    fn calculate_period_end(
        &self,
        period: &str,
        period_start: DateTime<Utc>,
    ) -> Result<DateTime<Utc>, AppError> {
        match period {
            "hourly" => Ok(period_start + Duration::hours(1) - Duration::seconds(1)),
            "daily" => Ok(period_start + Duration::days(1) - Duration::seconds(1)),
            "weekly" => Ok(period_start + Duration::weeks(1) - Duration::seconds(1)),
            "monthly" => {
                let next_month = if period_start.month() == 12 {
                    period_start
                        .with_year(period_start.year() + 1)
                        .unwrap()
                        .with_month(1)
                        .unwrap()
                } else {
                    period_start.with_month(period_start.month() + 1).unwrap()
                };
                Ok(next_month - Duration::seconds(1))
            }
            _ => Err(AppError::Internal(format!(
                "Invalid period type: {}",
                period
            ))),
        }
    }

    /// Create a summary from a group of usage records
    fn create_summary(
        &self,
        user_id: i32,
        model_id: String,
        period_type: String,
        period_start: DateTime<Utc>,
        period_end: DateTime<Utc>,
        records: Vec<crate::database::entities::UsageRecord>,
    ) -> Result<UsageSummary, AppError> {
        let total_requests = records.len() as u32;
        let total_input_tokens = records.iter().map(|r| r.input_tokens as i64).sum();
        let total_output_tokens = records.iter().map(|r| r.output_tokens as i64).sum();
        let total_tokens = records.iter().map(|r| r.total_tokens as i64).sum();

        let avg_response_time_ms = if !records.is_empty() {
            records
                .iter()
                .map(|r| r.response_time_ms as f32)
                .sum::<f32>()
                / records.len() as f32
        } else {
            0.0
        };

        let success_count = records.iter().filter(|r| r.success).count();
        let success_rate = if !records.is_empty() {
            success_count as f32 / records.len() as f32
        } else {
            0.0
        };

        let estimated_cost = records
            .iter()
            .filter_map(|r| r.cost_usd)
            .fold(Decimal::ZERO, |acc, cost| acc + cost);

        Ok(UsageSummary {
            id: 0, // Will be set by database
            user_id,
            model_id,
            period_type,
            period_start,
            period_end,
            total_requests,
            total_input_tokens,
            total_output_tokens,
            total_tokens,
            avg_response_time_ms,
            success_rate,
            estimated_cost: if estimated_cost > Decimal::ZERO {
                Some(estimated_cost)
            } else {
                None
            },
            created_at: Utc::now(),
            updated_at: Utc::now(),
        })
    }

    /// Clean up old usage records
    pub async fn cleanup_records(&self, retention_days: u32) -> Result<u64, AppError> {
        let deleted_count = self
            .database
            .usage()
            .cleanup_old_records(retention_days)
            .await
            .map_err(|e| AppError::Internal(format!("Failed to cleanup records: {}", e)))?;

        info!("Cleaned up {} old usage records", deleted_count);
        Ok(deleted_count)
    }

    /// Clean up old usage summaries
    pub async fn cleanup_summaries(&self, _retention_days: u32) -> Result<u64, AppError> {
        // Similar to cleanup_records but for summaries table
        // This would require adding a cleanup method to the DAO
        info!("Summary cleanup not yet implemented");
        Ok(0)
    }
}
