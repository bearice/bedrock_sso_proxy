use crate::database::{DatabaseManager, DatabaseResult, entities::*};
use chrono::{DateTime, Datelike, Duration, DurationRound, Utc};
use rust_decimal::Decimal;
use std::collections::HashMap;
use tracing::{error, info};

/// Period types for aggregation
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeriodType {
    Hourly,
    Daily,
    Weekly,
    Monthly,
}

impl PeriodType {
    /// Get the duration for this period type
    pub fn duration(&self) -> Duration {
        match self {
            PeriodType::Hourly => Duration::hours(1),
            PeriodType::Daily => Duration::days(1),
            PeriodType::Weekly => Duration::weeks(1),
            PeriodType::Monthly => Duration::days(30), // Approximation
        }
    }

    /// Round a datetime to the start of the period
    pub fn round_start(&self, dt: DateTime<Utc>) -> DateTime<Utc> {
        match self {
            PeriodType::Hourly => dt.duration_trunc(Duration::hours(1)).unwrap_or(dt),
            PeriodType::Daily => dt
                .date_naive()
                .and_hms_opt(0, 0, 0)
                .map(|naive| DateTime::from_naive_utc_and_offset(naive, Utc))
                .unwrap_or(dt),
            PeriodType::Weekly => {
                // Round to Monday 00:00:00
                let days_since_monday = dt.weekday().num_days_from_monday();
                let start_of_week = dt - Duration::days(days_since_monday as i64);
                start_of_week
                    .date_naive()
                    .and_hms_opt(0, 0, 0)
                    .map(|naive| DateTime::from_naive_utc_and_offset(naive, Utc))
                    .unwrap_or(dt)
            }
            PeriodType::Monthly => {
                // Round to 1st of month 00:00:00
                let naive_date = dt.date_naive().with_day(1).unwrap_or(dt.date_naive());
                naive_date
                    .and_hms_opt(0, 0, 0)
                    .map(|naive| DateTime::from_naive_utc_and_offset(naive, Utc))
                    .unwrap_or(dt)
            }
        }
    }

    /// Get the end of a period given the start
    pub fn period_end(&self, start: DateTime<Utc>) -> DateTime<Utc> {
        match self {
            PeriodType::Hourly => start + Duration::hours(1),
            PeriodType::Daily => start + Duration::days(1),
            PeriodType::Weekly => start + Duration::weeks(1),
            PeriodType::Monthly => {
                // Handle month boundaries properly
                let naive_date = start.date_naive();
                if let Some(next_month) = naive_date.with_month(naive_date.month() + 1) {
                    DateTime::from_naive_utc_and_offset(
                        next_month.and_hms_opt(0, 0, 0).unwrap_or_default(),
                        Utc,
                    )
                } else {
                    // Handle year boundary
                    let next_year = naive_date
                        .with_year(naive_date.year() + 1)
                        .and_then(|d| d.with_month(1))
                        .unwrap_or(naive_date);
                    DateTime::from_naive_utc_and_offset(
                        next_year.and_hms_opt(0, 0, 0).unwrap_or_default(),
                        Utc,
                    )
                }
            }
        }
    }

    /// Convert to string for database storage
    pub fn as_str(&self) -> &'static str {
        match self {
            PeriodType::Hourly => "hourly",
            PeriodType::Daily => "daily",
            PeriodType::Weekly => "weekly",
            PeriodType::Monthly => "monthly",
        }
    }
}

/// Key for grouping usage records
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct SummaryKey {
    user_id: i32,
    model_id: String,
}

/// Aggregated data for a summary group
#[derive(Debug, Default)]
struct SummaryData {
    total_requests: u32,
    total_input_tokens: i64,
    total_output_tokens: i64,
    total_tokens: i64,
    total_response_time: f64,
    successful_requests: u32,
    total_cost: Decimal,
}

/// Service for aggregating usage records into summaries
pub struct SummaryAggregator {
    database: std::sync::Arc<dyn DatabaseManager>,
}

impl SummaryAggregator {
    pub fn new(database: std::sync::Arc<dyn DatabaseManager>) -> Self {
        Self { database }
    }

    /// Generate summaries for a specific period
    pub async fn generate_summaries(
        &self,
        period_type: PeriodType,
        period_start: DateTime<Utc>,
    ) -> DatabaseResult<Vec<UsageSummary>> {
        let period_end = period_type.period_end(period_start);

        info!(
            "Generating {} summaries for period {} to {}",
            period_type.as_str(),
            period_start,
            period_end
        );

        // Get all usage records for this period
        let query = crate::database::dao::usage::UsageQuery {
            user_id: None,
            model_id: None,
            start_date: Some(period_start),
            end_date: Some(period_end),
            success_only: None,
            limit: None,
            offset: None,
        };

        let records = self.database.usage().get_records(&query).await?;

        if records.is_empty() {
            info!("No records found for period, skipping summary generation");
            return Ok(vec![]);
        }

        // Group records by user_id + model_id
        let mut grouped_data: HashMap<SummaryKey, SummaryData> = HashMap::new();

        for record in &records {
            let key = SummaryKey {
                user_id: record.user_id,
                model_id: record.model_id.clone(),
            };

            let data = grouped_data.entry(key).or_default();
            data.total_requests += 1;
            data.total_input_tokens += record.input_tokens as i64;
            data.total_output_tokens += record.output_tokens as i64;
            data.total_tokens += record.total_tokens as i64;
            data.total_response_time += record.response_time_ms as f64;

            if record.success {
                data.successful_requests += 1;
            }

            if let Some(cost) = record.cost_usd {
                data.total_cost += cost;
            }
        }

        // Convert grouped data to summaries
        let mut summaries = Vec::new();
        let now = Utc::now();

        for (key, data) in grouped_data {
            let avg_response_time_ms = if data.total_requests > 0 {
                (data.total_response_time / data.total_requests as f64) as f32
            } else {
                0.0
            };

            let success_rate = if data.total_requests > 0 {
                data.successful_requests as f32 / data.total_requests as f32
            } else {
                0.0
            };

            let summary = UsageSummary {
                id: 0, // Will be set by database
                user_id: key.user_id,
                model_id: key.model_id,
                period_type: period_type.as_str().to_string(),
                period_start,
                period_end,
                total_requests: data.total_requests,
                total_input_tokens: data.total_input_tokens,
                total_output_tokens: data.total_output_tokens,
                total_tokens: data.total_tokens,
                avg_response_time_ms,
                success_rate,
                estimated_cost: if data.total_cost > Decimal::ZERO {
                    Some(data.total_cost)
                } else {
                    None
                },
                created_at: now,
                updated_at: now,
            };

            summaries.push(summary);
        }

        info!(
            "Generated {} summaries for {} records",
            summaries.len(),
            records.len()
        );

        Ok(summaries)
    }

    /// Store summaries in the database, handling upserts
    pub async fn store_summaries(&self, summaries: &[UsageSummary]) -> DatabaseResult<usize> {
        let mut stored_count = 0;

        for summary in summaries {
            match self.database.usage().upsert_summary(summary).await {
                Ok(()) => stored_count += 1,
                Err(e) => {
                    error!(
                        "Failed to store summary for user {} model {}: {}",
                        summary.user_id, summary.model_id, e
                    );
                    return Err(e);
                }
            }
        }

        info!("Successfully stored {} summaries", stored_count);
        Ok(stored_count)
    }

    /// Generate and store summaries for a period
    pub async fn process_period(
        &self,
        period_type: PeriodType,
        period_start: DateTime<Utc>,
    ) -> DatabaseResult<usize> {
        let summaries = self.generate_summaries(period_type, period_start).await?;

        if summaries.is_empty() {
            return Ok(0);
        }

        self.store_summaries(&summaries).await
    }

    /// Get the latest period that needs summarization
    pub async fn get_next_period_to_process(
        &self,
        period_type: PeriodType,
    ) -> DatabaseResult<Option<DateTime<Utc>>> {
        // Find the latest summary for this period type
        let summaries = self
            .database
            .usage()
            .get_summaries(&crate::database::dao::usage::UsageQuery {
                user_id: None,
                model_id: None,
                start_date: None,
                end_date: None,
                success_only: None,
                limit: Some(1),
                offset: None,
            })
            .await?;

        let latest_period_end = summaries
            .iter()
            .filter(|s| s.period_type == period_type.as_str())
            .map(|s| s.period_end)
            .max();

        let next_period_start = if let Some(latest_end) = latest_period_end {
            latest_end
        } else {
            // No summaries exist, find earliest usage record
            let earliest_record_query = crate::database::dao::usage::UsageQuery {
                user_id: None,
                model_id: None,
                start_date: None,
                end_date: None,
                success_only: None,
                limit: Some(1),
                offset: None,
            };

            let records = self
                .database
                .usage()
                .get_records(&earliest_record_query)
                .await?;
            if let Some(earliest_record) = records.first() {
                period_type.round_start(earliest_record.request_time)
            } else {
                // No records at all
                return Ok(None);
            }
        };

        let period_end = period_type.period_end(next_period_start);

        // Only return periods that are complete (end time is in the past)
        if period_end <= Utc::now() {
            Ok(Some(next_period_start))
        } else {
            Ok(None)
        }
    }
}
