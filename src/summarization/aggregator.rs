use crate::database::{DatabaseManager, DatabaseResult, entities::*};
use chrono::{DateTime, Utc};
use rust_decimal::Decimal;
use std::collections::HashMap;
use tracing::info;

/// Key for grouping usage records
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct SummaryKey {
    user_id: i32,
    model_id: String,
}

/// Aggregated data for a summary group
#[derive(Debug, Default)]
struct SummaryData {
    total_requests: i32,
    total_input_tokens: i64,
    total_output_tokens: i64,
    total_tokens: i64,
    total_response_time: f64,
    successful_requests: i32,
    total_cost: Decimal,
}

/// Service for aggregating usage records into summaries using hierarchical approach
pub struct SummaryAggregator {
    database: std::sync::Arc<dyn DatabaseManager>,
}

impl SummaryAggregator {
    pub fn new(database: std::sync::Arc<dyn DatabaseManager>) -> Self {
        Self { database }
    }

    /// Generate summaries for a specific period using hierarchical approach
    pub async fn generate_summaries(
        &self,
        period_type: PeriodType,
        period_start: DateTime<Utc>,
    ) -> DatabaseResult<Vec<UsageSummary>> {
        self.generate_summaries_with_mode(period_type, period_start, false)
            .await
    }

    /// Generate summaries for a specific period, with optional backfill mode
    pub async fn generate_summaries_with_mode(
        &self,
        period_type: PeriodType,
        period_start: DateTime<Utc>,
        backfill: bool,
    ) -> DatabaseResult<Vec<UsageSummary>> {
        let period_end = period_type.period_end(period_start);

        // Only generate summaries for completed periods (except hourly which can be real-time)
        if period_type != PeriodType::Hourly && period_end > Utc::now() {
            info!(
                "Period {} to {} is not yet complete, skipping summary generation",
                period_start, period_end
            );
            return Ok(vec![]);
        }

        // In backfill mode, we force regeneration regardless of existing summaries
        if !backfill {
            // Quick check: if summaries already exist, skip unless backfill
            let existing_summaries = self
                .get_summaries_for_period(period_type, period_start, period_end)
                .await?;
            if !existing_summaries.is_empty() {
                info!(
                    "Summaries already exist for {} period {} to {}, skipping",
                    period_type.as_str(),
                    period_start,
                    period_end
                );
                return Ok(vec![]);
            }
        }

        info!(
            "Generating {} summaries for period {} to {} (backfill: {})",
            period_type.as_str(),
            period_start,
            period_end,
            backfill
        );

        match period_type {
            PeriodType::Hourly => {
                self.generate_hourly_summaries(period_start, period_end)
                    .await
            }
            PeriodType::Daily => {
                self.generate_daily_summaries(period_start, period_end)
                    .await
            }
            PeriodType::Weekly => {
                self.generate_weekly_summaries(period_start, period_end)
                    .await
            }
            PeriodType::Monthly => {
                self.generate_monthly_summaries(period_start, period_end)
                    .await
            }
        }
    }

    /// Generate hourly summaries from raw records (real-time capable)
    async fn generate_hourly_summaries(
        &self,
        period_start: DateTime<Utc>,
        period_end: DateTime<Utc>,
    ) -> DatabaseResult<Vec<UsageSummary>> {
        let query = crate::database::dao::usage::UsageQuery {
            start_date: Some(period_start),
            end_date: Some(period_end),
            ..Default::default()
        };

        let paginated_records = self.database.usage().get_records(&query).await?;

        if paginated_records.records.is_empty() {
            info!("No raw records found for hourly period, skipping");
            return Ok(vec![]);
        }

        self.aggregate_from_records(
            paginated_records.records,
            PeriodType::Hourly,
            period_start,
            period_end,
        )
        .await
    }

    /// Generate daily summaries from hourly summaries
    async fn generate_daily_summaries(
        &self,
        period_start: DateTime<Utc>,
        period_end: DateTime<Utc>,
    ) -> DatabaseResult<Vec<UsageSummary>> {
        let hourly_summaries = self
            .get_summaries_for_period(PeriodType::Hourly, period_start, period_end)
            .await?;

        if hourly_summaries.is_empty() {
            info!("No hourly summaries found for daily period, skipping");
            return Ok(vec![]);
        }

        self.aggregate_from_summaries(
            hourly_summaries,
            PeriodType::Daily,
            period_start,
            period_end,
        )
        .await
    }

    /// Generate weekly summaries from daily summaries
    async fn generate_weekly_summaries(
        &self,
        period_start: DateTime<Utc>,
        period_end: DateTime<Utc>,
    ) -> DatabaseResult<Vec<UsageSummary>> {
        let daily_summaries = self
            .get_summaries_for_period(PeriodType::Daily, period_start, period_end)
            .await?;

        if daily_summaries.is_empty() {
            info!("No daily summaries found for weekly period, skipping");
            return Ok(vec![]);
        }

        self.aggregate_from_summaries(
            daily_summaries,
            PeriodType::Weekly,
            period_start,
            period_end,
        )
        .await
    }

    /// Generate monthly summaries from daily summaries
    async fn generate_monthly_summaries(
        &self,
        period_start: DateTime<Utc>,
        period_end: DateTime<Utc>,
    ) -> DatabaseResult<Vec<UsageSummary>> {
        let daily_summaries = self
            .get_summaries_for_period(PeriodType::Daily, period_start, period_end)
            .await?;

        if daily_summaries.is_empty() {
            info!("No daily summaries found for monthly period, skipping");
            return Ok(vec![]);
        }

        self.aggregate_from_summaries(
            daily_summaries,
            PeriodType::Monthly,
            period_start,
            period_end,
        )
        .await
    }

    /// Get existing summaries for a specific period type and time range
    async fn get_summaries_for_period(
        &self,
        period_type: PeriodType,
        start_time: DateTime<Utc>,
        end_time: DateTime<Utc>,
    ) -> DatabaseResult<Vec<UsageSummary>> {
        let query = crate::database::dao::usage::UsageQuery {
            period_type: Some(period_type),
            start_date: Some(start_time),
            end_date: Some(end_time),
            ..Default::default()
        };

        self.database.usage().get_summaries(&query).await
    }

    /// Aggregate raw usage records into summaries
    async fn aggregate_from_records(
        &self,
        records: Vec<UsageRecord>,
        period_type: PeriodType,
        period_start: DateTime<Utc>,
        period_end: DateTime<Utc>,
    ) -> DatabaseResult<Vec<UsageSummary>> {
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

        self.build_summaries(grouped_data, period_type, period_start, period_end)
    }

    /// Aggregate existing summaries into higher-level summaries
    async fn aggregate_from_summaries(
        &self,
        summaries: Vec<UsageSummary>,
        period_type: PeriodType,
        period_start: DateTime<Utc>,
        period_end: DateTime<Utc>,
    ) -> DatabaseResult<Vec<UsageSummary>> {
        let mut grouped_data: HashMap<SummaryKey, SummaryData> = HashMap::new();

        for summary in &summaries {
            let key = SummaryKey {
                user_id: summary.user_id,
                model_id: summary.model_id.clone(),
            };

            let data = grouped_data.entry(key).or_default();
            data.total_requests += summary.total_requests;
            data.total_input_tokens += summary.total_input_tokens;
            data.total_output_tokens += summary.total_output_tokens;
            data.total_tokens += summary.total_tokens;

            // Weighted average for response time
            let weighted_response_time =
                summary.avg_response_time_ms * summary.total_requests as f32;
            data.total_response_time += weighted_response_time as f64;

            data.successful_requests += summary.successful_requests;

            if let Some(cost) = summary.estimated_cost {
                data.total_cost += cost;
            }
        }

        self.build_summaries(grouped_data, period_type, period_start, period_end)
    }

    /// Build final summary objects from aggregated data
    fn build_summaries(
        &self,
        grouped_data: HashMap<SummaryKey, SummaryData>,
        period_type: PeriodType,
        period_start: DateTime<Utc>,
        period_end: DateTime<Utc>,
    ) -> DatabaseResult<Vec<UsageSummary>> {
        let mut summaries = Vec::new();
        let now = Utc::now();

        for (key, data) in grouped_data {
            let avg_response_time_ms = if data.total_requests > 0 {
                (data.total_response_time / data.total_requests as f64) as f32
            } else {
                0.0
            };

            let summary = UsageSummary {
                id: 0, // Will be set by database
                user_id: key.user_id,
                model_id: key.model_id,
                period_type,
                period_start,
                period_end,
                total_requests: data.total_requests,
                successful_requests: data.successful_requests,
                total_input_tokens: data.total_input_tokens,
                total_output_tokens: data.total_output_tokens,
                total_tokens: data.total_tokens,
                avg_response_time_ms,
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
            "Generated {} {} summaries",
            summaries.len(),
            period_type.as_str()
        );

        Ok(summaries)
    }

    /// Store summaries in the database, handling upserts
    pub async fn store_summaries(&self, summaries: &[UsageSummary]) -> DatabaseResult<usize> {
        self.database.usage().upsert_many_summaries(summaries).await
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

    /// Get the latest period that needs summarization using watermark approach
    pub async fn get_next_period_to_process(
        &self,
        period_type: PeriodType,
    ) -> DatabaseResult<Option<DateTime<Utc>>> {
        // Step 1: Find the watermark (latest processed summary for this period type)
        let watermark_query = crate::database::dao::usage::UsageQuery {
            period_type: Some(period_type),
            limit: Some(1), // Latest summary (DESC order by default)
            ..Default::default()
        };

        let existing_summaries = self
            .database
            .usage()
            .get_summaries(&watermark_query)
            .await?;
        let watermark = existing_summaries.first().map(|s| s.period_end);

        // Step 2: Find next data after watermark using the hierarchical approach
        match period_type {
            PeriodType::Hourly => {
                // Find the first raw record after watermark (ASC order to get earliest)
                let next_record_query = crate::database::dao::usage::UsageQuery {
                    start_date: watermark, // Only records after watermark
                    limit: Some(1),        // First record
                    sort_order: crate::database::dao::usage::SortOrder::Asc,
                    ..Default::default()
                };

                let paginated_records = self
                    .database
                    .usage()
                    .get_records(&next_record_query)
                    .await?;
                if let Some(first_record) = paginated_records.records.first() {
                    let period_start = period_type.round_start(first_record.request_time);
                    let period_end = period_type.period_end(period_start);

                    if period_end <= chrono::Utc::now() {
                        Ok(Some(period_start))
                    } else {
                        Ok(None)
                    }
                } else {
                    Ok(None)
                }
            }
            _ => {
                // For daily/weekly/monthly, find first hourly summary after watermark (ASC order)
                let next_hourly_query = crate::database::dao::usage::UsageQuery {
                    period_type: Some(PeriodType::Hourly),
                    start_date: watermark, // Only summaries after watermark
                    limit: Some(1),        // First summary
                    sort_order: crate::database::dao::usage::SortOrder::Asc,
                    ..Default::default()
                };

                let hourly_summaries = self
                    .database
                    .usage()
                    .get_summaries(&next_hourly_query)
                    .await?;
                if let Some(first_hourly) = hourly_summaries.first() {
                    let period_start = period_type.round_start(first_hourly.period_start);
                    let period_end = period_type.period_end(period_start);

                    if period_end <= chrono::Utc::now() {
                        Ok(Some(period_start))
                    } else {
                        Ok(None)
                    }
                } else {
                    Ok(None)
                }
            }
        }
    }
}
