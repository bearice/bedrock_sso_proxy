use crate::database::entities::{
    PeriodType, UsageRecord, UsageSummary, usage_records, usage_summaries,
};
use crate::database::{DatabaseError, DatabaseResult};
use chrono::{DateTime, Utc};
use rust_decimal::Decimal;
use sea_orm::{
    ActiveModelTrait, ActiveValue, ColumnTrait, DatabaseConnection, EntityTrait, FromQueryResult,
    PaginatorTrait, QueryFilter, QueryOrder, QuerySelect, Set, TransactionTrait,
};
use sea_orm_migration::sea_query::OnConflict;

#[derive(Debug, Clone, Default)]
pub enum SortOrder {
    Asc,
    #[default]
    Desc,
}

/// Usage query parameters
#[derive(Debug, Default)]
pub struct UsageQuery {
    pub user_id: Option<i32>,
    pub model_id: Option<String>,
    pub period_type: Option<PeriodType>,
    pub start_date: Option<DateTime<Utc>>,
    pub end_date: Option<DateTime<Utc>>,
    pub success_only: Option<bool>,
    pub limit: Option<u32>,
    pub offset: Option<u32>,
    pub sort_order: SortOrder,
}

/// Paginated response wrapper
#[derive(Debug, serde::Serialize, utoipa::ToSchema)]
pub struct PaginatedRecords<T> {
    /// The actual data records
    pub records: Vec<T>,
    /// Total number of matching records (for pagination)
    pub total_count: u64,
    /// Number of records returned in this page
    pub page_size: u32,
    /// Number of records skipped (offset)
    pub offset: u32,
}

/// Usage statistics
#[derive(Debug, serde::Serialize, utoipa::ToSchema)]
pub struct UsageStats {
    pub total_requests: i32,
    pub total_input_tokens: u64,
    pub total_output_tokens: u64,
    pub total_tokens: u64,
    pub avg_response_time_ms: f32,
    pub success_rate: f32,
    pub total_cost: Option<Decimal>,
    pub unique_models: i32,
    /// Start date of the statistics period
    pub start_date: DateTime<Utc>,
    /// End date of the statistics period
    pub end_date: DateTime<Utc>,
}

/// Usage DAO for database operations
pub struct UsageDao {
    db: DatabaseConnection,
}

impl UsageDao {
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }

    /// Store a usage record
    pub async fn store_record(&self, record: &UsageRecord) -> DatabaseResult<()> {
        let active_model = usage_records::ActiveModel {
            id: ActiveValue::NotSet,
            user_id: Set(record.user_id),
            model_id: Set(record.model_id.clone()),
            endpoint_type: Set(record.endpoint_type.clone()),
            region: Set(record.region.clone()),
            request_time: Set(record.request_time),
            input_tokens: Set(record.input_tokens),
            output_tokens: Set(record.output_tokens),
            cache_write_tokens: Set(record.cache_write_tokens),
            cache_read_tokens: Set(record.cache_read_tokens),
            total_tokens: Set(record.total_tokens),
            response_time_ms: Set(record.response_time_ms),
            success: Set(record.success),
            error_message: Set(record.error_message.clone()),
            cost_usd: Set(record.cost_usd),
        };

        active_model
            .insert(&self.db)
            .await
            .map_err(|e| DatabaseError::Database(e.to_string()))?;

        Ok(())
    }

    /// Update or insert hourly summary record based on usage record using atomic upsert
    pub async fn update_hourly_summary(&self, usage_record: &UsageRecord) -> DatabaseResult<()> {
        let now = Utc::now();

        // Calculate hourly period boundaries
        let period_start = PeriodType::Hourly.round_start(usage_record.request_time);
        let period_end = PeriodType::Hourly.period_end(period_start);

        // Create summary record for new entry (INSERT case)
        let new_summary = usage_summaries::ActiveModel {
            id: ActiveValue::NotSet,
            user_id: Set(usage_record.user_id),
            model_id: Set(usage_record.model_id.clone()),
            period_type: Set(PeriodType::Hourly),
            period_start: Set(period_start),
            period_end: Set(period_end),
            total_requests: Set(1), // First request for this hour
            total_input_tokens: Set(usage_record.input_tokens as i64),
            total_output_tokens: Set(usage_record.output_tokens as i64),
            total_cache_write_tokens: Set(usage_record.cache_write_tokens.unwrap_or(0) as i64),
            total_cache_read_tokens: Set(usage_record.cache_read_tokens.unwrap_or(0) as i64),
            total_tokens: Set(usage_record.total_tokens as i64),
            avg_response_time_ms: Set(usage_record.response_time_ms as f32),
            successful_requests: Set(if usage_record.success { 1 } else { 0 }),
            estimated_cost: Set(usage_record.cost_usd),
            created_at: Set(now),
            updated_at: Set(now),
        };

        // Use SQL upsert with increment expressions for UPDATE case
        let success_increment = if usage_record.success { 1 } else { 0 };

        // Build the upsert query with proper aggregation logic
        let on_conflict = OnConflict::columns([
            usage_summaries::Column::UserId,
            usage_summaries::Column::ModelId,
            usage_summaries::Column::PeriodType,
            usage_summaries::Column::PeriodStart,
        ])
        .update_columns([
            usage_summaries::Column::PeriodEnd,
            usage_summaries::Column::UpdatedAt,
        ])
        // For numerical fields, we need to use expressions to increment values
        .value(
            usage_summaries::Column::TotalRequests,
            sea_orm::sea_query::Expr::col((
                usage_summaries::Entity,
                usage_summaries::Column::TotalRequests,
            ))
            .add(1),
        )
        .value(
            usage_summaries::Column::TotalInputTokens,
            sea_orm::sea_query::Expr::col((
                usage_summaries::Entity,
                usage_summaries::Column::TotalInputTokens,
            ))
            .add(usage_record.input_tokens as i64),
        )
        .value(
            usage_summaries::Column::TotalOutputTokens,
            sea_orm::sea_query::Expr::col((
                usage_summaries::Entity,
                usage_summaries::Column::TotalOutputTokens,
            ))
            .add(usage_record.output_tokens as i64),
        )
        .value(
            usage_summaries::Column::TotalCacheWriteTokens,
            sea_orm::sea_query::Expr::col((
                usage_summaries::Entity,
                usage_summaries::Column::TotalCacheWriteTokens,
            ))
            .add(usage_record.cache_write_tokens.unwrap_or(0) as i64),
        )
        .value(
            usage_summaries::Column::TotalCacheReadTokens,
            sea_orm::sea_query::Expr::col((
                usage_summaries::Entity,
                usage_summaries::Column::TotalCacheReadTokens,
            ))
            .add(usage_record.cache_read_tokens.unwrap_or(0) as i64),
        )
        .value(
            usage_summaries::Column::TotalTokens,
            sea_orm::sea_query::Expr::col((
                usage_summaries::Entity,
                usage_summaries::Column::TotalTokens,
            ))
            .add(usage_record.total_tokens as i64),
        )
        // Calculate weighted average response time: (old_avg * old_count + new_value) / (old_count + 1)
        .value(
            usage_summaries::Column::AvgResponseTimeMs,
            sea_orm::sea_query::Expr::expr(
                sea_orm::sea_query::Expr::col((
                    usage_summaries::Entity,
                    usage_summaries::Column::AvgResponseTimeMs,
                ))
                .mul(sea_orm::sea_query::Expr::col((
                    usage_summaries::Entity,
                    usage_summaries::Column::TotalRequests,
                )))
                .add(usage_record.response_time_ms as f32),
            )
            .div(
                sea_orm::sea_query::Expr::col((
                    usage_summaries::Entity,
                    usage_summaries::Column::TotalRequests,
                ))
                .add(1),
            ),
        )
        // Calculate weighted average success rate: (old_rate * old_count + new_success) / (old_count + 1)
        .value(
            usage_summaries::Column::SuccessfulRequests,
            sea_orm::sea_query::Expr::col((
                usage_summaries::Entity,
                usage_summaries::Column::SuccessfulRequests,
            ))
            .add(success_increment),
        )
        // Add to existing cost (handle NULL case)
        .value(
            usage_summaries::Column::EstimatedCost,
            match usage_record.cost_usd {
                Some(cost) => sea_orm::sea_query::Expr::expr(sea_orm::sea_query::Func::coalesce([
                    sea_orm::sea_query::Expr::col((
                        usage_summaries::Entity,
                        usage_summaries::Column::EstimatedCost,
                    ))
                    .into(),
                    sea_orm::sea_query::Expr::val(Decimal::ZERO).into(),
                ]))
                .add(cost),
                None => sea_orm::sea_query::Expr::col((
                    usage_summaries::Entity,
                    usage_summaries::Column::EstimatedCost,
                ))
                .into(),
            },
        )
        .to_owned();

        usage_summaries::Entity::insert(new_summary)
            .on_conflict(on_conflict)
            .exec(&self.db)
            .await
            .map_err(|e| DatabaseError::Database(e.to_string()))?;

        Ok(())
    }

    /// Get usage records with filtering and total count for pagination
    pub async fn get_records(
        &self,
        query: &UsageQuery,
    ) -> DatabaseResult<PaginatedRecords<UsageRecord>> {
        // Build base filter query (without pagination)
        let mut base_select = usage_records::Entity::find();

        // Apply filters to both count and data queries
        if let Some(user_id) = query.user_id {
            base_select = base_select.filter(usage_records::Column::UserId.eq(user_id));
        }
        if let Some(ref model_id) = query.model_id {
            base_select = base_select.filter(usage_records::Column::ModelId.eq(model_id));
        }
        if let Some(start_date) = query.start_date {
            base_select = base_select.filter(usage_records::Column::RequestTime.gte(start_date));
        }
        if let Some(end_date) = query.end_date {
            base_select = base_select.filter(usage_records::Column::RequestTime.lte(end_date));
        }
        if let Some(success_only) = query.success_only {
            base_select = base_select.filter(usage_records::Column::Success.eq(success_only));
        }

        // Get total count (without pagination)
        let total_count = base_select
            .clone()
            .count(&self.db)
            .await
            .map_err(|e| DatabaseError::Database(e.to_string()))?;

        // Apply ordering and pagination for data query
        let mut data_select = base_select;
        match query.sort_order {
            SortOrder::Desc => {
                data_select = data_select.order_by_desc(usage_records::Column::RequestTime)
            }
            SortOrder::Asc => {
                data_select = data_select.order_by_asc(usage_records::Column::RequestTime)
            }
        }

        let limit = query.limit.unwrap_or(50);
        let offset = query.offset.unwrap_or(0);

        data_select = data_select.limit(Some(limit as u64));
        data_select = data_select.offset(Some(offset as u64));

        let records = data_select
            .all(&self.db)
            .await
            .map_err(|e| DatabaseError::Database(e.to_string()))?;

        Ok(PaginatedRecords {
            records,
            total_count,
            page_size: limit,
            offset,
        })
    }

    /// Get aggregated usage statistics from pre-computed summaries
    /// Note: Stats are NOT paginated - they aggregate ALL matching records
    pub async fn get_stats(&self, query: &UsageQuery) -> DatabaseResult<UsageStats> {
        let mut select = usage_summaries::Entity::find();

        // Apply filters to summaries (ignore pagination params for stats)
        if let Some(user_id) = query.user_id {
            select = select.filter(usage_summaries::Column::UserId.eq(user_id));
        }
        if let Some(ref model_id) = query.model_id {
            select = select.filter(usage_summaries::Column::ModelId.eq(model_id));
        }
        if let Some(ref period_type) = query.period_type {
            select = select.filter(usage_summaries::Column::PeriodType.eq(*period_type));
        }
        if let Some(start_date) = query.start_date {
            select = select.filter(usage_summaries::Column::PeriodStart.gte(start_date));
        }
        if let Some(end_date) = query.end_date {
            select = select.filter(usage_summaries::Column::PeriodEnd.lte(end_date));
        }

        // NOTE: Deliberately ignoring query.limit and query.offset for stats
        // Stats should always aggregate ALL matching records, not just a page

        let summaries = select
            .all(&self.db)
            .await
            .map_err(|e| DatabaseError::Database(e.to_string()))?;

        if summaries.is_empty() {
            // Fallback to calculating from raw records if no summaries exist
            return self.get_stats_from_records(query).await;
        }

        // Aggregate across multiple summary records
        let total_requests: i32 = summaries.iter().map(|s| s.total_requests).sum();
        let total_input_tokens: u64 = summaries.iter().map(|s| s.total_input_tokens as u64).sum();
        let total_output_tokens: u64 = summaries.iter().map(|s| s.total_output_tokens as u64).sum();
        let total_tokens: u64 = summaries.iter().map(|s| s.total_tokens as u64).sum();

        // Calculate weighted average response time
        let total_response_time: f32 = summaries
            .iter()
            .map(|s| s.avg_response_time_ms * s.total_requests as f32)
            .sum();
        let avg_response_time_ms = if total_requests > 0 {
            total_response_time / total_requests as f32
        } else {
            0.0
        };

        let total_successful_requests: i32 = summaries.iter().map(|s| s.successful_requests).sum();
        let success_rate = if total_requests > 0 {
            total_successful_requests as f32 / total_requests as f32
        } else {
            0.0
        };

        // Sum total costs
        let total_cost = summaries
            .iter()
            .filter_map(|s| s.estimated_cost)
            .fold(Decimal::ZERO, |acc, cost| acc + cost);

        // Count unique models
        let unique_models = summaries
            .iter()
            .map(|s| &s.model_id)
            .collect::<std::collections::HashSet<_>>()
            .len() as i32;

        // Get date range from summaries
        let start_date = summaries
            .iter()
            .map(|s| s.period_start)
            .min()
            .unwrap_or_else(Utc::now);
        let end_date = summaries
            .iter()
            .map(|s| s.period_end)
            .max()
            .unwrap_or_else(Utc::now);

        Ok(UsageStats {
            total_requests,
            total_input_tokens,
            total_output_tokens,
            total_tokens,
            avg_response_time_ms,
            success_rate,
            total_cost: if total_cost > Decimal::ZERO {
                Some(total_cost)
            } else {
                None
            },
            unique_models,
            start_date,
            end_date,
        })
    }

    /// Fallback method to get stats from raw records (used when summaries don't exist)
    /// Note: Ignores pagination params since stats should aggregate ALL matching records
    async fn get_stats_from_records(&self, query: &UsageQuery) -> DatabaseResult<UsageStats> {
        let mut base_query = usage_records::Entity::find();

        // Apply filters (ignore pagination for stats)
        if let Some(user_id) = query.user_id {
            base_query = base_query.filter(usage_records::Column::UserId.eq(user_id));
        }
        if let Some(ref model_id) = query.model_id {
            base_query = base_query.filter(usage_records::Column::ModelId.eq(model_id));
        }
        if let Some(start_date) = query.start_date {
            base_query = base_query.filter(usage_records::Column::RequestTime.gte(start_date));
        }
        if let Some(end_date) = query.end_date {
            base_query = base_query.filter(usage_records::Column::RequestTime.lte(end_date));
        }
        if let Some(success_only) = query.success_only {
            base_query = base_query.filter(usage_records::Column::Success.eq(success_only));
        }

        // NOTE: Deliberately ignoring query.limit and query.offset for stats
        // Stats should aggregate ALL matching records, not just a page

        // Get count and aggregations
        let total_requests = base_query
            .clone()
            .count(&self.db)
            .await
            .map_err(|e| DatabaseError::Database(e.to_string()))?
            as i32;

        if total_requests == 0 {
            return Ok(UsageStats {
                total_requests: 0,
                total_input_tokens: 0,
                total_output_tokens: 0,
                total_tokens: 0,
                avg_response_time_ms: 0.0,
                success_rate: 0.0,
                total_cost: None,
                unique_models: 0,
                start_date: Utc::now(),
                end_date: Utc::now(),
            });
        }

        // Get all records to calculate aggregations
        let records = base_query
            .all(&self.db)
            .await
            .map_err(|e| DatabaseError::Database(e.to_string()))?;

        // Calculate aggregations
        let total_input_tokens: u64 = records.iter().map(|r| r.input_tokens as u64).sum();
        let total_output_tokens: u64 = records.iter().map(|r| r.output_tokens as u64).sum();
        let total_tokens: u64 = records.iter().map(|r| r.total_tokens as u64).sum();

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

        let total_cost = records
            .iter()
            .filter_map(|r| r.cost_usd)
            .fold(Decimal::ZERO, |acc, cost| acc + cost);

        let unique_models = records
            .iter()
            .map(|r| &r.model_id)
            .collect::<std::collections::HashSet<_>>()
            .len() as i32;

        let min_date = records
            .iter()
            .map(|r| r.request_time)
            .min()
            .unwrap_or_else(Utc::now);
        let max_date = records
            .iter()
            .map(|r| r.request_time)
            .max()
            .unwrap_or_else(Utc::now);

        Ok(UsageStats {
            total_requests,
            total_input_tokens,
            total_output_tokens,
            total_tokens,
            avg_response_time_ms,
            success_rate,
            total_cost: if total_cost > Decimal::ZERO {
                Some(total_cost)
            } else {
                None
            },
            unique_models,
            start_date: min_date,
            end_date: max_date,
        })
    }

    /// Store/update a batch of usage summaries using native upsert
    pub async fn upsert_many_summaries(&self, summaries: &[UsageSummary]) -> DatabaseResult<usize> {
        if summaries.is_empty() {
            return Ok(0);
        }

        let tx = self
            .db
            .begin()
            .await
            .map_err(|e| DatabaseError::Database(e.to_string()))?;

        let active_models: Vec<usage_summaries::ActiveModel> = summaries
            .iter()
            .map(|summary| usage_summaries::ActiveModel {
                id: ActiveValue::NotSet,
                user_id: Set(summary.user_id),
                model_id: Set(summary.model_id.clone()),
                period_type: Set(summary.period_type),
                period_start: Set(summary.period_start),
                period_end: Set(summary.period_end),
                total_requests: Set(summary.total_requests),
                successful_requests: Set(summary.successful_requests),
                total_input_tokens: Set(summary.total_input_tokens),
                total_output_tokens: Set(summary.total_output_tokens),
                total_cache_write_tokens: Set(summary.total_cache_write_tokens),
                total_cache_read_tokens: Set(summary.total_cache_read_tokens),
                total_tokens: Set(summary.total_tokens),
                avg_response_time_ms: Set(summary.avg_response_time_ms),
                estimated_cost: Set(summary.estimated_cost),
                created_at: Set(summary.created_at),
                updated_at: Set(summary.updated_at),
            })
            .collect();

        let on_conflict = OnConflict::columns([
            usage_summaries::Column::UserId,
            usage_summaries::Column::ModelId,
            usage_summaries::Column::PeriodType,
            usage_summaries::Column::PeriodStart,
        ])
        .update_columns([
            usage_summaries::Column::PeriodEnd,
            usage_summaries::Column::TotalRequests,
            usage_summaries::Column::SuccessfulRequests,
            usage_summaries::Column::TotalInputTokens,
            usage_summaries::Column::TotalOutputTokens,
            usage_summaries::Column::TotalCacheWriteTokens,
            usage_summaries::Column::TotalCacheReadTokens,
            usage_summaries::Column::TotalTokens,
            usage_summaries::Column::AvgResponseTimeMs,
            usage_summaries::Column::EstimatedCost,
            usage_summaries::Column::UpdatedAt,
        ])
        .to_owned();

        for model in active_models {
            usage_summaries::Entity::insert(model)
                .on_conflict(on_conflict.clone())
                .exec(&tx)
                .await
                .map_err(|e| DatabaseError::Database(e.to_string()))?;
        }

        tx.commit()
            .await
            .map_err(|e| DatabaseError::Database(e.to_string()))?;

        Ok(summaries.len())
    }

    /// Get usage summaries with filtering
    pub async fn get_summaries(&self, query: &UsageQuery) -> DatabaseResult<Vec<UsageSummary>> {
        let mut select = usage_summaries::Entity::find();

        // Apply filters
        if let Some(user_id) = query.user_id {
            select = select.filter(usage_summaries::Column::UserId.eq(user_id));
        }
        if let Some(ref model_id) = query.model_id {
            select = select.filter(usage_summaries::Column::ModelId.eq(model_id));
        }
        if let Some(ref period_type) = query.period_type {
            select = select.filter(usage_summaries::Column::PeriodType.eq(*period_type));
        }
        if let Some(start_date) = query.start_date {
            select = select.filter(usage_summaries::Column::PeriodStart.gte(start_date));
        }
        if let Some(end_date) = query.end_date {
            select = select.filter(usage_summaries::Column::PeriodEnd.lte(end_date));
        }

        // Apply ordering and pagination
        match query.sort_order {
            SortOrder::Desc => select = select.order_by_desc(usage_summaries::Column::PeriodStart),
            SortOrder::Asc => select = select.order_by_asc(usage_summaries::Column::PeriodStart),
        }

        if let Some(limit) = query.limit {
            select = select.limit(Some(limit as u64));
        }
        if let Some(offset) = query.offset {
            select = select.offset(Some(offset as u64));
        }

        let summaries = select
            .all(&self.db)
            .await
            .map_err(|e| DatabaseError::Database(e.to_string()))?;

        Ok(summaries)
    }

    /// Clean up old usage records
    pub async fn cleanup_old_records(&self, retention_days: u32) -> DatabaseResult<u64> {
        let cutoff = Utc::now() - chrono::Duration::days(retention_days as i64);
        let result = usage_records::Entity::delete_many()
            .filter(usage_records::Column::RequestTime.lt(cutoff))
            .exec(&self.db)
            .await
            .map_err(|e| DatabaseError::Database(e.to_string()))?;

        Ok(result.rows_affected)
    }

    /// Clean up old usage summaries for a specific period type
    pub async fn cleanup_old_summaries_by_period(
        &self,
        period_type: PeriodType,
        retention_days: u32,
    ) -> DatabaseResult<u64> {
        let cutoff = Utc::now() - chrono::Duration::days(retention_days as i64);
        let result = usage_summaries::Entity::delete_many()
            .filter(usage_summaries::Column::PeriodType.eq(period_type))
            .filter(usage_summaries::Column::PeriodStart.lt(cutoff))
            .exec(&self.db)
            .await
            .map_err(|e| DatabaseError::Database(e.to_string()))?;

        Ok(result.rows_affected)
    }

    /// Get top models by usage from pre-computed summaries
    pub async fn get_top_models(
        &self,
        limit: u32,
        start_date: Option<DateTime<Utc>>,
        end_date: Option<DateTime<Utc>>,
    ) -> DatabaseResult<Vec<(String, u64)>> {
        // First try to get from summaries
        let mut select = usage_summaries::Entity::find()
            .select_only()
            .column(usage_summaries::Column::ModelId)
            .column_as(usage_summaries::Column::TotalTokens.sum(), "total_tokens");

        if let Some(start_date) = start_date {
            select = select.filter(usage_summaries::Column::PeriodStart.gte(start_date));
        }
        if let Some(end_date) = end_date {
            select = select.filter(usage_summaries::Column::PeriodEnd.lte(end_date));
        }

        #[derive(FromQueryResult)]
        struct TopModel {
            model_id: String,
            total_tokens: Option<i64>,
        }

        let results: Vec<TopModel> = select
            .group_by(usage_summaries::Column::ModelId)
            .order_by_desc(usage_summaries::Column::TotalTokens.sum())
            .limit(Some(limit as u64))
            .into_model()
            .all(&self.db)
            .await
            .map_err(|e| DatabaseError::Database(e.to_string()))?;

        if !results.is_empty() {
            // Use summary data if available
            Ok(results
                .into_iter()
                .map(|r| (r.model_id, r.total_tokens.unwrap_or(0) as u64))
                .collect())
        } else {
            // Fallback to raw records if no summaries exist
            self.get_top_models_from_records(limit, start_date, end_date)
                .await
        }
    }

    /// Fallback method to get top models from raw records
    async fn get_top_models_from_records(
        &self,
        limit: u32,
        start_date: Option<DateTime<Utc>>,
        end_date: Option<DateTime<Utc>>,
    ) -> DatabaseResult<Vec<(String, u64)>> {
        let mut select = usage_records::Entity::find()
            .select_only()
            .column(usage_records::Column::ModelId)
            .column_as(usage_records::Column::TotalTokens.sum(), "total_tokens");

        if let Some(start_date) = start_date {
            select = select.filter(usage_records::Column::RequestTime.gte(start_date));
        }
        if let Some(end_date) = end_date {
            select = select.filter(usage_records::Column::RequestTime.lte(end_date));
        }

        #[derive(FromQueryResult)]
        struct TopModel {
            model_id: String,
            total_tokens: Option<i64>,
        }

        let results: Vec<TopModel> = select
            .group_by(usage_records::Column::ModelId)
            .order_by_desc(usage_records::Column::TotalTokens.sum())
            .limit(Some(limit as u64))
            .into_model()
            .all(&self.db)
            .await
            .map_err(|e| DatabaseError::Database(e.to_string()))?;

        Ok(results
            .into_iter()
            .map(|r| (r.model_id, r.total_tokens.unwrap_or(0) as u64))
            .collect())
    }

    /// Get unique model IDs from pre-computed summaries
    pub async fn get_unique_models(&self) -> DatabaseResult<Vec<String>> {
        // First try to get from summaries
        let summary_models = usage_summaries::Entity::find()
            .select_only()
            .column(usage_summaries::Column::ModelId)
            .distinct()
            .all(&self.db)
            .await
            .map_err(|e| DatabaseError::Database(e.to_string()))?;

        if !summary_models.is_empty() {
            // Use summary data if available
            Ok(summary_models.into_iter().map(|m| m.model_id).collect())
        } else {
            // Fallback to raw records if no summaries exist
            self.get_unique_models_from_records().await
        }
    }

    /// Fallback method to get unique models from raw records
    async fn get_unique_models_from_records(&self) -> DatabaseResult<Vec<String>> {
        let models = usage_records::Entity::find()
            .select_only()
            .column(usage_records::Column::ModelId)
            .distinct()
            .all(&self.db)
            .await
            .map_err(|e| DatabaseError::Database(e.to_string()))?;

        Ok(models.into_iter().map(|m| m.model_id).collect())
    }
}
