use crate::database::entities::{UsageRecord, UsageSummary, usage_records, usage_summaries};
use crate::database::{DatabaseError, DatabaseResult};
use chrono::{DateTime, Utc};
use rust_decimal::Decimal;
use sea_orm::{
    ActiveModelTrait, ActiveValue, ColumnTrait, DatabaseConnection, EntityTrait, FromQueryResult,
    PaginatorTrait, QueryFilter, QueryOrder, QuerySelect, Set,
};
use sea_orm_migration::sea_query::OnConflict;

/// Usage query parameters
#[derive(Debug, Default)]
pub struct UsageQuery {
    pub user_id: Option<i32>,
    pub model_id: Option<String>,
    pub start_date: Option<DateTime<Utc>>,
    pub end_date: Option<DateTime<Utc>>,
    pub success_only: Option<bool>,
    pub limit: Option<u32>,
    pub offset: Option<u32>,
}

/// Usage statistics
#[derive(Debug, serde::Serialize, utoipa::ToSchema)]
pub struct UsageStats {
    pub total_requests: u32,
    pub total_input_tokens: u64,
    pub total_output_tokens: u64,
    pub total_tokens: u64,
    pub avg_response_time_ms: f32,
    pub success_rate: f32,
    pub total_cost: Option<Decimal>,
    pub unique_models: u32,
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

    /// Get usage records with filtering
    pub async fn get_records(&self, query: &UsageQuery) -> DatabaseResult<Vec<UsageRecord>> {
        let mut select = usage_records::Entity::find();

        // Apply filters
        if let Some(user_id) = query.user_id {
            select = select.filter(usage_records::Column::UserId.eq(user_id));
        }
        if let Some(ref model_id) = query.model_id {
            select = select.filter(usage_records::Column::ModelId.eq(model_id));
        }
        if let Some(start_date) = query.start_date {
            select = select.filter(usage_records::Column::RequestTime.gte(start_date));
        }
        if let Some(end_date) = query.end_date {
            select = select.filter(usage_records::Column::RequestTime.lte(end_date));
        }
        if let Some(success_only) = query.success_only {
            select = select.filter(usage_records::Column::Success.eq(success_only));
        }

        // Apply ordering and pagination
        select = select.order_by_desc(usage_records::Column::RequestTime);

        if let Some(limit) = query.limit {
            select = select.limit(Some(limit as u64));
        }
        if let Some(offset) = query.offset {
            select = select.offset(Some(offset as u64));
        }

        let records = select
            .all(&self.db)
            .await
            .map_err(|e| DatabaseError::Database(e.to_string()))?;

        Ok(records)
    }

    /// Get aggregated usage statistics from pre-computed summaries
    pub async fn get_stats(&self, query: &UsageQuery) -> DatabaseResult<UsageStats> {
        let mut select = usage_summaries::Entity::find();

        // Apply filters to summaries
        if let Some(user_id) = query.user_id {
            select = select.filter(usage_summaries::Column::UserId.eq(user_id));
        }
        if let Some(ref model_id) = query.model_id {
            select = select.filter(usage_summaries::Column::ModelId.eq(model_id));
        }
        if let Some(start_date) = query.start_date {
            select = select.filter(usage_summaries::Column::PeriodStart.gte(start_date));
        }
        if let Some(end_date) = query.end_date {
            select = select.filter(usage_summaries::Column::PeriodEnd.lte(end_date));
        }

        let summaries = select
            .all(&self.db)
            .await
            .map_err(|e| DatabaseError::Database(e.to_string()))?;

        if summaries.is_empty() {
            // Fallback to calculating from raw records if no summaries exist
            return self.get_stats_from_records(query).await;
        }

        // Aggregate across multiple summary records
        let total_requests: u32 = summaries.iter().map(|s| s.total_requests).sum();
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

        // Calculate weighted average success rate
        let total_success_weighted: f32 = summaries
            .iter()
            .map(|s| s.success_rate * s.total_requests as f32)
            .sum();
        let success_rate = if total_requests > 0 {
            total_success_weighted / total_requests as f32
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
            .len() as u32;

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
    async fn get_stats_from_records(&self, query: &UsageQuery) -> DatabaseResult<UsageStats> {
        let mut base_query = usage_records::Entity::find();

        // Apply filters
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

        // Get count and aggregations
        let total_requests = base_query
            .clone()
            .count(&self.db)
            .await
            .map_err(|e| DatabaseError::Database(e.to_string()))?
            as u32;

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
            .len() as u32;

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

    /// Store/update usage summary using native upsert
    pub async fn upsert_summary(&self, summary: &UsageSummary) -> DatabaseResult<()> {
        let active_model = usage_summaries::ActiveModel {
            id: ActiveValue::NotSet,
            user_id: Set(summary.user_id),
            model_id: Set(summary.model_id.clone()),
            period_type: Set(summary.period_type.clone()),
            period_start: Set(summary.period_start),
            period_end: Set(summary.period_end),
            total_requests: Set(summary.total_requests),
            total_input_tokens: Set(summary.total_input_tokens),
            total_output_tokens: Set(summary.total_output_tokens),
            total_tokens: Set(summary.total_tokens),
            avg_response_time_ms: Set(summary.avg_response_time_ms),
            success_rate: Set(summary.success_rate),
            estimated_cost: Set(summary.estimated_cost),
            created_at: Set(summary.created_at),
            updated_at: Set(summary.updated_at),
        };

        let on_conflict = OnConflict::columns([
            usage_summaries::Column::UserId,
            usage_summaries::Column::ModelId,
            usage_summaries::Column::PeriodType,
            usage_summaries::Column::PeriodStart,
        ])
        .update_columns([
            usage_summaries::Column::PeriodEnd,
            usage_summaries::Column::TotalRequests,
            usage_summaries::Column::TotalInputTokens,
            usage_summaries::Column::TotalOutputTokens,
            usage_summaries::Column::TotalTokens,
            usage_summaries::Column::AvgResponseTimeMs,
            usage_summaries::Column::SuccessRate,
            usage_summaries::Column::EstimatedCost,
            usage_summaries::Column::UpdatedAt,
        ])
        .to_owned();

        usage_summaries::Entity::insert(active_model)
            .on_conflict(on_conflict)
            .exec(&self.db)
            .await
            .map_err(|e| DatabaseError::Database(e.to_string()))?;

        Ok(())
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
        if let Some(start_date) = query.start_date {
            select = select.filter(usage_summaries::Column::PeriodStart.gte(start_date));
        }
        if let Some(end_date) = query.end_date {
            select = select.filter(usage_summaries::Column::PeriodEnd.lte(end_date));
        }

        // Apply ordering and pagination
        select = select.order_by_desc(usage_summaries::Column::PeriodStart);

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
