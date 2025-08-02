pub mod api_keys;
pub mod audit_logs;
pub mod model_costs;
pub mod refresh_tokens;
pub mod usage_records;
pub mod usage_summaries;
pub mod users;

use chrono::{DateTime, Datelike, Duration, DurationRound, Utc};
use sea_orm::entity::prelude::*;
use sea_orm::sea_query::StringLen;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// Period types for usage aggregation
#[derive(Debug, Clone, Copy, PartialEq, Eq, EnumIter, DeriveActiveEnum, Serialize, Deserialize, ToSchema)]
#[sea_orm(rs_type = "String", db_type = "String(StringLen::N(16))")]
pub enum PeriodType {
    #[sea_orm(string_value = "hourly")]
    #[serde(rename = "hourly")]
    Hourly,
    #[sea_orm(string_value = "daily")]
    #[serde(rename = "daily")]
    Daily,
    #[sea_orm(string_value = "weekly")]
    #[serde(rename = "weekly")]
    Weekly,
    #[sea_orm(string_value = "monthly")]
    #[serde(rename = "monthly")]
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

    /// Calculate the end of the period
    pub fn period_end(&self, period_start: DateTime<Utc>) -> DateTime<Utc> {
        match self {
            PeriodType::Hourly => period_start + Duration::hours(1),
            PeriodType::Daily => period_start + Duration::days(1),
            PeriodType::Weekly => period_start + Duration::weeks(1),
            PeriodType::Monthly => {
                let naive_date = period_start.date_naive();
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

pub use api_keys::Entity as ApiKeys;
pub use audit_logs::Entity as AuditLogs;
pub use model_costs::Entity as ModelCosts;
pub use refresh_tokens::Entity as RefreshTokens;
pub use usage_records::Entity as UsageRecords;
pub use usage_summaries::Entity as UsageSummaries;
pub use users::Entity as Users;

// Type aliases
pub type UserRecord = users::Model;
pub type RefreshTokenData = refresh_tokens::Model;
pub type AuditLogEntry = audit_logs::Model;
pub type UsageRecord = usage_records::Model;
pub type UsageSummary = usage_summaries::Model;
pub type ModelCost = model_costs::Model;
pub type ApiKeyRecord = api_keys::Model;

// Export audit event type
pub use audit_logs::AuditEventType;

// Database entities use derive macro with TTL attributes
// All implementations are generated automatically via #[derive(CacheableDeriv)]
