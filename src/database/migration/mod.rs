use sea_orm_migration::prelude::*;

pub use sea_orm_migration::MigratorTrait;

mod m20241226_120000_create_users_table;
mod m20241226_120100_create_refresh_tokens_table;
mod m20241226_120200_create_audit_logs_table;
mod m20241226_120300_create_usage_records_table;
mod m20241226_120400_create_usage_summaries_table;
mod m20241226_120500_create_model_costs_table;
mod m20241226_120600_create_api_keys_table;
mod m20250127_000001_add_cache_token_fields;
mod m20250804_000001_add_user_state_column;
mod m20250806_135819_add_cache_tokens_to_summaries;
mod m20250806_140000_add_stop_reason_to_usage_records;

pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![
            Box::new(m20241226_120000_create_users_table::Migration),
            Box::new(m20241226_120100_create_refresh_tokens_table::Migration),
            Box::new(m20241226_120200_create_audit_logs_table::Migration),
            Box::new(m20241226_120300_create_usage_records_table::Migration),
            Box::new(m20241226_120400_create_usage_summaries_table::Migration),
            Box::new(m20241226_120500_create_model_costs_table::Migration),
            Box::new(m20241226_120600_create_api_keys_table::Migration),
            Box::new(m20250127_000001_add_cache_token_fields::Migration),
            Box::new(m20250804_000001_add_user_state_column::Migration),
            Box::new(m20250806_135819_add_cache_tokens_to_summaries::Migration),
            Box::new(m20250806_140000_add_stop_reason_to_usage_records::Migration),
        ]
    }
}

/// Common table and column identifiers
#[derive(Iden)]
pub enum Users {
    Table,
    Id,
    ProviderUserId,
    Provider,
    Email,
    DisplayName,
    CreatedAt,
    UpdatedAt,
    LastLogin,
    State,
}

#[derive(Iden)]
pub enum RefreshTokens {
    Table,
    Id,
    TokenHash,
    UserId,
    Provider,
    Email,
    CreatedAt,
    ExpiresAt,
    RotationCount,
    RevokedAt,
}

#[derive(Iden)]
pub enum AuditLogs {
    Table,
    Id,
    UserId,
    EventType,
    Provider,
    IpAddress,
    UserAgent,
    Success,
    ErrorMessage,
    CreatedAt,
    Metadata,
}

#[derive(Iden)]
pub enum UsageRecords {
    Table,
    Id,
    UserId,
    ModelId,
    EndpointType,
    Region,
    RequestTime,
    InputTokens,
    OutputTokens,
    CacheWriteTokens,
    CacheReadTokens,
    TotalTokens,
    ResponseTimeMs,
    Success,
    ErrorMessage,
    StopReason,
    CostUsd,
}

#[derive(Iden)]
pub enum UsageSummaries {
    Table,
    Id,
    UserId,
    ModelId,
    PeriodType,
    PeriodStart,
    PeriodEnd,
    TotalRequests,
    SuccessfulRequests,
    TotalInputTokens,
    TotalOutputTokens,
    TotalCacheWriteTokens,
    TotalCacheReadTokens,
    TotalTokens,
    AvgResponseTimeMs,
    EstimatedCost,
    CreatedAt,
    UpdatedAt,
}

#[derive(Iden)]
pub enum ModelCosts {
    Table,
    Id,
    Region,
    ModelId,
    InputCostPer1kTokens,
    OutputCostPer1kTokens,
    CacheWriteCostPer1kTokens,
    CacheReadCostPer1kTokens,
    UpdatedAt,
}

#[derive(Iden)]
pub enum ApiKeys {
    Table,
    Id,
    KeyHash,
    UserId,
    Name,
    Hint,
    CreatedAt,
    LastUsed,
    ExpiresAt,
    RevokedAt,
}
