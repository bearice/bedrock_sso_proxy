use sea_orm_migration::prelude::*;

pub use sea_orm_migration::MigratorTrait;

mod m20241226_120000_create_users_table;
mod m20241226_120100_create_refresh_tokens_table;
mod m20241226_120200_create_audit_logs_table;
mod m20241226_120300_create_usage_records_table;
mod m20241226_120400_create_usage_summaries_table;
mod m20241226_120500_create_model_costs_table;
mod m20241226_120600_create_api_keys_table;

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
    TotalTokens,
    ResponseTimeMs,
    Success,
    ErrorMessage,
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
    TotalInputTokens,
    TotalOutputTokens,
    TotalTokens,
    AvgResponseTimeMs,
    SuccessRate,
    EstimatedCost,
    CreatedAt,
    UpdatedAt,
}

#[derive(Iden)]
pub enum ModelCosts {
    Table,
    Id,
    ModelId,
    InputCostPer1kTokens,
    OutputCostPer1kTokens,
    UpdatedAt,
}

#[derive(Iden)]
pub enum ApiKeys {
    Table,
    Id,
    KeyHash,
    UserId,
    Name,
    CreatedAt,
    LastUsed,
    ExpiresAt,
    RevokedAt,
}
