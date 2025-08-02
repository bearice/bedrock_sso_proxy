use super::{UsageSummaries, Users};
use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(UsageSummaries::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(UsageSummaries::Id)
                            .integer()
                            .not_null()
                            .auto_increment()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(UsageSummaries::UserId).integer().not_null())
                    .col(ColumnDef::new(UsageSummaries::ModelId).string().not_null())
                    .col(
                        ColumnDef::new(UsageSummaries::PeriodType)
                            .string()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(UsageSummaries::PeriodStart)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(UsageSummaries::PeriodEnd)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(UsageSummaries::TotalRequests)
                            .integer()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(UsageSummaries::TotalInputTokens)
                            .big_integer()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(UsageSummaries::TotalOutputTokens)
                            .big_integer()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(UsageSummaries::TotalTokens)
                            .big_integer()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(UsageSummaries::AvgResponseTimeMs)
                            .float()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(UsageSummaries::SuccessfulRequests)
                            .integer()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(UsageSummaries::EstimatedCost)
                            .decimal_len(10, 6)
                            .null(),
                    )
                    .col(
                        ColumnDef::new(UsageSummaries::CreatedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(UsageSummaries::UpdatedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .to_owned(),
            )
            .await?;

        // Create foreign key constraint only for PostgreSQL (SQLite doesn't support adding FK after table creation)
        if manager.get_database_backend() == sea_orm::DatabaseBackend::Postgres {
            manager
                .create_foreign_key(
                    ForeignKey::create()
                        .name("fk_usage_summaries_user_id")
                        .from(UsageSummaries::Table, UsageSummaries::UserId)
                        .to(Users::Table, Users::Id)
                        .on_delete(ForeignKeyAction::Cascade)
                        .to_owned(),
                )
                .await?;
        }

        // Create unique index on user_id + model_id + period_type + period_start
        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("idx_usage_summaries_unique")
                    .table(UsageSummaries::Table)
                    .col(UsageSummaries::UserId)
                    .col(UsageSummaries::ModelId)
                    .col(UsageSummaries::PeriodType)
                    .col(UsageSummaries::PeriodStart)
                    .unique()
                    .to_owned(),
            )
            .await?;

        // Create index on period_start for time-based queries
        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("idx_usage_summaries_period_start")
                    .table(UsageSummaries::Table)
                    .col(UsageSummaries::PeriodStart)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(UsageSummaries::Table).to_owned())
            .await
    }
}
