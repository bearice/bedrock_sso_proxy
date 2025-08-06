use super::UsageSummaries;
use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Add cache token fields to usage_summaries table - separate statements for SQLite compatibility
        manager
            .alter_table(
                Table::alter()
                    .table(UsageSummaries::Table)
                    .add_column(
                        ColumnDef::new(UsageSummaries::TotalCacheWriteTokens)
                            .big_integer()
                            .not_null()
                            .default(0),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(UsageSummaries::Table)
                    .add_column(
                        ColumnDef::new(UsageSummaries::TotalCacheReadTokens)
                            .big_integer()
                            .not_null()
                            .default(0),
                    )
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Remove cache token fields from usage_summaries table - separate statements for SQLite compatibility
        manager
            .alter_table(
                Table::alter()
                    .table(UsageSummaries::Table)
                    .drop_column(UsageSummaries::TotalCacheWriteTokens)
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(UsageSummaries::Table)
                    .drop_column(UsageSummaries::TotalCacheReadTokens)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}
