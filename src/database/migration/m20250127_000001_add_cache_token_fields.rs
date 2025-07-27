use super::{ModelCosts, UsageRecords};
use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Add cache token fields to usage_records table - separate statements for SQLite compatibility
        manager
            .alter_table(
                Table::alter()
                    .table(UsageRecords::Table)
                    .add_column(
                        ColumnDef::new(UsageRecords::CacheWriteTokens)
                            .integer()
                            .null(),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(UsageRecords::Table)
                    .add_column(
                        ColumnDef::new(UsageRecords::CacheReadTokens)
                            .integer()
                            .null(),
                    )
                    .to_owned(),
            )
            .await?;

        // Add cache cost fields to model_costs table - separate statements for SQLite compatibility
        manager
            .alter_table(
                Table::alter()
                    .table(ModelCosts::Table)
                    .add_column(
                        ColumnDef::new(Alias::new("cache_write_cost_per_1k_tokens"))
                            .decimal_len(10, 6)
                            .null(),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(ModelCosts::Table)
                    .add_column(
                        ColumnDef::new(Alias::new("cache_read_cost_per_1k_tokens"))
                            .decimal_len(10, 6)
                            .null(),
                    )
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Remove cache token fields from usage_records table - separate statements for SQLite compatibility
        manager
            .alter_table(
                Table::alter()
                    .table(UsageRecords::Table)
                    .drop_column(UsageRecords::CacheWriteTokens)
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(UsageRecords::Table)
                    .drop_column(UsageRecords::CacheReadTokens)
                    .to_owned(),
            )
            .await?;

        // Remove cache cost fields from model_costs table - separate statements for SQLite compatibility
        manager
            .alter_table(
                Table::alter()
                    .table(ModelCosts::Table)
                    .drop_column(Alias::new("cache_write_cost_per_1k_tokens"))
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(ModelCosts::Table)
                    .drop_column(Alias::new("cache_read_cost_per_1k_tokens"))
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}
