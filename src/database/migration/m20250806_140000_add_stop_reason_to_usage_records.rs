use super::UsageRecords;
use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Add stop_reason field to usage_records table
        manager
            .alter_table(
                Table::alter()
                    .table(UsageRecords::Table)
                    .add_column(ColumnDef::new(UsageRecords::StopReason).string().null())
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Remove stop_reason field from usage_records table
        manager
            .alter_table(
                Table::alter()
                    .table(UsageRecords::Table)
                    .drop_column(UsageRecords::StopReason)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}
