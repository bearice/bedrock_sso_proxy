use super::{UsageRecords, Users};
use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(UsageRecords::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(UsageRecords::Id)
                            .integer()
                            .not_null()
                            .auto_increment()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(UsageRecords::UserId).integer().not_null())
                    .col(ColumnDef::new(UsageRecords::ModelId).string().not_null())
                    .col(
                        ColumnDef::new(UsageRecords::EndpointType)
                            .string()
                            .not_null(),
                    )
                    .col(ColumnDef::new(UsageRecords::Region).string().not_null())
                    .col(
                        ColumnDef::new(UsageRecords::RequestTime)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(UsageRecords::InputTokens)
                            .integer()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(UsageRecords::OutputTokens)
                            .integer()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(UsageRecords::TotalTokens)
                            .integer()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(UsageRecords::ResponseTimeMs)
                            .integer()
                            .not_null(),
                    )
                    .col(ColumnDef::new(UsageRecords::Success).boolean().not_null())
                    .col(ColumnDef::new(UsageRecords::ErrorMessage).string().null())
                    .col(
                        ColumnDef::new(UsageRecords::CostUsd)
                            .decimal_len(10, 6)
                            .null(),
                    )
                    .to_owned(),
            )
            .await?;

        // Create foreign key constraint only for PostgreSQL (SQLite doesn't support adding FK after table creation)
        if manager.get_database_backend() == sea_orm::DatabaseBackend::Postgres {
            manager
                .create_foreign_key(
                    ForeignKey::create()
                        .name("fk_usage_records_user_id")
                        .from(UsageRecords::Table, UsageRecords::UserId)
                        .to(Users::Table, Users::Id)
                        .on_delete(ForeignKeyAction::Cascade)
                        .to_owned(),
                )
                .await?;
        }

        // Create index on user_id for user queries
        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("idx_usage_records_user_id")
                    .table(UsageRecords::Table)
                    .col(UsageRecords::UserId)
                    .to_owned(),
            )
            .await?;

        // Create index on request_time for time-based queries and cleanup
        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("idx_usage_records_request_time")
                    .table(UsageRecords::Table)
                    .col(UsageRecords::RequestTime)
                    .to_owned(),
            )
            .await?;

        // Create index on model_id for model-based queries
        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("idx_usage_records_model_id")
                    .table(UsageRecords::Table)
                    .col(UsageRecords::ModelId)
                    .to_owned(),
            )
            .await?;

        // Create composite index for user + time queries
        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("idx_usage_records_user_time")
                    .table(UsageRecords::Table)
                    .col(UsageRecords::UserId)
                    .col(UsageRecords::RequestTime)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(UsageRecords::Table).to_owned())
            .await
    }
}
