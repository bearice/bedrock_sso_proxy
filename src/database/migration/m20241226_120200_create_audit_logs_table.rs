use super::{AuditLogs, Users};
use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(AuditLogs::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(AuditLogs::Id)
                            .integer()
                            .not_null()
                            .auto_increment()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(AuditLogs::UserId).integer().null())
                    .col(ColumnDef::new(AuditLogs::EventType).string().not_null())
                    .col(ColumnDef::new(AuditLogs::Provider).string().null())
                    .col(ColumnDef::new(AuditLogs::IpAddress).string().null())
                    .col(ColumnDef::new(AuditLogs::UserAgent).string().null())
                    .col(ColumnDef::new(AuditLogs::Success).boolean().not_null())
                    .col(ColumnDef::new(AuditLogs::ErrorMessage).string().null())
                    .col(
                        ColumnDef::new(AuditLogs::CreatedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .col(ColumnDef::new(AuditLogs::Metadata).string().null())
                    .to_owned(),
            )
            .await?;

        // Create foreign key constraint only for PostgreSQL (SQLite doesn't support adding FK after table creation)
        if manager.get_database_backend() == sea_orm::DatabaseBackend::Postgres {
            manager
                .create_foreign_key(
                    ForeignKey::create()
                        .name("fk_audit_logs_user_id")
                        .from(AuditLogs::Table, AuditLogs::UserId)
                        .to(Users::Table, Users::Id)
                        .on_delete(ForeignKeyAction::SetNull)
                        .to_owned(),
                )
                .await?;
        }

        // Create index on user_id for lookups
        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("idx_audit_logs_user_id")
                    .table(AuditLogs::Table)
                    .col(AuditLogs::UserId)
                    .to_owned(),
            )
            .await?;

        // Create index on created_at for cleanup and time-based queries
        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("idx_audit_logs_created_at")
                    .table(AuditLogs::Table)
                    .col(AuditLogs::CreatedAt)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(AuditLogs::Table).to_owned())
            .await
    }
}
