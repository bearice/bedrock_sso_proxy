use super::Users;
use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Add state column to users table
        manager
            .alter_table(
                Table::alter()
                    .table(Users::Table)
                    .add_column(
                        ColumnDef::new(Users::State)
                            .string_len(16)
                            .not_null()
                            .default("active"),
                    )
                    .to_owned(),
            )
            .await?;

        // Create index on state for efficient filtering
        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("idx_users_state")
                    .table(Users::Table)
                    .col(Users::State)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Drop the index first
        manager
            .drop_index(
                Index::drop()
                    .name("idx_users_state")
                    .table(Users::Table)
                    .to_owned(),
            )
            .await?;

        // Drop the state column
        manager
            .alter_table(
                Table::alter()
                    .table(Users::Table)
                    .drop_column(Users::State)
                    .to_owned(),
            )
            .await
    }
}
