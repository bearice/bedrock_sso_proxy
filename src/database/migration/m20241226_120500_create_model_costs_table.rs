use super::ModelCosts;
use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(ModelCosts::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(ModelCosts::Id)
                            .integer()
                            .not_null()
                            .auto_increment()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(ModelCosts::ModelId).string().not_null())
                    .col(ColumnDef::new(ModelCosts::Region).string().not_null())
                    .col(
                        ColumnDef::new(Alias::new("input_cost_per_1k_tokens"))
                            .decimal_len(10, 6)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(Alias::new("output_cost_per_1k_tokens"))
                            .decimal_len(10, 6)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(ModelCosts::UpdatedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .to_owned(),
            )
            .await?;

        // Create index on model_id for fast lookups (already unique, but explicit for clarity)
        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("idx_model_costs_region_model_id")
                    .table(ModelCosts::Table)
                    .col(ModelCosts::Region)
                    .col(ModelCosts::ModelId)
                    .unique()
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(ModelCosts::Table).to_owned())
            .await
    }
}
