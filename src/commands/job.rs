use crate::{
    Config,
    cache::CacheManager,
    database::{DatabaseManagerImpl, entities::PeriodType},
    summarization::SummarizationService,
};
use clap::Subcommand;
use std::sync::Arc;
use tracing::info;

#[derive(Subcommand)]
pub enum JobCommand {
    /// Generate usage summaries for improved query performance
    Summaries {
        #[arg(
            long,
            help = "Period type (hourly, daily, weekly, monthly)",
            default_value = "daily"
        )]
        period: String,

        #[arg(long, help = "Days to look back for processing", default_value = "30")]
        days_back: u32,

        #[arg(
            long,
            help = "Dry run - show what would be done without actually doing it"
        )]
        dry_run: bool,

        #[arg(long, help = "Specific user ID to process (optional)")]
        user_id: Option<i32>,

        #[arg(long, help = "Specific model ID to process (optional)")]
        model_id: Option<String>,

        #[arg(long, help = "Backfill mode - regenerate existing summaries")]
        backfill: bool,
    },

    /// Clean up old usage records and summaries
    Cleanup {
        #[arg(
            long,
            help = "Target to clean: 'records' for raw usage records, period type (hourly, daily, weekly, monthly) for summaries, or omit to clean all types"
        )]
        target: Option<String>,

        #[arg(
            long,
            help = "Days to look back for cleanup (uses config defaults if not specified)"
        )]
        days_back: Option<u32>,

        #[arg(
            long,
            help = "Dry run - show what would be done without actually doing it"
        )]
        dry_run: bool,
    },

    /// List available job types
    List,
}

pub async fn handle_job_command(
    command: JobCommand,
    config: &Config,
) -> Result<(), Box<dyn std::error::Error>> {
    let cache_manager = Arc::new(CacheManager::new_from_config(&config.cache).await?);
    let db_manager = Arc::new(DatabaseManagerImpl::new_from_config(config, cache_manager).await?);
    let summarization_service = Arc::new(SummarizationService::new(db_manager));

    match command {
        JobCommand::Summaries {
            period,
            days_back,
            dry_run,
            user_id,
            model_id,
            backfill,
        } => {
            info!("Running summaries job (dry_run: {})", dry_run);

            if dry_run {
                info!(
                    "DRY RUN: Would generate {} summaries for the last {} days",
                    period, days_back
                );
                return Ok(());
            }

            let count = summarization_service
                .generate_summaries(&period, days_back, user_id, model_id.as_deref(), backfill)
                .await?;

            info!("Successfully generated {} summaries", count);
        }

        JobCommand::Cleanup {
            target,
            days_back,
            dry_run,
        } => {
            info!("Running cleanup job (dry_run: {})", dry_run);

            if let Some(target) = target {
                // Clean specific target
                match target.as_str() {
                    "records" => {
                        // Clean up raw records - use config default if not specified
                        let retention_days =
                            days_back.unwrap_or(config.jobs.usage_cleanup.raw_records_days);

                        if dry_run {
                            info!(
                                "DRY RUN: Would clean up usage records older than {} days",
                                retention_days
                            );
                            return Ok(());
                        }

                        let count = summarization_service
                            .cleanup_records(retention_days)
                            .await?;
                        info!("Successfully cleaned up {} old records", count);
                    }

                    "hourly" | "daily" | "weekly" | "monthly" => {
                        // Clean up specific summary period type
                        let period_type = match target.as_str() {
                            "hourly" => PeriodType::Hourly,
                            "daily" => PeriodType::Daily,
                            "weekly" => PeriodType::Weekly,
                            "monthly" => PeriodType::Monthly,
                            _ => unreachable!(), // Already matched above
                        };

                        // Use config default if days_back not specified
                        let retention_days = days_back.unwrap_or_else(|| {
                            config.jobs.usage_cleanup.get_retention_days(period_type)
                        });

                        if dry_run {
                            info!(
                                "DRY RUN: Would clean up {:?} summaries older than {} days",
                                period_type, retention_days
                            );
                            return Ok(());
                        }

                        let count = summarization_service
                            .cleanup_summaries_by_period(period_type, retention_days)
                            .await?;

                        info!(
                            "Successfully cleaned up {} old {:?} summaries",
                            count, period_type
                        );
                    }

                    _ => {
                        return Err(format!(
                            "Invalid cleanup target: {target}. Valid options: records, hourly, daily, weekly, monthly"
                        ).into());
                    }
                }
            } else {
                // Clean all types - records + all summary periods
                let mut total_cleaned = 0;

                if dry_run {
                    info!("DRY RUN: Would clean up all types using config defaults:");
                    info!(
                        "  - Raw records: {} days",
                        config.jobs.usage_cleanup.raw_records_days
                    );
                    for period_type in [
                        PeriodType::Hourly,
                        PeriodType::Daily,
                        PeriodType::Weekly,
                        PeriodType::Monthly,
                    ] {
                        let retention_days =
                            config.jobs.usage_cleanup.get_retention_days(period_type);
                        info!("  - {:?} summaries: {} days", period_type, retention_days);
                    }
                    return Ok(());
                }

                // Clean raw records first
                let records_retention =
                    days_back.unwrap_or(config.jobs.usage_cleanup.raw_records_days);
                let records_cleaned = summarization_service
                    .cleanup_records(records_retention)
                    .await?;
                total_cleaned += records_cleaned;
                info!("Cleaned up {} raw usage records", records_cleaned);

                // Clean all summary period types
                for period_type in [
                    PeriodType::Hourly,
                    PeriodType::Daily,
                    PeriodType::Weekly,
                    PeriodType::Monthly,
                ] {
                    let retention_days = days_back.unwrap_or_else(|| {
                        config.jobs.usage_cleanup.get_retention_days(period_type)
                    });

                    let summaries_cleaned = summarization_service
                        .cleanup_summaries_by_period(period_type, retention_days)
                        .await?;

                    total_cleaned += summaries_cleaned;
                    info!(
                        "Cleaned up {} old {:?} summaries (retention: {} days)",
                        summaries_cleaned, period_type, retention_days
                    );
                }

                info!("Total items cleaned: {}", total_cleaned);
            }
        }

        JobCommand::List => {
            println!("Available job types:");
            println!("  summaries  - Generate usage summaries for improved query performance");
            println!(
                "  cleanup    - Clean up old usage records and summaries to manage database size"
            );
            println!();
            println!("Examples:");
            println!("  # Generate summaries");
            println!("  bedrock_proxy job summaries --period daily --days-back 30");
            println!("  bedrock_proxy job summaries --period weekly --user-id 123 --dry-run");
            println!();
            println!("  # Clean up all types (records + all summaries)");
            println!(
                "  bedrock_proxy job cleanup --dry-run                            # Uses config defaults for all types"
            );
            println!(
                "  bedrock_proxy job cleanup --days-back 30                       # Override to 30 days for all types"
            );
            println!();
            println!("  # Clean up specific targets");
            println!(
                "  bedrock_proxy job cleanup --target records --dry-run           # Raw records only (config: 30 days)"
            );
            println!(
                "  bedrock_proxy job cleanup --target daily --dry-run             # Daily summaries only (config: 90 days)"
            );
            println!(
                "  bedrock_proxy job cleanup --target hourly --days-back 3       # Hourly summaries with override"
            );
        }
    }

    Ok(())
}
