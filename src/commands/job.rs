use crate::{
    Config, cache::CacheManagerImpl, database::DatabaseManagerImpl,
    summarization::SummarizationService,
};
use clap::Subcommand;
use std::sync::Arc;
use tracing::info;

#[derive(Subcommand)]
pub enum JobCommand {
    /// Run a specific job type
    Run {
        #[arg(help = "Job type to run (summaries, cleanup)")]
        job_type: String,

        #[arg(
            long,
            help = "Period type for summaries (hourly, daily, weekly, monthly)"
        )]
        period: Option<String>,

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
    },

    /// List available job types
    List,

    /// Check job system status  
    Status,
}

pub async fn handle_job_command(
    command: JobCommand,
    config: &Config,
) -> Result<(), Box<dyn std::error::Error>> {
    let cache_manager = Arc::new(CacheManagerImpl::new_from_config(&config.cache).await?);
    let db_manager = Arc::new(DatabaseManagerImpl::new_from_config(config, cache_manager).await?);
    let summarization_service = Arc::new(SummarizationService::new(db_manager));

    match command {
        JobCommand::Run {
            job_type,
            period,
            days_back,
            dry_run,
            user_id,
            model_id,
        } => {
            info!("Running job: {} (dry_run: {})", job_type, dry_run);

            match job_type.as_str() {
                "summaries" => {
                    let period = period.unwrap_or_else(|| "daily".to_string());

                    if dry_run {
                        info!(
                            "DRY RUN: Would generate {} summaries for the last {} days",
                            period, days_back
                        );
                        return Ok(());
                    }

                    let count = summarization_service
                        .generate_summaries(&period, days_back, user_id, model_id.as_deref())
                        .await?;

                    info!("Successfully generated {} summaries", count);
                }

                "cleanup" => {
                    if dry_run {
                        info!(
                            "DRY RUN: Would clean up usage records older than {} days",
                            days_back
                        );
                        return Ok(());
                    }

                    let count = summarization_service.cleanup_records(days_back).await?;

                    info!("Successfully cleaned up {} old records", count);
                }

                _ => {
                    return Err(format!(
                        "Unknown job type: {}. Available: summaries, cleanup",
                        job_type
                    )
                    .into());
                }
            }
        }

        JobCommand::List => {
            println!("Available job types:");
            println!("  summaries  - Generate usage summaries for improved query performance");
            println!("  cleanup    - Clean up old usage records to manage database size");
            println!();
            println!("Examples:");
            println!("  bedrock_proxy job run summaries --period daily");
            println!("  bedrock_proxy job run cleanup --days-back 30 --dry-run");
        }

        JobCommand::Status => {
            println!("Job System Status:");
            println!("  Scheduler: Not implemented yet");
            println!("  Available Jobs: summaries, cleanup");
            println!("  Last Run: Not tracked yet");
        }
    }

    Ok(())
}
