use super::{Job, JobsConfig};
use crate::error::AppError;
use chrono::Utc;
use cron::Schedule;
use std::{str::FromStr, sync::Arc};
use tokio::{
    sync::{RwLock, broadcast, watch},
    task::JoinHandle,
    time::{Duration, Instant, interval_at},
};
use tracing::{error, info, warn};

/// Job scheduler that manages periodic execution of jobs
pub struct JobScheduler {
    config: JobsConfig,
    handles: Arc<RwLock<Vec<JoinHandle<()>>>>,
    shutdown_tx: broadcast::Sender<()>,
    shutdown_coordinator: Option<watch::Receiver<bool>>,
}

impl JobScheduler {
    pub fn new(config: JobsConfig) -> Self {
        let (shutdown_tx, _) = broadcast::channel(16);

        Self {
            config,
            handles: Arc::new(RwLock::new(Vec::new())),
            shutdown_tx,
            shutdown_coordinator: None,
        }
    }

    /// Create JobScheduler with graceful shutdown integration
    pub fn with_shutdown_coordinator(
        config: JobsConfig,
        shutdown_rx: watch::Receiver<bool>,
    ) -> Self {
        let (shutdown_tx, _) = broadcast::channel(16);

        Self {
            config,
            handles: Arc::new(RwLock::new(Vec::new())),
            shutdown_tx,
            shutdown_coordinator: Some(shutdown_rx),
        }
    }

    /// Start the job scheduler with registered jobs
    pub async fn start(&mut self, jobs: Vec<Arc<dyn Job>>) -> Result<(), AppError> {
        if !self.config.enabled {
            info!("Job scheduler disabled in configuration");
            return Ok(());
        }

        info!("Starting job scheduler with {} jobs", jobs.len());

        let mut handles = self.handles.write().await;
        for job in jobs {
            let handle = self.spawn_job_with_schedule(job).await?;
            handles.push(handle);
        }

        info!("Job scheduler started successfully");
        Ok(())
    }

    /// Stop the job scheduler and all running jobs
    pub async fn stop(&mut self) {
        info!("Stopping job scheduler...");

        // Send shutdown signal
        if let Err(e) = self.shutdown_tx.send(()) {
            warn!("Failed to send shutdown signal: {}", e);
        }

        // Wait for all jobs to complete
        let mut handles = self.handles.write().await;
        for handle in handles.drain(..) {
            if let Err(e) = handle.await {
                error!("Job handle failed during shutdown: {}", e);
            }
        }

        info!("Job scheduler stopped");
    }

    /// Spawn a job with its configured schedule
    async fn spawn_job_with_schedule(&self, job: Arc<dyn Job>) -> Result<JoinHandle<()>, AppError> {
        let schedule = self.get_schedule_for_job(job.name())?;
        let interval_duration = self.parse_cron_to_duration(&schedule)?;

        let job_name = job.name().to_string();
        let mut shutdown_rx = self.shutdown_tx.subscribe();
        let mut coordinator_rx = self.shutdown_coordinator.clone();

        let handle = tokio::spawn(async move {
            let mut interval = interval_at(Instant::now() + interval_duration, interval_duration);

            info!(
                "Job '{}' scheduled with interval {:?}",
                job_name, interval_duration
            );

            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        info!("Executing job '{}'", job_name);

                        match job.execute().await {
                            Ok(result) => {
                                if result.success {
                                    info!("Job '{}' completed: {}", job_name, result.message);
                                } else {
                                    warn!("Job '{}' failed: {}", job_name, result.message);
                                }
                            }
                            Err(e) => {
                                error!("Job '{}' execution error: {}", job_name, e);
                            }
                        }
                    }
                    _ = shutdown_rx.recv() => {
                        info!("Job '{}' received internal shutdown signal", job_name);
                        break;
                    }
                    _ = async {
                        if let Some(ref mut coord_rx) = coordinator_rx {
                            coord_rx.changed().await.ok();
                            *coord_rx.borrow()
                        } else {
                            false
                        }
                    }, if coordinator_rx.is_some() => {
                        info!("Job '{}' received global shutdown signal", job_name);
                        break;
                    }
                }
            }

            info!("Job '{}' stopped", job_name);
        });

        Ok(handle)
    }

    /// Get the schedule configuration for a specific job
    fn get_schedule_for_job(&self, job_name: &str) -> Result<String, AppError> {
        match job_name {
            "usage_summaries" => Ok(self.config.usage_summaries.schedule.clone()),
            "usage_cleanup" => Ok(self.config.usage_cleanup.schedule.clone()),
            _ => Err(AppError::Internal(format!("Unknown job: {job_name}"))),
        }
    }

    /// Parse a cron expression and calculate duration until next execution
    /// Uses 6-field format (sec min hour day month dow)
    fn parse_cron_to_duration(&self, cron: &str) -> Result<Duration, AppError> {
        let schedule = Schedule::from_str(cron)
            .map_err(|e| AppError::Internal(format!("Invalid cron expression '{cron}': {e}")))?;

        let now = Utc::now();
        let next_execution = schedule.upcoming(Utc).take(1).next().ok_or_else(|| {
            AppError::Internal(format!(
                "No upcoming execution found for cron expression: {cron}"
            ))
        })?;

        let duration_until_next = (next_execution - now)
            .to_std()
            .map_err(|e| AppError::Internal(format!("Failed to convert duration: {e}")))?;

        Ok(duration_until_next)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jobs::JobsConfig;

    fn create_test_scheduler() -> JobScheduler {
        let config = JobsConfig {
            enabled: true,
            usage_summaries: crate::jobs::UsageSummariesConfig {
                schedule: "0 0 2 * * *".to_string(),
                periods: vec!["daily".to_string()],
            },
            usage_cleanup: crate::jobs::UsageCleanupConfig {
                schedule: "0 0 3 * * *".to_string(),
                raw_records_days: 30,
                summaries_retention_days: crate::jobs::default_summaries_retention_days(),
            },
        };
        JobScheduler::new(config)
    }

    #[test]
    fn test_valid_cron_expressions() {
        let scheduler = create_test_scheduler();

        // Test common cron expressions (6-field format: sec min hour day month dow)
        let test_cases = vec![
            "0 0 * * * *",     // Every hour
            "0 0 2 * * *",     // Daily at 2 AM
            "0 0 */2 * * *",   // Every 2 hours
            "0 30 14 * * MON", // Every Monday at 2:30 PM
            "0 0 0 1 * *",     // Monthly on 1st
            "0 0 0 * * SUN",   // Weekly on Sunday
            "0 */15 * * * *",  // Every 15 minutes
        ];

        for cron_expr in test_cases {
            let result = scheduler.parse_cron_to_duration(cron_expr);
            assert!(
                result.is_ok(),
                "Failed to parse valid cron expression '{}': {:?}",
                cron_expr,
                result.err()
            );

            // Duration should be positive (not in the past)
            let duration = result.unwrap();
            assert!(
                duration.as_secs() > 0,
                "Duration should be positive for cron: {cron_expr}"
            );
        }
    }

    #[test]
    fn test_invalid_cron_expressions() {
        let scheduler = create_test_scheduler();

        let invalid_cases = vec![
            "",           // Empty string
            "invalid",    // Not a cron expression
            "60 * * * *", // Invalid minute (>59)
            "0 25 * * *", // Invalid hour (>23)
            "0 0 32 * *", // Invalid day (>31)
            "0 0 * 13 *", // Invalid month (>12)
            "0 0 * * 8",  // Invalid day of week (>7)
        ];

        for cron_expr in invalid_cases {
            let result = scheduler.parse_cron_to_duration(cron_expr);
            assert!(
                result.is_err(),
                "Should fail for invalid cron expression: {cron_expr}"
            );
        }
    }

    #[test]
    fn test_get_schedule_for_job() {
        let scheduler = create_test_scheduler();

        // Test known job names
        assert_eq!(
            scheduler.get_schedule_for_job("usage_summaries").unwrap(),
            "0 0 2 * * *"
        );
        assert_eq!(
            scheduler.get_schedule_for_job("usage_cleanup").unwrap(),
            "0 0 3 * * *"
        );

        // Test unknown job name
        assert!(scheduler.get_schedule_for_job("unknown_job").is_err());
    }

    #[test]
    fn test_complex_cron_expressions() {
        let scheduler = create_test_scheduler();

        // Test more complex expressions that the old parser couldn't handle (6-field format)
        let complex_cases = vec![
            "0 0 9-17 * * 1-5",      // Business hours (9 AM to 5 PM, Monday to Friday)
            "0 0 */6 * * *",         // Every 6 hours
            "0 30 2 1,15 * *",       // 2:30 AM on 1st and 15th of each month
            "0 0 0 * * MON,WED,FRI", // Monday, Wednesday, Friday at midnight
            "0 45 23 * * SUN",       // Sunday at 11:45 PM
        ];

        for cron_expr in complex_cases {
            let result = scheduler.parse_cron_to_duration(cron_expr);
            assert!(
                result.is_ok(),
                "Failed to parse complex cron expression '{}': {:?}",
                cron_expr,
                result.err()
            );
        }
    }
}
