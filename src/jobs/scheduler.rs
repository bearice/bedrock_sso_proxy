use super::{Job, JobsConfig};
use crate::error::AppError;
use std::sync::Arc;
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
            _ => Err(AppError::Internal(format!("Unknown job: {}", job_name))),
        }
    }

    /// Parse a simplified cron expression to a Duration
    /// This is a basic implementation - in production you'd want a proper cron parser
    fn parse_cron_to_duration(&self, cron: &str) -> Result<Duration, AppError> {
        // For now, support common patterns
        match cron {
            "0 * * * *" => Ok(Duration::from_secs(3600)), // Every hour
            "0 2 * * *" => Ok(Duration::from_secs(24 * 3600)), // Daily at 2 AM
            "0 3 * * *" => Ok(Duration::from_secs(24 * 3600)), // Daily at 3 AM
            "0 0 * * 0" => Ok(Duration::from_secs(7 * 24 * 3600)), // Weekly on Sunday
            "0 0 1 * *" => Ok(Duration::from_secs(30 * 24 * 3600)), // Monthly on 1st
            _ => {
                // For development/testing, allow short intervals
                if cron.starts_with("*/") {
                    if let Some(mins) = cron
                        .strip_prefix("*/")
                        .and_then(|s| s.split_whitespace().next())
                    {
                        if let Ok(minutes) = mins.parse::<u64>() {
                            return Ok(Duration::from_secs(minutes * 60));
                        }
                    }
                }
                Err(AppError::Internal(format!(
                    "Unsupported cron expression: {}. Supported: '0 * * * *', '0 2 * * *', '0 3 * * *', '0 0 * * 0', '0 0 1 * *', '*/N * * * *'",
                    cron
                )))
            }
        }
    }
}
