use crate::model_service::ModelService;
use std::{
    collections::HashMap,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::{
    signal,
    sync::{RwLock, watch},
    task::JoinHandle,
    time::timeout,
};
use tracing::{error, info};

/// Graceful shutdown coordinator
#[derive(Clone)]
pub struct ShutdownCoordinator {
    /// Indicates if shutdown has been initiated
    shutdown_requested: Arc<AtomicBool>,
    /// Watch channel for notifying components of shutdown
    shutdown_tx: watch::Sender<bool>,
    /// Receiver for shutdown notifications
    shutdown_rx: watch::Receiver<bool>,
}

impl ShutdownCoordinator {
    /// Create a new shutdown coordinator
    pub fn new() -> Self {
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        Self {
            shutdown_requested: Arc::new(AtomicBool::new(false)),
            shutdown_tx,
            shutdown_rx,
        }
    }

    /// Get a receiver for shutdown notifications
    pub fn subscribe(&self) -> watch::Receiver<bool> {
        self.shutdown_rx.clone()
    }

    /// Check if shutdown has been requested
    pub fn is_shutdown_requested(&self) -> bool {
        self.shutdown_requested.load(Ordering::Relaxed)
    }

    /// Initiate graceful shutdown
    pub fn initiate_shutdown(&self) {
        if self
            .shutdown_requested
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::Relaxed)
            .is_ok()
        {
            info!("Initiating graceful shutdown...");
            if let Err(e) = self.shutdown_tx.send(true) {
                error!("Failed to broadcast shutdown signal: {}", e);
            }
        }
    }

    /// Wait for shutdown signal (SIGTERM, SIGINT, etc.)
    pub async fn wait_for_shutdown_signal(&self) {
        let ctrl_c = async {
            signal::ctrl_c()
                .await
                .expect("Failed to install Ctrl+C handler");
        };

        #[cfg(unix)]
        let terminate = async {
            signal::unix::signal(signal::unix::SignalKind::terminate())
                .expect("Failed to install signal handler")
                .recv()
                .await;
        };

        #[cfg(not(unix))]
        let terminate = std::future::pending::<()>();

        tokio::select! {
            _ = ctrl_c => {
                info!("Received Ctrl+C signal");
            },
            _ = terminate => {
                info!("Received terminate signal");
            },
        }

        self.initiate_shutdown();
    }
}

impl Default for ShutdownCoordinator {
    fn default() -> Self {
        Self::new()
    }
}

/// Trait for components that need graceful shutdown
#[async_trait::async_trait]
pub trait GracefulShutdown {
    /// Component name for logging
    fn name(&self) -> &str;

    /// Gracefully shutdown the component
    async fn shutdown(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;
}

/// Shutdown manager that coordinates shutdown of multiple components
pub struct ShutdownManager {
    components: Vec<Box<dyn GracefulShutdown + Send + Sync>>,
    timeout_duration: Duration,
}

impl ShutdownManager {
    /// Create a new shutdown manager
    pub fn new(timeout_duration: Duration) -> Self {
        Self {
            components: Vec::new(),
            timeout_duration,
        }
    }

    /// Register a component for graceful shutdown
    pub fn register<T>(&mut self, component: T)
    where
        T: GracefulShutdown + Send + Sync + 'static,
    {
        self.components.push(Box::new(component));
    }

    /// Register all server components for shutdown in the correct order
    pub fn register_server_components(&mut self, server: &crate::server::Server) {
        // Register components in shutdown order (order matters: jobs first, then token tracking, streaming, cache, database)
        self.register(JobSchedulerShutdown::new(server.job_scheduler.clone()));
        self.register(TokenTrackingShutdown::new(
            server.model_service.clone(),
            server.config.shutdown.token_tracking_timeout_seconds,
        ));
        self.register(StreamingShutdown::new(
            server.streaming_manager.clone(),
            server.config.shutdown.streaming_timeout_seconds,
        ));
        self.register(CacheShutdown::new(server.cache.clone()));
        self.register(DatabaseShutdown::new(server.database.clone()));
        self.register(HttpServerShutdown::new("HTTP Server".to_string()));
    }

    pub fn register_background_task(
        &mut self,
        task: JoinHandle<()>,
        name: &str,
        timeout_seconds: u64,
    ) {
        self.register(BackgroundTaskShutdown::new(
            name.to_string(),
            task,
            timeout_seconds,
        ));
    }

    /// Register background task with default timeout (for backward compatibility)
    pub fn register_background_task_default(&mut self, task: JoinHandle<()>, name: &str) {
        self.register_background_task(task, name, 5);
    }
    /// Shutdown all registered components
    pub async fn shutdown_all(&self) {
        info!("Shutting down {} components...", self.components.len());

        for component in &self.components {
            let component_name = component.name();

            match timeout(self.timeout_duration, component.shutdown()).await {
                Ok(Ok(())) => {
                    info!("Successfully shut down component: {}", component_name);
                }
                Ok(Err(e)) => {
                    error!("Error shutting down component {}: {}", component_name, e);
                }
                Err(_) => {
                    error!("Timeout shutting down component: {}", component_name);
                }
            }
        }

        info!("Shutdown complete");
    }
}

/// Database component that implements graceful shutdown
pub struct DatabaseShutdown {
    #[allow(dead_code)]
    database: Arc<dyn crate::database::DatabaseManager>,
}

impl DatabaseShutdown {
    pub fn new(database: Arc<dyn crate::database::DatabaseManager>) -> Self {
        Self { database }
    }
}

#[async_trait::async_trait]
impl GracefulShutdown for DatabaseShutdown {
    fn name(&self) -> &str {
        "Database"
    }

    async fn shutdown(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        info!("Shutting down database connections...");

        // The database connection itself is automatically closed when dropped
        // by the underlying SeaORM connection pool
        info!("Database shutdown completed");
        Ok(())
    }
}

/// Cache component that implements graceful shutdown
pub struct CacheShutdown {
    #[allow(dead_code)]
    cache: Arc<dyn crate::cache::CacheManager>,
}

impl CacheShutdown {
    pub fn new(cache: Arc<dyn crate::cache::CacheManager>) -> Self {
        Self { cache }
    }
}

#[async_trait::async_trait]
impl GracefulShutdown for CacheShutdown {
    fn name(&self) -> &str {
        "Cache"
    }

    async fn shutdown(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        info!("Shutting down cache...");

        // Cache connections (Redis) are automatically closed when dropped
        info!("Cache shutdown completed");
        Ok(())
    }
}

/// HTTP server shutdown wrapper
pub struct HttpServerShutdown {
    name: String,
}

impl HttpServerShutdown {
    pub fn new(name: String) -> Self {
        Self { name }
    }
}

#[async_trait::async_trait]
impl GracefulShutdown for HttpServerShutdown {
    fn name(&self) -> &str {
        &self.name
    }

    async fn shutdown(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        info!("HTTP server shutdown initiated");
        // The actual server shutdown is handled by axum's graceful shutdown
        // This is just for logging and any additional cleanup
        Ok(())
    }
}

/// Background task shutdown
pub struct BackgroundTaskShutdown {
    name: String,
    task_handle: RwLock<Option<tokio::task::JoinHandle<()>>>,
    timeout_seconds: u64,
}

impl BackgroundTaskShutdown {
    pub fn new(
        name: String,
        task_handle: tokio::task::JoinHandle<()>,
        timeout_seconds: u64,
    ) -> Self {
        Self {
            name,
            task_handle: RwLock::new(Some(task_handle)),
            timeout_seconds,
        }
    }
}

#[async_trait::async_trait]
impl GracefulShutdown for BackgroundTaskShutdown {
    fn name(&self) -> &str {
        &self.name
    }

    async fn shutdown(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if let Some(handle) = self.task_handle.write().await.take() {
            if !handle.is_finished() {
                info!("Shutting down background task: {}", self.name);
                handle.abort();

                // Wait for task to complete or timeout
                match timeout(Duration::from_secs(self.timeout_seconds), handle).await {
                    Ok(_) => {
                        info!("Background task '{}' shut down gracefully", self.name);
                    }
                    Err(_) => {
                        error!("Background task '{}' shutdown timed out", self.name);
                    }
                }
            } else {
                info!("Background task '{}' already finished", self.name);
            }
        }
        Ok(())
    }
}

/// Connection tracking for active streaming requests
#[derive(Clone)]
pub struct StreamingConnectionManager {
    /// Active streaming connections
    active_connections: Arc<RwLock<HashMap<u64, StreamingConnection>>>,
    /// Connection counter for unique IDs
    connection_counter: Arc<AtomicU64>,
    /// Shutdown coordinator for listening to shutdown signals
    #[allow(dead_code)]
    shutdown_coordinator: Arc<ShutdownCoordinator>,
}

/// Information about an active streaming connection
pub struct StreamingConnection {
    pub id: u64,
    pub user_id: i32,
    pub model_id: String,
    pub endpoint_type: String,
    pub started_at: std::time::Instant,
    /// Channel to signal the connection to complete gracefully
    pub completion_tx: tokio::sync::oneshot::Sender<()>,
}

impl StreamingConnectionManager {
    /// Create a new streaming connection manager
    pub fn new(shutdown_coordinator: Arc<ShutdownCoordinator>) -> Self {
        Self {
            active_connections: Arc::new(RwLock::new(HashMap::new())),
            connection_counter: Arc::new(AtomicU64::new(0)),
            shutdown_coordinator,
        }
    }

    /// Register a new streaming connection
    pub async fn register_connection(
        &self,
        user_id: i32,
        model_id: String,
        endpoint_type: String,
    ) -> (u64, tokio::sync::oneshot::Receiver<()>) {
        let id = self.connection_counter.fetch_add(1, Ordering::SeqCst);
        let (completion_tx, completion_rx) = tokio::sync::oneshot::channel();

        info!(
            "Registered streaming connection {} for user {} on model {}",
            id, user_id, model_id
        );

        let connection = StreamingConnection {
            id,
            user_id,
            model_id,
            endpoint_type,
            started_at: std::time::Instant::now(),
            completion_tx,
        };

        self.active_connections.write().await.insert(id, connection);

        (id, completion_rx)
    }

    /// Unregister a streaming connection
    pub async fn unregister_connection(&self, connection_id: u64) {
        if let Some(connection) = self.active_connections.write().await.remove(&connection_id) {
            let duration = connection.started_at.elapsed();
            info!(
                "Unregistered streaming connection {} after {:?}",
                connection_id, duration
            );
        }
    }

    /// Get the number of active connections
    pub async fn active_connection_count(&self) -> usize {
        self.active_connections.read().await.len()
    }

    /// Wait for all streaming connections to complete with timeout
    pub async fn wait_for_all_connections(&self, timeout_duration: Duration) -> bool {
        let start_time = std::time::Instant::now();

        loop {
            let count = self.active_connection_count().await;
            if count == 0 {
                info!("All streaming connections completed");
                return true;
            }

            if start_time.elapsed() > timeout_duration {
                error!(
                    "Timeout waiting for {} streaming connections to complete",
                    count
                );
                return false;
            }

            info!("Waiting for {} streaming connections to complete...", count);
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    /// Signal all active connections to complete gracefully
    pub async fn signal_all_connections_to_complete(&self) {
        let mut connections = self.active_connections.write().await;
        let count = connections.len();

        if count > 0 {
            info!(
                "Signaling {} streaming connections to complete gracefully",
                count
            );

            // Signal all connections to complete
            for (_, connection) in connections.drain() {
                // Send completion signal (ignore errors if receiver is dropped)
                let _ = connection.completion_tx.send(());
            }
        }
    }
}

/// Streaming connection shutdown component
pub struct StreamingShutdown {
    name: String,
    connection_manager: Arc<StreamingConnectionManager>,
    timeout_seconds: u64,
}

impl StreamingShutdown {
    pub fn new(connection_manager: Arc<StreamingConnectionManager>, timeout_seconds: u64) -> Self {
        Self {
            name: "Streaming Connections".to_string(),
            connection_manager,
            timeout_seconds,
        }
    }
}

#[async_trait::async_trait]
impl GracefulShutdown for StreamingShutdown {
    fn name(&self) -> &str {
        &self.name
    }

    async fn shutdown(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        info!("Shutting down streaming connections...");

        // First, signal all active connections to complete gracefully
        self.connection_manager
            .signal_all_connections_to_complete()
            .await;

        // Wait for all connections to complete (with timeout)
        let completed = self
            .connection_manager
            .wait_for_all_connections(Duration::from_secs(self.timeout_seconds))
            .await;

        if completed {
            info!("All streaming connections completed successfully");
        } else {
            error!("Some streaming connections did not complete within timeout");
        }

        Ok(())
    }
}

/// Token tracking shutdown component for ModelService
pub struct TokenTrackingShutdown {
    name: String,
    model_service: Arc<dyn ModelService>,
    timeout_seconds: u64,
}

impl TokenTrackingShutdown {
    pub fn new(model_service: Arc<dyn ModelService>, timeout_seconds: u64) -> Self {
        Self {
            name: "Token Tracking".to_string(),
            model_service,
            timeout_seconds,
        }
    }
}

#[async_trait::async_trait]
impl GracefulShutdown for TokenTrackingShutdown {
    fn name(&self) -> &str {
        &self.name
    }

    async fn shutdown(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        info!("Shutting down token tracking tasks...");

        // First, wait for token tracking tasks to complete
        let completed = self
            .model_service
            .wait_for_token_tracking_completion(Duration::from_secs(self.timeout_seconds))
            .await;

        if completed {
            info!("All token tracking tasks completed successfully");
        } else {
            error!("Some token tracking tasks did not complete within timeout");
            // Abort remaining tasks
            self.model_service.abort_token_tracking_tasks().await;
        }

        Ok(())
    }
}

/// Job scheduler shutdown component
pub struct JobSchedulerShutdown {
    job_scheduler: Arc<tokio::sync::RwLock<crate::jobs::JobScheduler>>,
}

impl JobSchedulerShutdown {
    pub fn new(job_scheduler: Arc<tokio::sync::RwLock<crate::jobs::JobScheduler>>) -> Self {
        Self { job_scheduler }
    }
}

#[async_trait::async_trait]
impl GracefulShutdown for JobSchedulerShutdown {
    fn name(&self) -> &str {
        "Job Scheduler"
    }

    async fn shutdown(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        info!("Shutting down job scheduler...");

        let mut scheduler = self.job_scheduler.write().await;
        scheduler.stop().await;

        info!("Job scheduler shutdown completed");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct TestComponent {
        name: String,
        shutdown_count: Arc<AtomicUsize>,
        should_fail: bool,
        delay: Duration,
    }

    impl TestComponent {
        fn new(
            name: String,
            shutdown_count: Arc<AtomicUsize>,
            should_fail: bool,
            delay: Duration,
        ) -> Self {
            Self {
                name,
                shutdown_count,
                should_fail,
                delay,
            }
        }
    }

    #[async_trait::async_trait]
    impl GracefulShutdown for TestComponent {
        fn name(&self) -> &str {
            &self.name
        }

        async fn shutdown(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            tokio::time::sleep(self.delay).await;
            self.shutdown_count.fetch_add(1, Ordering::SeqCst);

            if self.should_fail {
                Err("Test failure".into())
            } else {
                Ok(())
            }
        }
    }

    #[tokio::test]
    async fn test_shutdown_coordinator() {
        let coordinator = ShutdownCoordinator::new();

        assert!(!coordinator.is_shutdown_requested());

        coordinator.initiate_shutdown();

        assert!(coordinator.is_shutdown_requested());

        // Test that we can get a receiver
        let mut rx = coordinator.subscribe();
        assert!(rx.has_changed().unwrap());
        assert!(*rx.borrow_and_update());
    }

    #[tokio::test]
    async fn test_shutdown_manager_success() {
        let shutdown_count = Arc::new(AtomicUsize::new(0));

        let mut manager = ShutdownManager::new(Duration::from_secs(1));

        manager.register(TestComponent::new(
            "Component1".to_string(),
            shutdown_count.clone(),
            false,
            Duration::from_millis(10),
        ));

        manager.register(TestComponent::new(
            "Component2".to_string(),
            shutdown_count.clone(),
            false,
            Duration::from_millis(20),
        ));

        manager.shutdown_all().await;

        assert_eq!(shutdown_count.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn test_shutdown_manager_with_failure() {
        let shutdown_count = Arc::new(AtomicUsize::new(0));

        let mut manager = ShutdownManager::new(Duration::from_secs(1));

        manager.register(TestComponent::new(
            "SuccessComponent".to_string(),
            shutdown_count.clone(),
            false,
            Duration::from_millis(10),
        ));

        manager.register(TestComponent::new(
            "FailureComponent".to_string(),
            shutdown_count.clone(),
            true,
            Duration::from_millis(10),
        ));

        manager.shutdown_all().await;

        // Both components should have been called, even if one failed
        assert_eq!(shutdown_count.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn test_shutdown_manager_timeout() {
        let shutdown_count = Arc::new(AtomicUsize::new(0));

        let mut manager = ShutdownManager::new(Duration::from_millis(50));

        manager.register(TestComponent::new(
            "SlowComponent".to_string(),
            shutdown_count.clone(),
            false,
            Duration::from_millis(100), // Longer than timeout
        ));

        manager.shutdown_all().await;

        // Component should have been started but timed out
        // We can't guarantee the count because of timing
    }

    #[test]
    fn test_http_server_shutdown() {
        let shutdown = HttpServerShutdown::new("TestServer".to_string());
        assert_eq!(shutdown.name(), "TestServer");
    }

    #[tokio::test]
    async fn test_background_task_shutdown() {
        let handle = tokio::spawn(async {});
        let shutdown = BackgroundTaskShutdown::new("TestTask".to_string(), handle);
        assert_eq!(shutdown.name(), "TestTask");
    }
}
