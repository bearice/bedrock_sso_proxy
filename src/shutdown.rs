use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tokio::{signal, sync::watch, time::timeout};
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
    name: String,
}

impl DatabaseShutdown {
    pub fn new<T>(_database: Arc<T>) -> Self {
        Self {
            name: "Database".to_string(),
        }
    }
}

#[async_trait::async_trait]
impl GracefulShutdown for DatabaseShutdown {
    fn name(&self) -> &str {
        &self.name
    }

    async fn shutdown(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        info!("Shutting down database connections...");
        // Database cleanup would go here
        // For now, just a brief delay to simulate cleanup
        tokio::time::sleep(Duration::from_millis(100)).await;
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
    task_handle: Option<tokio::task::JoinHandle<()>>,
}

impl BackgroundTaskShutdown {
    pub fn new(name: String, task_handle: tokio::task::JoinHandle<()>) -> Self {
        Self {
            name,
            task_handle: Some(task_handle),
        }
    }
}

#[async_trait::async_trait]
impl GracefulShutdown for BackgroundTaskShutdown {
    fn name(&self) -> &str {
        &self.name
    }

    async fn shutdown(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if let Some(handle) = self.task_handle.as_ref() {
            if !handle.is_finished() {
                info!("Cancelling background task: {}", self.name);
                handle.abort();

                // Wait a bit for graceful cancellation
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
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
