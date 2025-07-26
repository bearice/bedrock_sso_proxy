use super::{
    CacheStorage, DatabaseStorage, Storage, StorageResult,
    blackhole::BlackholeStorage,
    database::{DatabaseConfig, PostgresStorage, SqliteStorage},
    memory::MemoryCacheStorage,
    redis::{RedisCacheStorage, RedisConfig},
};
use crate::config::Config;

/// Storage backend types
#[derive(Debug, Clone)]
pub enum CacheBackend {
    Memory,
    Redis,
}

#[derive(Debug, Clone)]
pub enum DatabaseBackend {
    Memory,
    Sqlite,
    Postgres,
}

/// Storage factory configuration
#[derive(Debug, Clone)]
pub struct StorageFactoryConfig {
    pub cache_backend: CacheBackend,
    pub database_backend: DatabaseBackend,
    pub redis_config: RedisConfig,
    pub database_config: DatabaseConfig,
    pub memory_cleanup_interval: u64,
}

impl Default for StorageFactoryConfig {
    fn default() -> Self {
        Self {
            cache_backend: CacheBackend::Memory,
            database_backend: DatabaseBackend::Memory,
            redis_config: RedisConfig::default(),
            database_config: DatabaseConfig::default(),
            memory_cleanup_interval: 3600, // 1 hour
        }
    }
}

/// Storage factory for creating appropriate storage backends
pub struct StorageFactory;

impl StorageFactory {
    /// Create storage from application config
    pub async fn create_from_config(config: &Config) -> StorageResult<Storage> {
        let storage_config = Self::extract_storage_config(config);
        Self::create_storage(storage_config).await
    }

    /// Create storage with explicit configuration
    pub async fn create_storage(config: StorageFactoryConfig) -> StorageResult<Storage> {
        let cache = Self::create_cache_storage(&config).await?;
        let database = Self::create_database_storage(&config).await?;

        let storage = Storage::new(cache, database);

        // Run database migrations if enabled
        if config.database_config.migration_on_startup {
            storage.migrate().await?;
        }

        Ok(storage)
    }

    /// Create cache storage backend
    async fn create_cache_storage(
        config: &StorageFactoryConfig,
    ) -> StorageResult<Box<dyn CacheStorage>> {
        match config.cache_backend {
            CacheBackend::Memory => {
                let cache = MemoryCacheStorage::new(config.memory_cleanup_interval);
                Ok(Box::new(cache))
            }
            CacheBackend::Redis => {
                let cache = RedisCacheStorage::new(
                    &config.redis_config.url,
                    &config.redis_config.key_prefix,
                    config.redis_config.command_timeout_seconds,
                )
                .await?;
                Ok(Box::new(cache))
            }
        }
    }

    /// Create database storage backend
    async fn create_database_storage(
        config: &StorageFactoryConfig,
    ) -> StorageResult<Box<dyn DatabaseStorage>> {
        match config.database_backend {
            DatabaseBackend::Memory => {
                // Use blackhole storage when database is disabled
                let database = BlackholeStorage::new();
                Ok(Box::new(database))
            }
            DatabaseBackend::Sqlite => {
                let database = SqliteStorage::new(&config.database_config.url).await?;
                Ok(Box::new(database))
            }
            DatabaseBackend::Postgres => {
                let database = PostgresStorage::new(&config.database_config.url).await?;
                Ok(Box::new(database))
            }
        }
    }

    /// Extract storage configuration from application config
    pub fn extract_storage_config(config: &Config) -> StorageFactoryConfig {
        let cache_backend = if config.storage.redis.enabled {
            CacheBackend::Redis
        } else {
            CacheBackend::Memory
        };

        let database_backend = if config.storage.database.enabled {
            if config.storage.database.url.starts_with("postgres://") {
                DatabaseBackend::Postgres
            } else if config.storage.database.url.starts_with("sqlite://") {
                DatabaseBackend::Sqlite
            } else {
                // Default to SQLite in-memory if URL format is unrecognized
                DatabaseBackend::Sqlite
            }
        } else {
            // Use blackhole storage when database is disabled
            DatabaseBackend::Memory
        };

        let redis_config = RedisConfig {
            url: config.storage.redis.url.clone(),
            key_prefix: config.storage.redis.key_prefix.clone(),
            command_timeout_seconds: config.storage.redis.command_timeout_seconds,
            max_connections: config.storage.redis.max_connections,
        };

        let database_config = DatabaseConfig {
            url: config.storage.database.url.clone(),
            max_connections: config.storage.database.max_connections,
            migration_on_startup: config.storage.database.migration_on_startup,
        };

        StorageFactoryConfig {
            cache_backend,
            database_backend,
            redis_config,
            database_config,
            memory_cleanup_interval: config.cache.cleanup_interval,
        }
    }

    /// Create storage for testing with SQLite in-memory
    pub async fn create_test_storage() -> StorageResult<Storage> {
        let config = StorageFactoryConfig {
            cache_backend: CacheBackend::Memory,
            database_backend: DatabaseBackend::Sqlite,
            redis_config: RedisConfig::default(),
            database_config: DatabaseConfig {
                url: "sqlite::memory:".to_string(),
                max_connections: 5,
                migration_on_startup: true,
            },
            memory_cleanup_interval: 60, // 1 minute for testing
        };

        Self::create_storage(config).await
    }

    /// Create storage for testing with blackhole (no-op) database
    pub async fn create_blackhole_storage() -> StorageResult<Storage> {
        let config = StorageFactoryConfig {
            cache_backend: CacheBackend::Memory,
            database_backend: DatabaseBackend::Memory,
            redis_config: RedisConfig::default(),
            database_config: DatabaseConfig::default(),
            memory_cleanup_interval: 60, // 1 minute for testing
        };

        Self::create_storage(config).await
    }

    /// Create storage for development with SQLite
    pub async fn create_development_storage() -> StorageResult<Storage> {
        let config = StorageFactoryConfig {
            cache_backend: CacheBackend::Memory,
            database_backend: DatabaseBackend::Sqlite,
            redis_config: RedisConfig::default(),
            database_config: DatabaseConfig {
                url: "sqlite://./data/bedrock_sso.db".to_string(),
                max_connections: 5,
                migration_on_startup: true,
            },
            memory_cleanup_interval: 3600,
        };

        Self::create_storage(config).await
    }

    /// Create storage for production with Redis and PostgreSQL
    pub async fn create_production_storage(
        redis_url: &str,
        postgres_url: &str,
    ) -> StorageResult<Storage> {
        let config = StorageFactoryConfig {
            cache_backend: CacheBackend::Redis,
            database_backend: DatabaseBackend::Postgres,
            redis_config: RedisConfig {
                url: redis_url.to_string(),
                key_prefix: "bedrock_sso:".to_string(),
                command_timeout_seconds: 5,
                max_connections: 20,
            },
            database_config: DatabaseConfig {
                url: postgres_url.to_string(),
                max_connections: 20,
                migration_on_startup: true,
            },
            memory_cleanup_interval: 3600,
        };

        Self::create_storage(config).await
    }
}

/// Storage configuration extractor trait
pub trait StorageConfigExtractor {
    fn extract_storage_config(&self) -> StorageFactoryConfig;
}

impl StorageConfigExtractor for Config {
    fn extract_storage_config(&self) -> StorageFactoryConfig {
        StorageFactory::extract_storage_config(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    #[tokio::test]
    async fn test_create_test_storage() {
        let storage = StorageFactory::create_test_storage().await.unwrap();

        // Test health check
        storage.health_check().await.unwrap();

        // Test cache operations
        let validation = super::super::CachedValidation {
            user_id: "user123".to_string(),
            provider: "google".to_string(),
            email: "user@example.com".to_string(),
            validated_at: Utc::now(),
            expires_at: Utc::now() + chrono::Duration::hours(1),
            scopes: vec!["read".to_string()],
        };

        storage
            .cache
            .store_validation("key1", &validation, 3600)
            .await
            .unwrap();
        let retrieved = storage.cache.get_validation("key1").await.unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().user_id, "user123");

        // Test database operations
        let user = super::super::UserRecord {
            id: None,
            provider_user_id: "user123".to_string(),
            provider: "google".to_string(),
            email: "user@example.com".to_string(),
            display_name: Some("Test User".to_string()),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            last_login: None,
        };

        let user_id = storage.database.upsert_user(&user).await.unwrap();
        assert_eq!(user_id, 1);

        let retrieved = storage
            .database
            .get_user_by_provider("google", "user123")
            .await
            .unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().email, "user@example.com");
    }

    #[tokio::test]
    async fn test_create_development_storage() {
        // Use in-memory SQLite for testing
        let config = StorageFactoryConfig {
            cache_backend: CacheBackend::Memory,
            database_backend: DatabaseBackend::Sqlite,
            redis_config: RedisConfig::default(),
            database_config: DatabaseConfig {
                url: "sqlite::memory:".to_string(),
                max_connections: 5,
                migration_on_startup: true,
            },
            memory_cleanup_interval: 3600,
        };

        let storage = StorageFactory::create_storage(config).await.unwrap();

        // Test health check
        storage.health_check().await.unwrap();

        // Test that migrations ran
        let user = super::super::UserRecord {
            id: None,
            provider_user_id: "user123".to_string(),
            provider: "google".to_string(),
            email: "user@example.com".to_string(),
            display_name: Some("Test User".to_string()),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            last_login: None,
        };

        let user_id = storage.database.upsert_user(&user).await.unwrap();
        assert!(user_id > 0);
    }

    #[tokio::test]
    async fn test_storage_factory_config() {
        let config = StorageFactoryConfig::default();

        match config.cache_backend {
            CacheBackend::Memory => (),
            _ => panic!("Default cache backend should be Memory"),
        }

        match config.database_backend {
            DatabaseBackend::Memory => (),
            _ => panic!("Default database backend should be Memory"),
        }

        assert_eq!(config.memory_cleanup_interval, 3600);
        assert_eq!(config.redis_config.key_prefix, "bedrock_sso:");
        assert_eq!(config.database_config.max_connections, 5);
    }

    #[tokio::test]
    async fn test_postgres_storage_factory() {
        use crate::storage::postgres::tests::create_test_postgres_db;

        let test_db = create_test_postgres_db().await
            .expect("PostgreSQL database must be available for testing. Set POSTGRES_ADMIN_URL or ensure PostgreSQL is running.");

        let database_url = format!("postgres://localhost/{}", test_db.db_name);

        let config = StorageFactoryConfig {
            cache_backend: CacheBackend::Memory,
            database_backend: DatabaseBackend::Postgres,
            redis_config: RedisConfig::default(),
            database_config: DatabaseConfig {
                url: database_url,
                max_connections: 5,
                migration_on_startup: true,
            },
            memory_cleanup_interval: 3600,
        };

        let storage = StorageFactory::create_storage(config).await
            .expect("PostgreSQL database must be available for testing. Set POSTGRES_ADMIN_URL or ensure PostgreSQL is running.");

        // Test health check
        storage.health_check().await.unwrap();

        // Test basic database operations through factory-created storage
        let user = super::super::UserRecord {
            id: None,
            provider_user_id: "factory-user-postgres".to_string(),
            provider: "google".to_string(),
            email: "factory@example.com".to_string(),
            display_name: Some("Factory Test User".to_string()),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            last_login: None,
        };

        let user_id = storage.database.upsert_user(&user).await.unwrap();
        assert!(user_id > 0);

        let retrieved = storage
            .database
            .get_user_by_provider("google", "factory-user-postgres")
            .await
            .unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().email, "factory@example.com");

        // Test cache operations work with PostgreSQL backend
        let validation = super::super::CachedValidation {
            user_id: "factory-user-postgres".to_string(),
            provider: "google".to_string(),
            email: "factory@example.com".to_string(),
            validated_at: Utc::now(),
            expires_at: Utc::now() + chrono::Duration::hours(1),
            scopes: vec!["read".to_string()],
        };

        storage
            .cache
            .store_validation("factory-key", &validation, 3600)
            .await
            .unwrap();
        let retrieved_validation = storage.cache.get_validation("factory-key").await.unwrap();
        assert!(retrieved_validation.is_some());
        assert_eq!(
            retrieved_validation.unwrap().user_id,
            "factory-user-postgres"
        );
    }

    #[tokio::test]
    async fn test_database_backend_selection() {
        use crate::config::Config;

        // Test PostgreSQL URL detection
        let mut config = Config::default();
        config.storage.database.url = "postgres://user:pass@localhost:5432/test".to_string();
        config.storage.database.enabled = true;

        let storage_config = StorageFactory::extract_storage_config(&config);
        match storage_config.database_backend {
            DatabaseBackend::Postgres => (),
            _ => panic!("Should detect PostgreSQL from postgres:// URL"),
        }

        // Test SQLite URL detection
        config.storage.database.url = "sqlite://./test.db".to_string();
        let storage_config = StorageFactory::extract_storage_config(&config);
        match storage_config.database_backend {
            DatabaseBackend::Sqlite => (),
            _ => panic!("Should detect SQLite from sqlite:// URL"),
        }

        // Test unknown URL format defaults to SQLite
        config.storage.database.url = "unknown://format".to_string();
        let storage_config = StorageFactory::extract_storage_config(&config);
        match storage_config.database_backend {
            DatabaseBackend::Sqlite => (),
            _ => panic!("Should default to SQLite for unknown URL format"),
        }

        // Test disabled database defaults to Memory (blackhole)
        config.storage.database.enabled = false;
        let storage_config = StorageFactory::extract_storage_config(&config);
        match storage_config.database_backend {
            DatabaseBackend::Memory => (),
            _ => panic!("Should default to Memory when database disabled"),
        }
    }

    #[tokio::test]
    async fn test_create_blackhole_storage() {
        let storage = StorageFactory::create_blackhole_storage().await.unwrap();

        // Test health check
        storage.health_check().await.unwrap();

        // Test migrations (should be no-op)
        storage.migrate().await.unwrap();

        // Test that database operations return empty/default values
        let user = super::super::UserRecord {
            id: None,
            provider_user_id: "test-user".to_string(),
            provider: "google".to_string(),
            email: "test@example.com".to_string(),
            display_name: Some("Test User".to_string()),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            last_login: None,
        };

        // Should "succeed" but not actually store anything
        let user_id = storage.database.upsert_user(&user).await.unwrap();
        assert_eq!(user_id, 1);

        // Should return None since nothing is actually stored
        let retrieved = storage
            .database
            .get_user_by_provider("google", "test-user")
            .await
            .unwrap();
        assert!(retrieved.is_none());

        // Test cache operations still work (memory cache)
        let validation = super::super::CachedValidation {
            user_id: "user123".to_string(),
            provider: "google".to_string(),
            email: "user@example.com".to_string(),
            validated_at: chrono::Utc::now(),
            expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
            scopes: vec!["read".to_string()],
        };

        storage
            .cache
            .store_validation("key1", &validation, 3600)
            .await
            .unwrap();
        let retrieved = storage.cache.get_validation("key1").await.unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().user_id, "user123");
    }

    #[tokio::test]
    async fn test_production_storage_factory() {
        let redis_url = "redis://localhost:6379";
        let postgres_url = std::env::var("POSTGRES_TEST_URL")
            .unwrap_or_else(|_| "postgres://localhost/bedrock_sso_test".to_string());

        let storage =
            match StorageFactory::create_production_storage(redis_url, &postgres_url).await {
                Ok(storage) => storage,
                Err(_) => {
                    eprintln!("Skipping production storage test - services not available");
                    return;
                }
            };

        // Test health check works for production configuration
        storage.health_check().await.unwrap();

        // Verify production configuration was applied correctly
        // (Redis cache + PostgreSQL database should be configured)
        let user = super::super::UserRecord {
            id: None,
            provider_user_id: "prod-test-user".to_string(),
            provider: "google".to_string(),
            email: "prod@example.com".to_string(),
            display_name: Some("Production Test User".to_string()),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            last_login: None,
        };

        let user_id = storage.database.upsert_user(&user).await.unwrap();
        assert!(user_id > 0);
    }
}
