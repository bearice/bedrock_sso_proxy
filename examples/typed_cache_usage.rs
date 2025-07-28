use bedrock_sso_proxy::cache::CacheManagerImpl;
use bedrock_sso_proxy::database::entities::UserRecord;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create cache manager
    let cache_manager = CacheManagerImpl::new_memory();

    // Get a typed cache for UserRecord
    let user_cache = cache_manager.get_typed_cache::<UserRecord>();

    // Example user
    let user = UserRecord {
        id: 1,
        provider_user_id: "12345".to_string(),
        provider: "google".to_string(),
        email: "john@example.com".to_string(),
        display_name: Some("John Doe".to_string()),
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
        last_login: Some(chrono::Utc::now()),
    };

    // Cache the user
    user_cache.set_default("1", &user).await?;

    // Retrieve from cache
    let cached_user = user_cache.get("1").await?;
    println!("Cached user: {:?}", cached_user);

    // Cache-aside pattern
    let computed_user = user_cache
        .get_or_compute("2", || async {
            // Simulate database fetch
            let user = UserRecord {
                id: 2,
                provider_user_id: "67890".to_string(),
                provider: "github".to_string(),
                email: "jane@example.com".to_string(),
                display_name: Some("Jane Smith".to_string()),
                created_at: chrono::Utc::now(),
                updated_at: chrono::Utc::now(),
                last_login: Some(chrono::Utc::now()),
            };
            Ok::<UserRecord, Box<dyn std::error::Error + Send + Sync>>(user)
        })
        .await?;

    println!("Computed user: {:?}", computed_user);

    // Get cache stats
    let stats = user_cache.get_stats();
    println!("Cache stats: {:?}", stats);

    Ok(())
}
