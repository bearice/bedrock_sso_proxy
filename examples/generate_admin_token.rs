use bedrock_sso_proxy::{
    auth::jwt::{JwtService, JwtServiceImpl},
    config::Config,
    database::{DatabaseManager, DatabaseManagerImpl, entities::UserRecord},
    cache::CacheManager,
};
use chrono::Utc;
use jsonwebtoken::Algorithm;
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::load()?;
    let cache = Arc::new(CacheManager::new_from_config(&config.cache).await?);
    let database = Arc::new(DatabaseManagerImpl::new_from_config(&config, cache).await?);
    let jwt_service = Arc::new(JwtServiceImpl::new(config.jwt.secret.clone(), Algorithm::HS256)?);

    let user = UserRecord::new("google", "test_admin_123", "test-admin@example.com")
        .with_display_name(Some("Test Admin"))
        .with_last_login(Utc::now());

    let user_id = database.users().upsert(&user).await?;

    let mut claims = bedrock_sso_proxy::auth::jwt::OAuthClaims::new(user_id, 3600);
    claims.admin = true;
    let token = jwt_service.create_oauth_token(&claims)?;

    println!("Admin user token: {}", token);

    Ok(())
}
