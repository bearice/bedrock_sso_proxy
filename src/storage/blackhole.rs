use super::{
    AuditLogEntry, DatabaseStorage, RefreshTokenData, StorageResult, StoredModelCost, UsageQuery,
    UsageRecord, UsageStats, UsageSummary, UserRecord,
};
use async_trait::async_trait;
use chrono::{DateTime, Utc};

/// Blackhole database storage - discards all writes and returns empty results for reads
/// Used when database storage is disabled in configuration
#[derive(Default)]
pub struct BlackholeStorage;

impl BlackholeStorage {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl DatabaseStorage for BlackholeStorage {
    async fn migrate(&self) -> StorageResult<()> {
        // No-op - no migrations needed for blackhole storage
        Ok(())
    }

    async fn upsert_user(&self, _user: &UserRecord) -> StorageResult<i32> {
        // Return a fake user ID
        Ok(1)
    }

    async fn get_user_by_provider(
        &self,
        _provider: &str,
        _provider_user_id: &str,
    ) -> StorageResult<Option<UserRecord>> {
        // Always return None - no users stored
        Ok(None)
    }

    async fn get_user_by_id(&self, _user_id: i32) -> StorageResult<Option<UserRecord>> {
        // Always return None - no users stored
        Ok(None)
    }

    async fn get_user_by_email(&self, _email: &str) -> StorageResult<Option<UserRecord>> {
        // Always return None - no users stored
        Ok(None)
    }

    async fn update_last_login(&self, _user_id: i32) -> StorageResult<()> {
        // No-op - discard update
        Ok(())
    }

    async fn store_refresh_token(&self, _token: &RefreshTokenData) -> StorageResult<()> {
        // No-op - discard token
        Ok(())
    }

    async fn get_refresh_token(
        &self,
        _token_hash: &str,
    ) -> StorageResult<Option<RefreshTokenData>> {
        // Always return None - no tokens stored
        Ok(None)
    }

    async fn revoke_refresh_token(&self, _token_hash: &str) -> StorageResult<()> {
        // No-op - nothing to revoke
        Ok(())
    }

    async fn cleanup_expired_tokens(&self) -> StorageResult<u64> {
        // Return 0 - no tokens to clean up
        Ok(0)
    }

    async fn store_audit_log(&self, _entry: &AuditLogEntry) -> StorageResult<()> {
        // No-op - discard audit log
        Ok(())
    }

    async fn get_audit_logs_for_user(
        &self,
        _user_id: i32,
        _limit: u32,
        _offset: u32,
    ) -> StorageResult<Vec<AuditLogEntry>> {
        // Return empty vec - no audit logs stored
        Ok(Vec::new())
    }

    async fn cleanup_old_audit_logs(&self, _retention_days: u32) -> StorageResult<u64> {
        // Return 0 - no logs to clean up
        Ok(0)
    }

    async fn health_check(&self) -> StorageResult<()> {
        // Always healthy - blackhole never fails
        Ok(())
    }

    // Usage tracking methods
    async fn store_usage_record(&self, _record: &UsageRecord) -> StorageResult<()> {
        // No-op - discard usage record
        Ok(())
    }

    async fn get_usage_records(&self, _query: &UsageQuery) -> StorageResult<Vec<UsageRecord>> {
        // Return empty vec - no usage records stored
        Ok(Vec::new())
    }

    async fn get_usage_stats(&self, _query: &UsageQuery) -> StorageResult<UsageStats> {
        // Return empty stats
        let now = Utc::now();
        Ok(UsageStats {
            total_requests: 0,
            total_input_tokens: 0,
            total_output_tokens: 0,
            total_tokens: 0,
            avg_response_time_ms: 0.0,
            success_rate: 0.0,
            total_cost: None,
            unique_models: 0,
            date_range: (now, now),
        })
    }

    async fn upsert_usage_summary(&self, _summary: &UsageSummary) -> StorageResult<()> {
        // No-op - discard usage summary
        Ok(())
    }

    async fn get_usage_summaries(&self, _query: &UsageQuery) -> StorageResult<Vec<UsageSummary>> {
        // Return empty vec - no summaries stored
        Ok(Vec::new())
    }

    async fn cleanup_old_usage_records(&self, _retention_days: u32) -> StorageResult<u64> {
        // Return 0 - no records to clean up
        Ok(0)
    }

    async fn get_model_cost(&self, _model_id: &str) -> StorageResult<Option<StoredModelCost>> {
        // Always return None - no model costs stored
        Ok(None)
    }

    async fn upsert_model_cost(&self, _cost: &StoredModelCost) -> StorageResult<()> {
        // No-op - discard model cost
        Ok(())
    }

    async fn get_all_model_costs(&self) -> StorageResult<Vec<StoredModelCost>> {
        // Return empty vec - no model costs stored
        Ok(Vec::new())
    }

    async fn delete_model_cost(&self, _model_id: &str) -> StorageResult<()> {
        // No-op - nothing to delete
        Ok(())
    }

    async fn get_user_usage_records(
        &self,
        _user_id: i32,
        _limit: u32,
        _offset: u32,
        _model_filter: Option<&str>,
        _start_date: Option<DateTime<Utc>>,
        _end_date: Option<DateTime<Utc>>,
    ) -> StorageResult<Vec<UsageRecord>> {
        // Return empty vec - no usage records stored
        Ok(Vec::new())
    }

    async fn get_user_usage_stats(
        &self,
        _user_id: i32,
        _start_date: Option<DateTime<Utc>>,
        _end_date: Option<DateTime<Utc>>,
    ) -> StorageResult<UsageStats> {
        // Return empty stats
        let now = Utc::now();
        Ok(UsageStats {
            total_requests: 0,
            total_input_tokens: 0,
            total_output_tokens: 0,
            total_tokens: 0,
            avg_response_time_ms: 0.0,
            success_rate: 0.0,
            total_cost: None,
            unique_models: 0,
            date_range: (now, now),
        })
    }

    async fn get_system_usage_stats(
        &self,
        _start_date: Option<DateTime<Utc>>,
        _end_date: Option<DateTime<Utc>>,
    ) -> StorageResult<UsageStats> {
        // Return empty stats
        let now = Utc::now();
        Ok(UsageStats {
            total_requests: 0,
            total_input_tokens: 0,
            total_output_tokens: 0,
            total_tokens: 0,
            avg_response_time_ms: 0.0,
            success_rate: 0.0,
            total_cost: None,
            unique_models: 0,
            date_range: (now, now),
        })
    }

    async fn get_top_models_by_usage(
        &self,
        _limit: u32,
        _start_date: Option<DateTime<Utc>>,
        _end_date: Option<DateTime<Utc>>,
    ) -> StorageResult<Vec<(String, u64)>> {
        // Return empty vec - no usage data
        Ok(Vec::new())
    }

    async fn get_unique_model_ids(&self) -> StorageResult<Vec<String>> {
        // Return empty vec - no models used
        Ok(Vec::new())
    }

    // API Key management methods

    async fn store_api_key(&self, _api_key: &crate::auth::ApiKey) -> StorageResult<i32> {
        // Return a fake API key ID
        Ok(1)
    }

    async fn get_api_key_by_hash(&self, _key_hash: &str) -> StorageResult<Option<crate::auth::ApiKey>> {
        // Always return None - no API keys stored
        Ok(None)
    }

    async fn get_api_keys_for_user(&self, _user_id: i32) -> StorageResult<Vec<crate::auth::ApiKey>> {
        // Return empty vec - no API keys stored
        Ok(Vec::new())
    }

    async fn update_api_key_last_used(&self, _key_hash: &str) -> StorageResult<()> {
        // No-op - nothing to update
        Ok(())
    }

    async fn revoke_api_key(&self, _key_id: i32) -> StorageResult<()> {
        // No-op - nothing to revoke
        Ok(())
    }

    async fn cleanup_expired_api_keys(&self) -> StorageResult<u64> {
        // Return 0 - no API keys to clean up
        Ok(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    #[tokio::test]
    async fn test_blackhole_storage_basic_operations() {
        let storage = BlackholeStorage::new();

        // Test health check
        storage.health_check().await.unwrap();

        // Test migration
        storage.migrate().await.unwrap();

        // Test user operations
        let user = UserRecord {
            id: None,
            provider_user_id: "test-user".to_string(),
            provider: "google".to_string(),
            email: "test@example.com".to_string(),
            display_name: Some("Test User".to_string()),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            last_login: None,
        };

        let user_id = storage.upsert_user(&user).await.unwrap();
        assert_eq!(user_id, 1);

        // Should not find the user we just "stored"
        let retrieved_user = storage
            .get_user_by_provider("google", "test-user")
            .await
            .unwrap();
        assert!(retrieved_user.is_none());

        let retrieved_by_email = storage.get_user_by_email("test@example.com").await.unwrap();
        assert!(retrieved_by_email.is_none());

        // Test update last login (should not error)
        storage.update_last_login(1).await.unwrap();
    }

    #[tokio::test]
    async fn test_blackhole_storage_token_operations() {
        let storage = BlackholeStorage::new();

        let token = RefreshTokenData {
            token_hash: "test-hash".to_string(),
            user_id: "test-user".to_string(),
            provider: "google".to_string(),
            email: "test@example.com".to_string(),
            created_at: Utc::now(),
            expires_at: Utc::now() + chrono::Duration::days(30),
            rotation_count: 0,
            revoked_at: None,
        };

        // Store token (should not error)
        storage.store_refresh_token(&token).await.unwrap();

        // Should not find the token we just "stored"
        let retrieved_token = storage.get_refresh_token("test-hash").await.unwrap();
        assert!(retrieved_token.is_none());

        // Revoke token (should not error)
        storage.revoke_refresh_token("test-hash").await.unwrap();

        // Cleanup tokens
        let cleaned = storage.cleanup_expired_tokens().await.unwrap();
        assert_eq!(cleaned, 0);
    }

    #[tokio::test]
    async fn test_blackhole_storage_audit_operations() {
        let storage = BlackholeStorage::new();

        let audit_entry = AuditLogEntry {
            id: None,
            user_id: Some(1),
            event_type: "login".to_string(),
            provider: Some("google".to_string()),
            ip_address: Some("127.0.0.1".to_string()),
            user_agent: Some("Test Agent".to_string()),
            success: true,
            error_message: None,
            created_at: Utc::now(),
            metadata: None,
        };

        // Store audit log (should not error)
        storage.store_audit_log(&audit_entry).await.unwrap();

        // Should not find the audit log we just "stored"
        let logs = storage.get_audit_logs_for_user(1, 10, 0).await.unwrap();
        assert!(logs.is_empty());

        // Cleanup audit logs
        let cleaned = storage.cleanup_old_audit_logs(30).await.unwrap();
        assert_eq!(cleaned, 0);
    }

    #[tokio::test]
    async fn test_blackhole_storage_usage_operations() {
        let storage = BlackholeStorage::new();

        let usage_record = UsageRecord {
            id: None,
            user_id: 1,
            model_id: "test-model".to_string(),
            endpoint_type: "bedrock".to_string(),
            region: "us-east-1".to_string(),
            request_time: Utc::now(),
            input_tokens: 100,
            output_tokens: 50,
            total_tokens: 150,
            response_time_ms: 200,
            success: true,
            error_message: None,
            cost_usd: None,
        };

        // Store usage record (should not error)
        storage.store_usage_record(&usage_record).await.unwrap();

        // Should not find any usage records
        let query = UsageQuery {
            user_id: Some(1),
            model_id: None,
            start_date: None,
            end_date: None,
            success_only: None,
            limit: Some(10),
            offset: Some(0),
        };

        let records = storage.get_usage_records(&query).await.unwrap();
        assert!(records.is_empty());

        // Test usage stats - should be empty
        let stats = storage.get_usage_stats(&query).await.unwrap();
        assert_eq!(stats.total_requests, 0);
        assert_eq!(stats.total_tokens, 0);

        // Test user usage records
        let user_records = storage
            .get_user_usage_records(1, 10, 0, None, None, None)
            .await
            .unwrap();
        assert!(user_records.is_empty());

        // Test user usage stats
        let user_stats = storage.get_user_usage_stats(1, None, None).await.unwrap();
        assert_eq!(user_stats.total_requests, 0);

        // Test system usage stats
        let system_stats = storage.get_system_usage_stats(None, None).await.unwrap();
        assert_eq!(system_stats.total_requests, 0);

        // Test top models
        let top_models = storage
            .get_top_models_by_usage(5, None, None)
            .await
            .unwrap();
        assert!(top_models.is_empty());

        // Test unique model IDs
        let model_ids = storage.get_unique_model_ids().await.unwrap();
        assert!(model_ids.is_empty());

        // Cleanup usage records
        let cleaned = storage.cleanup_old_usage_records(30).await.unwrap();
        assert_eq!(cleaned, 0);
    }

    #[tokio::test]
    async fn test_blackhole_storage_model_cost_operations() {
        let storage = BlackholeStorage::new();

        let model_cost = StoredModelCost {
            id: None,
            model_id: "test-model".to_string(),
            input_cost_per_1k_tokens: rust_decimal::Decimal::from(1),
            output_cost_per_1k_tokens: rust_decimal::Decimal::from(5),
            updated_at: Utc::now(),
        };

        // Store model cost (should not error)
        storage.upsert_model_cost(&model_cost).await.unwrap();

        // Should not find the model cost we just "stored"
        let retrieved_cost = storage.get_model_cost("test-model").await.unwrap();
        assert!(retrieved_cost.is_none());

        // Should get empty list of all model costs
        let all_costs = storage.get_all_model_costs().await.unwrap();
        assert!(all_costs.is_empty());

        // Delete model cost (should not error)
        storage.delete_model_cost("test-model").await.unwrap();
    }
}
