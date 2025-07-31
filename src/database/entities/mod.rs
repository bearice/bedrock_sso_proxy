pub mod api_keys;
pub mod audit_logs;
pub mod model_costs;
pub mod refresh_tokens;
pub mod usage_records;
pub mod usage_summaries;
pub mod users;

pub use api_keys::Entity as ApiKeys;
pub use audit_logs::Entity as AuditLogs;
pub use model_costs::Entity as ModelCosts;
pub use refresh_tokens::Entity as RefreshTokens;
pub use usage_records::Entity as UsageRecords;
pub use usage_summaries::Entity as UsageSummaries;
pub use users::Entity as Users;

// Type aliases
pub type UserRecord = users::Model;
pub type RefreshTokenData = refresh_tokens::Model;
pub type AuditLogEntry = audit_logs::Model;
pub type UsageRecord = usage_records::Model;
pub type UsageSummary = usage_summaries::Model;
pub type ModelCost = model_costs::Model;
pub type ApiKeyRecord = api_keys::Model;

// Database entities use derive macro with TTL attributes
// All implementations are generated automatically via #[derive(CacheableDeriv)]
