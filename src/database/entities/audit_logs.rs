use crate::cache::object::typed_cache;
use chrono::{DateTime, Utc};
use sea_orm::entity::prelude::*;
use sea_orm::sea_query::StringLen;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// Audit event types for tracking user and system activities
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, EnumIter, DeriveActiveEnum, ToSchema,
)]
#[sea_orm(rs_type = "String", db_type = "String(StringLen::N(50))")]
pub enum AuditEventType {
    #[sea_orm(string_value = "login")]
    Login,
    #[sea_orm(string_value = "logout")]
    Logout,
    #[sea_orm(string_value = "oauth_start")]
    OAuthStart,
    #[sea_orm(string_value = "oauth_complete")]
    OAuthComplete,
    #[sea_orm(string_value = "token_refresh")]
    TokenRefresh,
    #[sea_orm(string_value = "api_key_create")]
    ApiKeyCreate,
    #[sea_orm(string_value = "api_key_delete")]
    ApiKeyDelete,
    #[sea_orm(string_value = "api_call")]
    ApiCall,
    #[sea_orm(string_value = "model_invoke")]
    ModelInvoke,
    #[sea_orm(string_value = "auth_failure")]
    AuthFailure,
    #[sea_orm(string_value = "oauth_login")]
    OAuthLogin,
    #[sea_orm(string_value = "oauth_login_failed")]
    OAuthLoginFailed,
}

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq, Serialize, Deserialize)]
#[sea_orm(table_name = "audit_logs")]
#[typed_cache(ttl = 1800)] // 30 minutes
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    pub user_id: Option<i32>,
    pub event_type: AuditEventType,
    pub provider: Option<String>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub success: bool,
    pub error_message: Option<String>,
    pub created_at: DateTime<Utc>,
    pub metadata: Option<String>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
