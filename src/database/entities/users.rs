use crate::cache::object::typed_cache;

use chrono::{DateTime, Utc};
use sea_orm::{entity::prelude::*, sea_query::StringLen};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// User state enum for tracking account status
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    EnumIter,
    DeriveActiveEnum,
    Serialize,
    Deserialize,
    ToSchema,
)]
#[sea_orm(rs_type = "String", db_type = "String(StringLen::N(16))")]
#[derive(Default)]
pub enum UserState {
    #[sea_orm(string_value = "active")]
    #[serde(rename = "active")]
    #[default]
    Active,
    #[sea_orm(string_value = "disabled")]
    #[serde(rename = "disabled")]
    Disabled,
    #[sea_orm(string_value = "expired")]
    #[serde(rename = "expired")]
    Expired,
}

impl UserState {
    /// Check if the user state allows authentication
    pub fn is_active(&self) -> bool {
        matches!(self, UserState::Active)
    }

    /// Check if the user state is disabled
    pub fn is_disabled(&self) -> bool {
        matches!(self, UserState::Disabled)
    }

    /// Check if the user state is expired
    pub fn is_expired(&self) -> bool {
        matches!(self, UserState::Expired)
    }

    /// Get a human-readable description of the state
    pub fn description(&self) -> &'static str {
        match self {
            UserState::Active => "User account is active and can be used normally",
            UserState::Disabled => "User account has been disabled by an administrator",
            UserState::Expired => "User account has expired and needs reactivation",
        }
    }

    /// Convert to string for database storage
    pub fn as_str(&self) -> &'static str {
        match self {
            UserState::Active => "active",
            UserState::Disabled => "disabled",
            UserState::Expired => "expired",
        }
    }
}

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq, Serialize, Deserialize)]
#[sea_orm(table_name = "users")]
#[typed_cache(ttl = 900)] // 15 minutes
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    pub provider_user_id: String,
    pub provider: String,
    pub email: String,
    pub display_name: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub last_login: Option<DateTime<Utc>>,
    #[sea_orm(column_type = "String(StringLen::N(16))", default_value = "active")]
    pub state: UserState,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

impl Default for Model {
    fn default() -> Self {
        let now = chrono::Utc::now();
        Self {
            id: 0, // Will be auto-assigned by database
            provider_user_id: String::new(),
            provider: String::new(),
            email: String::new(),
            display_name: None,
            created_at: now,
            updated_at: now,
            last_login: None,
            state: UserState::Active,
        }
    }
}

impl Model {
    /// Create a new user record with required fields
    pub fn new(
        provider: impl Into<String>,
        provider_user_id: impl Into<String>,
        email: impl Into<String>,
    ) -> Self {
        Self {
            provider: provider.into(),
            provider_user_id: provider_user_id.into(),
            email: email.into(),
            ..Default::default()
        }
    }

    /// Builder method to set display name
    pub fn with_display_name<T: std::ops::Deref>(mut self, display_name: Option<T>) -> Self
    where
        <T as std::ops::Deref>::Target: ToString,
    {
        self.display_name = display_name.as_deref().map(ToString::to_string);
        self
    }

    /// Builder method to set state
    pub fn with_state(mut self, state: UserState) -> Self {
        self.state = state;
        self
    }

    /// Builder method to set last login
    pub fn with_last_login(mut self, last_login: DateTime<Utc>) -> Self {
        self.last_login = Some(last_login);
        self
    }

    /// Builder method to set timestamps
    pub fn with_timestamps(mut self, created_at: DateTime<Utc>, updated_at: DateTime<Utc>) -> Self {
        self.created_at = created_at;
        self.updated_at = updated_at;
        self
    }

    /// Builder method to set ID (for tests)
    pub fn with_id(mut self, id: i32) -> Self {
        self.id = id;
        self
    }
}
