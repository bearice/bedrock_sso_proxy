// Context and permission utilities for GraphQL

/// User context for GraphQL operations with permission information
#[derive(Debug, Clone)]
pub struct UserContext {
    pub user_id: i32,
    pub is_admin: bool,
}

impl UserContext {
    pub fn new(user_id: i32, is_admin: bool) -> Self {
        Self {
            user_id,
            is_admin,
        }
    }

    /// Check if user can access data for the given user_id
    pub fn can_access_user_data(&self, target_user_id: i32) -> bool {
        self.user_id == target_user_id || self.is_admin
    }
}

use async_graphql::{Context, Guard, Result};

/// GraphQL permission guard for user-owned resources
pub struct UserOwnerGuard {
    pub user_id: i32,
}

#[async_trait::async_trait]
impl Guard for UserOwnerGuard {
    async fn check(&self, ctx: &Context<'_>) -> Result<()> {
        if let Ok(user_context) = ctx.data::<UserContext>() {
            if user_context.can_access_user_data(self.user_id) {
                Ok(())
            } else {
                Err("Access denied: insufficient permissions".into())
            }
        } else {
            Err("Access denied: no user context".into())
        }
    }
}

/// GraphQL permission guard for admin-only resources
pub struct AdminGuard;

#[async_trait::async_trait]
impl Guard for AdminGuard {
    async fn check(&self, ctx: &Context<'_>) -> Result<()> {
        if let Ok(user_context) = ctx.data::<UserContext>() {
            if user_context.is_admin {
                Ok(())
            } else {
                Err("Access denied: admin privileges required".into())
            }
        } else {
            Err("Access denied: no user context".into())
        }
    }
}

// Note: Above guards have lifetime issues - keeping inline checks as backup