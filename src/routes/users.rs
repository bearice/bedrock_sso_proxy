use crate::{
    database::{
        DatabaseError,
        entities::{UserRecord, UserState},
    },
    error::AppError,
    routes::ApiErrorResponse,
    server::Server,
};
use axum::{
    Json as AxumJson, Router,
    extract::{Path, Query, State},
    response::Json,
    routing::{get, put},
};
use chrono::{DateTime, Utc};
use sea_orm::{ColumnTrait, EntityTrait, PaginatorTrait, QueryFilter, QueryOrder, QuerySelect};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, OpenApi, ToSchema};

/// Admin user management API
#[derive(OpenApi)]
#[openapi(
    paths(
        list_users,
        get_user_by_id,
        search_users,
        update_user_state,
    ),
    components(schemas(
        UserResponse,
        UserListResponse,
        UserSearchQuery,
        UserListQuery,
        UpdateUserStateRequest,
        UserState,
        ApiErrorResponse
    )),
    tags(
        (name = "Admin User Management", description = "Admin user management endpoints")
    )
)]
pub struct AdminUsersApi;

/// User response model for API
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct UserResponse {
    /// User ID
    pub id: i32,
    /// Provider user ID (external ID from OAuth provider)
    pub provider_user_id: String,
    /// OAuth provider name
    pub provider: String,
    /// User email address
    pub email: String,
    /// Display name from OAuth provider
    pub display_name: Option<String>,
    /// Account creation timestamp
    pub created_at: DateTime<Utc>,
    /// Last update timestamp
    pub updated_at: DateTime<Utc>,
    /// Last login timestamp
    pub last_login: Option<DateTime<Utc>>,
    /// User account state
    pub state: UserState,
}

impl From<UserRecord> for UserResponse {
    fn from(user: UserRecord) -> Self {
        Self {
            id: user.id,
            provider_user_id: user.provider_user_id,
            provider: user.provider,
            email: user.email,
            display_name: user.display_name,
            created_at: user.created_at,
            updated_at: user.updated_at,
            last_login: user.last_login,
            state: user.state,
        }
    }
}

/// Response model for user list
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct UserListResponse {
    /// List of users
    pub users: Vec<UserResponse>,
    /// Total number of users matching the query
    pub total: usize,
    /// Number of users returned in this response
    pub count: usize,
    /// Offset used for pagination
    pub offset: u64,
    /// Limit used for pagination
    pub limit: u64,
}

/// Query parameters for user list
#[derive(Debug, Deserialize, ToSchema, IntoParams)]
pub struct UserListQuery {
    /// Maximum number of users to return (default: 50, max: 500)
    #[serde(default = "default_limit")]
    pub limit: u64,
    /// Number of users to skip for pagination (default: 0)
    #[serde(default)]
    pub offset: u64,
    /// Sort order: created_at, updated_at, last_login, email (default: created_at)
    #[serde(default = "default_sort")]
    pub sort: String,
    /// Sort direction: asc or desc (default: desc)
    #[serde(default = "default_order")]
    pub order: String,
}

/// Query parameters for user search
#[derive(Debug, Deserialize, ToSchema, IntoParams)]
pub struct UserSearchQuery {
    /// Search term to match against email, display_name, or provider_user_id
    pub q: String,
    /// Maximum number of users to return (default: 50, max: 500)
    #[serde(default = "default_limit")]
    pub limit: u64,
    /// Number of users to skip for pagination (default: 0)
    #[serde(default)]
    pub offset: u64,
}

fn default_limit() -> u64 {
    50
}

fn default_sort() -> String {
    "created_at".to_string()
}

fn default_order() -> String {
    "desc".to_string()
}

/// Request model for updating user state
#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateUserStateRequest {
    /// New user state
    pub state: UserState,
}

/// List all users with pagination and sorting
#[utoipa::path(
    get,
    path = "/api/admin/users",
    summary = "List users",
    description = "Get a paginated list of all users with optional sorting",
    params(UserListQuery),
    responses(
        (status = 200, description = "Users retrieved successfully", body = UserListResponse),
        (status = 400, description = "Invalid query parameters", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 403, description = "Forbidden - admin access required", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse)
    ),
    tag = "Admin User Management",
    security(
        ("jwt_auth" = [])
    )
)]
pub async fn list_users(
    State(server): State<Server>,
    Query(query): Query<UserListQuery>,
) -> Result<Json<UserListResponse>, AppError> {
    // Validate parameters
    if query.limit > 500 {
        return Err(AppError::BadRequest("Limit cannot exceed 500".to_string()));
    }

    if !["created_at", "updated_at", "last_login", "email"].contains(&query.sort.as_str()) {
        return Err(AppError::BadRequest(
            "Invalid sort field. Must be one of: created_at, updated_at, last_login, email"
                .to_string(),
        ));
    }

    if !["asc", "desc"].contains(&query.order.as_str()) {
        return Err(AppError::BadRequest(
            "Invalid order. Must be 'asc' or 'desc'".to_string(),
        ));
    }

    let db = server.database.connection();

    // Get total count
    let total_count = crate::database::entities::users::Entity::find()
        .count(db)
        .await
        .map_err(|e| AppError::Database(DatabaseError::Database(e.to_string())))?;

    // Build query with sorting and pagination
    let mut query_builder = crate::database::entities::users::Entity::find()
        .offset(query.offset)
        .limit(query.limit);

    // Apply sorting
    use crate::database::entities::users::Column;
    query_builder = match (query.sort.as_str(), query.order.as_str()) {
        ("created_at", "asc") => query_builder.order_by_asc(Column::CreatedAt),
        ("created_at", "desc") => query_builder.order_by_desc(Column::CreatedAt),
        ("updated_at", "asc") => query_builder.order_by_asc(Column::UpdatedAt),
        ("updated_at", "desc") => query_builder.order_by_desc(Column::UpdatedAt),
        ("last_login", "asc") => query_builder.order_by_asc(Column::LastLogin),
        ("last_login", "desc") => query_builder.order_by_desc(Column::LastLogin),
        ("email", "asc") => query_builder.order_by_asc(Column::Email),
        ("email", "desc") => query_builder.order_by_desc(Column::Email),
        _ => query_builder.order_by_desc(Column::CreatedAt), // fallback
    };

    let users = query_builder
        .all(db)
        .await
        .map_err(|e| AppError::Database(DatabaseError::Database(e.to_string())))?;

    let user_responses: Vec<UserResponse> = users.into_iter().map(UserResponse::from).collect();

    Ok(Json(UserListResponse {
        count: user_responses.len(),
        total: total_count as usize,
        users: user_responses,
        offset: query.offset,
        limit: query.limit,
    }))
}

/// Get user by ID
#[utoipa::path(
    get,
    path = "/api/admin/users/{user_id}",
    summary = "Get user by ID",
    description = "Get detailed information about a specific user",
    params(
        ("user_id" = i32, Path, description = "User ID")
    ),
    responses(
        (status = 200, description = "User retrieved successfully", body = UserResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 403, description = "Forbidden - admin access required", body = ApiErrorResponse),
        (status = 404, description = "User not found", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse)
    ),
    tag = "Admin User Management",
    security(
        ("jwt_auth" = [])
    )
)]
pub async fn get_user_by_id(
    State(server): State<Server>,
    Path(user_id): Path<i32>,
) -> Result<Json<UserResponse>, AppError> {
    let db = server.database.connection();

    let user = crate::database::entities::users::Entity::find_by_id(user_id)
        .one(db)
        .await
        .map_err(|e| AppError::Database(DatabaseError::Database(e.to_string())))?
        .ok_or(AppError::NotFound("User not found".to_string()))?;

    Ok(Json(UserResponse::from(user)))
}

/// Search users by email, display name, or provider user ID
#[utoipa::path(
    get,
    path = "/api/admin/users/search",
    summary = "Search users",
    description = "Search for users by email, display name, or provider user ID",
    params(UserSearchQuery),
    responses(
        (status = 200, description = "Search completed successfully", body = UserListResponse),
        (status = 400, description = "Invalid search parameters", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 403, description = "Forbidden - admin access required", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse)
    ),
    tag = "Admin User Management",
    security(
        ("jwt_auth" = [])
    )
)]
pub async fn search_users(
    State(server): State<Server>,
    Query(query): Query<UserSearchQuery>,
) -> Result<Json<UserListResponse>, AppError> {
    // Validate parameters
    if query.limit > 500 {
        return Err(AppError::BadRequest("Limit cannot exceed 500".to_string()));
    }

    if query.q.trim().is_empty() {
        return Err(AppError::BadRequest(
            "Search query cannot be empty".to_string(),
        ));
    }

    if query.q.len() < 2 {
        return Err(AppError::BadRequest(
            "Search query must be at least 2 characters".to_string(),
        ));
    }

    let db = server.database.connection();
    let search_term = format!("%{}%", query.q.trim());

    use crate::database::entities::users::Column;

    // Build search query - search in email, display_name, and provider_user_id
    let search_filter = Column::Email
        .like(&search_term)
        .or(Column::DisplayName.like(&search_term))
        .or(Column::ProviderUserId.like(&search_term));

    // Get total count for search results
    let total_count = crate::database::entities::users::Entity::find()
        .filter(search_filter.clone())
        .count(db)
        .await
        .map_err(|e| AppError::Database(DatabaseError::Database(e.to_string())))?;

    // Get paginated results
    let users = crate::database::entities::users::Entity::find()
        .filter(search_filter)
        .offset(query.offset)
        .limit(query.limit)
        .order_by_desc(Column::CreatedAt) // Most recent first
        .all(db)
        .await
        .map_err(|e| AppError::Database(DatabaseError::Database(e.to_string())))?;

    let user_responses: Vec<UserResponse> = users.into_iter().map(UserResponse::from).collect();

    Ok(Json(UserListResponse {
        count: user_responses.len(),
        total: total_count as usize,
        users: user_responses,
        offset: query.offset,
        limit: query.limit,
    }))
}

/// Update user state
#[utoipa::path(
    put,
    path = "/api/admin/users/{user_id}/state",
    summary = "Update user state",
    description = "Update the state of a user (active, disabled, or expired)",
    params(
        ("user_id" = i32, Path, description = "User ID")
    ),
    request_body = UpdateUserStateRequest,
    responses(
        (status = 200, description = "User state updated successfully", body = UserResponse),
        (status = 400, description = "Invalid request data", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 403, description = "Forbidden - admin access required", body = ApiErrorResponse),
        (status = 404, description = "User not found", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse)
    ),
    tag = "Admin User Management",
    security(
        ("jwt_auth" = [])
    )
)]
pub async fn update_user_state(
    State(server): State<Server>,
    Path(user_id): Path<i32>,
    AxumJson(request): AxumJson<UpdateUserStateRequest>,
) -> Result<Json<UserResponse>, AppError> {
    // Check if user exists first
    let db = server.database.connection();
    let _existing_user = crate::database::entities::users::Entity::find_by_id(user_id)
        .one(db)
        .await
        .map_err(|e| AppError::Database(DatabaseError::Database(e.to_string())))?
        .ok_or(AppError::NotFound("User not found".to_string()))?;

    // Update the user state using the DAO
    let updated_user = server
        .database
        .users()
        .update_state(user_id, request.state)
        .await
        .map_err(AppError::Database)?;

    Ok(Json(UserResponse::from(updated_user)))
}

/// Create admin user routes
pub fn create_admin_user_routes() -> Router<Server> {
    Router::new()
        .route("/admin/users", get(list_users))
        .route("/admin/users/search", get(search_users))
        .route("/admin/users/{user_id}", get(get_user_by_id))
        .route("/admin/users/{user_id}/state", put(update_user_state))
}
