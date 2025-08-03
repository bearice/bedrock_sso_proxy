use async_graphql::http::GraphiQLSource;
use async_graphql_axum::{GraphQLRequest, GraphQLResponse};
use axum::{
    extract::State,
    response::{Html, IntoResponse},
    routing::{get, post},
    Extension, Router,
};

use crate::{
    auth::jwt::OAuthClaims,
    error::AppError,
    graphql::context::UserContext,
    Server,
};

/// GraphQL query handler with authentication
pub async fn graphql_handler(
    Extension(claims): Extension<OAuthClaims>,
    State(server): State<Server>,
    req: GraphQLRequest,
) -> Result<GraphQLResponse, AppError> {
    let db = server.database.connection();
    
    // Create user context directly from JWT claims
    let user_context = UserContext::new(claims.sub, claims.admin);

    // Get the GraphQL schema
    let schema = server.graphql_schema.clone().ok_or_else(|| {
        AppError::Internal("GraphQL schema not initialized".to_string())
    })?;

    // Execute GraphQL request with context
    let response = schema
        .execute(req.into_inner().data(db.clone()).data(user_context))
        .await;

    Ok(response.into())
}

/// GraphQL playground handler
pub async fn graphql_playground() -> impl IntoResponse {
    Html(GraphiQLSource::build().endpoint("/graphql").finish())
}

/// Create protected GraphQL routes (requires authentication)
pub fn create_graphql_routes() -> Router<Server> {
    Router::new()
        .route("/graphql", post(graphql_handler))
}

/// Create public GraphQL playground route (no authentication required)
pub fn create_graphql_playground_routes() -> Router<Server> {
    Router::new()
        .route("/graphql/playground", get(graphql_playground))
}

