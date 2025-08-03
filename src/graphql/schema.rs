use async_graphql::{EmptyMutation, EmptySubscription, Schema};

use crate::graphql::query::QueryRoot;

pub type AppSchema = Schema<QueryRoot, EmptyMutation, EmptySubscription>;

/// Create the GraphQL schema
pub fn create_schema() -> AppSchema {
    Schema::build(QueryRoot, EmptyMutation, EmptySubscription).finish()
}