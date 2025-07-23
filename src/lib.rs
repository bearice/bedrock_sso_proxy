pub mod auth;
pub mod aws_http;
pub mod config;
pub mod error;
pub mod health;
// pub mod metrics;     // TODO: Fix lifetime issues in Phase 9
// pub mod rate_limit;  // TODO: Fix rate limiter implementation in Phase 9
pub mod routes;
pub mod server;
pub mod shutdown;
pub mod storage;

pub use config::Config;
pub use server::Server;
