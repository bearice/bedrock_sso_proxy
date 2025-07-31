//! OAuth authentication module
//! 
//! This module provides OAuth 2.0 authentication functionality with support for
//! multiple providers including Google, GitHub, Microsoft, GitLab, Auth0, and Okta.

pub mod flows;
pub mod health;
pub mod providers;
pub mod service;
pub mod state;

// Re-export the main service and commonly used types
pub use service::{OAuthService, OAuthHealthCheckerWrapper};
pub use flows::{
    AuthorizeResponse, OAuthFlows, ProviderInfo, ProvidersResponse, RefreshRequest, 
    TokenRequest, TokenResponse,
};
pub use health::OAuthHealthChecker;
pub use providers::{get_display_name, initialize_oauth_clients, Oauth2Client};
pub use state::{StateData, OAUTH_STATE_TTL_SECONDS};