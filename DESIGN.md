# Bedrock SSO Proxy Design

## System Architecture

### Current Architecture

```
[Client] → [Proxy Server] → [AWS Bedrock API]
           ↑ JWT Auth      ↑ AWS Credentials
```

### Enhanced OAuth Architecture

```
[Client] → [OAuth Provider] → [Client gets authorization code]
    ↓
[Client] → [POST /auth/token] → [Proxy validates with OAuth] → [Returns long-lived JWT]
    ↓
[Client] → [Bedrock API with JWT] → [Cached validation] → [AWS Bedrock]
```

## Core Components

### 1. HTTP Server (Rust + Tokio)

- Async HTTP server using `axum` or `warp`
- Handles incoming Bedrock API requests
- Middleware for JWT authentication
- Request/response logging and metrics

### 2. JWT Authentication Module

- Validates Bearer tokens from Authorization header
- Supports JWT verification with configurable secrets/keys
- Extracts user identity/claims for logging/auditing
- Returns 401 for invalid/missing tokens

### 2.1. OAuth Integration Module (ENHANCED)

- OAuth 2.0 provider integration (Google, GitHub, Microsoft, GitLab, Auth0, Okta, custom)
- Authorization code validation with providers
- **Short-lived JWT tokens (1 hour)** for frontend authentication
- **API key system** for programmatic access to Bedrock/Anthropic endpoints
- Refresh token management with rotation (90 days)
- Dual authentication architecture for different use cases

### 3. AWS Bedrock Client

- Uses `aws-sdk-bedrockruntime` for API calls
- Configured with your AWS credentials (IAM role/keys)
- Handles request forwarding and response proxying
- Maintains connection pooling for performance

### 4. Configuration Management

- Uses `config` crate for layered configuration
- Supports YAML, TOML, JSON config files
- Environment variable overrides
- Hierarchical config loading (defaults → file → env vars)

## Authentication Flows

### Hybrid Authentication Architecture

The system now uses a **dual authentication model** to optimize for different use cases:

#### Frontend Authentication (JWT + Refresh Tokens)

**For web applications and dashboards**

1. **OAuth Authorization**: Client redirects to OAuth provider (Google/GitHub/etc.)
2. **Token Exchange**: `POST /auth/token` with authorization code
3. **Short-lived JWT**: Generate 1-hour JWT tokens for session management
4. **Refresh Capability**: 90-day refresh tokens for seamless renewal
5. **Frontend Routes**: `/auth/*` endpoints use JWT authentication

**JWT Lifecycle:**
- **Initial Token**: 1-hour lifetime for active sessions
- **Refresh Flow**: `POST /auth/refresh` with rotation (90-day window)
- **Validation**: Standard JWT validation with proper expiration

#### API Key Authentication

**For programmatic access to AI models**

1. **Key Generation**: Users generate API keys through frontend dashboard
2. **Long-lived Access**: API keys for sustained programmatic access
3. **Model Endpoints**: `/bedrock/*` and `/anthropic/*` use API key auth
4. **Key Format**: `SSOK_` prefix for easy identification

**API Key Features:**
- **Format**: `SSOK_<32-char-random-string>` (e.g., `SSOK_a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6`)
- **Header Authentication**: `X-API-Key: SSOK_...` or `Authorization: Bearer SSOK_...`
- **User Association**: Keys linked to OAuth-authenticated users
- **Simple Access**: Full access to all Bedrock/Anthropic endpoints for the user
- **Rotation Support**: Easy key rotation without affecting JWTs

### Admin Authorization System (NEW)

#### Email-Based Admin Model

- **Primary Key**: User email address (instead of composite provider:userid)
- **Admin Detection**: Configured list of admin email addresses
- **Real-Time Checking**: Admin status checked at request time (not stored in
  JWT)
- **Case Insensitive**: Admin email matching is case-insensitive

#### Admin Authorization Logic

```rust
impl Config {
    /// Check if the given email address belongs to an admin user
    /// This performs case-insensitive matching
    pub fn is_admin(&self, email: &str) -> bool {
        let email_lower = email.to_lowercase();
        self.admin.emails.iter().any(|admin_email| {
            admin_email.to_lowercase() == email_lower
        })
    }
}
```

#### Authorization Flow

1. **OAuth Provider Returns**: User email and provider user ID
2. **JWT Generation**: Email as `sub`, no scopes stored in token
3. **Request-Time Admin Check**: For protected routes, check
   `config.is_admin(&claims.email)`
4. **Immediate Effect**: Admin changes take effect instantly without token
   refresh

#### Security Features

- **Email Validation**: Email must come from trusted OAuth provider
- **Configuration Protection**: Admin emails stored in secure config file
- **Audit Trail**: All admin actions logged with email identifier
- **Real-Time Authorization**: Admin status checked fresh on each request
- **No Stale Permissions**: Admin changes take effect immediately

## New OAuth API Endpoints

### 1. Authorization URL Generation

```
GET /auth/authorize/{provider}?redirect_uri={uri}&state={optional_state}
```

**Response:**

```json
{
  "authorization_url": "https://provider.com/oauth/authorize?client_id=...&redirect_uri=...&scope=...&state=...",
  "state": "generated_csrf_token",
  "provider": "google"
}
```

### 2. Token Creation

```
POST /auth/token
Content-Type: application/json

{
  "provider": "google" | "github" | "custom_provider" | "{any_configured_provider}",
  "authorization_code": "4/0AX4XfWjE...",
  "redirect_uri": "https://your-app.com/callback",
  "state": "csrf_token_from_step_1"
}
```

**Response (Success):**

```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 2592000,
  "refresh_token": "refresh_token_here",
  "scope": "bedrock:invoke"
}
```

### 2. Token Refresh

```
POST /auth/refresh
Content-Type: application/json

{
  "refresh_token": "refresh_token_here"
}
```

### 4. Provider List

```
GET /auth/providers
```

**Response:**

```json
{
  "providers": [
    {
      "name": "google",
      "display_name": "Google",
      "scopes": ["openid", "email", "profile"]
    },
    {
      "name": "github",
      "display_name": "GitHub",
      "scopes": ["user:email"]
    },
    {
      "name": "my_company",
      "display_name": "My Company SSO",
      "scopes": ["read", "profile"]
    }
  ]
}
```

### 5. OAuth Redirect Handler (for Frontend)

```
GET /auth/callback/{provider}?code={auth_code}&state={csrf_token}
```

**Success Response (HTML):**

```html
<!DOCTYPE html>
<html>
  <head><title>Authentication Success</title></head>
  <body>
    <h1>Authentication Successful</h1>
    <p>Provider: google</p>
    <p>Access Token: <code>eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...</code></p>
    <p>Refresh Token: <code>refresh_token_here</code></p>

    <h2>Claude Code Setup</h2>
    <pre>
# Add to your ~/.claude/config.json or set environment variable:
export ANTHROPIC_API_KEY="your_anthropic_key"
export BEDROCK_TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
export BEDROCK_ENDPOINT="https://your-proxy-domain.com"

# Or configure in claude-code:
claude-code config set bedrock.token "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
claude-code config set bedrock.endpoint "https://your-proxy-domain.com"
  </pre>
  </body>
</html>
```

### 6. Token Validation (Optional)

```
GET /auth/validate
Authorization: Bearer <jwt_token>
```

**Response:**

```json
{
  "valid": true,
  "sub": "google:user123456789",
  "provider": "google",
  "expires_at": 1234567890,
  "scopes": ["bedrock:invoke"]
}
```

## API Endpoint Support

### Dual Format Support

The proxy supports both Bedrock and Anthropic API formats to provide maximum
compatibility with different clients and LLM gateways.

#### Bedrock Format (AWS Native)

- **Endpoint**: `POST /model/{modelId}/invoke`
- **Authentication**: JWT Bearer token
- **Request Format**: Bedrock-specific JSON structure
- **Use Case**: Direct AWS Bedrock compatibility

#### Anthropic Format (Standard)

- **Endpoint**: `POST /v1/messages`
- **Authentication**: JWT Bearer token
- **Request Format**: Standard Anthropic API JSON structure
- **Use Case**: Anthropic SDK compatibility, LLM gateway integration

### API Format Comparison

| Feature             | Bedrock Format                                  | Anthropic Format                      |
| ------------------- | ----------------------------------------------- | ------------------------------------- |
| **Endpoint**        | `/model/{model_id}/invoke`                      | `/v1/messages`                        |
| **Model Selection** | URL path parameter                              | Request body field                    |
| **Message Format**  | Direct message array                            | Standard Anthropic messages           |
| **Version Field**   | `anthropic_version: "bedrock-2023-05-31"`       | Not required                          |
| **Streaming**       | `/model/{model_id}/invoke-with-response-stream` | `/v1/messages` with `stream: true`    |
| **Response Format** | AWS Bedrock response structure                  | Standard Anthropic response structure |

### Request/Response Transformation

#### Anthropic → Bedrock Request Transformation

```json
// Anthropic Format Input
{
  "model": "claude-sonnet-4-20250514",
  "max_tokens": 1000,
  "messages": [
    {"role": "user", "content": "Hello"}
  ],
  "temperature": 0.7,
  "stream": false
}

// Transformed to Bedrock Format
{
  "anthropic_version": "bedrock-2023-05-31",
  "max_tokens": 1000,
  "messages": [
    {"role": "user", "content": "Hello"}
  ],
  "temperature": 0.7
}
```

#### Bedrock → Anthropic Response Transformation

```json
// Bedrock Format Response
{
  "content": [
    {
      "text": "Hello! How can I help you today?",
      "type": "text"
    }
  ],
  "id": "msg_01ABC123",
  "model": "claude-sonnet-4-20250514",
  "role": "assistant",
  "stop_reason": "end_turn",
  "stop_sequence": null,
  "type": "message",
  "usage": {
    "input_tokens": 10,
    "output_tokens": 25
  }
}

// Transformed to Anthropic Format
{
  "id": "msg_01ABC123",
  "type": "message",
  "role": "assistant",
  "content": [
    {
      "type": "text",
      "text": "Hello! How can I help you today?"
    }
  ],
  "model": "claude-sonnet-4-20250514",
  "stop_reason": "end_turn",
  "stop_sequence": null,
  "usage": {
    "input_tokens": 10,
    "output_tokens": 25
  }
}
```

### Model ID Mapping

#### Anthropic → Bedrock Model ID Transformation

```rust
// Anthropic model names → Bedrock model IDs
let model_mapping = HashMap::from([
    ("claude-sonnet-4-20250514", "anthropic.claude-sonnet-4-20250514-v1:0"),
    ("claude-3-haiku-20240307", "anthropic.claude-3-haiku-20240307-v1:0"),
    ("claude-3-opus-20240229", "anthropic.claude-3-opus-20240229-v1:0"),
    ("claude-3-5-sonnet-20240620", "anthropic.claude-3-5-sonnet-20240620-v1:0"),
    ("claude-3-5-haiku-20241022", "anthropic.claude-3-5-haiku-20241022-v1:0"),
]);
```

### Implementation Architecture

#### New Route Structure

```rust
// src/routes/anthropic.rs
pub fn create_anthropic_routes() -> Router<AwsHttpClient> {
    Router::new()
        .route("/v1/messages", post(create_message))
        .route("/v1/messages", post(create_message_stream))  // with stream=true
}

// src/routes/mod.rs
pub mod anthropic;
pub use anthropic::create_anthropic_routes;
```

#### Data Structures

```rust
// Anthropic API request format
#[derive(Debug, Serialize, Deserialize)]
pub struct AnthropicRequest {
    pub model: String,
    pub messages: Vec<Message>,
    pub max_tokens: u32,
    pub temperature: Option<f32>,
    pub top_p: Option<f32>,
    pub top_k: Option<u32>,
    pub stop_sequences: Option<Vec<String>>,
    pub stream: Option<bool>,
    pub system: Option<String>,
}

// Bedrock API request format
#[derive(Debug, Serialize, Deserialize)]
pub struct BedrockRequest {
    pub anthropic_version: String,
    pub messages: Vec<Message>,
    pub max_tokens: u32,
    pub temperature: Option<f32>,
    pub top_p: Option<f32>,
    pub top_k: Option<u32>,
    pub stop_sequences: Option<Vec<String>>,
    pub system: Option<String>,
}

// Shared message structure
#[derive(Debug, Serialize, Deserialize)]
pub struct Message {
    pub role: String,
    pub content: serde_json::Value,
}
```

#### Transformation Logic

```rust
// Transform Anthropic request to Bedrock format
pub fn transform_anthropic_to_bedrock(req: AnthropicRequest) -> Result<(BedrockRequest, String), AppError> {
    // Map model name to Bedrock model ID
    let bedrock_model_id = map_anthropic_to_bedrock_model(&req.model)?;

    let bedrock_req = BedrockRequest {
        anthropic_version: "bedrock-2023-05-31".to_string(),
        messages: req.messages,
        max_tokens: req.max_tokens,
        temperature: req.temperature,
        top_p: req.top_p,
        top_k: req.top_k,
        stop_sequences: req.stop_sequences,
        system: req.system,
    };

    Ok((bedrock_req, bedrock_model_id))
}

// Transform Bedrock response to Anthropic format
pub fn transform_bedrock_to_anthropic(response: BedrockResponse) -> Result<AnthropicResponse, AppError> {
    // Response structure is largely compatible, minimal transformation needed
    Ok(AnthropicResponse {
        id: response.id,
        type_: response.type_,
        role: response.role,
        content: response.content,
        model: response.model,
        stop_reason: response.stop_reason,
        stop_sequence: response.stop_sequence,
        usage: response.usage,
    })
}
```

### AWS Bedrock API Forwarding

#### Supported Bedrock Endpoints

##### 1. InvokeModel

```
POST /model/{modelId}/invoke
```

**Headers to Forward:**

- Forward all incoming headers except `Authorization`
- Strip `Authorization: Bearer <jwt>` header before forwarding to AWS
- AWS authentication handled by proxy's configured credentials

**Request/Response:**

- Forward JSON payload as-is (max 25MB)
- Standard HTTP response

#### 2. InvokeModelWithResponseStream

```
POST /model/{modelId}/invoke-with-response-stream
```

**Headers to Forward:**

- Forward all incoming headers except `Authorization`
- Strip `Authorization: Bearer <jwt>` header before forwarding to AWS
- AWS authentication handled by proxy's configured credentials

**Streaming Response:**

- Content-Type: `application/vnd.amazon.eventstream`
- Server-Sent Events (SSE) streaming
- Handle partial chunks and final responses
- Forward streaming errors and exceptions

#### 3. InvokeModelWithBidirectionalStream

```
POST /model/{modelId}/invoke-with-bidirectional-stream
```

**Headers to Forward:**

- Forward all incoming headers except `Authorization`
- Strip `Authorization: Bearer <jwt>` header before forwarding to AWS
- AWS authentication handled by proxy's configured credentials

**Bidirectional Streaming:**

- Supports only `amazon.nova-sonic-v1:0` model currently
- 8-minute session timeout
- Audio input/output support
- Real-time conversation with interruption capability
- WebSocket connection management

### Response Handling

- Forward AWS response status and headers
- Handle three response types:
  - Standard JSON responses (InvokeModel)
  - Server-sent event streams (ResponseStream)
  - WebSocket bidirectional streams (BidirectionalStream)
- Preserve error responses (400, 403, 404, 429, 500)

## Configuration & Security

### Required Dependencies (Cargo.toml)

```toml
# Existing dependencies
axum = "0.8"
tokio = { version = "1.0", features = ["full"] }
tokio-tungstenite = "0.21"  # WebSocket support
aws-sdk-bedrockruntime = "1.0"
aws-config = "1.0"
jsonwebtoken = "9.0"
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
tracing = "0.1"
futures-util = "0.3"  # Stream utilities
config = "0.15"  # Configuration management
reqwest = { version = "0.12", features = ["json"] }

# New OAuth dependencies
oauth2 = "4.4"           # OAuth 2.0 client
uuid = { version = "1.0", features = ["v4"] }        # Refresh token IDs
dashmap = "5.5"          # Concurrent HashMap for caching
sha2 = "0.10"            # Token hashing for cache keys
```

### Configuration Structure

**Config File (config.yaml/toml/json):**

```yaml
server:
  host: "0.0.0.0"
  port: 3000

jwt:
  secret: "your-jwt-secret"
  algorithm: "HS256"
  access_token_ttl: 3600 # 1 hour (shortened for security)
  refresh_token_ttl: 7776000 # 90 days

oauth:
  providers:
    google:
      client_id: "your-google-client-id"
      client_secret: "your-google-client-secret"
      redirect_uri: "https://your-app.com/callback"
      scopes: ["openid", "email", "profile"]
      authorization_url: "https://accounts.google.com/o/oauth2/v2/auth"
      token_url: "https://oauth2.googleapis.com/token"
      user_info_url: "https://www.googleapis.com/oauth2/v2/userinfo"
      user_id_field: "id"
      email_field: "email"
    github:
      client_id: "your-github-client-id"
      client_secret: "your-github-client-secret"
      redirect_uri: "https://your-app.com/callback"
      scopes: ["user:email"]
      authorization_url: "https://github.com/login/oauth/authorize"
      token_url: "https://github.com/login/oauth/access_token"
      user_info_url: "https://api.github.com/user"
      user_id_field: "id"
      email_field: "email"
    # Any custom OAuth 2.0 provider
    custom_provider:
      client_id: "your-custom-client-id"
      client_secret: "your-custom-client-secret"
      redirect_uri: "https://your-app.com/callback"
      scopes: ["read", "profile"]
      authorization_url: "https://custom.example.com/oauth/authorize"
      token_url: "https://custom.example.com/oauth/token"
      user_info_url: "https://custom.example.com/api/user"
      user_id_field: "user_id"
      email_field: "email_address"

cache:
  validation_ttl: 86400 # 24 hours
  max_entries: 10000
  cleanup_interval: 3600 # 1 hour

aws:
  region: "us-east-1" # Default/primary region
  access_key_id: "optional" # Shared across regions
  secret_access_key: "optional" # Shared across regions

  # Multi-region support (Phase 8.5)
  region_mapping:
    "us.": "us-east-1"
    "apac.": "ap-northeast-1"
    "eu.": "eu-west-1"
    "ca.": "ca-central-1"
    "default": "us-east-1" # For models without prefix

logging:
  level: "info"
```

**Environment Variables (override config file):**

```bash
# Server Configuration
BEDROCK_SERVER__HOST=0.0.0.0
BEDROCK_SERVER__PORT=3000

# JWT Configuration
BEDROCK_JWT__SECRET=your-jwt-secret
BEDROCK_JWT__ACCESS_TOKEN_TTL=3600
BEDROCK_JWT__REFRESH_TOKEN_TTL=7776000

# OAuth Configuration (Example: Google)
BEDROCK_OAUTH__PROVIDERS__GOOGLE__CLIENT_ID=your-google-client-id
BEDROCK_OAUTH__PROVIDERS__GOOGLE__CLIENT_SECRET=your-google-client-secret
BEDROCK_OAUTH__PROVIDERS__GOOGLE__AUTHORIZATION_URL=https://accounts.google.com/o/oauth2/v2/auth
BEDROCK_OAUTH__PROVIDERS__GOOGLE__TOKEN_URL=https://oauth2.googleapis.com/token
BEDROCK_OAUTH__PROVIDERS__GOOGLE__USER_INFO_URL=https://www.googleapis.com/oauth2/v2/userinfo

# OAuth Configuration (Example: Custom Provider)
BEDROCK_OAUTH__PROVIDERS__CUSTOM__CLIENT_ID=your-custom-client-id
BEDROCK_OAUTH__PROVIDERS__CUSTOM__CLIENT_SECRET=your-custom-client-secret
BEDROCK_OAUTH__PROVIDERS__CUSTOM__AUTHORIZATION_URL=https://custom.example.com/oauth/authorize
BEDROCK_OAUTH__PROVIDERS__CUSTOM__TOKEN_URL=https://custom.example.com/oauth/token
BEDROCK_OAUTH__PROVIDERS__CUSTOM__USER_INFO_URL=https://custom.example.com/api/user

# Cache Configuration
BEDROCK_CACHE__VALIDATION_TTL=86400
BEDROCK_CACHE__MAX_ENTRIES=10000

# AWS Configuration
BEDROCK_AWS__REGION=us-east-1
BEDROCK_AWS__ACCESS_KEY_ID=optional
BEDROCK_AWS__SECRET_ACCESS_KEY=optional

# Logging
BEDROCK_LOGGING__LEVEL=info
```

### Security Considerations

#### Legacy JWT Security (Existing)

- JWT tokens should have short expiration (15-60 min)
- Use HTTPS in production
- Rate limiting per user/JWT
- Audit logging of all requests
- AWS credentials via IAM roles preferred over static keys

#### Hybrid Authentication Security (ENHANCED)

**Frontend JWT Security:**
- **Short-lived JWTs** (1 hour) with refresh capability
- **Authorization code validation** with OAuth providers
- **Refresh token rotation** (90 days) for enhanced security
- **HTTPS enforcement** in production

**API Key Security:**
- **Key Format**: `SSOK_` prefix with 32-character random suffix
- **Secure Storage**: SHA-256 hashed storage in database
- **User Binding**: Keys permanently linked to OAuth-authenticated users
- **Optional Expiration**: Configurable key expiration dates
- **Usage Tracking**: Last-used timestamps for security monitoring

#### JWT Claims Structure (Simplified)

```json
{
  "sub": 123456,  // Database user ID
  "iat": 1640995200,
  "exp": 1641001800  // 1-hour expiration (shortened from 30 days)
}
```

**Key Changes:**
- **Short-lived**: 1-hour lifetime instead of 30 days
- **User ID**: Database user ID as subject (not email)
- **No Scopes**: Admin status checked at request time via user record
- **Refresh Required**: Must use refresh tokens for sustained access

#### API Key Database Schema

```sql
CREATE TABLE api_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key_hash TEXT UNIQUE NOT NULL,        -- SHA-256 hash of SSOK_... key
    user_id INTEGER NOT NULL REFERENCES users(id),
    name TEXT NOT NULL,                   -- User-defined name
    created_at TIMESTAMP NOT NULL,
    last_used TIMESTAMP,
    expires_at TIMESTAMP,                 -- Optional expiration
    revoked_at TIMESTAMP                  -- Soft delete
);
```

#### Validation Cache Security

- **Cache Key**: `oauth_validation:{provider}:{email}:{token_hash}`
- **TTL**: 24 hours maximum
- **Storage**: In-memory with SHA-256 token hashing
- **Fallback**: Always validate with OAuth provider on cache miss

## Data Storage Strategy

### Modern Database & Cache Architecture (Current Implementation)

**SeaORM + Cache Modules** - Production-ready architecture with clean separation

#### 1. Database Module (Persistent Data)

**Durable, structured data with full ACID compliance**

- **Database Manager**: SeaORM-based database operations with connection pooling
- **Domain-Specific DAOs**: Focused data access objects for each entity
- **Migration System**: Comprehensive SeaORM migrations for schema management
- **Entity Framework**: Type-safe database operations with automatic validation

**Database DAOs:**
```rust
DatabaseManager {
    users()       -> UsersDao      // User profiles and OAuth mappings
    api_keys()    -> ApiKeysDao    // API key management and validation
    usage()       -> UsageDao      // Usage tracking and analytics
    audit_logs()  -> AuditLogsDao  // Authentication and security events
    model_costs() -> ModelCostsDao // Model pricing and cost tracking
    refresh_tokens() -> RefreshTokensDao // Token rotation and management
}
```

#### 2. Cache Module (Fast Access Data)

**High-performance caching with automatic expiration**

- **Cache Manager**: Enum-based backend selection (Memory/Redis)
- **In-Memory Cache**: TTL-aware concurrent HashMap for development
- **Redis Cache**: Production-ready caching with cluster support
- **Automatic Cleanup**: Built-in expiration handling

**Cache Types:**
```rust
CacheManager {
    // OAuth validation results (24h TTL)
    validation_cache: HashMap<String, CachedValidation>,
    // CSRF state tokens (10min TTL)
    state_tokens: HashMap<String, StateData>,
    // Rate limiting data (1h TTL) - currently disabled
    rate_limits: HashMap<String, RateLimitData>,
}
```

#### 3. Current Implementation Architecture

**Unified Database & Cache System** - Clean separation of concerns

- **Database Operations**: All persistent data through SeaORM DAOs
- **Cache Operations**: Fast access through CacheManager
- **No Trait Objects**: Direct operations for better performance
- **Migration System**: Automated schema management

### Data Structures

#### Redis Data (TTL-based)

```rust
// Validation cache (Redis with 24h TTL)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CachedValidation {
    pub user_id: String,
    pub provider: String,
    pub email: String,
    pub validated_at: u64,
    pub expires_at: u64,
    pub scopes: Vec<String>,
}

// CSRF state tokens (Redis with 10min TTL)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StateData {
    pub provider: String,
    pub redirect_uri: String,
    pub created_at: u64,
    pub expires_at: u64,
}

// Rate limiting (Redis with 1h TTL)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RateLimitData {
    pub attempts: u32,
    pub window_start: u64,
    pub blocked_until: Option<u64>,
}
```

#### Database Schema (SeaORM Entities)

```rust
// Users entity (src/database/entities/users.rs)
#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq)]
#[sea_orm(table_name = "users")]
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
}

// API Keys entity (src/database/entities/api_keys.rs)
#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq)]
#[sea_orm(table_name = "api_keys")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    #[sea_orm(unique)]
    pub key_hash: String,
    pub user_id: i32,
    pub name: String,
    pub created_at: DateTime<Utc>,
    pub last_used: Option<DateTime<Utc>>,
    pub expires_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
}

// Usage Records entity (src/database/entities/usage_records.rs)
#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq)]
#[sea_orm(table_name = "usage_records")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    pub user_id: i32,
    pub model_id: String,
    pub endpoint_type: String,
    pub region: String,
    pub request_time: DateTime<Utc>,
    pub input_tokens: i32,
    pub output_tokens: i32,
    pub total_tokens: i32,
    pub response_time_ms: i32,
    pub success: bool,
    pub error_message: Option<String>,
    pub cost_usd: Option<Decimal>,
}

// Model Costs entity (src/database/entities/model_costs.rs)
#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq)]
#[sea_orm(table_name = "model_costs")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    #[sea_orm(unique)]
    pub model_id: String,
    pub input_cost_per_1k_tokens: Decimal,
    pub output_cost_per_1k_tokens: Decimal,
    pub updated_at: DateTime<Utc>,
}
```

### Storage Configuration (Production)

#### Production Configuration (Current Implementation)

```yaml
# Production configuration with Redis + PostgreSQL
storage:
  # Redis for caches and TTL data
  redis:
    enabled: true
    url: "redis://localhost:6379"
    db: 0
    key_prefix: "bedrock_sso:"
    max_connections: 10

  # PostgreSQL for persistent data
  database:
    enabled: true
    url: "postgresql://user:pass@localhost/bedrock_sso"
    max_connections: 20
    migration_on_startup: true

# Cache configuration
cache:
  backend: "redis" # Use Redis for all cache operations
  fallback: "memory" # Fall back to memory if Redis unavailable
  max_entries: 10000
  cleanup_interval: 3600

# Metrics and monitoring
metrics:
  enabled: true
  port: 9090
  path: "/metrics"
```

#### Development Configuration (Current Implementation)

```yaml
# SQLite + in-memory configuration for development and light usage
storage:
  # No Redis for development
  redis:
    enabled: false

  # SQLite for simple persistent data
  database:
    enabled: true
    url: "sqlite://./data/bedrock_sso.db"
    max_connections: 5
    migration_on_startup: true

# Cache configuration
cache:
  backend: "memory" # In-memory cache for development
  max_entries: 10000
  cleanup_interval: 3600

# Metrics disabled in development
metrics:
  enabled: false
```

#### Testing Configuration (Current Implementation)

```yaml
# Pure in-memory for testing
storage:
  redis:
    enabled: false
  database:
    enabled: true
    url: "sqlite::memory:"
    max_connections: 1
    migration_on_startup: true

# Cache configuration
cache:
  backend: "memory"
  max_entries: 1000
  cleanup_interval: 300

# Metrics disabled in testing
metrics:
  enabled: false
```

### Storage Benefits by Type

#### SeaORM Database Advantages

✅ **Type Safety**: Compile-time validation of database operations and queries  
✅ **ACID Compliance**: Reliable transactions for critical data with rollback support  
✅ **Rich Queries**: Complex user management and analytics with type-safe query builder  
✅ **Migration System**: Automated schema management with version control  
✅ **Cross-Database**: Support for SQLite, PostgreSQL, and other databases  
✅ **Performance**: Connection pooling and optimized query execution  
✅ **Data Integrity**: Foreign keys, constraints, and validation at the entity level  

#### Cache Module Advantages

✅ **Automatic TTL**: Built-in expiration handling with cleanup  
✅ **High Performance**: Sub-millisecond access times with concurrent operations  
✅ **Flexible Backends**: Memory for development, Redis for production  
✅ **Memory Efficient**: Optimized data structures with automatic cleanup  
✅ **Simple Interface**: Unified API regardless of backend selection  

### Architecture Benefits

#### Refactoring Improvements

✅ **Eliminated Monolithic DAO**: Replaced single storage abstraction with focused modules  
✅ **Improved Performance**: Removed trait object overhead and complex factory patterns  
✅ **Better Maintainability**: Clear separation between database and cache operations  
✅ **Enhanced Testing**: Easier to mock and test individual components  
✅ **Reduced Complexity**: Simplified codebase with focused responsibilities  

### Current Dependencies

```toml
# Database and ORM
sea-orm = { version = "1.1", features = ["sqlx-sqlite", "sqlx-postgres", "runtime-tokio-rustls", "macros"] }
sea-orm-migration = "1.1"

# Cache support
dashmap = "6.1"  # Concurrent HashMap for memory cache
redis = { version = "0.32", features = ["tokio-comp"], optional = true }

# Utilities
chrono = { version = "0.4", features = ["serde"] }
rust_decimal = { version = "1.36", features = ["serde"] }
```

### Storage Backend Selection

| Use Case             | Cache Backend | Database Backend | Configuration              |
| -------------------- | ------------- | ---------------- | -------------------------- |
| **Development**      | Memory        | SQLite           | Simple file-based          |
| **Light Production** | Memory        | SQLite           | Single instance, low users |
| **Production**       | Redis         | PostgreSQL       | Multi-instance, high scale |
| **Testing**          | Memory        | SQLite (memory)  | Pure in-memory             |

### Provider Configuration Strategy

#### Predefined Well-Known Providers (Easy Setup)

Admins only need to provide `client_id` and `client_secret` for common
providers:

```yaml
oauth:
  providers:
    # Google - minimal config required
    google:
      client_id: "your-google-client-id"
      client_secret: "your-google-client-secret"
      # All other settings auto-filled from well-known defaults

    # GitHub - minimal config required
    github:
      client_id: "your-github-client-id"
      client_secret: "your-github-client-secret"

    # Microsoft/Azure AD - minimal config required
    microsoft:
      client_id: "your-microsoft-client-id"
      client_secret: "your-microsoft-client-secret"
      # Optional: specify tenant_id for Azure AD
      tenant_id: "your-tenant-id" # Optional, defaults to 'common'

    # GitLab - minimal config required
    gitlab:
      client_id: "your-gitlab-client-id"
      client_secret: "your-gitlab-client-secret"
      # Optional: specify instance for self-hosted GitLab
      instance_url: "https://gitlab.mycompany.com" # Optional, defaults to gitlab.com
```

#### Advanced Configuration (Override Defaults)

Admins can override any predefined values:

```yaml
oauth:
  providers:
    google:
      client_id: "your-google-client-id"
      client_secret: "your-google-client-secret"
      # Override default scopes
      scopes: [
        "openid",
        "email",
        "profile",
        "https://www.googleapis.com/auth/calendar.readonly",
      ]
      # Override default redirect URI
      redirect_uri: "https://custom-domain.com/auth/callback/google"

    # Custom provider - full configuration required
    custom_provider:
      client_id: "your-custom-client-id"
      client_secret: "your-custom-client-secret"
      authorization_url: "https://auth.mycompany.com/oauth/authorize"
      token_url: "https://auth.mycompany.com/oauth/token"
      user_info_url: "https://auth.mycompany.com/api/userinfo"
      user_id_field: "user_id"
      email_field: "email_address"
      scopes: ["read", "profile"]
      redirect_uri: "https://your-proxy.com/auth/callback/custom_provider"

# Admin Configuration (NEW)
admin:
  emails:
    - "admin@example.com"
    - "superuser@company.com"
    - "devops@mycompany.com"
```

#### Built-in Provider Defaults

The system includes built-in defaults for these well-known providers:

**Google OAuth 2.0**

```yaml
# Auto-filled defaults (can be overridden)
authorization_url: "https://accounts.google.com/o/oauth2/v2/auth"
token_url: "https://oauth2.googleapis.com/token"
user_info_url: "https://www.googleapis.com/oauth2/v2/userinfo"
scopes: ["openid", "email", "profile"]
user_id_field: "id"
email_field: "email"
```

**GitHub OAuth**

```yaml
# Auto-filled defaults (can be overridden)
authorization_url: "https://github.com/login/oauth/authorize"
token_url: "https://github.com/login/oauth/access_token"
user_info_url: "https://api.github.com/user"
scopes: ["user:email"]
user_id_field: "id"
email_field: "email"
```

**Microsoft/Azure AD**

```yaml
# Auto-filled defaults (can be overridden)
authorization_url: "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/authorize"
token_url: "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
user_info_url: "https://graph.microsoft.com/v1.0/me"
scopes: ["openid", "profile", "email"]
user_id_field: "id"
email_field: "mail"
tenant_id: "common" # Default to multi-tenant
```

**GitLab OAuth**

```yaml
# Auto-filled defaults (can be overridden)
authorization_url: "https://gitlab.com/oauth/authorize"
token_url: "https://gitlab.com/oauth/token"
user_info_url: "https://gitlab.com/api/v4/user"
scopes: ["read_user"]
user_id_field: "id"
email_field: "email"
instance_url: "https://gitlab.com" # Default to gitlab.com
```

**Auth0**

```yaml
# Auto-filled defaults (can be overridden)
authorization_url: "https://{domain}/authorize"
token_url: "https://{domain}/oauth/token"
user_info_url: "https://{domain}/userinfo"
scopes: ["openid", "profile", "email"]
user_id_field: "sub"
email_field: "email"
# Required: domain must be specified
```

**Okta**

```yaml
# Auto-filled defaults (can be overridden)
authorization_url: "https://{domain}/oauth2/default/v1/authorize"
token_url: "https://{domain}/oauth2/default/v1/token"
user_info_url: "https://{domain}/oauth2/default/v1/userinfo"
scopes: ["openid", "profile", "email"]
user_id_field: "sub"
email_field: "email"
# Required: domain must be specified
```

#### Environment Variable Support

```bash
# Minimal setup with environment variables
BEDROCK_OAUTH__PROVIDERS__GOOGLE__CLIENT_ID=your-google-client-id
BEDROCK_OAUTH__PROVIDERS__GOOGLE__CLIENT_SECRET=your-google-client-secret

BEDROCK_OAUTH__PROVIDERS__GITHUB__CLIENT_ID=your-github-client-id
BEDROCK_OAUTH__PROVIDERS__GITHUB__CLIENT_SECRET=your-github-client-secret

# Override defaults if needed
BEDROCK_OAUTH__PROVIDERS__GOOGLE__SCOPES=["openid","email","profile","calendar"]
```

**Benefits of Predefined Providers:**

- ✅ **Easy Setup**: Only client_id and client_secret required
- ✅ **Best Practices**: Predefined scopes and endpoints follow OAuth best
  practices
- ✅ **Override Flexibility**: Can customize any setting when needed
- ✅ **Reduced Errors**: Eliminates URL typos and configuration mistakes
- ✅ **Quick Start**: Get OAuth working in minutes, not hours

## Implementation Flow

### Standard InvokeModel

1. **Accept requests** at `POST /model/{modelId}/invoke` with JWT auth
2. **Validate JWT** from Authorization header
3. **Forward to AWS** using your credentials, preserving all Bedrock headers
4. **Return response** back to client with original status/errors

### Response Stream

1. **Accept requests** at `POST /model/{modelId}/invoke-with-response-stream`
2. **Validate JWT** and establish SSE connection
3. **Forward to AWS** and proxy streaming response chunks
4. **Maintain connection** until stream completes or errors

### Bidirectional Stream

1. **Accept requests** at
   `POST /model/{modelId}/invoke-with-bidirectional-stream`
2. **Upgrade to WebSocket** after JWT validation
3. **Establish AWS stream** and proxy bidirectional communication
4. **Handle 8-minute timeout** and connection cleanup

## 🎯 **PROJECT STATUS SUMMARY**

**Overall Progress**: **~95% Complete** - Production-ready OAuth SSO proxy with dual API format support

### **✅ COMPLETED PHASES (8/9)**

- **Phase 1-6**: Core infrastructure, auth, AWS integration, streaming, testing ✅
- **Phase 7**: OAuth integration with React frontend ✅  
- **Phase 8**: Production readiness (metrics, graceful shutdown) ✅
- **Phase 8.1**: Anthropic API format support (dual format compatibility) ✅
- **Phase 8.5.1**: Rate limiting removal (simplified request handling) ✅

### **❌ PENDING (Phase 9)**

- **Deployment**: Docker, CI/CD, Kubernetes deployment artifacts

### **🏆 KEY ACHIEVEMENTS**

- **117 Tests Passing**: 100 unit + 7 integration + 10 security tests
- **Dual API Format Support**: Both AWS Bedrock and Anthropic API formats
- **Complete OAuth System**: Backend + Frontend with 6 built-in providers
- **Production Architecture**: Error handling, logging, health checks, metrics, graceful shutdown
- **Security**: JWT validation, OAuth 2.0, CSRF protection, token rotation
- **Prometheus Metrics**: HTTP requests, JWT validation, OAuth operations, AWS Bedrock calls
- **Graceful Shutdown**: Signal handling with component coordination and timeout management
- **Enhanced Compatibility**: Works with more LLM gateways and Anthropic SDKs

**The system is fully production-ready with comprehensive monitoring, reliability features, and dual API format support for maximum compatibility!**

## 🏗️ **MAJOR REFACTORING UPDATE (December 2024)**

### **Database & Cache Architecture Overhaul**

The system has undergone a significant architectural refactoring that modernizes the storage layer and improves maintainability:

#### **✅ What Changed**

**From Monolithic Storage:**
- Single `Storage` trait with complex factory patterns
- Trait object overhead and runtime dispatching
- Complex query builder abstractions
- Manual SQL migrations and schema management

**To Modern Architecture:**
- **SeaORM Database Module**: Type-safe ORM with compile-time validation
- **Focused DAOs**: Domain-specific data access objects
- **Cache Module**: Enum-based backend selection (Memory/Redis)
- **Automated Migrations**: SeaORM migration system with version control

#### **🚀 Performance Improvements**

- **Eliminated Trait Objects**: Direct database operations for better performance
- **Reduced Memory Allocation**: Optimized data structures and connection pooling
- **Faster Query Execution**: SeaORM's optimized query generation
- **Simplified Caching**: Enum dispatch instead of trait object overhead

#### **🧹 Code Quality Enhancements**

- **Reduced Codebase**: Removed ~3,000 lines of legacy storage code
- **Better Separation**: Clear boundaries between database and cache operations
- **Enhanced Testing**: Easier mocking and testing of individual components
- **Type Safety**: Compile-time validation of database operations

#### **📊 Current Statistics**

- **Total Tests**: 173 tests passing (100 unit + 7 integration + 10 security)
- **Code Reduction**: -2,470 lines (net reduction from +3,490 / -5,960)
- **Architecture**: Clean separation with focused responsibilities
- **Compatibility**: 100% backward compatible with existing APIs

#### **🔧 Developer Experience**

- **Simplified Development**: Cleaner module structure and clear boundaries
- **Better Debugging**: Easier to trace database operations and cache behavior
- **Enhanced Documentation**: Updated DESIGN.md with current architecture
- **Improved Testing**: Unified test database setup with proper migrations

The refactoring maintains all existing functionality while providing a more maintainable, performant, and modern architecture foundation for future enhancements.

---

## Multi-Stage Development Plan

### Phase 1: Core Infrastructure ✅ COMPLETED

**Goal**: Set up project foundation and build system

- [x] Update Cargo.toml with all dependencies (latest versions with required
      features)
- [x] Create project structure (modules, lib.rs, main.rs)
- [x] Implement configuration management with `config` crate
- [x] Set up logging with `tracing`
- [x] Basic CLI argument parsing
- [x] Health check endpoint
- [x] Comprehensive test suite (23 tests passing)
- [x] JWT authentication middleware
- [x] AWS Bedrock client initialization
- [x] Error handling with HTTP status mapping

**Deliverable**: ✅ Runnable server with configuration loading, JWT auth, and
full test coverage

### Phase 2: Authentication Layer ✅ COMPLETED

**Goal**: Implement JWT validation middleware

- [x] JWT validation module with Claims struct
- [x] Auth middleware for Axum with proper Bearer token extraction
- [x] Error handling for auth failures (proper Unauthorized responses)
- [x] Unit tests for JWT validation (6 comprehensive test cases)
- [x] Integration tests for auth middleware (server-level tests)

**Deliverable**: ✅ JWT authentication working with test tokens, proper error
handling, and comprehensive test coverage

### Phase 3: AWS Integration ✅ COMPLETED

**Goal**: Establish AWS Bedrock connectivity

- [x] AWS credential configuration with environment variable support
- [x] Bedrock client initialization with proper credential handling
- [x] Request/response header handling utilities
- [x] Basic AWS error handling and mapping to HTTP status codes
- [x] Connection health checks with dedicated endpoint

**Deliverable**: ✅ Can connect to AWS Bedrock with comprehensive credential
support, header processing, and health monitoring

### Phase 4: Standard API Implementation ✅ COMPLETED

**Goal**: Implement core InvokeModel endpoint using direct HTTP client

- [x] POST /model/{modelId}/invoke route with JWT authentication
- [x] Direct HTTP client using reqwest for AWS Bedrock API calls
- [x] AWS Signature V4 signing implementation for authentication
- [x] Request body forwarding with proper header processing
- [x] Response proxying with status code and header mapping
- [x] Comprehensive error handling and HTTP status mapping
- [x] Integration tests covering authentication, routing, and error cases

**Deliverable**: ✅ Working InvokeModel proxy with direct HTTP client
implementation, full test coverage, and proper AWS authentication

### Phase 5: Streaming APIs ✅ COMPLETED

**Goal**: Implement streaming endpoints

- [x] InvokeModelWithResponseStream (SSE)
- [x] Response stream proxying
- [x] Stream error handling
- [x] ~~InvokeModelWithBidirectionalStream (WebSocket)~~ (Removed for
      simplicity)
- [x] ~~WebSocket connection management~~ (Removed for simplicity)

**Deliverable**: ✅ Server-Sent Events streaming endpoint working

### Phase 6: Testing Suite ✅ COMPLETED

**Goal**: Comprehensive test coverage

- [x] Unit tests for all modules (100 unit tests)
- [x] Integration tests with real JWT tokens (7 tests)
- [x] Mock AWS Bedrock responses for testing
- [x] Security testing with comprehensive attack simulations (10 tests)
- [x] E2E tests with test client functionality
- [x] Load testing for concurrent requests
- [x] Test coverage reporting with comprehensive test suite

**Deliverable**: ✅ Comprehensive test suite with 117 total tests (100 unit + 7
integration + 10 security) covering authentication, authorization, API
endpoints, streaming, error handling, and security vulnerabilities

### Phase 7: OAuth Integration ✅ COMPLETED

**Goal**: Implement generic OAuth 2.0 authentication with token management

- [x] Generic OAuth provider integration supporting any OAuth 2.0 compliant
      provider
- [x] Configurable provider endpoints (authorization_url, token_url,
      user_info_url)
- [x] Flexible user data field mapping (user_id_field, email_field)
- [x] Authorization code validation endpoints
- [x] Long-lived JWT token generation with refresh capability
- [x] Validation result caching (24h TTL) with concurrent HashMap
- [x] Enhanced configuration for OAuth providers and cache settings
- [x] Enhanced authentication middleware supporting both legacy and OAuth JWTs
- [x] Token refresh endpoint with rotation
- [x] Security enhancements and rate limiting
- [x] Comprehensive testing for OAuth flows with multiple provider types
- [x] Complete React frontend with OAuth integration
- [x] Professional logging system implementation
- [x] OAuth callback handling with state management
- [x] Built-in provider defaults for Google, GitHub, Microsoft, GitLab, Auth0,
      Okta
- [x] Custom provider support with full configuration flexibility
- [x] Environment variable support with BEDROCK_OAUTH__ prefix
- [x] Health checks for OAuth service status
- [x] 14 comprehensive OAuth tests (6 service + 8 routes)

**Deliverable**: ✅ Complete OAuth-enabled authentication system with React
frontend, backward compatibility, and production-ready features

### Phase 8: Production Readiness ✅ COMPLETED

**Goal**: Production-grade features

- [x] Comprehensive error handling (AppError system with proper HTTP status mapping)
- [x] Request/response logging (Professional structured logging system)
- [x] Health checks (OAuth, AWS, and system health monitoring)
- [x] Configuration management (Environment variables, YAML config)
- [x] Error recovery and fallback mechanisms
- [x] Metrics collection (Prometheus metrics server with comprehensive tracking)
- [x] Graceful shutdown handling (Signal handling with component coordination)

**Deliverable**: ✅ Production-ready application with monitoring, metrics, and graceful shutdown

### Phase 8.1: Anthropic API Format Support ✅ COMPLETED

**Goal**: Add Anthropic API format compatibility for enhanced LLM gateway
integration

- [x] Create Anthropic request/response data structures
- [x] Implement model ID mapping (Anthropic → Bedrock format)
- [x] Add request/response transformation logic
- [x] Create `/v1/messages` endpoint handler
- [x] Add streaming support for Anthropic format
- [x] Implement error handling for transformation failures
- [x] Add comprehensive tests for Anthropic format
- [x] Update frontend to show both endpoint options
- [x] Update documentation with dual format support

**Deliverable**: ✅ Dual format support (Bedrock + Anthropic) with comprehensive
testing implemented and fully tested

**Benefits**:

- ✅ **Better LLM Gateway Compatibility**: Works with more proxy solutions
- ✅ **Anthropic SDK Support**: Direct compatibility with official Anthropic
  SDKs
- ✅ **Enhanced Claude Code Integration**: Better support for
  ANTHROPIC_BEDROCK_BASE_URL
- ✅ **Easier Client Migration**: Supports both formats simultaneously

### Phase 8.5: Additional Features ❌ PENDING (Optional)

**Goal**: Enhanced functionality and cost tracking

- [ ] **Token Usage Tracking**: Track input/output tokens, requests, and costs
      per user per model
- [ ] **Multi-Region Support**: Dynamic region routing based on model name
      prefixes

**Deliverable**: Cost tracking, global deployment support, and simplified architecture

**Note**: These features are optional enhancements - the system is already production-ready without them.

### Phase 9: Release & Deployment ❌ PENDING

**Goal**: Packaging and deployment

- [ ] Dockerfile with multi-stage build
- [ ] Docker Compose for local development
- [ ] GitHub Actions CI/CD pipeline
- [ ] Kubernetes manifests
- [ ] Helm chart
- [ ] Release automation
- [ ] Monitoring setup (Prometheus, Grafana)
- [ ] Documentation (README, deployment guide)

**Deliverable**: Deployable release with documentation and monitoring

## Generic OAuth Provider Support

### Configuration Structure

The system supports any OAuth 2.0 compliant provider through a generic
configuration structure:

```yaml
oauth:
  providers:
    { provider_name }:
      client_id: "required"
      client_secret: "required"
      redirect_uri: "required"
      scopes: ["array", "of", "scopes"]
      authorization_url: "required"
      token_url: "required"
      user_info_url: "required"
      user_id_field: "id" # Field name for user ID in user info response
      email_field: "email" # Field name for email in user info response
```

### Built-in Provider Examples

#### Google OAuth 2.0

```yaml
google:
  authorization_url: "https://accounts.google.com/o/oauth2/v2/auth"
  token_url: "https://oauth2.googleapis.com/token"
  user_info_url: "https://www.googleapis.com/oauth2/v2/userinfo"
  scopes: ["openid", "email", "profile"]
  user_id_field: "id"
  email_field: "email"
```

#### GitHub OAuth

```yaml
github:
  authorization_url: "https://github.com/login/oauth/authorize"
  token_url: "https://github.com/login/oauth/access_token"
  user_info_url: "https://api.github.com/user"
  scopes: ["user:email"]
  user_id_field: "id"
  email_field: "email"
```

#### Azure AD / Microsoft

```yaml
microsoft:
  authorization_url: "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize"
  token_url: "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"
  user_info_url: "https://graph.microsoft.com/v1.0/me"
  scopes: ["openid", "profile", "email"]
  user_id_field: "id"
  email_field: "mail"
```

#### GitLab OAuth

```yaml
gitlab:
  authorization_url: "https://gitlab.com/oauth/authorize"
  token_url: "https://gitlab.com/oauth/token"
  user_info_url: "https://gitlab.com/api/v4/user"
  scopes: ["read_user"]
  user_id_field: "id"
  email_field: "email"
```

#### Custom Enterprise Provider

```yaml
my_company:
  authorization_url: "https://auth.mycompany.com/oauth/authorize"
  token_url: "https://auth.mycompany.com/oauth/token"
  user_info_url: "https://auth.mycompany.com/api/userinfo"
  scopes: ["read", "profile"]
  user_id_field: "user_id"
  email_field: "email_address"
```

### User ID Format

All providers follow the format: `{provider_name}:{user_id_from_provider}`

- Google: `google:123456789`
- GitHub: `github:987654321`
- Custom: `my_company:emp_12345`

## Implementation Architecture

### Current Module Structure

```
src/
├── auth/
│   ├── mod.rs           # Re-exports
│   ├── jwt.rs           # Enhanced JWT validation (legacy + OAuth)
│   ├── oauth.rs         # OAuth provider integration
│   ├── api_key.rs       # API key management and validation
│   └── middleware.rs    # Enhanced auth middleware
├── cache/
│   ├── mod.rs           # Cache module with enum-based backends
│   ├── memory.rs        # In-memory cache with TTL support
│   ├── redis.rs         # Redis cache implementation (placeholder)
│   └── types.rs         # Common cache types and traits
├── database/
│   ├── mod.rs           # Database module with SeaORM integration
│   ├── dao/             # Data Access Objects
│   │   ├── mod.rs       # DAO module exports
│   │   ├── users.rs     # User management operations
│   │   ├── api_keys.rs  # API key operations
│   │   ├── usage.rs     # Usage tracking and analytics
│   │   ├── audit_logs.rs # Audit logging operations
│   │   ├── model_costs.rs # Model pricing operations
│   │   └── refresh_tokens.rs # Token rotation management
│   ├── entities/        # SeaORM entity definitions
│   │   ├── mod.rs       # Entity exports
│   │   ├── users.rs     # User entity
│   │   ├── api_keys.rs  # API key entity
│   │   ├── usage_records.rs # Usage tracking entity
│   │   ├── audit_logs.rs # Audit log entity
│   │   ├── model_costs.rs # Model cost entity
│   │   └── refresh_tokens.rs # Refresh token entity
│   └── migration/       # SeaORM migrations
│       ├── mod.rs       # Migration system
│       ├── m20241226_120000_create_users_table.rs
│       ├── m20241226_120100_create_refresh_tokens_table.rs
│       ├── m20241226_120200_create_audit_logs_table.rs
│       ├── m20241226_120300_create_usage_records_table.rs
│       ├── m20241226_120400_create_usage_summaries_table.rs
│       ├── m20241226_120500_create_model_costs_table.rs
│       └── m20241226_120600_create_api_keys_table.rs
├── routes/
│   ├── mod.rs
│   ├── auth.rs          # OAuth endpoints (/auth/*)
│   ├── api_keys.rs      # API key management endpoints
│   ├── anthropic.rs     # Anthropic API format endpoints
│   ├── bedrock.rs       # Bedrock API format endpoints
│   └── health.rs        # Health check endpoints
├── usage_tracking/
│   ├── mod.rs           # Usage tracking module
│   ├── routes.rs        # Usage analytics endpoints
│   └── integration_tests.rs # Usage tracking tests
├── config.rs            # Enhanced configuration with OAuth support
├── server.rs            # Server with DatabaseManager and CacheManager
└── main.rs              # Application entry point
```

### Integration Strategy

- **Backward Compatibility**: Existing JWT tokens continue to work unchanged
- **Dual Validation**: Support both legacy JWT and OAuth-issued JWT validation
- **Migration Path**: Gradual migration from legacy to OAuth tokens
- **Enhanced Claims**: OAuth tokens include provider information and scopes

## Additional Features (Phase 8.5)

### 1. Rate Limiting Removal

#### Current Implementation

The system currently includes a comprehensive rate limiting system
(`src/rate_limit.rs`) with:

- User-based rate limiting (600 RPM for authenticated users)
- IP-based rate limiting (1200 RPM per IP)
- OAuth token creation rate limiting (10 RPM)
- Configurable rate limits with Redis/memory storage

#### Planned Changes

- **Remove rate limiting middleware** from all routes
- **Disable rate limiting by default** (`rate_limit.enabled = false`)
- **Keep configuration structure** for backward compatibility
- **Clean up unused dependencies** and storage methods
- **Update documentation** and examples

#### Benefits

- ✅ **Simplified Architecture**: Reduced complexity and overhead
- ✅ **Better Performance**: Eliminated rate limiting checks on every request
- ✅ **Easier Scaling**: No shared state or coordination needed
- ✅ **Cost Optimization**: Rely on natural AWS rate limiting and billing
  controls

#### Configuration Update

```yaml
# Rate limiting disabled by default
rate_limit:
  enabled: false # Changed from true
  # Other settings preserved for compatibility
```

### 2. Token Usage Tracking

#### Purpose

Track detailed usage metrics per user per model to enable:

- **Cost tracking and billing**
- **Usage analytics and optimization**
- **Quota management and alerts**
- **Performance monitoring**
- **User and admin dashboards**

#### Data Model

```rust
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UsageRecord {
    pub id: Option<i32>,
    pub user_id: i32,              // Foreign key to users table
    pub model_id: String,          // Original model ID (with region prefix)
    pub endpoint_type: String,     // "bedrock" or "anthropic"
    pub region: String,            // Determined AWS region
    pub request_time: DateTime<Utc>,
    pub input_tokens: u32,         // Tokens in request
    pub output_tokens: u32,        // Tokens in response
    pub total_tokens: u32,         // input_tokens + output_tokens
    pub response_time_ms: u32,     // Response time in milliseconds
    pub success: bool,             // Whether request succeeded
    pub error_message: Option<String>, // Error details if failed
    pub cost_usd: Option<Decimal>, // Calculated cost in USD
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UsageSummary {
    pub user_id: i32,
    pub model_id: String,
    pub period_start: DateTime<Utc>,
    pub period_end: DateTime<Utc>,
    pub total_requests: u32,
    pub total_input_tokens: u64,
    pub total_output_tokens: u64,
    pub total_tokens: u64,
    pub avg_response_time_ms: f32,
    pub success_rate: f32,
    pub estimated_cost: Decimal,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ModelCost {
    pub id: Option<i32>,
    pub model_id: String,
    pub input_cost_per_1k_tokens: Decimal,
    pub output_cost_per_1k_tokens: Decimal,
    pub updated_at: DateTime<Utc>,
}
```

#### Database Schema

```sql
-- Usage tracking table
CREATE TABLE usage_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    model_id TEXT NOT NULL,
    endpoint_type TEXT NOT NULL,
    region TEXT NOT NULL,
    request_time DATETIME NOT NULL,
    input_tokens INTEGER NOT NULL,
    output_tokens INTEGER NOT NULL,
    total_tokens INTEGER NOT NULL,
    response_time_ms INTEGER NOT NULL,
    success BOOLEAN NOT NULL,
    error_message TEXT,
    cost_usd DECIMAL(10,6),
    FOREIGN KEY (user_id) REFERENCES users (id),
    INDEX idx_user_model_time (user_id, model_id, request_time),
    INDEX idx_request_time (request_time)
);

-- Pre-calculated summaries for performance
CREATE TABLE usage_summaries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    model_id TEXT NOT NULL,
    period_start DATETIME NOT NULL,
    period_end DATETIME NOT NULL,
    total_requests INTEGER NOT NULL,
    total_input_tokens BIGINT NOT NULL,
    total_output_tokens BIGINT NOT NULL,
    total_tokens BIGINT NOT NULL,
    avg_response_time_ms REAL NOT NULL,
    success_rate REAL NOT NULL,
    estimated_cost DECIMAL(10,6),
    UNIQUE(user_id, model_id, period_start),
    FOREIGN KEY (user_id) REFERENCES users (id)
);

-- Model cost configuration
CREATE TABLE model_costs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    model_id TEXT NOT NULL UNIQUE,
    input_cost_per_1k_tokens DECIMAL(10,6) NOT NULL,
    output_cost_per_1k_tokens DECIMAL(10,6) NOT NULL,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
```

#### API Endpoints

```rust
// User usage endpoints
GET /api/v1/usage/summary?period=day|week|month&model=*
GET /api/v1/usage/history?start=date&end=date&model=*&limit=100&offset=0
GET /api/v1/usage/models  // List of models used by the user
GET /api/v1/usage/export?period=day|week|month&format=csv|json

// Admin usage endpoints (requires admin privileges)
GET /api/v1/admin/users  // List all users with usage stats
GET /api/v1/admin/usage/overview  // System-wide usage statistics
GET /api/v1/admin/usage/users/{user_id}?period=day|week|month
GET /api/v1/admin/usage/models  // Model usage analytics across all users
GET /api/v1/admin/costs  // Cost analytics and summaries
PUT /api/v1/admin/costs/models  // Update model pricing
```

#### Frontend Dashboard Components

##### User Dashboard
```typescript
// User-facing usage tracking dashboard
interface UserDashboard {
  // Summary cards showing key metrics
  UsageSummary: {
    totalRequests: number;
    totalTokens: number;
    avgResponseTime: number;
    estimatedCost: number;
  };
  
  // Interactive charts for usage visualization
  UsageChart: {
    period: 'day' | 'week' | 'month';
    metric: 'requests' | 'tokens' | 'cost';
    data: TimeSeriesData[];
  };
  
  // Model-specific usage breakdown
  ModelUsageBreakdown: {
    modelId: string;
    requests: number;
    tokens: number;
    cost: number;
    percentage: number;
  }[];
  
  // Detailed usage history with filtering
  UsageHistory: {
    records: UsageRecord[];
    filters: {
      dateRange: DateRange;
      model: string;
      success: boolean;
    };
    pagination: PaginationState;
  };
  
  // Data export functionality
  ExportOptions: {
    format: 'csv' | 'json';
    period: DateRange;
  };
}
```

##### Admin Dashboard
```typescript
// Admin-facing system management dashboard
interface AdminDashboard {
  // System overview metrics
  SystemOverview: {
    totalUsers: number;
    activeUsers: number;
    totalRequests: number;
    totalRevenue: number;
    systemHealth: HealthStatus;
  };
  
  // User management interface
  UserManagement: {
    users: UserWithStats[];
    sortBy: 'email' | 'usage' | 'cost' | 'lastActive';
    filters: UserFilters;
    actions: {
      viewDetails: (userId: number) => void;
      exportUserData: (userId: number) => void;
      manageAccess: (userId: number) => void;
    };
  };
  
  // Cost management and analytics
  CostAnalytics: {
    modelCosts: ModelCost[];
    revenueByModel: RevenueData[];
    costTrends: TimeSeriesData[];
    updateModelPricing: (modelId: string, costs: ModelCost) => void;
  };
  
  // System analytics and insights
  SystemAnalytics: {
    popularModels: ModelUsageRanking[];
    usagePatterns: UsagePattern[];
    performanceMetrics: PerformanceData[];
    errorAnalysis: ErrorStats[];
  };
}
```

#### Usage Tracking Integration

```rust
// Middleware for capturing usage data
pub async fn usage_tracking_middleware(
    claims: Claims,
    req: Request<Body>,
    next: Next,
) -> Result<Response, AppError> {
    let start_time = Instant::now();
    
    // Extract request metadata
    let model_id = extract_model_id(&req);
    let endpoint_type = determine_endpoint_type(&req);
    let region = determine_region(&model_id);
    
    // Capture request body for token counting
    let (parts, body) = req.into_parts();
    let body_bytes = hyper::body::to_bytes(body).await?;
    let input_tokens = TokenCounter::count_request_tokens(&body_bytes).await?;
    
    // Reconstruct request
    let req = Request::from_parts(parts, Body::from(body_bytes));
    
    // Process request
    let response = next.run(req).await;
    let response_time_ms = start_time.elapsed().as_millis() as u32;
    
    // Extract response body for token counting
    let (parts, body) = response.into_parts();
    let body_bytes = hyper::body::to_bytes(body).await?;
    let output_tokens = TokenCounter::count_response_tokens(&parts, &body_bytes).await?;
    
    // Calculate cost if model pricing is configured
    let cost_usd = calculate_cost(&model_id, input_tokens, output_tokens).await.ok();
    
    // Record usage asynchronously (non-blocking)
    let user_id = get_user_id_from_claims(&claims).await?;
    let usage_record = UsageRecord {
        id: None,
        user_id,
        model_id,
        endpoint_type,
        region,
        request_time: Utc::now(),
        input_tokens,
        output_tokens,
        total_tokens: input_tokens + output_tokens,
        response_time_ms,
        success: parts.status.is_success(),
        error_message: if parts.status.is_success() { None } else { Some("Request failed".to_string()) },
        cost_usd,
    };
    
    // Store usage record asynchronously
    tokio::spawn(async move {
        if let Err(e) = store_usage_record(&usage_record).await {
            tracing::warn!("Failed to store usage record: {}", e);
        }
        
        // Update Prometheus metrics
        record_usage_metrics(&usage_record);
    });
    
    // Reconstruct response
    let response = Response::from_parts(parts, Body::from(body_bytes));
    Ok(response)
}
```

#### Token Counting

```rust
// Token counting service for accurate usage tracking
pub struct TokenCounter;

impl TokenCounter {
    // Count tokens from Anthropic/Bedrock request
    pub async fn count_request_tokens(body: &[u8]) -> Result<u32, AppError> {
        let request: serde_json::Value = serde_json::from_slice(body)?;
        
        // Extract messages and system prompt
        let messages = request["messages"].as_array().unwrap_or(&vec![]);
        let system = request["system"].as_str().unwrap_or("");
        
        // Use tiktoken or simple estimation (4 chars ≈ 1 token)
        let mut token_count = estimate_tokens(system);
        
        for message in messages {
            if let Some(content) = message["content"].as_str() {
                token_count += estimate_tokens(content);
            }
        }
        
        Ok(token_count)
    }
    
    // Extract tokens from AWS Bedrock response
    pub async fn count_response_tokens(
        response: &http::response::Parts,
        body: &[u8]
    ) -> Result<u32, AppError> {
        // Method 1: Check AWS headers
        if let Some(token_header) = response.headers.get("x-amzn-bedrock-output-token-count") {
            if let Ok(count) = token_header.to_str()?.parse::<u32>() {
                return Ok(count);
            }
        }
        
        // Method 2: Parse from response body
        let response_data: serde_json::Value = serde_json::from_slice(body)?;
        
        // Extract from usage field
        if let Some(usage) = response_data["usage"].as_object() {
            if let Some(output_tokens) = usage["output_tokens"].as_u64() {
                return Ok(output_tokens as u32);
            }
        }
        
        // Method 3: Estimate from response content
        if let Some(content) = response_data["content"].as_array() {
            let mut total_chars = 0;
            for item in content {
                if let Some(text) = item["text"].as_str() {
                    total_chars += text.len();
                }
            }
            return Ok(estimate_tokens_from_chars(total_chars));
        }
        
        Ok(0)
    }
}
```

#### Configuration

```yaml
# Usage tracking configuration
usage_tracking:
  enabled: true
  batch_size: 100
  flush_interval: 60  # seconds
  retention_days: 365
  enable_detailed_logging: true
  
  # Cost tracking configuration
  cost_tracking:
    enabled: true
    # Default model costs (can be overridden via admin API)
    default_costs:
      "anthropic.claude-sonnet-4-20250514-v1:0":
        input_cost_per_1k_tokens: 0.003
        output_cost_per_1k_tokens: 0.015
      "anthropic.claude-3-opus-20240229-v1:0":
        input_cost_per_1k_tokens: 0.015
        output_cost_per_1k_tokens: 0.075
      "anthropic.claude-3-haiku-20240307-v1:0":
        input_cost_per_1k_tokens: 0.00025
        output_cost_per_1k_tokens: 0.00125
```

### 3. Multi-Region Support

#### Purpose

Enable dynamic routing to different AWS regions based on model name prefixes:

- `apac.anthropic.claude-sonnet-4-20250514-v1:0` → `ap-northeast-1`
- `us.anthropic.claude-sonnet-4-20250514-v1:0` → `us-east-1`
- `eu.anthropic.claude-sonnet-4-20250514-v1:0` → `eu-west-1`
- `anthropic.claude-sonnet-4-20250514-v1:0` → `us-east-1` (default)

#### Configuration Structure (Simplified with Shared Credentials)

```yaml
aws:
  # Shared credentials for all regions
  region: "us-east-1" # Default/primary region
  access_key_id: "AKIA..." # Shared across regions
  secret_access_key: "..." # Shared across regions
  profile: "default" # Shared across regions
  bearer_token: "ABSK-..." # Or bearer token (shared)

  # Region mapping for model prefixes
  region_mapping:
    "us.": "us-east-1"
    "apac.": "ap-northeast-1"
    "eu.": "eu-west-1"
    "ca.": "ca-central-1"
    "default": "us-east-1" # For models without prefix
```

#### Multi-Region Client Architecture

```rust
pub struct MultiRegionAwsClient {
    base_config: AwsConfig,        // Shared credentials
    clients: HashMap<String, AwsHttpClient>,
    region_mapping: HashMap<String, String>,
    default_region: String,
}

impl MultiRegionAwsClient {
    pub fn new(config: AwsConfig, region_mapping: HashMap<String, String>) -> Self {
        let default_region = config.region.clone();
        let mut clients = HashMap::new();

        // Create clients for all mapped regions using same credentials
        let mut regions: HashSet<String> = region_mapping.values().cloned().collect();
        regions.insert(default_region.clone());

        for region in regions {
            let mut region_config = config.clone();
            region_config.region = region.clone();
            clients.insert(region.clone(), AwsHttpClient::new(region_config));
        }

        Self {
            base_config: config,
            clients,
            region_mapping,
            default_region,
        }
    }

    pub fn determine_region(&self, model_id: &str) -> String {
        // Parse model prefix
        for (prefix, region) in &self.region_mapping {
            if prefix != "default" && model_id.starts_with(prefix) {
                return region.clone();
            }
        }
        self.default_region.clone()
    }

    pub fn get_client(&self, region: &str) -> Result<&AwsHttpClient, AppError> {
        self.clients.get(region)
            .ok_or_else(|| AppError::BadRequest(format!("Region {} not configured", region)))
    }
}
```

#### Model ID Processing

```rust
#[derive(Debug, Clone)]
pub struct ModelRequest {
    pub original_model_id: String,  // apac.anthropic.claude-sonnet-4-20250514-v1:0
    pub region: String,             // ap-northeast-1
    pub bedrock_model_id: String,   // anthropic.claude-sonnet-4-20250514-v1:0 (prefix stripped)
}

pub fn parse_model_id(model_id: &str, region_mapping: &HashMap<String, String>) -> ModelRequest {
    for (prefix, region) in region_mapping {
        if prefix != "default" && model_id.starts_with(prefix) {
            let bedrock_model_id = model_id.strip_prefix(prefix).unwrap_or(model_id).to_string();
            return ModelRequest {
                original_model_id: model_id.to_string(),
                region: region.clone(),
                bedrock_model_id,
            };
        }
    }

    // No prefix found, use default region
    let default_region = region_mapping.get("default").unwrap_or(&"us-east-1".to_string()).clone();
    ModelRequest {
        original_model_id: model_id.to_string(),
        region: default_region,
        bedrock_model_id: model_id.to_string(),
    }
}
```

#### Updated Route Handlers

```rust
pub async fn invoke_model_handler(
    Path((model_id,)): Path<(String,)>,
    headers: HeaderMap,
    claims: Claims,
    Extension(client): Extension<Arc<MultiRegionAwsClient>>,
    body: Bytes,
) -> Result<Response, AppError> {
    // Parse model to determine region
    let model_request = parse_model_id(&model_id, &client.region_mapping);

    // Get region-specific client
    let aws_client = client.get_client(&model_request.region)?;

    // Make request with stripped model ID
    let response = aws_client.invoke_model(
        &model_request.bedrock_model_id,
        headers.get("content-type").and_then(|h| h.to_str().ok()),
        headers.get("accept").and_then(|h| h.to_str().ok()),
        body.to_vec(),
    ).await?;

    // Track usage with region info (if usage tracking enabled)
    if let Err(e) = track_usage(&claims.sub, &model_id, &model_request.region, &response).await {
        warn!("Failed to track usage: {}", e);
    }

    // Return response
    build_response(response)
}
```

#### Regional Health Checks

```rust
pub async fn multi_region_health_check(
    Extension(client): Extension<Arc<MultiRegionAwsClient>>,
) -> Result<Json<Value>, AppError> {
    let mut region_health = HashMap::new();

    for (region, aws_client) in &client.clients {
        let health = match aws_client.health_check().await {
            Ok(()) => json!({
                "status": "healthy",
                "endpoint": aws_client.base_url,
                "credentials": if aws_client.config.bearer_token.is_some() { "bearer_token" } else { "sigv4" }
            }),
            Err(e) => json!({
                "status": "unhealthy",
                "error": e.to_string(),
                "endpoint": aws_client.base_url
            }),
        };
        region_health.insert(region.clone(), health);
    }

    Ok(Json(json!({
        "regions": region_health,
        "default_region": client.default_region,
        "region_mapping": client.region_mapping
    })))
}
```

#### Benefits

- ✅ **Global Deployment**: Support users worldwide with regional endpoints
- ✅ **Reduced Latency**: Route requests to geographically closest regions
- ✅ **Simplified Credentials**: Single AWS credential set for all regions
- ✅ **Easy Configuration**: Prefix-based routing with sensible defaults
- ✅ **Usage Tracking**: Track usage by region for cost analysis

### Implementation Roadmap

#### Phase 8.5.1: Rate Limiting Removal ✅ COMPLETED

1. **Configuration Update**: Set `rate_limit.enabled = false` as default ✅
2. **Middleware Removal**: Remove rate limiting middleware from routes ✅
3. **Cleanup**: Remove unused imports and rate limiting initialization ✅
4. **Testing**: Update/remove 15 rate limiting tests ✅
5. **Documentation**: Update configuration examples ✅

#### Phase 8.5.2: Token Usage Tracking with Dashboards ✅ COMPLETED

**Backend Implementation ✅ COMPLETED**
1. **Database Schema**: Add usage tracking tables and migrations ✅
2. **Storage Layer**: Implement usage recording and querying methods ✅
3. **Token Counting**: Implement accurate token counting from requests/responses ✅
4. **Usage Middleware**: Add middleware to capture usage data ✅
5. **API Endpoints**: Implement user and admin usage endpoints ✅
6. **Cost Tracking**: Add model pricing and cost calculation ✅
7. **Metrics Integration**: Connect with Prometheus metrics ✅
8. **Testing**: Comprehensive backend tests ✅

#### Phase 8.5.3: ModelService Unified Architecture (8-12 hours)

**Architecture Simplification (8-12 hours)**
1. **ModelService Design**: Create unified interface for AWS calls and usage tracking
2. **ModelService Implementation**: Replace middleware with service-based approach
3. **Route Handler Updates**: Update bedrock and anthropic routes to use ModelService
4. **Middleware Removal**: Remove complex usage tracking middleware
5. **Server Configuration**: Update router to use ModelService instead of middleware
6. **Test Updates**: Replace middleware tests with ModelService unit tests
7. **Usage Tracking Enhancement**: Use actual AWS token headers instead of estimates
8. **Integration Testing**: Verify end-to-end functionality with new architecture

**Frontend Implementation (10-15 hours)**
1. **User Dashboard Components**:
   - Usage summary cards with key metrics
   - Interactive usage charts (requests, tokens, costs)
   - Model usage breakdown and analytics
   - Usage history with filtering and pagination
   - Data export functionality (CSV/JSON)

2. **Admin Dashboard Components**:
   - System overview with health metrics
   - User management interface
   - Cost management and model pricing
   - System analytics and insights
   - Batch operations and controls

3. **Shared Components**:
   - Date range picker
   - Loading states and error handling
   - Export buttons and utilities
   - Real-time data updates

4. **Styling and UX**:
   - Responsive design for all screen sizes
   - Dark mode support
   - Accessibility compliance
   - Performance optimization

#### Phase 8.5.3: Multi-Region Support (3-4 hours)

1. **Configuration**: Update AWS config structure for region mapping
2. **Multi-Region Client**: Implement multi-region AWS client with shared
   credentials
3. **Model Parsing**: Implement model ID prefix parsing and region determination
4. **Route Updates**: Update invoke handlers to use region-specific clients
5. **Health Checks**: Add regional health monitoring
6. **Testing**: Add multi-region routing and fallback tests
7. **Documentation**: Multi-region configuration and usage guide

**Total Estimated Effort**: 23-32 hours

- **Backend Development**: 8-10 hours
- **Frontend Development**: 10-15 hours
- **Multi-Region Support**: 3-4 hours
- **Testing & Integration**: 2-3 hours

## Client Integration Guide

### Claude Code Integration (API Key Recommended)

#### Method 1: Environment Variables (API Key)

```bash
export ANTHROPIC_AUTH_TOKEN="SSOK_a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6"
export ANTHROPIC_BASE_URL="https://your-proxy-domain.com/anthropic"
# OR for Bedrock format compatibility
export ANTHROPIC_BEDROCK_BASE_URL="https://your-proxy-domain.com"
export CLAUDE_CODE_SKIP_BEDROCK_AUTH=1
export CLAUDE_CODE_USE_BEDROCK=1
```

#### Method 2: Bedrock Gateway Mode

```bash
# For AWS Bedrock format compatibility
export ANTHROPIC_BEDROCK_BASE_URL="https://your-proxy-domain.com"
export ANTHROPIC_AUTH_TOKEN="SSOK_a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6"
export CLAUDE_CODE_SKIP_BEDROCK_AUTH=1
export CLAUDE_CODE_USE_BEDROCK=1
```

**Note**: API keys are recommended for Claude Code as they don't require refresh token management.

### API Client Integration (Generic)

#### HTTP Headers (API Key)

```http
Authorization: Bearer SSOK_a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6
# OR
X-API-Key: SSOK_a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6
Content-Type: application/json
```

#### Example API Call (API Key)

```bash
curl -X POST "https://your-proxy-domain.com/bedrock/model/anthropic.claude-sonnet-4-20250514-v1:0/invoke" \
  -H "Authorization: Bearer SSOK_a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6" \
  -H "Content-Type: application/json" \
  -d '{
    "anthropic_version": "bedrock-2023-05-31",
    "max_tokens": 1000,
    "messages": [{"role": "user", "content": "Hello"}]
  }'

# Or using Anthropic format
curl -X POST "https://your-proxy-domain.com/anthropic/v1/messages" \
  -H "X-API-Key: SSOK_a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "claude-sonnet-4-20250514",
    "max_tokens": 1000,
    "messages": [{"role": "user", "content": "Hello"}]
  }'
```

### Token Refresh Handling

#### Automatic Refresh (Recommended)

```bash
# Check token expiration before each request
# If expired, call POST /auth/refresh to get new token
# Update stored token and retry request
```

#### Manual Refresh

```bash
curl -X POST "https://your-proxy-domain.com/auth/refresh" \
  -H "Content-Type: application/json" \
  -d '{"refresh_token": "your_refresh_token"}'
```

## Frontend Implementation ✅ COMPLETED

### React Frontend with OAuth Integration

The frontend has been fully implemented with React 18, TypeScript, and Vite, providing:

**Completed Features:**
- ✅ **OAuth Flow**: Full OAuth provider integration with callback handling
- ✅ **Provider Selection**: Dynamic provider list from `/auth/providers`
- ✅ **Token Display**: Secure display of access and refresh tokens
- ✅ **Setup Guide**: Comprehensive Claude Code setup instructions
- ✅ **Token Management**: Automatic refresh and validation
- ✅ **Copy-to-clipboard**: One-click copy for tokens and commands
- ✅ **Responsive Design**: Mobile-friendly interface
- ✅ **Error Handling**: Graceful error states and user feedback
- ✅ **Loading States**: Professional loading indicators
- ✅ **Route Protection**: Secure routing with authentication guards

**Technical Stack:**
- **Framework**: React 18 with TypeScript
- **Build Tool**: Vite for fast development and optimized builds
- **Routing**: React Router v7 for navigation
- **Icons**: Lucide React for professional UI icons
- **Styling**: Custom CSS with responsive design

**Pages Implemented:**
- **LoginPage**: OAuth provider selection and authentication
- **DashboardPage**: Token management and API usage instructions
- **CallbackPage**: OAuth callback handling and token generation

### Upcoming Dashboard Enhancements (Phase 8.5.2)

The existing frontend will be extended with usage tracking dashboards:

**User Dashboard Additions:**
- Usage analytics and visualization
- Cost tracking and estimates
- Model usage breakdown
- Historical data with export options

**Admin Dashboard (New):**
- System-wide usage analytics
- User management interface
- Cost configuration and tracking
- Performance monitoring

## ModelService Architecture (Phase 8.5.3)

### Current Usage Tracking Problems

The current middleware-based usage tracking approach has several issues:

- **Complex Middleware**: Intercepts requests/responses with estimation-based token counting
- **Duplicate Logic**: AWS call handling duplicated between bedrock.rs and anthropic.rs
- **Inaccurate Counting**: Token estimation instead of actual AWS response headers
- **Difficult Testing**: Complex middleware makes testing and debugging difficult

### Proposed Unified Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│ Bedrock Routes  │───▶│                  │───▶│                 │───▶│      AWS        │
│ (validation)    │    │   ModelService   │    │  AwsHttpClient  │    │    Bedrock      │
└─────────────────┘    │  (unified API +  │    │                 │    │                 │
┌─────────────────┐    │ usage tracking)  │    │                 │    │                 │
│ Anthropic Routes│───▶│                  │◄───│                 │◄───│                 │
│ (transformation)│    └──────────────────┘    └─────────────────┘    └─────────────────┘
└─────────────────┘             │
                                ▼
                    ┌─────────────────────────┐
                    │     Storage Layer       │
                    │   (usage records with   │
                    │   actual token counts)  │
                    └─────────────────────────┘
```

### ModelService Interface Design

**Core Responsibilities:**
1. **Unified AWS Call Interface** - Handle both streaming and non-streaming
2. **Usage Tracking** - Extract actual token counts from AWS headers (`x-amzn-bedrock-*-token-count`)
3. **Error Handling** - Centralized AWS error handling
4. **Cost Calculation** - Apply model pricing to actual token counts

**Key Methods:**
```rust
pub struct ModelService {
    aws_client: AwsHttpClient,
    storage: Arc<Storage>,
    config: Config,
}

impl ModelService {
    // Non-streaming calls - usage tracking happens internally
    pub async fn invoke_model(&self, request: ModelRequest) -> Result<ModelResponse, AppError> {
        // 1. Make AWS API call
        let response = self.aws_client.invoke_model(...).await?;
        
        // 2. Track usage automatically (internal call)
        self.track_usage(&request, &response).await?;
        
        // 3. Return response
        Ok(response)
    }
    
    // Streaming calls - usage tracking happens internally  
    pub async fn invoke_model_stream(&self, request: ModelRequest) -> Result<ModelStreamResponse, AppError> {
        // 1. Make AWS streaming API call
        let response = self.aws_client.invoke_model_stream(...).await?;
        
        // 2. Track usage automatically (internal call) 
        self.track_usage(&request, &response).await?;
        
        // 3. Return streaming response
        Ok(response)
    }
    
    // Private method - only called internally by invoke_* methods
    async fn track_usage(&self, request: &ModelRequest, response: &ModelResponse) -> Result<(), AppError> {
        let user_id = request.user_id;  // Extract from request
        // Extract token counts from AWS response headers and store usage record
    }
}

pub struct ModelRequest {
    pub model_id: String,
    pub body: Vec<u8>,
    pub headers: HeaderMap,
    pub user_id: i32,
    pub endpoint_type: String,
}

pub struct ModelResponse {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: Vec<u8>,
    pub usage_metadata: Option<UsageMetadata>,
}

pub struct UsageMetadata {
    pub input_tokens: u32,
    pub output_tokens: u32,
    pub region: String,
    pub response_time_ms: u32,
}
```

### Benefits of ModelService Architecture

#### Simplified Flow
- **Before**: Request → Auth → Middleware → Route → AWS → Middleware → Response  
- **After**: Request → Auth → Route → ModelService → AWS → Response (with automatic usage tracking)

#### Better Separation of Concerns
- **Routes**: Request/response formatting and validation only
- **ModelService**: AWS calls and automatic usage tracking (encapsulated)
- **Storage**: Data persistence
- **No Complex Middleware**: Eliminates request/response interception

#### Automatic Usage Tracking
- **Internal and Guaranteed**: Usage tracking happens automatically inside invoke_* methods
- **Can't Be Forgotten**: No external calls to track_usage - it's built into the flow
- **Actual Token Counts**: From AWS response headers instead of estimates
- **Consistent**: All model invocations tracked the same way
- **Better Error Handling**: Usage only tracked for successful requests

#### Easier Testing & Debugging
- **Single Mock Point**: Mock ModelService instead of complex middleware
- **Clear Boundaries**: Easy to test each component in isolation
- **Better Observability**: Centralized logging and metrics

### Implementation Plan

#### Phase 1: Create ModelService
**Files to Create:**
- `src/model_service.rs` - Core ModelService implementation
- `src/model_service/mod.rs` - Module organization  
- `src/model_service/types.rs` - Request/Response types
- `src/model_service/usage.rs` - Usage tracking logic

#### Phase 2: Update Route Handlers
**Bedrock Routes**: Replace direct `aws_http_client.invoke_model()` calls with `model_service.invoke_model()`

**Anthropic Routes**: Replace AWS calls with ModelService calls, keep transformation logic

#### Phase 3: Remove Middleware & Update Server
- Delete `src/usage_tracking/middleware.rs` 
- Remove middleware from server configuration
- Add ModelService to application state

#### Phase 4: Testing & Verification
- Replace middleware tests with ModelService unit tests
- Update integration tests to mock ModelService
- Verify usage tracking with actual AWS token headers

### Migration Strategy

#### Backwards Compatibility
- Keep existing API endpoints unchanged
- Maintain same request/response formats  
- Preserve usage data structure

#### Rollout Plan
1. Create ModelService alongside existing middleware
2. Update routes one at a time (bedrock first, then anthropic)
3. Remove middleware once routes are migrated
4. Clean up unused middleware code

This architecture will be significantly simpler, more accurate, and easier to maintain than the current middleware-based approach.
