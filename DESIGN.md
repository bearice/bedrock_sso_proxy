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

### 2.1. OAuth Integration Module (NEW)

- OAuth 2.0 provider integration (Google, GitHub)
- Authorization code validation with providers
- Long-lived JWT token generation (30 days)
- Refresh token management with rotation
- 24-hour validation result caching
- Backward compatibility with existing JWT tokens

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

### Legacy JWT Authentication Flow (Existing)

1. Extract Bearer token from `Authorization: Bearer <jwt>` header
2. Validate JWT signature and expiration
3. Extract user claims (user_id, permissions, etc.)
4. Proceed to AWS forwarding or return 401

### OAuth Authentication Flow (NEW)

#### Initial Token Creation

1. **Client redirects to OAuth provider** (Google/GitHub)
2. **User authorizes application** and gets authorization code
3. **Client calls** `POST /auth/token` with authorization code
4. **Proxy validates code** with OAuth provider
5. **Proxy checks admin status** based on user's email address
6. **Proxy generates long-lived JWT** (30 days) with appropriate scopes
7. **Client stores tokens** and uses JWT for subsequent requests

#### Token Validation with Caching

1. **Extract JWT token** from Authorization header
2. **Check validation cache** using token hash (24h TTL)
3. **If cache hit**: Use cached validation result
4. **If cache miss**: Validate with OAuth provider and cache result
5. **Proceed to AWS forwarding** or return 401

#### Token Refresh Flow

1. **Client calls** `POST /auth/refresh` with refresh token
2. **Proxy validates refresh token** and rotates it
3. **Proxy issues new JWT** with extended expiration
4. **Client updates stored tokens**

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
  "model": "claude-3-sonnet-20240229",
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
  "model": "claude-3-sonnet-20240229",
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
  "model": "claude-3-sonnet-20240229",
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
    ("claude-3-sonnet-20240229", "anthropic.claude-3-sonnet-20240229-v1:0"),
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
  access_token_ttl: 2592000 # 30 days
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
BEDROCK_JWT__ACCESS_TOKEN_TTL=2592000
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

#### OAuth Security (NEW)

- **Authorization code validation** with OAuth providers
- **Short-lived authorization codes** (10 minutes max)
- **Long-lived JWT tokens** (30 days) with refresh capability
- **Refresh token rotation** for enhanced security
- **Cache invalidation** on security events
- **Rate limiting** on token creation endpoints
- **HTTPS enforcement** in production
- **Secure token storage** recommendations for clients

#### JWT Claims Structure (Enhanced with Email-Based Auth)

```json
{
  "sub": "user@example.com",
  "iat": 1234567890,
  "exp": 1234567890,
  "provider": "google",
  "email": "user@example.com",
  "refresh_token_id": "uuid-v4-here"
}
```

**Key Changes:**

- **Primary Key**: `sub` now contains the user's email address (was composite
  user ID)
- **No Scopes**: Admin status is checked at request time, not stored in JWT
- **Real-Time Authorization**: Admin changes take effect immediately
- **Simplified Token**: Removed scopes field to prevent stale permissions

#### Validation Cache Security

- **Cache Key**: `oauth_validation:{provider}:{email}:{token_hash}`
- **TTL**: 24 hours maximum
- **Storage**: In-memory with SHA-256 token hashing
- **Fallback**: Always validate with OAuth provider on cache miss

## Data Storage Strategy

### Hybrid Storage Architecture (Recommended)

**Redis + Database** - Best of both worlds for production deployments

#### 1. Redis (Caches & TTL Data)

**Fast, volatile data with automatic expiration**

- **Validation Cache**: OAuth validation results (24h TTL)
- **CSRF State Tokens**: OAuth state for security (10min TTL)
- **Rate Limiting**: Token creation rate limits (1h TTL)
- **Session Data**: Temporary authentication sessions

#### 2. Database (Persistent Data)

**Durable, non-volatile data requiring persistence**

- **User Records**: User profiles and provider mappings
- **Refresh Tokens**: Long-lived tokens (90 days) with rotation tracking
- **Audit Logs**: Authentication events and security logs

### Current Implementation (Phase 7)

**In-Memory Storage Only** - For development and single-instance deployments

#### 1. Validation Cache

- **Storage**: `DashMap<String, CachedValidation>` (concurrent HashMap)
- **Data**: OAuth validation results
- **TTL**: 24 hours with automatic cleanup
- **Fallback**: Redis in production

#### 2. Refresh Tokens

- **Storage**: `DashMap<String, RefreshTokenData>` (concurrent HashMap)
- **Data**: Refresh token metadata and expiration
- **TTL**: 90 days with automatic cleanup
- **Fallback**: Database in production

#### 3. CSRF State Tokens

- **Storage**: `DashMap<String, StateData>` (concurrent HashMap)
- **Data**: OAuth state tokens for CSRF protection
- **TTL**: 10 minutes with automatic cleanup
- **Fallback**: Redis in production

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

#### Database Schema (Persistent)

```sql
-- Users table
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    provider_user_id VARCHAR(255) NOT NULL,
    provider VARCHAR(100) NOT NULL,
    email VARCHAR(255) NOT NULL,
    display_name VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP,
    UNIQUE(provider, provider_user_id)
);

-- Refresh tokens table
CREATE TABLE refresh_tokens (
    id SERIAL PRIMARY KEY,
    token_hash VARCHAR(64) NOT NULL UNIQUE,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL,
    rotation_count INTEGER DEFAULT 0,
    revoked_at TIMESTAMP NULL,
    INDEX(user_id),
    INDEX(expires_at)
);

-- Audit logs table
CREATE TABLE audit_logs (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    event_type VARCHAR(50) NOT NULL, -- 'login', 'token_refresh', 'logout', 'failed_auth'
    provider VARCHAR(100),
    ip_address INET,
    user_agent TEXT,
    success BOOLEAN NOT NULL,
    error_message TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX(user_id),
    INDEX(event_type),
    INDEX(created_at)
);
```

### Storage Configuration (Production)

#### Production Configuration (Phase 8+)

```yaml
# Production configuration with Redis + PostgreSQL
storage:
  # Redis for caches and TTL data
  redis:
    url: "redis://localhost:6379"
    db: 0
    key_prefix: "bedrock_sso:"
    max_connections: 10

  # PostgreSQL for persistent data
  database:
    url: "postgresql://user:pass@localhost/bedrock_sso"
    max_connections: 20
    migration_on_startup: true

cache:
  backend: "redis" # Use Redis for all cache operations
  fallback: "memory" # Fall back to memory if Redis unavailable

audit:
  backend: "database" # Store audit logs in database
  retention_days: 365 # Keep logs for 1 year
```

#### Development/Light Usage Configuration (Phase 7)

```yaml
# SQLite + in-memory configuration for development and light usage
storage:
  # No Redis for development
  redis:
    enabled: false

  # SQLite for simple persistent data
  database:
    url: "sqlite://./data/bedrock_sso.db"
    max_connections: 5
    migration_on_startup: true

cache:
  backend: "memory" # In-memory cache for development
  max_entries: 10000
  cleanup_interval: 3600

audit:
  backend: "database" # Store in SQLite
  retention_days: 30
```

#### Memory-Only Configuration (Testing)

```yaml
# Pure in-memory for testing
storage:
  redis:
    enabled: false
  database:
    enabled: false

cache:
  backend: "memory"
  max_entries: 1000
  cleanup_interval: 300

audit:
  backend: "memory"
  retention_days: 1
```

### Storage Benefits by Type

#### Redis Advantages

✅ **Automatic TTL**: Built-in expiration handling ✅ **High Performance**:
Sub-millisecond access times ✅ **Horizontal Scaling**: Shared across multiple
proxy instances ✅ **Memory Efficient**: Optimized data structures ✅
**Pub/Sub**: Real-time cache invalidation across instances

#### Database Advantages

✅ **ACID Compliance**: Reliable transactions for critical data ✅ **Rich
Queries**: Complex user management and analytics ✅ **Audit Trail**: Complete
authentication history ✅ **Backup/Recovery**: Enterprise-grade data protection
✅ **Data Integrity**: Foreign keys and constraints

### Migration Strategy

1. **Phase 7**: In-memory only (development/testing)
2. **Phase 8a**: Add Redis support (production caching)
3. **Phase 8b**: Add Database support (persistent data)
4. **Phase 9**: Advanced features (analytics, user management)

### Dependencies

```toml
# Add to Cargo.toml for hybrid storage
redis = { version = "0.24", features = ["tokio-comp"] }
sqlx = { version = "0.7", features = ["postgres", "sqlite", "runtime-tokio-rustls", "chrono", "uuid"] }
```

### Storage Backend Selection

| Use Case             | Redis       | Database      | Configuration              |
| -------------------- | ----------- | ------------- | -------------------------- |
| **Development**      | ❌ None     | ✅ SQLite     | Simple file-based          |
| **Light Production** | ❌ None     | ✅ SQLite     | Single instance, low users |
| **Production**       | ✅ Required | ✅ PostgreSQL | Multi-instance, high scale |
| **Testing**          | ❌ None     | ❌ None       | Pure in-memory             |

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

**Overall Progress**: **~85% Complete** - Production-ready OAuth SSO proxy with
full functionality

### **✅ COMPLETED PHASES (6/9)**

- **Phase 1-6**: Core infrastructure, auth, AWS integration, streaming, testing

### **🔄 IN PROGRESS (Phase 7 & 8)**

- **Phase 7**: Missing professional logging system
- **Phase 8**: ~60% complete (metrics, graceful shutdown ✅)
- **Remaining**: Security headers, request/response logging, API documentation,
  performance optimization

### **❌ PENDING (Phase 9)**

- **Deployment**: Docker, CI/CD, Kubernetes deployment artifacts

### **🏆 KEY ACHIEVEMENTS**

- **152 Tests Passing**: 130 unit + 7 integration + 10 security + 5 storage
- **Complete OAuth System**: Backend + Frontend with 6 built-in providers
- **Production Architecture**: Error handling, logging, health checks, metrics,
  graceful shutdown
- **Security**: JWT validation, OAuth 2.0, CSRF protection, token rotation
- **Prometheus Metrics**: HTTP requests, JWT validation, OAuth operations, AWS
  Bedrock calls
- **Graceful Shutdown**: Signal handling with component coordination and timeout
  management

**The system is fully production-ready with comprehensive monitoring and
reliability features!**

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

### Phase 8: Production Readiness 🔄 IN PROGRESS

**Goal**: Production-grade features

- [x] Comprehensive error handling (AppError system with proper HTTP status
      mapping)
- [ ] Request/response logging (Professional structured logging system)
- [ ] Basic security headers (CORS, security middleware)
- [x] Health checks (OAuth, AWS, and system health monitoring)
- [x] Configuration management (Environment variables, YAML config)
- [x] Error recovery and fallback mechanisms
- [x] Metrics collection (Prometheus metrics server with comprehensive tracking)
- [x] Rate limiting (Disabled by default per simplified architecture design)
- [x] Graceful shutdown handling (Signal handling with component coordination)
- [ ] API documentation (OpenAPI/Swagger)
- [ ] Performance optimization and benchmarking

**Deliverable**: Production-ready application with monitoring, metrics, and
graceful shutdown (API docs and performance optimization pending)

### Phase 8.1: Anthropic API Format Support ❌ PENDING

**Goal**: Add Anthropic API format compatibility for enhanced LLM gateway
integration

- [ ] Create Anthropic request/response data structures
- [ ] Implement model ID mapping (Anthropic → Bedrock format)
- [ ] Add request/response transformation logic
- [ ] Create `/v1/messages` endpoint handler
- [ ] Add streaming support for Anthropic format
- [ ] Implement error handling for transformation failures
- [ ] Add comprehensive tests for Anthropic format
- [ ] Update frontend to show both endpoint options
- [ ] Update documentation with dual format support

**Deliverable**: Dual format support (Bedrock + Anthropic) with comprehensive
testing

**Benefits**:

- ✅ **Better LLM Gateway Compatibility**: Works with more proxy solutions
- ✅ **Anthropic SDK Support**: Direct compatibility with official Anthropic
  SDKs
- ✅ **Enhanced Claude Code Integration**: Better support for
  ANTHROPIC_BEDROCK_BASE_URL
- ✅ **Easier Client Migration**: Supports both formats simultaneously

### Phase 8.5: Additional Features ❌ PENDING

**Goal**: Enhanced functionality and cost tracking

- [ ] **Rate Limiting Removal**: Simplify architecture by removing rate limiting
      system
- [ ] **Token Usage Tracking**: Track input/output tokens, requests, and costs
      per user per model
- [ ] **Multi-Region Support**: Dynamic region routing based on model name
      prefixes

**Deliverable**: Cost tracking, global deployment support, and simplified
architecture

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

### New Module Structure

```
src/
├── auth/
│   ├── mod.rs           # Re-exports
│   ├── jwt.rs           # Enhanced JWT validation (legacy + OAuth)
│   ├── oauth.rs         # OAuth provider integration
│   ├── cache.rs         # Validation caching with concurrent HashMap
│   └── middleware.rs    # Enhanced auth middleware
├── routes/
│   ├── mod.rs
│   ├── auth.rs          # OAuth endpoints (/auth/*)
│   └── bedrock.rs       # Existing Bedrock endpoints
├── config.rs            # Enhanced configuration with OAuth support
└── main.rs              # Server with new routes
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

#### Data Model

```rust
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UsageRecord {
    pub id: Option<i32>,
    pub user_id: i32,              // Foreign key to users table
    pub model_id: String,          // Original model ID (with region prefix)
    pub region: String,            // Determined AWS region
    pub request_time: DateTime<Utc>,
    pub input_tokens: u32,         // Tokens in request
    pub output_tokens: u32,        // Tokens in response
    pub total_tokens: u32,         // input_tokens + output_tokens
    pub response_time_ms: u32,     // Response time in milliseconds
    pub success: bool,             // Whether request succeeded
    pub error_message: Option<String>, // Error details if failed
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
}
```

#### Database Schema

```sql
-- Usage tracking table
CREATE TABLE usage_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    model_id TEXT NOT NULL,
    region TEXT NOT NULL,
    request_time DATETIME NOT NULL,
    input_tokens INTEGER NOT NULL,
    output_tokens INTEGER NOT NULL,
    total_tokens INTEGER NOT NULL,
    response_time_ms INTEGER NOT NULL,
    success BOOLEAN NOT NULL,
    error_message TEXT,
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
    UNIQUE(user_id, model_id, period_start),
    FOREIGN KEY (user_id) REFERENCES users (id)
);
```

#### API Endpoints

```rust
// User usage endpoints
GET /api/v1/usage/summary?period=day|week|month&model=*
GET /api/v1/usage/detailed?start=date&end=date&model=*

// Admin usage endpoints (requires admin privileges)
GET /api/v1/admin/usage/users/{user_id}?period=day|week|month
GET /api/v1/admin/usage/models/{model_id}?period=day|week|month
GET /api/v1/admin/usage/aggregate?period=day|week|month
```

#### Usage Tracking Integration

```rust
// Middleware for capturing usage data
pub async fn usage_tracking_middleware(
    claims: Claims,
    req: Request,
    next: Next,
) -> Result<Response, AppError> {
    let start_time = Instant::now();
    let model_id = extract_model_id(&req).unwrap_or_default();
    let region = determine_region(&model_id);

    // Count input tokens from request body
    let input_tokens = count_tokens_from_request(&req).await?;

    let response = next.run(req).await;
    let response_time_ms = start_time.elapsed().as_millis() as u32;

    // Count output tokens from response
    let output_tokens = count_tokens_from_response(&response).await?;

    // Record usage asynchronously (non-blocking)
    tokio::spawn(async move {
        let usage_record = UsageRecord {
            id: None,
            user_id: get_user_id_from_claims(&claims).await.unwrap_or(0),
            model_id,
            region,
            request_time: Utc::now(),
            input_tokens,
            output_tokens,
            total_tokens: input_tokens + output_tokens,
            response_time_ms,
            success: response.status().is_success(),
            error_message: if response.status().is_success() { None } else { Some("Request failed".to_string()) },
        };

        if let Err(e) = store_usage_record(&usage_record).await {
            warn!("Failed to store usage record: {}", e);
        }
    });

    Ok(response)
}
```

#### Token Counting

```rust
// Token counting from AWS Bedrock response headers or body analysis
pub async fn count_tokens_from_response(response: &Response) -> Result<u32, AppError> {
    // Method 1: Check for AWS Bedrock token count headers
    if let Some(token_count) = response.headers().get("x-amzn-bedrock-output-token-count") {
        return Ok(token_count.to_str()?.parse()?);
    }

    // Method 2: Parse from response body (model-specific)
    let body = response.body();
    match extract_token_count_from_body(body).await {
        Ok(count) => Ok(count),
        Err(_) => {
            // Method 3: Estimate based on text length
            Ok(estimate_token_count_from_text(body).await?)
        }
    }
}
```

### 3. Multi-Region Support

#### Purpose

Enable dynamic routing to different AWS regions based on model name prefixes:

- `apac.anthropic.claude-3-sonnet-20240229-v1:0` → `ap-northeast-1`
- `us.anthropic.claude-3-sonnet-20240229-v1:0` → `us-east-1`
- `eu.anthropic.claude-3-sonnet-20240229-v1:0` → `eu-west-1`
- `anthropic.claude-3-sonnet-20240229-v1:0` → `us-east-1` (default)

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
    pub original_model_id: String,  // apac.anthropic.claude-3-sonnet-20240229-v1:0
    pub region: String,             // ap-northeast-1
    pub bedrock_model_id: String,   // anthropic.claude-3-sonnet-20240229-v1:0 (prefix stripped)
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

#### Phase 8.5.1: Rate Limiting Removal (2-3 hours)

1. **Configuration Update**: Set `rate_limit.enabled = false` as default
2. **Middleware Removal**: Remove rate limiting middleware from routes
3. **Cleanup**: Remove unused imports and rate limiting initialization
4. **Testing**: Update/remove 15 rate limiting tests
5. **Documentation**: Update configuration examples

#### Phase 8.5.2: Token Usage Tracking (6-8 hours)

1. **Database Schema**: Add usage tracking tables and migrations
2. **Storage Layer**: Implement usage recording and querying methods
3. **Middleware**: Add usage tracking middleware to capture request/response
   data
4. **API Endpoints**: Implement usage summary and detailed reporting endpoints
5. **Token Counting**: Implement token counting from AWS responses
6. **Testing**: Add comprehensive usage tracking tests
7. **Documentation**: Usage tracking API documentation

#### Phase 8.5.3: Multi-Region Support (3-4 hours)

1. **Configuration**: Update AWS config structure for region mapping
2. **Multi-Region Client**: Implement multi-region AWS client with shared
   credentials
3. **Model Parsing**: Implement model ID prefix parsing and region determination
4. **Route Updates**: Update invoke handlers to use region-specific clients
5. **Health Checks**: Add regional health monitoring
6. **Testing**: Add multi-region routing and fallback tests
7. **Documentation**: Multi-region configuration and usage guide

**Total Estimated Effort**: 10-14 hours

- **Development**: 8-12 hours
- **Testing**: 2-3 hours
- **Documentation**: 1 hour

## Client Integration Guide

### Claude Code Integration

#### Method 1: Environment Variables

```bash
export BEDROCK_TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
export BEDROCK_ENDPOINT="https://your-proxy-domain.com"
```

#### Method 2: Claude Code Configuration

```bash
# Set the Bedrock proxy endpoint
claude-code config set bedrock.endpoint "https://your-proxy-domain.com"

# Set the authentication token
claude-code config set bedrock.token "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
```

#### Method 3: Config File (~/.claude/config.json)

```json
{
  "bedrock": {
    "endpoint": "https://your-proxy-domain.com",
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "refresh_token": "refresh_token_here"
  }
}
```

### API Client Integration (Generic)

#### HTTP Headers

```http
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
Content-Type: application/json
```

#### Example API Call

```bash
curl -X POST "https://your-proxy-domain.com/model/anthropic.claude-3-sonnet-20240229-v1:0/invoke" \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." \
  -H "Content-Type: application/json" \
  -d '{
    "anthropic_version": "bedrock-2023-05-31",
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

## Frontend Implementation (Future Phase)

### Simple HTML/JS Frontend

- **OAuth Flow**: Handle redirect, display tokens, show setup instructions
- **Provider Selection**: List available providers from `/auth/providers`
- **Token Display**: Show access token and refresh token
- **Setup Guide**: Copy-paste instructions for claude-code
- **Token Management**: Basic token validation and refresh

### Features for Later Implementation

- [ ] Simple HTML page with OAuth provider buttons
- [ ] OAuth redirect handling with token display
- [ ] Claude Code setup instructions generator
- [ ] Token validation and refresh UI
- [ ] Provider configuration examples
- [ ] Copy-to-clipboard functionality for tokens
