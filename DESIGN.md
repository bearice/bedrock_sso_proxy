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
5. **Proxy generates long-lived JWT** (30 days) with refresh token
6. **Client stores tokens** and uses JWT for subsequent requests

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

## AWS Bedrock API Forwarding

### Supported Endpoints

#### 1. InvokeModel
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
  access_token_ttl: 2592000  # 30 days
  refresh_token_ttl: 7776000  # 90 days

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
  validation_ttl: 86400  # 24 hours
  max_entries: 10000
  cleanup_interval: 3600  # 1 hour

aws:
  region: "us-east-1"
  access_key_id: "optional"
  secret_access_key: "optional"

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

#### JWT Claims Structure (Enhanced)
```json
{
  "sub": "google:123456789",
  "iat": 1234567890,
  "exp": 1234567890,
  "provider": "google",
  "email": "user@example.com",
  "scopes": ["bedrock:invoke"],
  "refresh_token_id": "uuid-v4-here"
}
```

#### Validation Cache Security
- **Cache Key**: `oauth_validation:{provider}:{user_id}:{token_hash}`
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
  backend: "redis"      # Use Redis for all cache operations
  fallback: "memory"    # Fall back to memory if Redis unavailable
  
audit:
  backend: "database"   # Store audit logs in database
  retention_days: 365   # Keep logs for 1 year
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
  backend: "memory"     # In-memory cache for development
  max_entries: 10000
  cleanup_interval: 3600

audit:
  backend: "database"   # Store in SQLite
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
✅ **Automatic TTL**: Built-in expiration handling
✅ **High Performance**: Sub-millisecond access times
✅ **Horizontal Scaling**: Shared across multiple proxy instances
✅ **Memory Efficient**: Optimized data structures
✅ **Pub/Sub**: Real-time cache invalidation across instances

#### Database Advantages  
✅ **ACID Compliance**: Reliable transactions for critical data
✅ **Rich Queries**: Complex user management and analytics
✅ **Audit Trail**: Complete authentication history
✅ **Backup/Recovery**: Enterprise-grade data protection
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

| Use Case | Redis | Database | Configuration |
|----------|-------|----------|---------------|
| **Development** | ❌ None | ✅ SQLite | Simple file-based |
| **Light Production** | ❌ None | ✅ SQLite | Single instance, low users |
| **Production** | ✅ Required | ✅ PostgreSQL | Multi-instance, high scale |
| **Testing** | ❌ None | ❌ None | Pure in-memory |

### Provider Configuration Strategy

#### Predefined Well-Known Providers (Easy Setup)
Admins only need to provide `client_id` and `client_secret` for common providers:

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
      tenant_id: "your-tenant-id"  # Optional, defaults to 'common'
      
    # GitLab - minimal config required
    gitlab:
      client_id: "your-gitlab-client-id"
      client_secret: "your-gitlab-client-secret"
      # Optional: specify instance for self-hosted GitLab
      instance_url: "https://gitlab.mycompany.com"  # Optional, defaults to gitlab.com
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
      scopes: ["openid", "email", "profile", "https://www.googleapis.com/auth/calendar.readonly"]
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
tenant_id: "common"  # Default to multi-tenant
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
instance_url: "https://gitlab.com"  # Default to gitlab.com
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
- ✅ **Best Practices**: Predefined scopes and endpoints follow OAuth best practices
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
1. **Accept requests** at `POST /model/{modelId}/invoke-with-bidirectional-stream`
2. **Upgrade to WebSocket** after JWT validation
3. **Establish AWS stream** and proxy bidirectional communication
4. **Handle 8-minute timeout** and connection cleanup

## Multi-Stage Development Plan

### Phase 1: Core Infrastructure ✅ COMPLETED
**Goal**: Set up project foundation and build system
- [x] Update Cargo.toml with all dependencies (latest versions with required features)
- [x] Create project structure (modules, lib.rs, main.rs)
- [x] Implement configuration management with `config` crate
- [x] Set up logging with `tracing`
- [x] Basic CLI argument parsing
- [x] Health check endpoint
- [x] Comprehensive test suite (23 tests passing)
- [x] JWT authentication middleware
- [x] AWS Bedrock client initialization
- [x] Error handling with HTTP status mapping

**Deliverable**: ✅ Runnable server with configuration loading, JWT auth, and full test coverage

### Phase 2: Authentication Layer ✅ COMPLETED
**Goal**: Implement JWT validation middleware
- [x] JWT validation module with Claims struct
- [x] Auth middleware for Axum with proper Bearer token extraction
- [x] Error handling for auth failures (proper Unauthorized responses)
- [x] Unit tests for JWT validation (6 comprehensive test cases)
- [x] Integration tests for auth middleware (server-level tests)

**Deliverable**: ✅ JWT authentication working with test tokens, proper error handling, and comprehensive test coverage

### Phase 3: AWS Integration ✅ COMPLETED
**Goal**: Establish AWS Bedrock connectivity
- [x] AWS credential configuration with environment variable support
- [x] Bedrock client initialization with proper credential handling
- [x] Request/response header handling utilities
- [x] Basic AWS error handling and mapping to HTTP status codes
- [x] Connection health checks with dedicated endpoint

**Deliverable**: ✅ Can connect to AWS Bedrock with comprehensive credential support, header processing, and health monitoring

### Phase 4: Standard API Implementation ✅ COMPLETED
**Goal**: Implement core InvokeModel endpoint using direct HTTP client
- [x] POST /model/{modelId}/invoke route with JWT authentication
- [x] Direct HTTP client using reqwest for AWS Bedrock API calls
- [x] AWS Signature V4 signing implementation for authentication
- [x] Request body forwarding with proper header processing
- [x] Response proxying with status code and header mapping
- [x] Comprehensive error handling and HTTP status mapping
- [x] Integration tests covering authentication, routing, and error cases

**Deliverable**: ✅ Working InvokeModel proxy with direct HTTP client implementation, full test coverage, and proper AWS authentication

### Phase 5: Streaming APIs ✅
**Goal**: Implement streaming endpoints  
- [x] InvokeModelWithResponseStream (SSE)
- [x] Response stream proxying  
- [x] Stream error handling
- [x] ~~InvokeModelWithBidirectionalStream (WebSocket)~~ (Removed for simplicity)
- [x] ~~WebSocket connection management~~ (Removed for simplicity)

**Deliverable**: Server-Sent Events streaming endpoint working

### Phase 6: Testing Suite ✅ COMPLETED
**Goal**: Comprehensive test coverage
- [x] Unit tests for all modules (66.79% coverage achieved)
- [x] Integration tests with real JWT tokens (7 tests)
- [x] Mock AWS Bedrock responses for testing
- [x] Security testing with comprehensive attack simulations (10 tests)
- [x] E2E tests with test client functionality
- [x] Load testing for concurrent requests
- [x] Test coverage reporting with cargo-tarpaulin

**Deliverable**: ✅ Comprehensive test suite with 71 total tests (54 unit + 7 integration + 10 security) covering authentication, authorization, API endpoints, streaming, error handling, and security vulnerabilities

### Phase 7: OAuth Integration (NEW)
**Goal**: Implement generic OAuth 2.0 authentication with token management
- [ ] Generic OAuth provider integration supporting any OAuth 2.0 compliant provider
- [ ] Configurable provider endpoints (authorization_url, token_url, user_info_url)
- [ ] Flexible user data field mapping (user_id_field, email_field)
- [ ] Authorization code validation endpoints
- [ ] Long-lived JWT token generation with refresh capability
- [ ] Validation result caching (24h TTL) with concurrent HashMap
- [ ] Enhanced configuration for OAuth providers and cache settings
- [ ] Enhanced authentication middleware supporting both legacy and OAuth JWTs
- [ ] Token refresh endpoint with rotation
- [ ] Security enhancements and rate limiting
- [ ] Comprehensive testing for OAuth flows with multiple provider types

**Deliverable**: Generic OAuth-enabled authentication system with backward compatibility

### Phase 8: Production Readiness
**Goal**: Production-grade features
- [ ] Comprehensive error handling
- [ ] Request/response logging
- [ ] Metrics collection (Prometheus)
- [ ] Rate limiting per user
- [ ] Graceful shutdown
- [ ] Security headers
- [ ] API documentation (OpenAPI)
- [ ] Performance optimization

**Deliverable**: Production-ready application

### Phase 9: Release & Deployment
**Goal**: Packaging and deployment
- [ ] Dockerfile with multi-stage build
- [ ] Docker Compose for local development
- [ ] GitHub Actions CI/CD pipeline
- [ ] Kubernetes manifests
- [ ] Helm chart
- [ ] Release automation
- [ ] Monitoring setup
- [ ] Documentation (README, deployment guide)

**Deliverable**: Deployable release with documentation

## Generic OAuth Provider Support

### Configuration Structure
The system supports any OAuth 2.0 compliant provider through a generic configuration structure:

```yaml
oauth:
  providers:
    {provider_name}:
      client_id: "required"
      client_secret: "required"
      redirect_uri: "required"
      scopes: ["array", "of", "scopes"]
      authorization_url: "required"
      token_url: "required" 
      user_info_url: "required"
      user_id_field: "id"        # Field name for user ID in user info response
      email_field: "email"       # Field name for email in user info response
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