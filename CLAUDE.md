# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with
code in this repository.

## Project Overview

**Bedrock SSO Proxy** is a JWT-authenticated HTTP proxy server that provides
secure access to AWS Bedrock APIs. It acts as an intermediary between clients
and AWS Bedrock, handling JWT authentication and request forwarding with AWS
Signature V4 signing.

## Architecture

```
[Client] → [Proxy Server with Service Layer] → [AWS Bedrock API]
           ↑ Dual Auth + TypedCache        ↑ BedrockRuntime + Usage Tracking
```

**Service-Based Architecture:**

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Web Client    │    │  API Client      │    │  Admin Client   │
│ (OAuth + JWT)   │    │ (API Keys)       │    │ (Email-based)   │
└─────────┬───────┘    └────────┬─────────┘    └─────────┬───────┘
          │                     │                        │
          └─────────────────────┼────────────────────────┘
                                │
                    ┌───────────▼───────────┐
                    │    Router Layer       │
                    │  (Auth Middleware)    │
                    └───────────┬───────────┘
                                │
                ┌───────────────▼───────────────┐
                │       Service Layer           │
                │ • ModelService (Usage Track) │
                │ • HealthService (Monitoring) │
                │ • OAuthService (Auth Flow)   │
                │ • JwtService (Token Mgmt)    │
                └───────────────┬───────────────┘
                                │
            ┌───────────────────▼───────────────────┐
            │        Infrastructure Layer           │
            │ • TypedCache (Structural Hashing)    │
            │ • Database (SeaORM + Migrations)     │
            │ • BedrockRuntime (AWS Integration)   │
            │ • CostTracking (CSV + Batch Ops)     │
            └───────────────────┬───────────────────┘
                                │
                    ┌───────────▼───────────┐
                    │     AWS Bedrock       │
                    │   (Signature V4)      │
                    └───────────────────────┘
```

### Core Components

- **`src/server/mod.rs`**: Service-based HTTP server with dependency injection
- **`src/auth/`**: Multi-strategy authentication (JWT, OAuth, API keys)
- **`src/model_service/`**: Model invocation with usage tracking and cost
  monitoring
- **`src/database/`**: SeaORM-based data access with cached DAOs
- **`src/cache/`**: TypedCache system with Redis/memory backends
- **`src/aws/bedrock.rs`**: AWS Bedrock runtime with health checks

### Key Routes

**Health & Status:**

- `GET /health` - Public health check endpoint

**Bedrock Format (AWS Native):**

- `POST /bedrock/model/{model_id}/invoke` - Standard model invocation (JWT
  protected)
- `POST /bedrock/model/{model_id}/invoke-with-response-stream` - Streaming
  responses (JWT protected)

**Anthropic Format (Standard API):**

- `POST /anthropic/v1/messages` - Standard Anthropic API with streaming support
  (JWT protected)

The proxy now supports both AWS Bedrock and standard Anthropic API formats for
maximum compatibility.

### Authentication

The proxy supports **dual authentication** methods:

1. **JWT Authentication**: OAuth-based web authentication for browser access
2. **API Key Authentication**: Programmatic access for applications and scripts

### API Key Management

**Create API Key** (requires JWT authentication):

```bash
curl -X POST "http://localhost:3000/api/keys" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "My App Key",
    "expires_in_days": 90
  }'
```

**List API Keys**:

```bash
curl "http://localhost:3000/api/keys" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
```

**Revoke API Key**:

```bash
curl -X DELETE "http://localhost:3000/api/keys/{key_id}" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
```

### API Usage Examples

**Bedrock Format (JWT Auth):**

```bash
curl -X POST "http://localhost:3000/bedrock/model/anthropic.claude-sonnet-4-20250514-v1:0/invoke" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "anthropic_version": "bedrock-2023-05-31",
    "max_tokens": 1000,
    "messages": [{"role": "user", "content": "Hello!"}]
  }'
```

**Bedrock Format (API Key Auth):**

```bash
curl -X POST "http://localhost:3000/bedrock/model/anthropic.claude-sonnet-4-20250514-v1:0/invoke" \
  -H "Authorization: Bearer SSOK_your_api_key_here" \
  -H "Content-Type: application/json" \
  -d '{
    "anthropic_version": "bedrock-2023-05-31",
    "max_tokens": 1000,
    "messages": [{"role": "user", "content": "Hello!"}]
  }'
```

**Anthropic Format (API Key with X-API-Key header):**

```bash
curl -X POST "http://localhost:3000/anthropic/v1/messages" \
  -H "X-API-Key: SSOK_your_api_key_here" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "claude-sonnet-4-20250514",
    "max_tokens": 1000,
    "messages": [{"role": "user", "content": "Hello!"}]
  }'
```

**Anthropic Format (Streaming with API Key):**

```bash
curl -X POST "http://localhost:3000/anthropic/v1/messages" \
  -H "Authorization: Bearer SSOK_your_api_key_here" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "claude-sonnet-4-20250514",
    "max_tokens": 1000,
    "messages": [{"role": "user", "content": "Hello!"}],
    "stream": true
  }'
```

## Development Commands

### Build and Development

```bash
cargo build                   # Build project (debug mode with unminified frontend + source maps)
cargo build --release         # Production build (minified frontend + source maps)
cargo build --features frontend # Force frontend build in dev mode
cargo run --bin bedrock_proxy # Run server
cargo test                    # Run all tests (117 total)
cargo clippy                  # Lint code (required before commit)
cargo fmt                     # Format code (required before commit)
cargo clean                   # Clean Rust build artifacts only
./clean-all.sh                # Alternative: run cleanup script directly
```

**Note**: Frontend is automatically built with appropriate optimizations:

- **Debug mode** (`cargo build`): Unminified code with source maps for
  development debugging
- **Release mode** (`cargo build --release`): Minified code with source maps for
  production

### Frontend Development

```bash
cd frontend                   # Change to frontend directory
npm install                   # Install dependencies
npm run dev                   # Start development server
npm run build                 # Build for production (minified + source maps)
npm run build:debug           # Build for development (unminified + source maps)
npm run lint                  # Lint TypeScript/React code (required before commit)
npm run lint:fix              # Auto-fix linting issues
npm run format                # Format code with Prettier (required before commit)
npm run format:check          # Check code formatting
npm run type-check            # TypeScript type checking
```

### E2E Testing

```bash
# Build and run the test client
cargo build --example e2e_client
cargo run --example e2e_client -- health         # Health check
cargo run --example e2e_client -- chat           # Interactive chat
cargo run --example e2e_client -- message --text "Hello" # Single message
```

### Testing

```bash
cargo test                    # All tests (unit + integration + security)
cargo test auth               # Authentication tests only
cargo test security           # Security vulnerability tests
cargo test --test jwt_integration_tests # JWT integration tests
cargo test --test cached_integration_test # Cached DAO tests
cargo test --test usage_tracking_integration_tests # Usage tracking tests
```

### CLI Commands

```bash
# Database migration commands
cargo run --bin bedrock_proxy -- migrate up       # Run all pending migrations
cargo run --bin bedrock_proxy -- migrate down     # Rollback last migration
cargo run --bin bedrock_proxy -- migrate status   # Show migration status
```

## Service Layer Architecture

The proxy uses a service-based architecture with dependency injection for
testability and modularity:

### Core Services

**ModelService** (`src/model_service/`):

- Model invocation with usage tracking and cost monitoring
- Handles both Bedrock and Anthropic API formats
- Streams responses with connection management
- Tracks token usage and costs per request

**AuthService Layer** (`src/auth/`):

- **JwtService**: Token generation, validation, and refresh
- **OAuthService**: Multi-provider OAuth flow management
- **ApiKeyService**: API key generation, validation, and revocation
- **Middleware**: Unified authentication (JWT or API keys)

**DatabaseManager** (`src/database/`):

- **Cached DAOs**: Users, API keys with TypedCache integration
- **Direct DAOs**: Usage tracking, audit logs, refresh tokens
- **Migration management**: Automated schema updates

**CacheManager** (`src/cache/`):

- **TypedCache**: Structural hashing with automatic invalidation
- **Backend abstraction**: Memory (dev) or Redis (prod)
- **Health monitoring**: Connection status and performance metrics

### Service Dependencies

Services are injected through the `Server` struct:

```rust
pub struct Server {
    pub config: Arc<Config>,
    pub jwt_service: Arc<dyn JwtService>,
    pub model_service: Arc<dyn ModelService>,
    pub oauth_service: Arc<OAuthService>,
    pub health_service: Arc<HealthService>,
    pub database: Arc<dyn DatabaseManager>,
    pub cache: Arc<dyn CacheManager>,
}
```

This enables:

- **Easy testing**: Services can be mocked individually
- **Health monitoring**: Each service provides health checks
- **Graceful shutdown**: Services coordinate shutdown sequence
- **Configuration**: Services share configuration through dependency injection

## Key Dependencies

- **`axum ^0.8`** - Web framework with WebSocket support
- **`tokio ^1.0`** - Async runtime with full features
- **`reqwest ^0.12`** - HTTP client with JSON and streaming
- **`jsonwebtoken ^9.0`** - JWT validation (HS256 only)
- **`aws-sigv4 ^1.0`** - AWS request signing
- **`config ^0.15`** - Configuration management
- **`sea-orm ^1.1`** - Database ORM with migrations
- **`redis ^0.32`** - Redis client for distributed caching

## Configuration

### File Structure

Configuration uses hierarchical loading: defaults → YAML file → environment
variables

```yaml
server:
  host: "0.0.0.0"
  port: 3000
jwt:
  secret: "your-jwt-secret"
aws:
  region: "us-east-1"
  access_key_id: "optional"
  secret_access_key: "optional"
logging:
  level: "info"
cache:
  backend: "memory" # or "redis"
  redis_url: "redis://localhost:6379"
  redis_key_prefix: "bedrock_sso:"
  validation_ttl: 3600
  max_entries: 10000
  cleanup_interval: 3600
database:
  enabled: true
  url: "sqlite://./data/bedrock_sso.db"
  max_connections: 5
  migration_on_startup: true
metrics:
  enabled: true
  port: 9090
```

### Environment Variables

Use `BEDROCK_` prefix with double underscores for nesting:

- `BEDROCK_SERVER__PORT=3000`
- `BEDROCK_JWT__SECRET=secret`
- `BEDROCK_AWS__REGION=us-east-1`
- `BEDROCK_CACHE__BACKEND=redis`
- `BEDROCK_CACHE__REDIS_URL=redis://localhost:6379`
- `BEDROCK_CACHE__REDIS_KEY_PREFIX=bedrock_sso:`
- `BEDROCK_DATABASE__URL=sqlite://./data/bedrock_sso.db`
- `BEDROCK_METRICS__ENABLED=true`
- `BEDROCK_METRICS__PORT=9090`

### Cache Configuration

The proxy supports both in-memory and Redis caching:

**Memory Cache (Default):**

- Suitable for single-instance deployments
- No external dependencies
- Data lost on restart

**Redis Cache:**

- Suitable for production/distributed deployments
- Persistent across restarts
- Scalable for multiple instances

```yaml
cache:
  backend: "redis" # "memory" or "redis"
  redis_url: "redis://localhost:6379" # Redis connection URL
  redis_key_prefix: "bedrock_sso:" # Key prefix to avoid conflicts
  validation_ttl: 3600 # JWT validation cache TTL (seconds)
  max_entries: 10000 # Max cache entries (memory only)
  cleanup_interval: 3600 # Cache cleanup interval (seconds)
```

**Cache Usage:**

- OAuth state tokens (temporary, ~10 minutes)
- JWT validation results (configurable TTL)
- API key lookups (until revoked)

## Development Best Practices

- If there is any functional update, update DESIGN.md too
- You should always follow design in DESIGN.md when coding
- After each phase, do a commit and make it easy to review and rewind
- When adding a dep, make sure it's the latest version
- You should add tests for new code when a phase is finished

### Pre-Commit Workflow (REQUIRED)

**Backend (Rust):**

```bash
cargo fmt          # Format code
cargo clippy       # Check linting/warnings
cargo test         # Run tests
```

**Frontend (React/TypeScript):**

```bash
cd frontend
npm run format     # Format with Prettier
npm run lint       # ESLint checks
npm run type-check # TypeScript validation
```

**Always run these before committing** - no exceptions! This ensures code
quality and consistency.

## Project Status

**Completed Phases (8/9)**:

- ✅ Phase 1: Core infrastructure and configuration
- ✅ Phase 2: JWT authentication layer
- ✅ Phase 3: AWS Bedrock integration with credential handling
- ✅ Phase 4: Standard API implementation with direct HTTP client
- ✅ Phase 5: Streaming API implementation (SSE)
- ✅ Phase 6: Comprehensive testing suite (117 tests)
- ✅ Phase 7: OAuth integration with React frontend
- ✅ Phase 8: Production readiness (metrics, graceful shutdown)
- ✅ Phase 8.1: Anthropic API format support (dual format compatibility)
- ✅ Phase 8.5.1: Rate limiting removal (simplified request handling)

**Remaining Phases**:

- ❌ Phase 9: Deployment (Docker, CI/CD, Kubernetes)

## Testing Architecture

- **Unit Tests**: 100 tests covering all modules including OAuth functionality
- **Integration Tests**: 7 tests with real JWT token validation
- **Security Tests**: 10 comprehensive security attack simulations
- **Total Test Coverage**: 117 tests passing (100 unit + 7 integration + 10
  security)
- **Test Coverage**: Authentication, OAuth, routing, streaming, error handling,
  security vulnerabilities

## Security Features

- **JWT Validation**: HS256 with strict expiration validation, zero leeway
- **OAuth 2.0 Integration**: Full OAuth flow with state validation and CSRF
  protection
- **Token Management**: Refresh token rotation and validation result caching
- **Header Processing**: Strips Authorization headers before AWS forwarding
- **AWS Signing**: Proper Signature V4 implementation for AWS authentication
- **Error Handling**: No sensitive information exposure in responses
- **Multi-Provider Support**: Google, GitHub, Microsoft, GitLab, Auth0, Okta,
  and custom providers

## Project Workflow Notes

- When clearing context between phases, summarize key changes and prepare notes
  for the next phase of development
- Keep track of context clearing to ensure continuity and understanding of
  project progression

## Development Workflow

### Service Testing

For testing individual services, use the `test_utils::TestServerBuilder`:

```rust
// Create test server with all services
let server = TestServerBuilder::new().build().await;

// Test with mocked services
let server = TestServerBuilder::new()
    .with_jwt_service(mock_jwt_service)
    .with_model_service(mock_model_service)
    .build().await;
```

### Working with TypedCache

The TypedCache system provides automatic cache invalidation:

```rust
// Define cached object
#[derive(CachedObject)]
struct User {
    id: String,
    email: String,
}

// Get typed cache
let cache = cache_manager.get_typed_cache::<User>();

// Operations are type-safe and auto-invalidate
cache.set("user_123", &user).await?;
```

### Running Specific Tests

```bash
# Run specific test file
cargo test --test jwt_integration_tests

# Run specific test function
cargo test test_jwt_validation

# Run tests with output
cargo test -- --nocapture

# Run single test module
cargo test auth::tests::
```

### Database Development

```bash
# Create new migration
sea-orm-cli migrate generate create_new_table

# Reset database (dev only)
rm data/bedrock_sso.db
cargo run --bin bedrock_proxy -- migrate up
```

### Background Process Note

- If you need to run a test server, ask user to do it, you can not spawn
  background process.

## Important Project Notes

### Architecture Decision Records

- **Service-based design**: All major functionality is isolated in services with
  dependency injection
- **TypedCache**: Structural hashing prevents cache invalidation bugs
- **Dual authentication**: JWT for web clients, API keys for programmatic access
- **Graceful shutdown**: Services coordinate shutdown in proper order (tokens →
  streaming → cache → database)

### Key Patterns

- **Health checks**: All services implement `HealthChecker` trait for monitoring
- **Error handling**: Consistent error types across layers with proper HTTP
  status mapping
- **Configuration**: Hierarchical loading (defaults → YAML → env vars)
- **Testing**: `TestServerBuilder` for integration tests with service mocking

### Performance Considerations

- **Streaming**: Long-lived connections are tracked and properly closed during
  shutdown
- **Caching**: TypedCache with structural hashing for efficient invalidation
- **Database**: SeaORM with connection pooling and async operations
- **Memory**: Request body size limited to 10MB to prevent DoS attacks

### Coding Guidelines

- **Imports**: If you are referring to something in the crate, import it instead
  using an absolute path
- Use import as possible, unless it causes naming conflicts
- When using entities in database, use type alias instead of raw Model name,
  like UserRecord against users::Model
