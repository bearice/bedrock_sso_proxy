# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with
code in this repository.

## Project Overview

**Bedrock SSO Proxy** is a JWT-authenticated HTTP proxy server that provides
secure access to AWS Bedrock APIs. It acts as an intermediary between clients
and AWS Bedrock, handling JWT authentication and request forwarding with AWS
Signature V4 signing.

The proxy includes comprehensive OpenAPI documentation accessible at `/docs` for
interactive API exploration and testing.

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
            │ • Cost System (CSV + Batch Ops)      │
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

**API Documentation:**

- `GET /docs` - Interactive Swagger UI documentation
- `GET /openapi.yaml` - OpenAPI specification in YAML format
- `GET /openapi.json` - OpenAPI specification in JSON format

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
cargo test --test api_key_integration_tests # API key integration tests
cargo test --test cached_integration_test # Cached DAO tests
cargo test --test cost_integration_tests # Cost tracking integration tests
cargo test --test usage_integration_tests # Usage tracking tests
```

### CLI Commands

```bash
# Database initialization commands (for deployment and cluster setup)
cargo run --bin bedrock_proxy -- init                                          # Initialize database with migrations and default data
cargo run --bin bedrock_proxy -- init --skip-costs                             # Initialize database without seeding model costs
cargo run --bin bedrock_proxy -- init --force-seed                             # Force re-seed default data even if exists

# Database migration commands
cargo run --bin bedrock_proxy -- migrate up       # Run all pending migrations
cargo run --bin bedrock_proxy -- migrate down     # Rollback last migration
cargo run --bin bedrock_proxy -- migrate status   # Show migration status

# Job management and background processing commands
cargo run --bin bedrock_proxy -- job list                                      # List available job types
cargo run --bin bedrock_proxy -- job status                                    # Check job system status

# Usage summary generation (improves API performance - runs automatically or manually)
cargo run --bin bedrock_proxy -- job summaries --period daily --days-back 30   # Generate daily summaries for last 30 days
cargo run --bin bedrock_proxy -- job summaries --period weekly                  # Generate weekly summaries (default: 30 days)
cargo run --bin bedrock_proxy -- job summaries --period monthly --days-back 90 # Generate monthly summaries for last 90 days
cargo run --bin bedrock_proxy -- job summaries --user-id 123                    # Process specific user only
cargo run --bin bedrock_proxy -- job summaries --model-id claude-sonnet-4       # Process specific model only
cargo run --bin bedrock_proxy -- job summaries --dry-run                        # Preview what would be generated

# Database cleanup commands
cargo run --bin bedrock_proxy -- job cleanup --dry-run                          # Preview cleanup of all types (uses config defaults)
cargo run --bin bedrock_proxy -- job cleanup --days-back 30                     # Clean all types with 30-day override
cargo run --bin bedrock_proxy -- job cleanup --target records --dry-run         # Preview raw records only (uses config: 30 days)
cargo run --bin bedrock_proxy -- job cleanup --target daily --days-back 180    # Clean daily summaries with override
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

**SummarizationService** (`src/summarization/`):

- **Usage data aggregation**: Converts raw records into performance summaries
- **Multi-period support**: Hourly, daily, weekly, monthly summaries
- **Cleanup operations**: Manages data retention policies
- **Summaries-first queries**: Optimized statistics with fallback to raw records

**Job System** (`src/jobs/`):

- **JobScheduler**: Cron-based background job execution with graceful shutdown
- **SummariesJob**: Automatic usage summary generation
- **CleanupJob**: Automatic data retention and cleanup
- **Dual deployment**: Internal (in-process) or external (cron/K8s) execution

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

**Security Note**: The JWT secret is required and must be provided via configuration file or the `BEDROCK_JWT__SECRET` environment variable. The application will fail to start if no JWT secret is configured.

```yaml
server:
  host: "0.0.0.0"
  port: 3000
jwt:
  secret: "your-jwt-secret"     # REQUIRED - Must be provided via config or env var
aws:
  region: "us-east-1"
  access_key_id: "optional"     # If not provided, uses AWS credential chain
  secret_access_key: "optional" # If not provided, uses AWS credential chain
  profile: "optional"           # AWS profile name from ~/.aws/config
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
  migration_on_startup: true  # Set to false for cluster deployments (disables migrations + cost init)
metrics:
  enabled: true
  port: 9090
jobs:
  enabled: true
  usage_summaries:
    schedule: "0 2 * * *"  # Daily at 2 AM
    periods: ["daily"]
  usage_cleanup:
    schedule: "0 3 * * *"  # Daily at 3 AM
    raw_records_days: 30
    summaries_retention_days:  # Period-specific retention (defaults provided if not specified)
      hourly: 7     # Keep hourly summaries for 7 days
      daily: 90     # Keep daily summaries for 90 days
      weekly: 365   # Keep weekly summaries for 1 year
      monthly: 1095 # Keep monthly summaries for 3 years
shutdown:
  timeout_seconds: 30
  streaming_timeout_seconds: 30
  token_tracking_timeout_seconds: 30
  background_task_timeout_seconds: 5
```

### Environment Variables

Use `BEDROCK_` prefix with double underscores for nesting:

- `BEDROCK_SERVER__PORT=3000`
- `BEDROCK_JWT__SECRET=your-secret-key`  # REQUIRED
- `BEDROCK_AWS__REGION=us-east-1`
- `BEDROCK_CACHE__BACKEND=redis`
- `BEDROCK_CACHE__REDIS_URL=redis://localhost:6379`
- `BEDROCK_CACHE__REDIS_KEY_PREFIX=bedrock_sso:`
- `BEDROCK_DATABASE__URL=sqlite://./data/bedrock_sso.db`
- `BEDROCK_DATABASE__MIGRATION_ON_STARTUP=false`  # For cluster deployments
- `BEDROCK_METRICS__ENABLED=true`
- `BEDROCK_METRICS__PORT=9090`
- `BEDROCK_JOBS__ENABLED=true`
- `BEDROCK_JOBS__USAGE_SUMMARIES__SCHEDULE="0 2 * * *"`
- `BEDROCK_JOBS__USAGE_CLEANUP__RAW_RECORDS_DAYS=30`
- `BEDROCK_JOBS__USAGE_CLEANUP__SUMMARIES_RETENTION_DAYS__HOURLY=7`
- `BEDROCK_JOBS__USAGE_CLEANUP__SUMMARIES_RETENTION_DAYS__DAILY=90`
- `BEDROCK_JOBS__USAGE_CLEANUP__SUMMARIES_RETENTION_DAYS__WEEKLY=365`
- `BEDROCK_JOBS__USAGE_CLEANUP__SUMMARIES_RETENTION_DAYS__MONTHLY=1095`
- `BEDROCK_SHUTDOWN__TIMEOUT_SECONDS=30`
- `BEDROCK_SHUTDOWN__STREAMING_TIMEOUT_SECONDS=30`

### AWS Credential Chain Support

The proxy now supports the standard AWS credential chain, trying credentials in this order:

1. **Explicit config**: `access_key_id` and `secret_access_key` from configuration
2. **Environment variables**: `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`
3. **AWS profiles**: `~/.aws/credentials` and `~/.aws/config` files
4. **IAM roles**: EC2 instance roles, ECS task roles, Lambda execution roles
5. **AWS SSO**: Single Sign-On credentials
6. **Container credentials**: ECS/Fargate container metadata service

**Usage Examples:**

```bash
# Using environment variables
export AWS_ACCESS_KEY_ID=your_access_key
export AWS_SECRET_ACCESS_KEY=your_secret_key
export AWS_REGION=us-east-1
cargo run --bin bedrock_proxy

# Using AWS profile
export AWS_PROFILE=my-profile
cargo run --bin bedrock_proxy

# Using explicit configuration
echo "aws:
  region: us-east-1
  profile: my-profile" > config.yaml
cargo run --bin bedrock_proxy
```

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

- **Unit Tests**: 221 tests covering all modules including OAuth functionality
- **Integration Tests**: 49 tests across 5 test files
  - JWT integration tests: 7 tests
  - API key integration tests: 6 tests
  - Cached DAO tests: 8 tests
  - Cost integration tests: 10 tests
  - Usage integration tests: 8 tests
- **Security Tests**: 13 comprehensive security attack simulations
- **Total Test Coverage**: 285 tests passing (221 unit + 49 integration + 13 security + 1 doc)
- **Test Coverage**: Authentication, OAuth, routing, streaming, error handling, security vulnerabilities, caching, cost tracking, usage tracking

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

### Coding Guidelines (!!IMPORTANT!!)

- If you are referring to something in the crate, you MUST import it instead using an absolute path
- You MUST use import as possible, unless it causes naming conflicts
- When using entities in database, you MUST use type alias instead of raw Model name,
  like UserRecord against users::Model see `src/database/entities/mod.rs` or following defs.
    ```
    // Type aliases
    pub type UserRecord = users::Model;
    pub type RefreshTokenData = refresh_tokens::Model;
    pub type AuditLogEntry = audit_logs::Model;
    pub type UsageRecord = usage_records::Model;
    pub type UsageSummary = usage_summaries::Model;
    pub type ModelCost = model_costs::Model;
    pub type ApiKeyRecord = api_keys::Model;
    ```
- If you need to run a test server, you must ask user to do it, you can not spawn background process.

## Deployment

### Docker

**Quick Start with Docker:**

```bash
# Build the image
docker build -t bedrock-sso-proxy .

# Run with minimal configuration
docker run -p 3000:3000 \
  -e BEDROCK_JWT__SECRET=your-super-secret-jwt-key \
  -e BEDROCK_AWS__REGION=us-east-1 \
  -v ./data:/app/data \
  bedrock-sso-proxy
```

**Using Docker Compose (Recommended):**

```bash
# Development with PostgreSQL and Redis
docker-compose up

# Production deployment with Traefik
docker-compose -f docker-compose.yml -f docker-compose.prod.yml up -d

# View logs
docker-compose logs -f bedrock-proxy

# Check database connection
docker-compose exec postgres psql -U bedrock -d bedrock_sso -c "\l"
```

### Kubernetes

**Deploy to Kubernetes:**

```bash
# Create namespace
kubectl create namespace bedrock-sso-proxy

# Apply all manifests
kubectl apply -f k8s/ -n bedrock-sso-proxy

# Check deployment status
kubectl get pods -n bedrock-sso-proxy
kubectl get services -n bedrock-sso-proxy

# View logs
kubectl logs -f deployment/bedrock-sso-proxy -n bedrock-sso-proxy
```

**Required Configuration:**

Before deploying, update the following files:

1. **`k8s/secrets.yaml`** - Add your actual secrets (base64 encoded):
   ```bash
   echo -n "your-jwt-secret" | base64
   echo -n "your-aws-access-key" | base64
   ```

2. **`k8s/ingress.yaml`** - Update the hostname:
   ```yaml
   - host: your-domain.com  # Replace with your actual domain
   ```

3. **`k8s/configmap.yaml`** - Update AWS region and other settings as needed

### Environment Variables

**Production Environment Variables:**

```bash
# Required
export BEDROCK_JWT__SECRET=your-super-secret-jwt-key-change-this
export AWS_ACCESS_KEY_ID=your-aws-access-key
export AWS_SECRET_ACCESS_KEY=your-aws-secret-key

# Optional but recommended
export BEDROCK_AWS__REGION=us-east-1
export BEDROCK_CACHE__BACKEND=redis
export BEDROCK_CACHE__REDIS_URL=redis://redis:6379
export BEDROCK_DATABASE__URL=postgres://user:pass@postgres:5432/bedrock_sso
export BEDROCK_METRICS__ENABLED=true
export BEDROCK_JOBS__ENABLED=true
```

### CI/CD Pipeline

The project includes GitHub Actions workflows:

- **`ci.yml`**: Runs on every push/PR with full test suite
- **`release.yml`**: Builds and publishes Docker images on releases

**Creating a Release:**

```bash
# Tag and push
git tag v1.0.0
git push origin v1.0.0

# Or create release via GitHub UI
# This triggers automatic Docker image build and push to ghcr.io
```

**Using Pre-built Images:**

```bash
# Pull latest image
docker pull ghcr.io/bearice/bedrock_sso_proxy:latest

# Or specific version
docker pull ghcr.io/bearice/bedrock_sso_proxy:v1.0.0
```

### Database Initialization

For safe cluster deployments, use the `init` command instead of relying on in-process migration:

```bash
# Basic initialization (recommended for production)
cargo run --bin bedrock_proxy -- init

# Skip default model cost data if you'll import your own
cargo run --bin bedrock_proxy -- init --skip-costs

# Force re-seed default data (useful for updates)
cargo run --bin bedrock_proxy -- init --force-seed
```

**Why use `init` instead of automatic migration?**

- **Cluster Safety**: Multiple pods can safely run `init` concurrently without conflicts
- **Idempotent**: Safe to run multiple times, won't duplicate data
- **Default Data**: Automatically seeds common Claude model costs for immediate use
- **Deployment Control**: Explicit control over when database setup occurs
- **No Distributed Locks**: Avoids complexity of coordination between instances

**Default Model Cost Data:**

The `init` command seeds comprehensive cost data from embedded CSV with 300+ model/region combinations including:
- **Claude Models**: Latest Claude 4 (Sonnet & Opus), Claude 3.7, Claude 3.5, and Claude 3 across all AWS regions
- **Other Providers**: Amazon Nova/Titan, Meta Llama, Mistral, Cohere, DeepSeek, AI21 models
- **All AWS Regions**: us-east-1, us-west-2, eu-central-1, ap-southeast-1, and 15+ more regions
- **Cache Pricing**: Includes cache read/write costs where available for supported models

**Configuration for Cluster Deployments:**

For safe cluster deployments, disable automatic initialization:

```yaml
database:
  migration_on_startup: false  # Disables both migrations and cost initialization
```

Or via environment variable:
```bash
export BEDROCK_DATABASE__MIGRATION_ON_STARTUP=false
```

**Deployment Sequence:**
1. Run `init` once during deployment (init job, sidecar, or manually)
2. Start application instances with `migration_on_startup: false`
3. Application instances connect to ready database without attempting initialization

### Production Checklist

**Database Initialization:**
- [ ] Run `cargo run --bin bedrock_proxy -- init` during deployment
- [ ] Verify default model cost data is seeded (or import your own)
- [ ] Test database connectivity from all instances

**Security:**
- [ ] Change default JWT secret (`BEDROCK_JWT__SECRET`)
- [ ] Use proper AWS credentials (IAM roles recommended)
- [ ] Enable HTTPS/TLS termination
- [ ] Configure proper CORS settings
- [ ] Review and set appropriate timeouts

**Performance:**
- [ ] Use Redis for caching in production
- [ ] Configure database connection pooling
- [ ] Set up proper resource limits (CPU/memory)
- [ ] Enable metrics collection
- [ ] Configure log aggregation

**Monitoring:**
- [ ] Set up health check endpoints (`/health`)
- [ ] Configure Prometheus metrics scraping (port 9090)
- [ ] Set up alerting for service failures
- [ ] Monitor disk usage for SQLite databases
- [ ] Configure log rotation

**Backup:**
- [ ] Regular database backups
- [ ] Backup encryption keys and secrets
- [ ] Test disaster recovery procedures

### Troubleshooting

**Common Issues:**

1. **JWT Secret Error**: Ensure `BEDROCK_JWT__SECRET` is set and not the default value
2. **AWS Credentials**: Check AWS credential chain and permissions
3. **Database Connection**: Verify database URL and connectivity
4. **Redis Connection**: Ensure Redis is running and accessible
5. **Port Conflicts**: Check if ports 3000/9090 are available

**Debug Commands:**

```bash
# Check container logs
docker logs bedrock-sso-proxy

# Check health endpoint
curl http://localhost:3000/health

# Check metrics
curl http://localhost:3000:9090/metrics

# Test JWT token generation (development only)
curl -X POST http://localhost:3000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"test","password":"test"}'
```

## Testing Memories

- If you need to run tests in `/test`, remember to use `cargo test --test ***_integration_tests` not `cargo test ***_integration_tests`
- Follow Conventional Commits format when writing commit messages
