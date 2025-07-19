# Bedrock SSO Proxy Design

## System Architecture

```
[Client] → [Proxy Server] → [AWS Bedrock API]
           ↑ JWT Auth      ↑ AWS Credentials
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

## JWT Authentication Flow

1. Extract Bearer token from `Authorization: Bearer <jwt>` header
2. Validate JWT signature and expiration
3. Extract user claims (user_id, permissions, etc.)
4. Proceed to AWS forwarding or return 401

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
axum = "0.7"
tokio = { version = "1.0", features = ["full"] }
tokio-tungstenite = "0.21"  # WebSocket support
aws-sdk-bedrockruntime = "1.0"
aws-config = "1.0"
jsonwebtoken = "9.0"
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
tracing = "0.1"
futures-util = "0.3"  # Stream utilities
config = "0.14"  # Configuration management
```

### Configuration Structure

**Config File (config.yaml/toml/json):**
```yaml
server:
  port: 3000
  host: "0.0.0.0"

jwt:
  secret: "your-jwt-secret"
  
aws:
  region: "us-east-1"
  # Credentials via IAM role, env vars, or config
  
logging:
  level: "info"
```

**Environment Variables (override config file):**
- `SERVER__PORT` - Server port
- `JWT__SECRET` - JWT signing secret  
- `AWS__REGION` - AWS region
- `AWS_ACCESS_KEY_ID` - AWS access key
- `AWS_SECRET_ACCESS_KEY` - AWS secret key
- `LOGGING__LEVEL` - Log level

### Security Considerations
- JWT tokens should have short expiration (15-60 min)
- Use HTTPS in production
- Rate limiting per user/JWT
- Audit logging of all requests
- AWS credentials via IAM roles preferred over static keys

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

### Phase 7: Production Readiness
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

### Phase 8: Release & Deployment
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