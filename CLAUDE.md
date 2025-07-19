# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**Bedrock SSO Proxy** is a JWT-authenticated HTTP proxy server that provides secure access to AWS Bedrock APIs. It acts as an intermediary between clients and AWS Bedrock, handling JWT authentication and request forwarding with AWS Signature V4 signing.

## Architecture

```
[Client with JWT] → [Proxy Server] → [AWS Bedrock API]
                    ↑ JWT Auth      ↑ AWS Signature V4
```

### Core Components

- **`src/server.rs`**: Axum-based HTTP server with health checks and JWT-protected routes
- **`src/auth.rs`**: JWT authentication middleware with HS256 validation
- **`src/aws_http.rs`**: Direct HTTP client for AWS Bedrock with Signature V4 signing
- **`src/config.rs`**: Configuration management using YAML files and environment variables
- **`src/error.rs`**: Comprehensive error handling with proper HTTP status mapping

### Key Routes

- `GET /health` - Public health check endpoint
- `POST /model/{model_id}/invoke` - Standard model invocation (JWT protected)
- `POST /model/{model_id}/invoke-with-response-stream` - Streaming responses (JWT protected)

## Development Commands

### Build and Development
```bash
cargo build                   # Build project
cargo build --release         # Production build
cargo run --bin bedrock_proxy # Run server
cargo test                    # Run all tests (71 total)
cargo clippy                  # Lint code (required before commit)
cargo fmt                     # Format code (required before commit)
```

### E2E Testing
```bash
# Build and run the test client
cargo build --bin bedrock_e2e_client
cargo run --bin bedrock_e2e_client -- health         # Health check
cargo run --bin bedrock_e2e_client -- chat           # Interactive chat
cargo run --bin bedrock_e2e_client -- message --text "Hello" # Single message
```

### Testing
```bash
cargo test                    # All tests (unit + integration + security)
cargo test auth               # Authentication tests only
cargo test security           # Security vulnerability tests
cargo test --test integration # Integration tests only
```

## Key Dependencies

- **`axum ^0.8`** - Web framework with WebSocket support
- **`tokio ^1.0`** - Async runtime with full features
- **`reqwest ^0.12`** - HTTP client with JSON and streaming
- **`jsonwebtoken ^9.0`** - JWT validation (HS256 only)
- **`aws-sigv4 ^1.0`** - AWS request signing
- **`config ^0.15`** - Configuration management

## Configuration

### File Structure
Configuration uses hierarchical loading: defaults → YAML file → environment variables

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
```

### Environment Variables
Use `BEDROCK_` prefix with double underscores for nesting:
- `BEDROCK_SERVER__PORT=3000`
- `BEDROCK_JWT__SECRET=secret`
- `BEDROCK_AWS__REGION=us-east-1`

## Development Best Practices

- If there is any functional update, update DESIGN.md too
- You should always follow design in DESIGN.md when coding
- After each phase, do a commit and make it easy to review and rewind
- When adding a dep, make sure it's the latest version
- Before commit, use cargo clippy to check code and cargo fmt to format
- You should add tests for new code when a phase is finished

## Project Status

**Completed Phases (6/8)**:
- ✅ Phase 1: Core infrastructure and configuration
- ✅ Phase 2: JWT authentication layer
- ✅ Phase 3: AWS Bedrock integration with credential handling
- ✅ Phase 4: Standard API implementation with direct HTTP client
- ✅ Phase 5: Streaming API implementation (SSE)
- ✅ Phase 6: Comprehensive testing suite (71 tests)

**Remaining Phases**:
- 🔄 Phase 7: Production features (metrics, rate limiting, graceful shutdown)
- 🔄 Phase 8: Deployment (Docker, CI/CD, Kubernetes)

## Testing Architecture

- **Unit Tests**: 54 tests covering all modules (66.79% coverage)
- **Integration Tests**: 7 tests with real JWT token validation
- **Security Tests**: 10 comprehensive security attack simulations
- **Test Coverage**: Authentication, routing, streaming, error handling, security vulnerabilities

## Security Features

- **JWT Validation**: HS256 with strict expiration validation, zero leeway
- **Header Processing**: Strips Authorization headers before AWS forwarding
- **AWS Signing**: Proper Signature V4 implementation for AWS authentication
- **Error Handling**: No sensitive information exposure in responses

## Project Workflow Notes

- When clearing context between phases, summarize key changes and prepare notes for the next phase of development
- Keep track of context clearing to ensure continuity and understanding of project progression