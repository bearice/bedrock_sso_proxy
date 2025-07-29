# Bedrock SSO Proxy Design

## Overview

A JWT-authenticated HTTP proxy server that provides secure access to AWS Bedrock APIs with dual authentication methods and comprehensive usage tracking.

## System Architecture

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

## Core Components

### Service Layer

**ModelService**: Unified model invocation with automatic usage tracking and cost calculation. Handles both streaming and non-streaming requests with request/response transformation between Anthropic and Bedrock formats.

**HealthService**: Comprehensive health checking with service registration pattern for extensible monitoring.

**OAuthService**: OAuth 2.0 flow management supporting multiple providers (Google, GitHub, Microsoft, etc.) with state validation.

**JwtService**: JWT lifecycle management with trait abstraction for testability.

### Infrastructure Layer

**TypedCache System**: Revolutionary type-safe caching with structural hashing that automatically invalidates cache when type definitions change. Supports both memory and Redis backends.

**Database Layer**: SeaORM-based persistence with cached DAO pattern for performance optimization.

**BedrockRuntime**: AWS Bedrock API client with trait abstraction and mock support for testing.

**CostTracking**: Simplified CSV-based pricing system with batch operations and region-aware cost calculation.

## Authentication Architecture

### Dual Authentication Model

**Frontend Authentication (OAuth + JWT)**
- OAuth 2.0 flow with multiple provider support
- Short-lived JWT tokens (1 hour) for web sessions
- Refresh token rotation for sustained access

**API Key Authentication**
- Long-lived API keys for programmatic access
- Format: `SSOK_<32-char-random-string>`
- Full access to Bedrock/Anthropic endpoints

### Admin Authorization
- Email-based admin identification
- Configurable admin email list
- Admin-only endpoints for user management

## API Compatibility

**Dual Format Support:**
- **Bedrock Format**: Native AWS Bedrock API (`/bedrock/*`)
- **Anthropic Format**: Standard Anthropic API (`/anthropic/*`)

**Authentication Methods:**
- `Authorization: Bearer <JWT>` for web clients
- `Authorization: Bearer <API_KEY>` for programmatic access
- `X-API-Key: <API_KEY>` for Anthropic format compatibility

## Configuration Design

**Module-Based Configuration:**
- Hierarchical loading: Defaults → YAML → Environment variables
- Domain-specific modules: server, auth, aws, database, cache, metrics
- Environment mapping: `BEDROCK_MODULE__FIELD` pattern

## Data Storage Strategy

**Database (Persistent):**
- SeaORM entities with automatic migrations
- Users, API Keys, Usage Records, Model Costs, Audit Logs

**TypedCache (Performance):**
- Structural hashing with automatic type safety
- Cached DAO pattern for database acceleration
- Backend-agnostic (Memory/Redis)

## Testing Architecture

**TestServerBuilder Pattern:**
- Centralized test infrastructure eliminating code duplication
- Configurable backends: Memory/Real database, Memory/Redis cache, Mock/Real AWS
- Service trait abstractions for comprehensive mocking

## Key Design Decisions

### Why Service Layer?
- **Separation of Concerns**: Clear boundaries between routing, business logic, and infrastructure
- **Testability**: Trait abstractions enable comprehensive mocking
- **Maintainability**: Changes isolated to specific service layers

### Why TypedCache?
- **Type Safety**: Compile-time guarantees prevent cache corruption
- **Automatic Invalidation**: Structural hashing detects type changes
- **Performance**: Zero-overhead abstractions with backend flexibility

### Why Dual Authentication?
- **Flexibility**: Web clients need session management, APIs need long-lived access
- **Security**: Short-lived JWTs for browsers, controlled API keys for automation
- **User Experience**: OAuth for easy onboarding, API keys for integration

### Why ModelService?
- **Unified Interface**: Single point for all model invocations
- **Automatic Tracking**: Built-in usage and cost tracking
- **Error Handling**: Centralized AWS error management
- **Testing**: Single mock point for all AWS interactions

## Production Features

- **Graceful Shutdown**: Proper resource cleanup with configurable timeouts
- **Health Monitoring**: Comprehensive health checks with service registration
- **Metrics Integration**: Prometheus metrics for observability
- **Cost Tracking**: Real-time usage and cost calculation
- **Streaming Support**: Full streaming API support with token tracking
- **Multi-Region**: Region-aware routing and cost calculation

## Security Features

- **JWT Validation**: HS256 with strict expiration validation
- **OAuth 2.0 Integration**: Full OAuth flow with CSRF protection
- **Header Processing**: Strips authentication headers before AWS forwarding
- **Audit Logging**: Comprehensive security event logging
- **Rate Limiting**: Configurable (currently disabled for simplicity)

---

*For detailed implementation examples, API usage, and configuration options, see the code documentation and README.*