# Integration Test Analysis and TODO

## Current Integration Test Coverage ✅

### Well-Covered Areas:
- **JWT Authentication** (7 tests in `tests/jwt_integration_tests.rs`)
  - Token validation and expiration
  - Malformed authorization headers
  - Concurrent request handling
  - Invalid signature detection
  - Custom claims support

- **API Key Authentication** (6 tests in `src/auth/api_key.rs`)
  - Authorization header and X-API-Key header support
  - Invalid and revoked key handling
  - Dual authentication support

- **Cached DAO Operations** (20+ tests in `src/database/dao/cached.rs`)
  - Cache hit/miss scenarios
  - Cache invalidation
  - Error handling
  - Cache key building

- **Usage Tracking** (tests in `src/usage/mod.rs`)
  - Usage record creation and retrieval
  - Pagination and filtering
  - Authorization validation

- **Cost Tracking** (10 tests in `src/cost/mod.rs`)
  - Model cost CRUD operations
  - CSV bulk updates
  - Admin-only access control

- **Security Vulnerabilities** (13 tests in `tests/security_tests.rs`)
  - SQL injection attempts
  - XSS prevention
  - Malformed request handling
  - Invalid content types

## Missing Integration Test Areas ❌

### High Priority:

#### 1. OAuth Flow Integration Tests
**File**: `tests/oauth_integration_tests.rs`
- [ ] OAuth authorization flow (authorize → callback → token)
- [ ] OAuth state validation across requests
- [ ] OAuth token refresh workflow
- [ ] OAuth provider-specific flows (Google, GitHub, etc.)
- [ ] OAuth error handling (invalid state, expired codes)
- [ ] OAuth logout and session management

#### 2. API Endpoint Integration Tests
**File**: `tests/api_integration_tests.rs`
- [ ] Bedrock model invocation (`POST /bedrock/model/{id}/invoke`)
- [ ] Bedrock streaming (`POST /bedrock/model/{id}/invoke-with-response-stream`)
- [ ] Anthropic API format (`POST /anthropic/v1/messages`)
- [ ] Anthropic streaming support
- [ ] API key management endpoints (create, list, revoke)
- [ ] Health check with different check types (`/health?check=all|cache|db|aws`)
- [ ] Error response format validation
- [ ] Request/response header handling

#### 3. Service Integration Tests
**File**: `tests/service_integration_tests.rs`
- [ ] ModelService with real/mock AWS Bedrock integration
- [ ] Cache service with Redis/memory backends
- [ ] Database service with migrations
- [ ] Health service with all components
- [ ] Graceful shutdown integration
- [ ] Service dependency injection validation

### Medium Priority:

#### 4. End-to-End Workflow Tests
**File**: `tests/e2e_integration_tests.rs`
- [ ] Complete OAuth → JWT → API call flow
- [ ] API key creation → model invocation flow
- [ ] Streaming response handling end-to-end
- [ ] Error propagation through full stack
- [ ] Metrics collection during requests
- [ ] Token refresh during long-running operations

#### 5. Configuration Integration Tests
**File**: `tests/config_integration_tests.rs`
- [ ] Environment variable configuration loading
- [ ] YAML file configuration loading
- [ ] Configuration validation and error handling
- [ ] Service startup with different configurations
- [ ] Cache backend switching (memory ↔ Redis)
- [ ] AWS configuration validation

### Low Priority:

#### 6. Database Migration Integration Tests
**File**: `tests/migration_integration_tests.rs`
- [ ] Migration up/down cycles
- [ ] Schema validation after migrations
- [ ] Data integrity during migrations
- [ ] Migration rollback scenarios
- [ ] Migration failure recovery

## Test Architecture Improvements

### Current Structure:
```
tests/
├── jwt_integration_tests.rs           # JWT authentication integration (7 tests)
├── api_key_integration_tests.rs       # API key authentication integration (6 tests)
├── cached_integration_test.rs         # Cached DAO integration (8 tests)
├── cost_integration_tests.rs          # Cost tracking integration (10 tests)
├── usage_integration_tests.rs         # Usage tracking integration (8 tests)
├── security_tests.rs                  # Security vulnerability tests (13 tests)
└── common/                            # Shared test utilities
    └── mod.rs
```

### Recommended Additional Tests:
```
tests/
├── jwt_integration_tests.rs           # ✅ JWT authentication integration
├── api_key_integration_tests.rs       # ✅ API key authentication integration
├── cached_integration_test.rs         # ✅ Cached DAO integration
├── cost_integration_tests.rs          # ✅ Cost tracking integration
├── usage_integration_tests.rs         # ✅ Usage tracking integration
├── oauth_integration_tests.rs         # ❌ OAuth flow integration (NEEDED)
├── api_integration_tests.rs           # ❌ API endpoint integration (NEEDED)
├── service_integration_tests.rs       # ❌ Service layer integration (NEEDED)
├── e2e_integration_tests.rs           # ❌ End-to-end workflows (NEEDED)
├── config_integration_tests.rs        # ❌ Configuration integration (NEEDED)
├── migration_integration_tests.rs     # ❌ Database migration integration (NEEDED)
├── security_tests.rs                  # ✅ Security vulnerability tests
└── common/                            # Shared test utilities
    ├── mod.rs
    ├── oauth_helpers.rs              # OAuth test utilities
    ├── api_helpers.rs                # API test utilities
    └── mock_services.rs              # Mock service implementations
```

## Test Metrics

### Current Test Coverage:
- **Total Tests**: 285 (221 unit + 49 integration + 13 security + 1 doc)
- **Unit Tests**: 221 tests in `src/` modules
- **Integration Tests**: 49 tests across 5 test files
- **Security Tests**: 13 tests
- **Success Rate**: 100% (all tests passing)

### Integration Test Distribution:
- **JWT Integration**: 7 tests (in `tests/jwt_integration_tests.rs`)
- **API Key Integration**: 6 tests (in `tests/api_key_integration_tests.rs`)
- **Cached DAO Integration**: 8 tests (in `tests/cached_integration_test.rs`)
- **Usage Tracking Integration**: 8 tests (in `tests/usage_integration_tests.rs`)
- **Cost Tracking Integration**: 10 tests (in `tests/cost_integration_tests.rs`)
- **Security Tests**: 13 tests (in `tests/security_tests.rs`)

## Implementation Notes

### Test Harness Extensions Needed:
- OAuth mock server integration
- AWS Bedrock mock service
- Redis test container management
- Database migration test utilities
- Streaming response validation helpers

### Test Data Management:
- Standardized test user creation
- OAuth provider mock responses
- Model response fixtures
- Error response templates

### Performance Considerations:
- Parallel test execution where possible
- Shared test database for integration tests
- Connection pooling for Redis tests
- Proper cleanup between tests

## Completed Tasks:
- [x] Renamed `integration_tests.rs` to `jwt_integration_tests.rs`
- [x] Updated documentation in `CLAUDE.md`
- [x] Verified all existing tests still pass
- [x] Analyzed current integration test coverage
- [x] Identified missing integration test areas
- [x] Reverted problematic commit d06eaf0 that moved integration tests to src/
- [x] Restored proper Rust testing structure with integration tests in tests/
- [x] Updated documentation to reflect correct test structure and counts

## Next Steps:
1. Implement OAuth integration tests (highest priority)
2. Add API endpoint integration tests
3. Create service integration tests
4. Extend test utilities for new test types
5. Add performance benchmarks to integration tests

---

# Real-Time Usage Tracking & Cap System

## Architecture Overview

**Hybrid Strategy:**
- **Redis**: Real-time tracking (hourly summaries + usage caps)
- **Database**: Historical analytics (daily/weekly/monthly summaries)
- **Atomic Operations**: Consistent updates across both systems

## Phase 1: Real-Time Hourly Summaries in Redis

### 1.1 Redis Key Structure
```
# Hourly summaries (real-time)
usage_summary:user_{user_id}:hourly:{YYYY-MM-DDTHH} 
→ {requests: int, input_tokens: int, output_tokens: int, cost_cents: int}

# Usage caps (real-time tracking)
usage_cap:user_{user_id}:daily:{YYYY-MM-DD}
usage_cap:user_{user_id}:hourly:{YYYY-MM-DDTHH}
→ {requests: int, tokens: int, cost_cents: int}
```

### 1.2 Update Model Service
```rust
// In src/model_service/streaming.rs
tokio::spawn(async move {
    // 1. Insert usage record to DB (existing)
    if let Err(e) = usage_dao.create_usage_record(&usage_record).await {
        tracing::error!("Failed to save usage record: {}", e);
        return;
    }
    
    // 2. Update Redis summaries (NEW)
    if let Err(e) = cache_manager.update_hourly_summary(&usage_record).await {
        tracing::error!("Failed to update hourly summary: {}", e);
    }
    
    // 3. Update Redis usage caps (NEW)
    if let Err(e) = cache_manager.update_usage_caps(&usage_record).await {
        tracing::error!("Failed to update usage caps: {}", e);
    }
});
```

### 1.3 Cache Manager Implementation
```rust
// In src/cache/mod.rs
impl CacheManager {
    async fn update_hourly_summary(&self, usage: &UsageRecord) -> Result<()>;
    async fn update_usage_caps(&self, usage: &UsageRecord) -> Result<()>;
    async fn get_current_usage(&self, user_id: i32, period: CapPeriod) -> Result<UsageStats>;
}
```

## Phase 2: Usage Cap System

### 2.1 Database Schema
```sql
-- User cap configurations
CREATE TABLE user_cap_configs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    cap_type VARCHAR(10) NOT NULL, -- 'hourly', 'daily', 'monthly'
    max_requests INTEGER,
    max_tokens BIGINT,
    max_cost_cents BIGINT,
    is_active BOOLEAN DEFAULT TRUE,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    
    FOREIGN KEY (user_id) REFERENCES users(id),
    UNIQUE(user_id, cap_type)
);
```

### 2.2 Pre-Request Cap Validation
```rust
// In src/model_service/mod.rs
impl ModelService {
    async fn invoke_model(&self, request: &InvokeRequest) -> Result<Response> {
        // 1. Validate usage caps BEFORE expensive Bedrock call
        self.usage_cap_service.validate_caps(request.user_id, request).await?;
        
        // 2. Make Bedrock API call (existing)
        let response = self.bedrock_client.invoke(request).await?;
        
        // ... rest of implementation
    }
}
```

### 2.3 Usage Cap Service
```rust
// New: src/usage_cap/mod.rs
pub struct UsageCapService {
    cache: Arc<dyn CacheManager>,
    database: Arc<dyn DatabaseManager>,
}

impl UsageCapService {
    async fn validate_caps(&self, user_id: i32, request: &InvokeRequest) -> Result<()>;
    async fn get_user_caps(&self, user_id: i32) -> Result<Vec<UserCap>>;
}
```

## Phase 3: Batch Job System (Historical Summaries)

### 3.1 Job Scheduler Enhancement
```rust
// In src/jobs/scheduler.rs
impl JobScheduler {
    pub fn new() -> Self {
        // Hourly: Move completed hours Redis → Database  
        schedule_job("5 * * * *", PersistHourlyJob);
        
        // Daily: Generate from hourly summaries
        schedule_job("1 0 * * *", DailySummaryJob);
        
        // Weekly: Generate every Monday
        schedule_job("5 0 * * 1", WeeklySummaryJob);
        
        // Monthly: Generate on 1st of month
        schedule_job("10 0 1 * *", MonthlySummaryJob);
    }
}
```

### 3.2 Persistence Jobs
```rust
// New: src/jobs/persist_hourly.rs
pub struct PersistHourlyJob;

impl Job for PersistHourlyJob {
    async fn run(&self, context: &JobContext) -> Result<()> {
        // 1. Get completed hour data from Redis
        // 2. Save to usage_summaries table
        // 3. Delete from Redis (cleanup)
    }
}
```

## Phase 4: API Endpoints (Usage Caps Management)

### 4.1 New Routes
```rust
// In src/routes/usage_caps.rs
Router::new()
    .route("/usage/caps", post(create_cap).get(list_caps))
    .route("/usage/caps/:id", put(update_cap).delete(delete_cap))
    .route("/usage/caps/status", get(get_cap_status))
```

### 4.2 API Schemas
```rust
#[derive(Deserialize, ToSchema)]
pub struct CreateCapRequest {
    pub cap_type: CapType, // hourly, daily, monthly
    pub max_requests: Option<u32>,
    pub max_tokens: Option<i64>, 
    pub max_cost_cents: Option<i64>,
}

#[derive(Serialize, ToSchema)]
pub struct CapStatusResponse {
    pub cap_type: CapType,
    pub current_usage: UsageStats,
    pub limits: CapLimits,
    pub percentage_used: f32,
    pub reset_time: DateTime<Utc>,
    pub is_exceeded: bool,
}
```

## Phase 5: Frontend Integration

### 5.1 Usage Cap Components
```typescript
// New: src/components/usage/UsageCaps.tsx
export function UsageCaps() {
    // Display cap status, create/edit caps, show warnings
}

// New: src/components/usage/CapStatus.tsx  
export function CapStatus() {
    // Real-time cap usage progress bars
}
```

### 5.2 Dashboard Updates
```typescript
// Update: src/components/usage/UsageStats.tsx
// Show real-time data from Redis + DB hybrid queries
```

## Phase 6: Error Handling & UX

### 6.1 Cap Exceeded Error Response
```rust
#[derive(Debug, Serialize, ToSchema)]
pub struct UsageCapExceededError {
    pub error: String,
    pub cap_type: String,
    pub limit_type: String, // "requests", "tokens", "cost"
    pub current_usage: i64,
    pub limit: i64, 
    pub reset_time: DateTime<Utc>,
    pub retry_after_seconds: u64,
}
```

### 6.2 Frontend Error Handling
```typescript
// Clear error messages when caps are exceeded
// Show countdown to reset time
// Display current usage vs. limits
```

## Implementation Order

1. **Phase 1**: Redis hourly summaries (real-time dashboard)
2. **Phase 2**: Usage cap validation system  
3. **Phase 3**: Batch jobs for historical data
4. **Phase 4**: Cap management APIs
5. **Phase 5**: Frontend cap management UI
6. **Phase 6**: Error handling & UX polish

## Benefits

**Performance**: Sub-millisecond cap validation, real-time dashboard
**Accuracy**: Atomic operations, no race conditions  
**Scalability**: Redis handles high-frequency updates efficiently
**User Experience**: Immediate feedback, clear limits, predictable resets
**Data Integrity**: Historical summaries are perfectly accurate
**Cost Efficiency**: Prevent expensive API calls when caps exceeded

This architecture gives you **lightning-fast real-time usage tracking** with **reliable historical analytics** and **instant usage cap enforcement**.

## Technical Details

### Redis Operations
```rust
// Atomic increment operations
redis.pipeline()
    .hincrby("usage_summary:user_123:hourly:2025-01-31T15", "requests", 1)
    .hincrby("usage_summary:user_123:hourly:2025-01-31T15", "input_tokens", 150)
    .hincrby("usage_summary:user_123:hourly:2025-01-31T15", "output_tokens", 75)
    .hincrby("usage_summary:user_123:hourly:2025-01-31T15", "cost_cents", 25)
    .expire("usage_summary:user_123:hourly:2025-01-31T15", 3600 * 25) // Auto cleanup
    .query_async(&mut conn).await?;
```

### Database Migration
```sql
-- Migration: Add user cap configurations table
-- File: src/database/migration/m20250131_create_user_cap_configs.rs
CREATE TABLE user_cap_configs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    cap_type VARCHAR(10) NOT NULL CHECK (cap_type IN ('hourly', 'daily', 'monthly')),
    max_requests INTEGER CHECK (max_requests > 0),
    max_tokens BIGINT CHECK (max_tokens > 0),
    max_cost_cents BIGINT CHECK (max_cost_cents > 0),
    is_active BOOLEAN DEFAULT TRUE,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE(user_id, cap_type)
);

-- Index for fast cap lookups
CREATE INDEX idx_user_cap_configs_user_active ON user_cap_configs(user_id, is_active);
```

### Error Handling
```rust
// Custom error types for usage caps
#[derive(Debug, thiserror::Error)]
pub enum UsageCapError {
    #[error("Daily usage cap exceeded: {current}/{limit} {resource_type}. Resets at {reset_time}")]
    DailyCapExceeded {
        current: i64,
        limit: i64,
        resource_type: String,
        reset_time: DateTime<Utc>,
    },
    
    #[error("Hourly usage cap exceeded: {current}/{limit} {resource_type}. Resets at {reset_time}")]
    HourlyCapExceeded {
        current: i64,
        limit: i64,
        resource_type: String, 
        reset_time: DateTime<Utc>,
    },
}
```

### Configuration
```yaml
# Add to config.yaml
redis:
  # Usage tracking keys
  usage_summary_prefix: "usage_summary:"
  usage_cap_prefix: "usage_cap:"
  
  # TTL settings
  hourly_summary_ttl: 90000  # 25 hours
  daily_cap_ttl: 90000       # 25 hours  
  hourly_cap_ttl: 7200       # 2 hours

usage_caps:
  # Default caps for new users
  default_daily_requests: 1000
  default_daily_tokens: 100000
  default_daily_cost_cents: 1000  # $10
  
  # Enable cap enforcement
  enforce_caps: true
  
  # Grace period before enforcement
  grace_period_minutes: 5
```

This comprehensive plan provides a complete roadmap for implementing real-time usage tracking with Redis-backed usage caps and efficient historical analytics.