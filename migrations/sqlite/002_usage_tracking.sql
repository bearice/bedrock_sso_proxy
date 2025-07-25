-- Usage tracking schema for Bedrock SSO Proxy (SQLite version)
-- This migration adds tables for tracking token usage, costs, and model pricing

-- Usage records table - stores detailed usage information per request
CREATE TABLE IF NOT EXISTS usage_records (
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
    cost_usd REAL,
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);

-- Pre-calculated summaries for performance (hourly/daily/monthly aggregates)
CREATE TABLE IF NOT EXISTS usage_summaries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    model_id TEXT NOT NULL,
    period_type TEXT NOT NULL,
    period_start DATETIME NOT NULL,
    period_end DATETIME NOT NULL,
    total_requests INTEGER NOT NULL,
    total_input_tokens BIGINT NOT NULL,
    total_output_tokens BIGINT NOT NULL,
    total_tokens BIGINT NOT NULL,
    avg_response_time_ms REAL NOT NULL,
    success_rate REAL NOT NULL,
    estimated_cost REAL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(user_id, model_id, period_type, period_start),
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);

-- Model cost configuration
CREATE TABLE IF NOT EXISTS model_costs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    model_id TEXT NOT NULL UNIQUE,
    input_cost_per_1k_tokens REAL NOT NULL,
    output_cost_per_1k_tokens REAL NOT NULL,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_usage_records_user_model_time ON usage_records(user_id, model_id, request_time);
CREATE INDEX IF NOT EXISTS idx_usage_records_request_time ON usage_records(request_time);
CREATE INDEX IF NOT EXISTS idx_usage_records_user_id ON usage_records(user_id);
CREATE INDEX IF NOT EXISTS idx_usage_records_model_id ON usage_records(model_id);
CREATE INDEX IF NOT EXISTS idx_usage_records_success ON usage_records(success);

CREATE INDEX IF NOT EXISTS idx_usage_summaries_user_model ON usage_summaries(user_id, model_id);
CREATE INDEX IF NOT EXISTS idx_usage_summaries_period ON usage_summaries(period_type, period_start);
CREATE INDEX IF NOT EXISTS idx_usage_summaries_user_period ON usage_summaries(user_id, period_type, period_start);

CREATE INDEX IF NOT EXISTS idx_model_costs_model_id ON model_costs(model_id);

-- Insert default model costs if they don't exist
INSERT OR IGNORE INTO model_costs (model_id, input_cost_per_1k_tokens, output_cost_per_1k_tokens) VALUES
    ('anthropic.claude-3-sonnet-20240229-v1:0', 0.003, 0.015),
    ('anthropic.claude-3-opus-20240229-v1:0', 0.015, 0.075),
    ('anthropic.claude-3-haiku-20240307-v1:0', 0.00025, 0.00125),
    ('anthropic.claude-3-5-sonnet-20240620-v1:0', 0.003, 0.015),
    ('anthropic.claude-3-5-haiku-20241022-v1:0', 0.001, 0.005);