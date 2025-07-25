-- Initial schema for Bedrock SSO Proxy
-- This migration creates the core tables for user management, refresh tokens, and audit logs

-- Users table
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    provider_user_id VARCHAR(255) NOT NULL,
    provider VARCHAR(100) NOT NULL,
    email VARCHAR(255) NOT NULL,
    display_name VARCHAR(255),
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMPTZ,
    UNIQUE(provider, provider_user_id)
);

-- Refresh tokens table
CREATE TABLE IF NOT EXISTS refresh_tokens (
    id SERIAL PRIMARY KEY,
    token_hash VARCHAR(64) NOT NULL UNIQUE,
    user_id TEXT NOT NULL,
    provider VARCHAR(100) NOT NULL,
    email VARCHAR(255) NOT NULL,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMPTZ NOT NULL,
    rotation_count INTEGER DEFAULT 0,
    revoked_at TIMESTAMPTZ
);

-- Audit logs table
CREATE TABLE IF NOT EXISTS audit_logs (
    id SERIAL PRIMARY KEY,
    user_id INTEGER,
    event_type VARCHAR(50) NOT NULL,
    provider VARCHAR(100),
    ip_address TEXT,
    user_agent TEXT,
    success BOOLEAN NOT NULL,
    error_message TEXT,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    metadata JSONB
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_provider ON users(provider, provider_user_id);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_expires_at ON refresh_tokens(expires_at);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user_id ON refresh_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_user_id ON audit_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs(created_at);
CREATE INDEX IF NOT EXISTS idx_audit_logs_event_type ON audit_logs(event_type);

-- Comments for documentation
COMMENT ON TABLE users IS 'OAuth users from various providers';
COMMENT ON TABLE refresh_tokens IS 'Refresh tokens for OAuth authentication with rotation support';
COMMENT ON TABLE audit_logs IS 'Audit trail for authentication events and user actions';

COMMENT ON COLUMN users.provider_user_id IS 'User ID from the OAuth provider';
COMMENT ON COLUMN users.provider IS 'OAuth provider name (google, github, etc.)';
COMMENT ON COLUMN users.email IS 'User email address (primary identifier)';
COMMENT ON COLUMN users.display_name IS 'User display name from OAuth provider';

COMMENT ON COLUMN refresh_tokens.token_hash IS 'SHA-256 hash of the refresh token';
COMMENT ON COLUMN refresh_tokens.user_id IS 'User ID from OAuth provider (string identifier)';
COMMENT ON COLUMN refresh_tokens.provider IS 'OAuth provider name';
COMMENT ON COLUMN refresh_tokens.email IS 'User email address';
COMMENT ON COLUMN refresh_tokens.rotation_count IS 'Number of times this token has been rotated';
COMMENT ON COLUMN refresh_tokens.revoked_at IS 'When this token was revoked (if applicable)';

COMMENT ON COLUMN audit_logs.user_id IS 'Database user ID (references users.id)';
COMMENT ON COLUMN audit_logs.event_type IS 'Type of event (login, logout, token_refresh, etc.)';
COMMENT ON COLUMN audit_logs.provider IS 'OAuth provider name';
COMMENT ON COLUMN audit_logs.ip_address IS 'Client IP address';
COMMENT ON COLUMN audit_logs.user_agent IS 'Client User-Agent string';
COMMENT ON COLUMN audit_logs.success IS 'Whether the operation was successful';
COMMENT ON COLUMN audit_logs.error_message IS 'Error message if operation failed';
COMMENT ON COLUMN audit_logs.metadata IS 'Additional metadata in JSON format';