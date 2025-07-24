-- Migration tracking table for PostgreSQL
-- This table tracks which migrations have been executed to avoid re-running them

CREATE TABLE IF NOT EXISTS migration_tracking (
    id SERIAL PRIMARY KEY,
    migration_name TEXT NOT NULL UNIQUE,
    executed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    checksum TEXT,
    execution_time_ms INTEGER DEFAULT 0
);

-- Index for fast lookup of executed migrations
CREATE INDEX IF NOT EXISTS idx_migration_tracking_name ON migration_tracking(migration_name);
CREATE INDEX IF NOT EXISTS idx_migration_tracking_executed_at ON migration_tracking(executed_at);