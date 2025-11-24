-- Initial database schema for TruffleHog REST API

-- Create extension for UUID generation
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- API Keys table for authentication
CREATE TABLE IF NOT EXISTS api_keys (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    key_hash VARCHAR(255) NOT NULL UNIQUE,
    name VARCHAR(255) NOT NULL,
    rate_limit INTEGER DEFAULT 100,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_used_at TIMESTAMP,
    is_active BOOLEAN DEFAULT TRUE,
    metadata JSONB DEFAULT '{}'::jsonb
);

CREATE INDEX idx_api_keys_hash ON api_keys(key_hash);
CREATE INDEX idx_api_keys_active ON api_keys(is_active);

-- Scan Jobs table
CREATE TABLE IF NOT EXISTS scan_jobs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    repo_url TEXT NOT NULL,
    status VARCHAR(50) NOT NULL DEFAULT 'queued',
    progress INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    error_message TEXT,
    options JSONB DEFAULT '{}'::jsonb,
    api_key_id UUID REFERENCES api_keys(id) ON DELETE SET NULL,
    chunks_scanned BIGINT DEFAULT 0,
    bytes_scanned BIGINT DEFAULT 0,
    secrets_found INTEGER DEFAULT 0,
    verified_secrets INTEGER DEFAULT 0,
    unverified_secrets INTEGER DEFAULT 0
);

CREATE INDEX idx_scan_jobs_status ON scan_jobs(status);
CREATE INDEX idx_scan_jobs_created_at ON scan_jobs(created_at DESC);
CREATE INDEX idx_scan_jobs_api_key ON scan_jobs(api_key_id);

-- Scan Results table
CREATE TABLE IF NOT EXISTS scan_results (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    job_id UUID NOT NULL REFERENCES scan_jobs(id) ON DELETE CASCADE,
    detector_type VARCHAR(255) NOT NULL,
    detector_name VARCHAR(255) NOT NULL,
    secret TEXT NOT NULL,
    verified BOOLEAN DEFAULT FALSE,
    verification_error TEXT,
    raw_result JSONB NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    source_metadata JSONB DEFAULT '{}'::jsonb,
    line_number INTEGER,
    file_path TEXT,
    commit_hash VARCHAR(255),
    redacted_secret TEXT
);

CREATE INDEX idx_scan_results_job_id ON scan_results(job_id);
CREATE INDEX idx_scan_results_verified ON scan_results(verified);
CREATE INDEX idx_scan_results_detector_type ON scan_results(detector_type);
CREATE INDEX idx_scan_results_created_at ON scan_results(created_at DESC);

-- Webhook Configurations table
CREATE TABLE IF NOT EXISTS webhook_configs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    url TEXT NOT NULL,
    secret VARCHAR(255) NOT NULL,
    events TEXT[] NOT NULL DEFAULT ARRAY['scan.completed'],
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    api_key_id UUID REFERENCES api_keys(id) ON DELETE CASCADE,
    retry_count INTEGER DEFAULT 3,
    timeout_seconds INTEGER DEFAULT 30,
    headers JSONB DEFAULT '{}'::jsonb
);

CREATE INDEX idx_webhook_configs_active ON webhook_configs(is_active);
CREATE INDEX idx_webhook_configs_api_key ON webhook_configs(api_key_id);

-- Webhook Deliveries table for tracking
CREATE TABLE IF NOT EXISTS webhook_deliveries (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    webhook_id UUID NOT NULL REFERENCES webhook_configs(id) ON DELETE CASCADE,
    job_id UUID REFERENCES scan_jobs(id) ON DELETE SET NULL,
    event VARCHAR(100) NOT NULL,
    payload JSONB NOT NULL,
    response_status INTEGER,
    response_body TEXT,
    delivered_at TIMESTAMP,
    retry_count INTEGER DEFAULT 0,
    next_retry_at TIMESTAMP,
    error_message TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_webhook_deliveries_webhook_id ON webhook_deliveries(webhook_id);
CREATE INDEX idx_webhook_deliveries_job_id ON webhook_deliveries(job_id);
CREATE INDEX idx_webhook_deliveries_created_at ON webhook_deliveries(created_at DESC);
CREATE INDEX idx_webhook_deliveries_next_retry ON webhook_deliveries(next_retry_at) WHERE next_retry_at IS NOT NULL;

-- Update trigger for webhook_configs
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

CREATE TRIGGER update_webhook_configs_updated_at
    BEFORE UPDATE ON webhook_configs
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- Create a view for job summaries
CREATE OR REPLACE VIEW scan_job_summaries AS
SELECT 
    j.id,
    j.repo_url,
    j.status,
    j.progress,
    j.created_at,
    j.completed_at,
    j.chunks_scanned,
    j.bytes_scanned,
    j.secrets_found,
    j.verified_secrets,
    j.unverified_secrets,
    COUNT(r.id) as result_count,
    COUNT(CASE WHEN r.verified = TRUE THEN 1 END) as verified_count,
    COUNT(CASE WHEN r.verified = FALSE THEN 1 END) as unverified_count
FROM scan_jobs j
LEFT JOIN scan_results r ON r.job_id = j.id
GROUP BY j.id;

