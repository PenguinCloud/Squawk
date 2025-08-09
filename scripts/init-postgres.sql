-- PostgreSQL initialization script for Squawk
-- This script sets up the database schema for testing

-- Create the database (this is handled by POSTGRES_DB env var, but good to have)
-- CREATE DATABASE squawk;

-- Connect to the squawk database
\c squawk;

-- Create tokens table
CREATE TABLE IF NOT EXISTS tokens (
    id SERIAL PRIMARY KEY,
    token VARCHAR(255) UNIQUE NOT NULL,
    name VARCHAR(100) NOT NULL,
    description TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_used TIMESTAMP,
    active BOOLEAN DEFAULT TRUE
);

-- Create domains table
CREATE TABLE IF NOT EXISTS domains (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) UNIQUE NOT NULL,
    description TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create token_domains junction table
CREATE TABLE IF NOT EXISTS token_domains (
    token_id INTEGER REFERENCES tokens(id) ON DELETE CASCADE,
    domain_id INTEGER REFERENCES domains(id) ON DELETE CASCADE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (token_id, domain_id)
);

-- Create query_logs table
CREATE TABLE IF NOT EXISTS query_logs (
    id SERIAL PRIMARY KEY,
    token_id INTEGER REFERENCES tokens(id) ON DELETE SET NULL,
    domain_queried VARCHAR(255) NOT NULL,
    query_type VARCHAR(10),
    status VARCHAR(20),
    client_ip VARCHAR(45),
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create indexes for better performance
CREATE INDEX IF NOT EXISTS idx_tokens_active_token ON tokens(active, token) WHERE active = true;
CREATE INDEX IF NOT EXISTS idx_tokens_token ON tokens(token);
CREATE INDEX IF NOT EXISTS idx_token_domains_token ON token_domains(token_id);
CREATE INDEX IF NOT EXISTS idx_token_domains_domain ON token_domains(domain_id);
CREATE INDEX IF NOT EXISTS idx_domains_name ON domains(name);
CREATE INDEX IF NOT EXISTS idx_query_logs_timestamp ON query_logs(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_query_logs_token ON query_logs(token_id);
CREATE INDEX IF NOT EXISTS idx_query_logs_status ON query_logs(status);

-- Insert test data for development/testing
INSERT INTO tokens (token, name, description, active) VALUES 
    ('test-token-for-development', 'Development Token', 'Token for development and testing', true),
    ('admin-token-12345', 'Admin Token', 'Administrative access token', true),
    ('client-token-67890', 'Client Token', 'Limited client access token', true),
    ('inactive-token', 'Inactive Token', 'Disabled token for testing', false)
ON CONFLICT (token) DO NOTHING;

INSERT INTO domains (name, description) VALUES 
    ('*', 'Wildcard - access to all domains'),
    ('example.com', 'Example domain for testing'),
    ('test.com', 'Test domain'),
    ('api.example.com', 'API subdomain'),
    ('internal.company.com', 'Internal company domain'),
    ('dev.example.com', 'Development domain')
ON CONFLICT (name) DO NOTHING;

-- Grant permissions (token_domains relationships)
-- Development token gets wildcard access
INSERT INTO token_domains (token_id, domain_id) 
SELECT t.id, d.id 
FROM tokens t, domains d 
WHERE t.token = 'test-token-for-development' 
  AND d.name = '*'
ON CONFLICT DO NOTHING;

-- Admin token gets access to specific domains
INSERT INTO token_domains (token_id, domain_id) 
SELECT t.id, d.id 
FROM tokens t, domains d 
WHERE t.token = 'admin-token-12345' 
  AND d.name IN ('example.com', 'api.example.com', 'internal.company.com')
ON CONFLICT DO NOTHING;

-- Client token gets limited access
INSERT INTO token_domains (token_id, domain_id) 
SELECT t.id, d.id 
FROM tokens t, domains d 
WHERE t.token = 'client-token-67890' 
  AND d.name IN ('example.com', 'dev.example.com')
ON CONFLICT DO NOTHING;

-- Insert some sample query logs for testing
INSERT INTO query_logs (token_id, domain_queried, query_type, status, client_ip, timestamp) 
SELECT 
    t.id,
    'example.com',
    'A',
    'allowed',
    '127.0.0.1',
    CURRENT_TIMESTAMP - INTERVAL '1 hour'
FROM tokens t 
WHERE t.token = 'test-token-for-development';

INSERT INTO query_logs (token_id, domain_queried, query_type, status, client_ip, timestamp) 
SELECT 
    t.id,
    'blocked.example.com',
    'A',
    'denied',
    '192.168.1.100',
    CURRENT_TIMESTAMP - INTERVAL '30 minutes'
FROM tokens t 
WHERE t.token = 'client-token-67890';

-- Create a view for easier token permission queries
CREATE OR REPLACE VIEW token_permissions AS
SELECT 
    t.id as token_id,
    t.token,
    t.name as token_name,
    t.active,
    d.id as domain_id,
    d.name as domain_name,
    td.created_at as permission_granted_at
FROM tokens t
JOIN token_domains td ON t.id = td.token_id
JOIN domains d ON td.domain_id = d.id;

-- Create a view for query statistics
CREATE OR REPLACE VIEW query_statistics AS
SELECT 
    t.name as token_name,
    ql.status,
    COUNT(*) as query_count,
    DATE_TRUNC('day', ql.timestamp) as query_date
FROM query_logs ql
LEFT JOIN tokens t ON ql.token_id = t.id
GROUP BY t.name, ql.status, DATE_TRUNC('day', ql.timestamp)
ORDER BY query_date DESC, query_count DESC;

-- Grant permissions to the application user
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO squawk_user;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO squawk_user;

-- Print success message
\echo 'PostgreSQL database initialization completed successfully!'
\echo 'Test tokens created:'
\echo '- test-token-for-development (wildcard access)'
\echo '- admin-token-12345 (admin access)'  
\echo '- client-token-67890 (limited access)'
\echo ''
\echo 'Test domains created:'
\echo '- * (wildcard)'
\echo '- example.com, test.com, api.example.com'
\echo '- internal.company.com, dev.example.com'