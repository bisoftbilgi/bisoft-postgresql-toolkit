-- sql_firewall--0.1.0.sql

-- Prevent direct execution of this file.
\echo Use "CREATE EXTENSION sql_firewall" to load this file. \quit

-- Table to store the firewall rules.
CREATE TABLE sql_firewall_rules (
    rule_id SERIAL PRIMARY KEY,
    role_name NAME NOT NULL,
    database_name NAME NOT NULL,
    command_type TEXT NOT NULL,
    query_fingerprint BIGINT NOT NULL,
    is_approved BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- Prevent duplicate rules for the same role, database, query, and command.
    UNIQUE (role_name, database_name, query_fingerprint, command_type)
);

-- Table to log all firewall activity.
CREATE TABLE sql_firewall_activity_log (
    log_id BIGSERIAL PRIMARY KEY,
    log_time TIMESTAMPTZ NOT NULL DEFAULT now(),
    role_name NAME,
    database_name NAME,
    action TEXT NOT NULL, -- e.g., ALLOWED, BLOCKED, LEARNED
    reason TEXT,          -- e.g., "Rule not approved", "Rate limit exceeded"
    query_text TEXT,
    command_type TEXT
);

-- Set permissions so that only superusers can access the tables (recommended for security).
REVOKE ALL ON TABLE sql_firewall_rules FROM PUBLIC;
REVOKE ALL ON TABLE sql_firewall_activity_log FROM PUBLIC;
