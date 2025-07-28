-- complain if script is sourced in psql, rather than via CREATE EXTENSION
\echo Use "CREATE EXTENSION sql_firewall" to load this file. \quit

-- Table for logging firewall activity.
-- This table records every action taken by the firewall.
CREATE TABLE sql_firewall_activity_log (
    log_id SERIAL PRIMARY KEY,
    log_time TIMESTAMPTZ NOT NULL DEFAULT now(),
    role_name NAME,
    database_name NAME,
    action TEXT,
    reason TEXT,
    query_text TEXT,
    command_type TEXT
);

-- Table for a user's command type approvals (NEW LOGIC).
-- Stores approvals for command types (SELECT, INSERT, etc.) for each role.
CREATE TABLE sql_firewall_command_approvals (
    id SERIAL PRIMARY KEY,
    role_name NAME NOT NULL,
    command_type TEXT NOT NULL,
    is_approved BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (role_name, command_type)
);

-- Table for regular expression-based rules.
-- Stores regex patterns to detect and block threats like SQL injection.
CREATE TABLE sql_firewall_regex_rules (
    id SERIAL PRIMARY KEY,
    pattern TEXT NOT NULL UNIQUE,
    description TEXT,
    action TEXT NOT NULL DEFAULT 'BLOCK' CHECK (action = 'BLOCK'),
    is_active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Function to reset activity logs for a specific role.
-- Useful for resetting rate-limit counters.
CREATE FUNCTION sql_firewall_reset_log_for_role(rolename name)
RETURNS bigint
AS '$libdir/sql_firewall', 'sql_firewall_reset_log_for_role'
LANGUAGE C STRICT;

-- Permissions
-- Granting permissions to PUBLIC allows the extension's C code, running with
-- the privileges of any user, to read and write to these tables via SPI.
GRANT SELECT, INSERT ON TABLE sql_firewall_command_approvals TO PUBLIC;
GRANT USAGE ON SEQUENCE sql_firewall_command_approvals_id_seq TO PUBLIC;

GRANT SELECT, INSERT ON TABLE sql_firewall_activity_log TO PUBLIC;
GRANT USAGE ON SEQUENCE sql_firewall_activity_log_log_id_seq TO PUBLIC;

GRANT SELECT ON TABLE sql_firewall_regex_rules TO PUBLIC;

