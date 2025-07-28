-- complain if script is sourced in psql, rather than via CREATE EXTENSION
\echo Use "CREATE EXTENSION sql_firewall" to load this file. \quit

---
-- Table for logging firewall activity.
-- This table records every action taken by the firewall, such as allowing,
-- blocking, or learning a query.
---
CREATE TABLE sql_firewall_activity_log (
    log_id SERIAL PRIMARY KEY,
    log_time TIMESTAMPTZ NOT NULL DEFAULT now(),
    role_name NAME NOT NULL,
    database_name NAME,
    action TEXT NOT NULL,
    reason TEXT,
    query_text TEXT NOT NULL,
    command_type TEXT
);

---
-- Table for hash-based query rules.
-- Stores query "fingerprints" (hashes) for specific roles and commands.
-- Used by the 'learn' and 'enforce' modes.
---
CREATE TABLE sql_firewall_rules (
    rule_id SERIAL PRIMARY KEY,
    role_name NAME NOT NULL,
    command_type TEXT NOT NULL,
    query_fingerprint BIGINT NOT NULL,
    database_name NAME,
    is_approved BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (role_name, command_type, query_fingerprint, database_name)
);

---
-- Table for regular expression-based rules.
-- Stores regex patterns to detect and block threats like SQL injection.
---
CREATE TABLE sql_firewall_regex_rules (
    id SERIAL PRIMARY KEY,
    pattern TEXT NOT NULL UNIQUE,
    description TEXT,
    action VARCHAR(10) NOT NULL DEFAULT 'BLOCK' CHECK (action IN ('BLOCK', 'ALLOW')),
    is_active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

---
-- Permissions
-- Granting SELECT to PUBLIC allows the extension's C code, running with the
-- privileges of any user, to read the rules from these tables via SPI.
---
GRANT SELECT ON TABLE sql_firewall_rules TO PUBLIC;
GRANT SELECT ON TABLE sql_firewall_regex_rules TO PUBLIC;
CREATE FUNCTION sql_firewall_reset_log_for_role(rolename name)
RETURNS bigint
AS '$libdir/sql_firewall', 'sql_firewall_reset_log_for_role'
LANGUAGE C STRICT;
