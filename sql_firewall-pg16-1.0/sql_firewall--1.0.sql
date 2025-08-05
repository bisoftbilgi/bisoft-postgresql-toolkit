-- ============== Tables (core) ==============

-- Activity log table
CREATE TABLE IF NOT EXISTS public.sql_firewall_activity_log (
    log_id SERIAL PRIMARY KEY,
    log_time TIMESTAMPTZ DEFAULT now(),
    role_name NAME,  -- Changed from TEXT to NAME to match C code
    database_name NAME,  -- Changed from db_name and TEXT to NAME
    query_text TEXT,  -- Changed from query to query_text
    application_name TEXT,
    client_ip TEXT,
    command_type TEXT,  -- Changed from command to command_type
    action TEXT,
    reason TEXT
);

COMMENT ON TABLE public.sql_firewall_activity_log IS 'Log of all actions performed by the SQL Firewall.';
COMMENT ON COLUMN public.sql_firewall_activity_log.action IS 'Action performed: ALLOWED, BLOCKED, LEARNED, etc.';
COMMENT ON COLUMN public.sql_firewall_activity_log.reason IS 'Reason for the action: Rate limit, Blacklisted keyword, etc.';

-- Create indexes for better performance
CREATE INDEX IF NOT EXISTS idx_activity_log_role_time ON public.sql_firewall_activity_log(role_name, log_time);
CREATE INDEX IF NOT EXISTS idx_activity_log_command_time ON public.sql_firewall_activity_log(role_name, command_type, log_time);
CREATE INDEX IF NOT EXISTS idx_activity_log_action ON public.sql_firewall_activity_log(action);

-- Command approvals
CREATE TABLE IF NOT EXISTS public.sql_firewall_command_approvals (
    id SERIAL PRIMARY KEY,
    role_name NAME NOT NULL,
    command_type TEXT NOT NULL,
    is_approved BOOLEAN DEFAULT false NOT NULL,
    created_at TIMESTAMPTZ DEFAULT now() NOT NULL,
    UNIQUE (role_name, command_type)
);

COMMENT ON TABLE public.sql_firewall_command_approvals IS 'Approval status of command types per role.';
COMMENT ON COLUMN public.sql_firewall_command_approvals.is_approved IS 'If true, this role is allowed to execute the command type.';

-- Regex rules
CREATE TABLE IF NOT EXISTS public.sql_firewall_regex_rules (
    id SERIAL PRIMARY KEY,
    pattern TEXT NOT NULL UNIQUE,
    description TEXT,
    action TEXT NOT NULL DEFAULT 'BLOCK' CHECK (action IN ('BLOCK')),
    is_active BOOLEAN DEFAULT true NOT NULL,
    created_at TIMESTAMPTZ DEFAULT now() NOT NULL
);

COMMENT ON TABLE public.sql_firewall_regex_rules IS 'Regex rules used to match and block SQL queries.';
COMMENT ON COLUMN public.sql_firewall_regex_rules.pattern IS 'Regex pattern to apply on the query text.';
COMMENT ON COLUMN public.sql_firewall_regex_rules.action IS 'Action to perform when the pattern matches.';

-- Quiet hours
CREATE TABLE IF NOT EXISTS public.sql_firewall_quiet_hours (
    start_time TEXT,
    end_time TEXT
);

COMMENT ON TABLE public.sql_firewall_quiet_hours IS 'Time ranges during which queries are blocked. Format: HH24:MI';

-- Blocked IPs
CREATE TABLE IF NOT EXISTS public.sql_firewall_blocked_ips (
    ip_address TEXT PRIMARY KEY
);

COMMENT ON TABLE public.sql_firewall_blocked_ips IS 'List of client IPs to be blocked.';

-- Blocked applications
CREATE TABLE IF NOT EXISTS public.sql_firewall_blocked_apps (
    application_name TEXT PRIMARY KEY
);

COMMENT ON TABLE public.sql_firewall_blocked_apps IS 'List of application_name values to be blocked.';

-- Blocked keywords
CREATE TABLE IF NOT EXISTS public.sql_firewall_keywords (
    keyword TEXT PRIMARY KEY
);

COMMENT ON TABLE public.sql_firewall_keywords IS 'SQL keywords to be blocked if found in queries.';

-- ============== Sample Rule ==============
INSERT INTO public.sql_firewall_regex_rules (pattern, description)
VALUES ('(or|--|#)\\s+\\d+\\s*=\\s*\\d+', 'Block simple SQL injection pattern')
ON CONFLICT (pattern) DO NOTHING;

-- ============== C Functions ==============

CREATE OR REPLACE FUNCTION sql_firewall_reset_log_for_role(role_name NAME)
RETURNS BIGINT
AS '$libdir/sql_firewall', 'sql_firewall_reset_log_for_role'
LANGUAGE C STRICT;

COMMENT ON FUNCTION sql_firewall_reset_log_for_role(NAME) IS
'Superuser only. Clears the activity log for the given role.';

CREATE OR REPLACE FUNCTION sql_firewall_approve_all_for_role(role_name NAME)
RETURNS BIGINT
AS '$libdir/sql_firewall', 'sql_firewall_approve_all_for_role'
LANGUAGE C STRICT;

COMMENT ON FUNCTION sql_firewall_approve_all_for_role(NAME) IS
'Superuser only. Approves all pending commands for the given role.';

CREATE OR REPLACE FUNCTION sql_firewall_reject_all_for_role(role_name NAME)
RETURNS BIGINT
AS '$libdir/sql_firewall', 'sql_firewall_reject_all_for_role'
LANGUAGE C STRICT;

COMMENT ON FUNCTION sql_firewall_reject_all_for_role(NAME) IS
'Superuser only. Rejects (unapproves) all approved commands for the given role.';

-- ============== Permissions ==============

GRANT SELECT, INSERT ON public.sql_firewall_activity_log TO PUBLIC;
GRANT USAGE, SELECT ON SEQUENCE public.sql_firewall_activity_log_log_id_seq TO PUBLIC;

GRANT SELECT, INSERT ON public.sql_firewall_command_approvals TO PUBLIC;
GRANT USAGE, SELECT ON SEQUENCE public.sql_firewall_command_approvals_id_seq TO PUBLIC;

GRANT SELECT ON public.sql_firewall_regex_rules TO PUBLIC;
GRANT SELECT ON public.sql_firewall_quiet_hours TO PUBLIC;
GRANT SELECT ON public.sql_firewall_blocked_ips TO PUBLIC;
GRANT SELECT ON public.sql_firewall_blocked_apps TO PUBLIC;
GRANT SELECT ON public.sql_firewall_keywords TO PUBLIC;
