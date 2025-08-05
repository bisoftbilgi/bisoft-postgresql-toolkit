-- TABLES
CREATE TABLE IF NOT EXISTS public.sql_firewall_activity_log (
    log_id SERIAL PRIMARY KEY,
    log_time TIMESTAMPTZ DEFAULT now(),
    role TEXT,
    db_name TEXT,
    query TEXT,
    application_name TEXT,
    client_ip TEXT,
    command TEXT,
    action TEXT,
    reason TEXT
);

COMMENT ON TABLE public.sql_firewall_activity_log IS 'Log of all actions performed by the SQL Firewall.';
COMMENT ON COLUMN public.sql_firewall_activity_log.action IS 'Action performed: ALLOWED, BLOCKED, LEARNED, etc.';
COMMENT ON COLUMN public.sql_firewall_activity_log.reason IS 'Reason for the action: Rate limit, Blacklisted keyword, etc.';

CREATE TABLE public.sql_firewall_command_approvals (
    id SERIAL PRIMARY KEY,
    role_name NAME NOT NULL,
    command_type TEXT NOT NULL,
    is_approved BOOLEAN DEFAULT false NOT NULL,
    created_at TIMESTAMPTZ DEFAULT now() NOT NULL,
    UNIQUE (role_name, command_type)
);

COMMENT ON TABLE public.sql_firewall_command_approvals IS 'Approval status of command types per role.';
COMMENT ON COLUMN public.sql_firewall_command_approvals.is_approved IS 'If true, this role is allowed to execute the command type.';

CREATE TABLE public.sql_firewall_regex_rules (
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

INSERT INTO public.sql_firewall_regex_rules (pattern, description)
VALUES ('(or|--|#)\s+\d+\s*=\s*\d+', 'Block simple SQL injection pattern')
ON CONFLICT (pattern) DO NOTHING;

-- C-function declarations
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

CREATE OR REPLACE FUNCTION sql_firewall_reject_all_for_role(role_name NAME)
RETURNS BIGINT
AS '$libdir/sql_firewall', 'sql_firewall_reject_all_for_role'
LANGUAGE C STRICT;

