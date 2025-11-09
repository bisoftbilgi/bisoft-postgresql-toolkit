-- Core tables for sql_firewall_rs. These definitions mirror the legacy C extension
-- but grant the necessary privileges so any role can interact with the firewall.

CREATE TABLE IF NOT EXISTS public.sql_firewall_activity_log (
    log_id           SERIAL PRIMARY KEY,
    log_time         TIMESTAMPTZ DEFAULT now() NOT NULL,
    role_name        NAME,
    database_name    NAME,
    query_text       TEXT,
    application_name TEXT,
    client_ip        TEXT,
    command_type     TEXT,
    action           TEXT,
    reason           TEXT
);

COMMENT ON TABLE  public.sql_firewall_activity_log IS 'Log of all actions performed by the SQL Firewall.';
COMMENT ON COLUMN public.sql_firewall_activity_log.action IS 'Action performed: ALLOWED, BLOCKED, LEARNED, etc.';
COMMENT ON COLUMN public.sql_firewall_activity_log.reason IS 'Reason for the action: Rate limit, blacklisted keyword, etc.';

CREATE INDEX IF NOT EXISTS idx_sqlfw_activity_role_time
    ON public.sql_firewall_activity_log(role_name, log_time);
CREATE INDEX IF NOT EXISTS idx_sqlfw_activity_role_cmd_time
    ON public.sql_firewall_activity_log(role_name, command_type, log_time);
CREATE INDEX IF NOT EXISTS idx_sqlfw_activity_action
    ON public.sql_firewall_activity_log(action);

GRANT SELECT, INSERT, UPDATE ON public.sql_firewall_activity_log TO PUBLIC;
GRANT USAGE, SELECT ON SEQUENCE public.sql_firewall_activity_log_log_id_seq TO PUBLIC;

CREATE TABLE IF NOT EXISTS public.sql_firewall_command_approvals (
    id           SERIAL PRIMARY KEY,
    role_name    NAME        NOT NULL,
    command_type TEXT        NOT NULL,
    is_approved  BOOLEAN     NOT NULL DEFAULT false,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (role_name, command_type)
);

COMMENT ON TABLE  public.sql_firewall_command_approvals IS 'Approval status of command types per role.';
COMMENT ON COLUMN public.sql_firewall_command_approvals.is_approved IS 'If true, this role is allowed to execute the command type.';

GRANT SELECT, INSERT, UPDATE ON public.sql_firewall_command_approvals TO PUBLIC;
GRANT USAGE, SELECT ON SEQUENCE public.sql_firewall_command_approvals_id_seq TO PUBLIC;

CREATE TABLE IF NOT EXISTS public.sql_firewall_regex_rules (
    id          SERIAL PRIMARY KEY,
    pattern     TEXT    NOT NULL UNIQUE,
    description TEXT,
    action      TEXT    NOT NULL DEFAULT 'BLOCK' CHECK (action = 'BLOCK'),
    is_active   BOOLEAN NOT NULL DEFAULT true,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

COMMENT ON TABLE  public.sql_firewall_regex_rules IS 'Regex rules used to match and block SQL queries.';
COMMENT ON COLUMN public.sql_firewall_regex_rules.pattern IS 'Regex pattern to apply on the query text.';

GRANT SELECT, INSERT, UPDATE, DELETE ON public.sql_firewall_regex_rules TO PUBLIC;
GRANT USAGE, SELECT ON SEQUENCE public.sql_firewall_regex_rules_id_seq TO PUBLIC;

INSERT INTO public.sql_firewall_regex_rules (pattern, description)
SELECT '(or|--|#)\s+\d+\s*=\s*\d+', 'Block simple SQL injection pattern'
WHERE NOT EXISTS (
    SELECT 1 FROM public.sql_firewall_regex_rules WHERE pattern = '(or|--|#)\s+\d+\s*=\s*\d+'
);

CREATE TABLE IF NOT EXISTS public.sql_firewall_query_fingerprints (
    id               SERIAL PRIMARY KEY,
    fingerprint      TEXT        NOT NULL,
    normalized_query TEXT        NOT NULL,
    role_name        NAME        NOT NULL,
    command_type     TEXT        NOT NULL,
    sample_query     TEXT        NOT NULL,
    hit_count        INTEGER     NOT NULL DEFAULT 1,
    is_approved      BOOLEAN     NOT NULL DEFAULT false,
    last_seen        TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (fingerprint, role_name, command_type)
);

COMMENT ON TABLE  public.sql_firewall_query_fingerprints IS 'Normalized query fingerprints tracked per role.';
COMMENT ON COLUMN public.sql_firewall_query_fingerprints.hit_count IS 'Number of times this fingerprint has been observed.';
COMMENT ON COLUMN public.sql_firewall_query_fingerprints.is_approved IS 'If true, queries matching this fingerprint are allowed.';

CREATE INDEX IF NOT EXISTS idx_sqlfw_fingerprint_role
    ON public.sql_firewall_query_fingerprints(role_name, fingerprint);
CREATE INDEX IF NOT EXISTS idx_sqlfw_fingerprint_last_seen
    ON public.sql_firewall_query_fingerprints(last_seen);

GRANT SELECT, INSERT, UPDATE ON public.sql_firewall_query_fingerprints TO PUBLIC;
GRANT USAGE, SELECT ON SEQUENCE public.sql_firewall_query_fingerprints_id_seq TO PUBLIC;
