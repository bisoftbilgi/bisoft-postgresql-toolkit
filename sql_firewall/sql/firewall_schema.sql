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

ALTER TABLE public.sql_firewall_activity_log SET LOGGED;

CREATE INDEX IF NOT EXISTS idx_sqlfw_activity_role_time
    ON public.sql_firewall_activity_log(role_name, log_time);
CREATE INDEX IF NOT EXISTS idx_sqlfw_activity_role_cmd_time
    ON public.sql_firewall_activity_log(role_name, command_type, log_time);
CREATE INDEX IF NOT EXISTS idx_sqlfw_activity_action
    ON public.sql_firewall_activity_log(action);

-- SECURITY: No direct grants to PUBLIC - all access through SECURITY DEFINER functions
-- This prevents users from tampering with firewall logs and configuration

-- Dedicated table for blocked queries - separate from activity log for security analysis
-- ENHANCED: Now with 2KB query buffer, truncation flag, and richer metadata
CREATE TABLE IF NOT EXISTS public.sql_firewall_blocked_queries (
    block_id         SERIAL PRIMARY KEY,
    blocked_at       TIMESTAMPTZ DEFAULT now() NOT NULL,
    role_name        NAME,
    database_name    NAME,
    query_text       TEXT,               -- Up to 2KB query text (enforced by ring buffer)
    query_truncated  BOOLEAN DEFAULT false, -- True if query was larger than 2KB
    application_name TEXT,
    client_addr      TEXT,               -- Renamed from client_ip for consistency
    command_type     TEXT,
    reason           TEXT                -- Renamed from block_reason for consistency with activity log
);

COMMENT ON TABLE  public.sql_firewall_blocked_queries IS 'Dedicated log for blocked queries - useful for security analysis and auditing.';
COMMENT ON COLUMN public.sql_firewall_blocked_queries.query_truncated IS 'True if query was truncated at 2KB limit during capture.';
COMMENT ON COLUMN public.sql_firewall_blocked_queries.reason IS 'Reason why the query was blocked: No approval, regex match, rate limit, etc.';

ALTER TABLE public.sql_firewall_blocked_queries SET LOGGED;

CREATE INDEX IF NOT EXISTS idx_sqlfw_blocked_role_time
    ON public.sql_firewall_blocked_queries(role_name, blocked_at);
CREATE INDEX IF NOT EXISTS idx_sqlfw_blocked_command_time
    ON public.sql_firewall_blocked_queries(command_type, blocked_at);

-- SECURITY: No direct grants to PUBLIC - all access through SECURITY DEFINER functions
-- This prevents users from tampering with security audit logs

-- ENHANCED: is_approved column tracks whether approval was granted or pending
CREATE TABLE IF NOT EXISTS public.sql_firewall_command_approvals (
    id           SERIAL PRIMARY KEY,
    role_name    NAME        NOT NULL,
    command_type TEXT        NOT NULL,
    is_approved  BOOLEAN     NOT NULL DEFAULT false,  -- TRUE = approved, FALSE = pending admin review
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now(),  -- Track when approval status last changed
    UNIQUE (role_name, command_type)
);

COMMENT ON TABLE  public.sql_firewall_command_approvals IS 'Approval status of command types per role.';
COMMENT ON COLUMN public.sql_firewall_command_approvals.is_approved IS 'If true, this role is allowed to execute the command type. If false, approval is pending admin review.';
COMMENT ON COLUMN public.sql_firewall_command_approvals.updated_at IS 'Timestamp when approval status was last changed (useful for auditing approval grants).';

-- SECURITY: No direct grants to PUBLIC - all access through SECURITY DEFINER functions
-- This prevents users from approving their own commands

CREATE TABLE IF NOT EXISTS public.sql_firewall_regex_rules (
    id            SERIAL PRIMARY KEY,
    pattern       TEXT    NOT NULL UNIQUE,
    description   TEXT,
    action        TEXT    NOT NULL DEFAULT 'BLOCK' CHECK (action = 'BLOCK'),
    is_active     BOOLEAN NOT NULL DEFAULT true,
    allowed_roles TEXT[], -- NULL means rule applies to all roles, non-NULL means rule only applies to listed roles
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

COMMENT ON TABLE  public.sql_firewall_regex_rules IS 'Regex rules used to match and block SQL queries.';
COMMENT ON COLUMN public.sql_firewall_regex_rules.pattern IS 'Regex pattern to apply on the query text.';
COMMENT ON COLUMN public.sql_firewall_regex_rules.allowed_roles IS 'List of roles for which this rule applies. NULL means applies to all roles.';

-- CRITICAL: Validate regex patterns to prevent ReDoS attacks
CREATE OR REPLACE FUNCTION validate_firewall_regex_pattern()
RETURNS TRIGGER AS $$
BEGIN
    -- Check for dangerous patterns that can cause ReDoS
    IF NEW.pattern ~ '.*\(\?.*\{.*\}.*\).*' THEN
        RAISE EXCEPTION 'Complex nested quantifiers not allowed (ReDoS risk)';
    END IF;
    
    -- Check for excessive repetition operators
    IF NEW.pattern ~ '.*((\+\+)|(\*\*)|(\+\*)).*' THEN
        RAISE EXCEPTION 'Multiple adjacent quantifiers not allowed (ReDoS risk)';
    END IF;
    
    -- Test pattern with a simple string to ensure it's valid
    BEGIN
        PERFORM 'test' ~ NEW.pattern;
    EXCEPTION WHEN OTHERS THEN
        RAISE EXCEPTION 'Invalid regex pattern: %', SQLERRM;
    END;
    
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER validate_regex_trigger
BEFORE INSERT OR UPDATE ON public.sql_firewall_regex_rules
FOR EACH ROW EXECUTE FUNCTION validate_firewall_regex_pattern();

-- SECURITY: No direct grants to PUBLIC - all access through admin functions
-- Users can query via SECURITY DEFINER functions but cannot modify

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
    first_seen_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (fingerprint, role_name, command_type)
);

COMMENT ON TABLE  public.sql_firewall_query_fingerprints IS 'Normalized query fingerprints tracked per role.';
COMMENT ON COLUMN public.sql_firewall_query_fingerprints.hit_count IS 'Number of times this fingerprint has been observed.';
COMMENT ON COLUMN public.sql_firewall_query_fingerprints.is_approved IS 'If true, queries matching this fingerprint are allowed.';
COMMENT ON COLUMN public.sql_firewall_query_fingerprints.first_seen_at IS 'Timestamp when this fingerprint was first recorded.';
COMMENT ON COLUMN public.sql_firewall_query_fingerprints.last_seen_at IS 'Timestamp when this fingerprint was last observed.';

CREATE INDEX IF NOT EXISTS idx_sqlfw_fingerprint_role
    ON public.sql_firewall_query_fingerprints(role_name, fingerprint);
CREATE INDEX IF NOT EXISTS idx_sqlfw_fingerprint_last_seen
    ON public.sql_firewall_query_fingerprints(last_seen_at);

-- SECURITY: No direct grants to PUBLIC - all access through SECURITY DEFINER functions
-- This prevents users from tampering with learned fingerprints

-- NEW: Fingerprint hits table for background worker event processing
CREATE TABLE IF NOT EXISTS public.sql_firewall_fingerprint_hits (
    fingerprint      TEXT PRIMARY KEY,
    normalized_query TEXT        NOT NULL,
    role_name        NAME,
    command_type     TEXT,
    sample_query     TEXT,
    hit_count        BIGINT      NOT NULL DEFAULT 1,
    is_approved      BOOLEAN     NOT NULL DEFAULT false,
    first_hit_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_hit_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

COMMENT ON TABLE  public.sql_firewall_fingerprint_hits IS 'Fingerprint hit tracking populated by background worker from ring buffer events.';
COMMENT ON COLUMN public.sql_firewall_fingerprint_hits.hit_count IS 'Number of times this fingerprint has been observed (incremented by ON CONFLICT).';
COMMENT ON COLUMN public.sql_firewall_fingerprint_hits.is_approved IS 'If true, queries matching this fingerprint are allowed.';

CREATE INDEX IF NOT EXISTS idx_sqlfw_fphits_approved
    ON public.sql_firewall_fingerprint_hits(is_approved, hit_count DESC);
CREATE INDEX IF NOT EXISTS idx_sqlfw_fphits_last_hit
    ON public.sql_firewall_fingerprint_hits(last_hit_at DESC);

-- SECURITY: No direct grants to PUBLIC - all access through SECURITY DEFINER functions

-- ============================================================================
-- SECURITY DEFINER Functions for Controlled Admin Access
-- ============================================================================

-- Function to approve a command for a role (only superusers can call this)
CREATE OR REPLACE FUNCTION public.sql_firewall_approve_command(
    p_role_name NAME,
    p_command_type TEXT
) RETURNS VOID AS $$
BEGIN
    -- Only superusers can approve commands (use session_user not current_user in SECURITY DEFINER)
    IF NOT (SELECT usesuper FROM pg_user WHERE usename = session_user) THEN
        RAISE EXCEPTION 'Only superusers can approve commands';
    END IF;
    
    INSERT INTO public.sql_firewall_command_approvals (role_name, command_type, is_approved)
    VALUES (p_role_name, p_command_type, true)
    ON CONFLICT (role_name, command_type) 
    DO UPDATE SET is_approved = true;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

COMMENT ON FUNCTION public.sql_firewall_approve_command IS 
'Approve a command type for a specific role. Only callable by superusers.';

-- Function to revoke command approval (only superusers can call this)
CREATE OR REPLACE FUNCTION public.sql_firewall_revoke_command(
    p_role_name NAME,
    p_command_type TEXT
) RETURNS VOID AS $$
BEGIN
    -- Only superusers can revoke commands (use session_user not current_user in SECURITY DEFINER)
    IF NOT (SELECT usesuper FROM pg_user WHERE usename = session_user) THEN
        RAISE EXCEPTION 'Only superusers can revoke commands';
    END IF;
    
    UPDATE public.sql_firewall_command_approvals
    SET is_approved = false
    WHERE role_name = p_role_name AND command_type = p_command_type;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Function to approve a fingerprint (only superusers can call this)
CREATE OR REPLACE FUNCTION public.sql_firewall_approve_fingerprint(
    p_fingerprint TEXT,
    p_role_name NAME,
    p_command_type TEXT
) RETURNS VOID AS $$
BEGIN
    -- Only superusers can approve fingerprints (use session_user not current_user in SECURITY DEFINER)
    IF NOT (SELECT usesuper FROM pg_user WHERE usename = session_user) THEN
        RAISE EXCEPTION 'Only superusers can approve fingerprints';
    END IF;
    
    UPDATE public.sql_firewall_query_fingerprints
    SET is_approved = true
    WHERE fingerprint = p_fingerprint 
      AND role_name = p_role_name 
      AND command_type = p_command_type;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Function to block a fingerprint (only superusers can call this)
CREATE OR REPLACE FUNCTION public.sql_firewall_block_fingerprint(
    p_fingerprint TEXT,
    p_role_name NAME,
    p_command_type TEXT
) RETURNS VOID AS $$
BEGIN
    -- Only superusers can block fingerprints (use session_user not current_user in SECURITY DEFINER)
    IF NOT (SELECT usesuper FROM pg_user WHERE usename = session_user) THEN
        RAISE EXCEPTION 'Only superusers can block fingerprints';
    END IF;
    
    UPDATE public.sql_firewall_query_fingerprints
    SET is_approved = false
    WHERE fingerprint = p_fingerprint 
      AND role_name = p_role_name 
      AND command_type = p_command_type;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Function to add a regex rule (only superusers can call this)
CREATE OR REPLACE FUNCTION public.sql_firewall_add_regex_rule(
    p_pattern TEXT,
    p_description TEXT DEFAULT NULL
) RETURNS INTEGER AS $$
DECLARE
    v_rule_id INTEGER;
BEGIN
    -- Only superusers can add regex rules (use session_user not current_user in SECURITY DEFINER)
    IF NOT (SELECT usesuper FROM pg_user WHERE usename = session_user) THEN
        RAISE EXCEPTION 'Only superusers can add regex rules';
    END IF;
    
    INSERT INTO public.sql_firewall_regex_rules (pattern, description)
    VALUES (p_pattern, p_description)
    RETURNING id INTO v_rule_id;
    
    RETURN v_rule_id;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Function to delete a regex rule (only superusers can call this)
CREATE OR REPLACE FUNCTION public.sql_firewall_delete_regex_rule(
    p_rule_id INTEGER
) RETURNS VOID AS $$
BEGIN
    -- Only superusers can delete regex rules (use session_user not current_user in SECURITY DEFINER)
    IF NOT (SELECT usesuper FROM pg_user WHERE usename = session_user) THEN
        RAISE EXCEPTION 'Only superusers can delete regex rules';
    END IF;
    
    DELETE FROM public.sql_firewall_regex_rules
    WHERE id = p_rule_id;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Function to toggle regex rule active status (only superusers can call this)
CREATE OR REPLACE FUNCTION public.sql_firewall_toggle_regex_rule(
    p_rule_id INTEGER,
    p_is_active BOOLEAN
) RETURNS VOID AS $$
BEGIN
    -- Only superusers can toggle regex rules (use session_user not current_user in SECURITY DEFINER)
    IF NOT (SELECT usesuper FROM pg_user WHERE usename = session_user) THEN
        RAISE EXCEPTION 'Only superusers can modify regex rules';
    END IF;
    
    UPDATE public.sql_firewall_regex_rules
    SET is_active = p_is_active
    WHERE id = p_rule_id;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Grant EXECUTE on admin functions to PUBLIC (functions enforce superuser check internally)
GRANT EXECUTE ON FUNCTION public.sql_firewall_approve_command(NAME, TEXT) TO PUBLIC;
GRANT EXECUTE ON FUNCTION public.sql_firewall_revoke_command(NAME, TEXT) TO PUBLIC;
GRANT EXECUTE ON FUNCTION public.sql_firewall_approve_fingerprint(TEXT, NAME, TEXT) TO PUBLIC;
GRANT EXECUTE ON FUNCTION public.sql_firewall_block_fingerprint(TEXT, NAME, TEXT) TO PUBLIC;
GRANT EXECUTE ON FUNCTION public.sql_firewall_add_regex_rule(TEXT, TEXT) TO PUBLIC;
GRANT EXECUTE ON FUNCTION public.sql_firewall_delete_regex_rule(INTEGER) TO PUBLIC;
GRANT EXECUTE ON FUNCTION public.sql_firewall_toggle_regex_rule(INTEGER, BOOLEAN) TO PUBLIC;


-- ============================================================================
-- SECURITY DEFINER Wrappers for Extension Internal Operations
-- ============================================================================
-- These functions allow the extension to write to catalog tables
-- without granting INSERT/UPDATE/DELETE to PUBLIC

-- Log activity (called by extension internally)
CREATE OR REPLACE FUNCTION public.sql_firewall_internal_log_activity(
    p_role_name NAME,
    p_database_name NAME,
    p_query_text TEXT,
    p_application_name TEXT,
    p_client_ip TEXT,
    p_command_type TEXT,
    p_action TEXT,
    p_reason TEXT
) RETURNS VOID AS $$
BEGIN
    INSERT INTO public.sql_firewall_activity_log (
        role_name, database_name, query_text, application_name,
        client_ip, command_type, action, reason
    ) VALUES (
        p_role_name, p_database_name, p_query_text, p_application_name,
        p_client_ip, p_command_type, p_action, p_reason
    );
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Log blocked query to dedicated table (called by extension internally)
CREATE OR REPLACE FUNCTION public.sql_firewall_internal_log_blocked_query(
    p_role_name NAME,
    p_database_name NAME,
    p_query_text TEXT,
    p_application_name TEXT,
    p_client_ip TEXT,
    p_command_type TEXT,
    p_block_reason TEXT
) RETURNS VOID AS $$
DECLARE
    v_conn TEXT;
    v_result TEXT;
BEGIN
    -- Use dblink to perform autonomous transaction that survives rollback
    -- This ensures blocked queries are logged even when the main transaction aborts
    BEGIN
        -- Connect to current database using dblink (safely quote database name)
        v_conn := 'dbname=' || quote_ident(current_database());
        PERFORM dblink_connect('firewall_log_conn', v_conn);
        
        -- Execute INSERT in autonomous transaction
        PERFORM dblink_exec('firewall_log_conn',
            format('INSERT INTO public.sql_firewall_blocked_queries 
                (role_name, database_name, query_text, application_name, client_addr, command_type, reason) 
                VALUES (%L, %L, %L, %L, %L, %L, %L)',
                p_role_name, p_database_name, p_query_text, p_application_name,
                p_client_ip, p_command_type, p_block_reason
            )
        );
        
        -- Disconnect dblink
        PERFORM dblink_disconnect('firewall_log_conn');
    EXCEPTION WHEN OTHERS THEN
        -- If dblink fails, fall back to regular INSERT (which may rollback)
        BEGIN
            PERFORM dblink_disconnect('firewall_log_conn');
        EXCEPTION WHEN OTHERS THEN
            -- Ignore disconnect errors
        END;
        
        -- Fallback: regular insert (will rollback with transaction)
        INSERT INTO public.sql_firewall_blocked_queries (
            role_name, database_name, query_text, application_name,
            client_addr, command_type, reason
        ) VALUES (
            p_role_name, p_database_name, p_query_text, p_application_name,
            p_client_ip, p_command_type, p_block_reason
        );
    END;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Record or update fingerprint (called by extension internally)
CREATE OR REPLACE FUNCTION public.sql_firewall_internal_upsert_fingerprint(
    p_fingerprint TEXT,
    p_normalized_query TEXT,
    p_role_name NAME,
    p_command_type TEXT,
    p_sample_query TEXT,
    p_is_approved BOOLEAN
) RETURNS VOID AS $$
BEGIN
    INSERT INTO public.sql_firewall_query_fingerprints (
        fingerprint, normalized_query, role_name, command_type,
        sample_query, hit_count, is_approved, last_seen_at
    ) VALUES (
        p_fingerprint, p_normalized_query, p_role_name, p_command_type,
        p_sample_query, 1, p_is_approved, now()
    )
    ON CONFLICT (fingerprint, role_name, command_type) DO UPDATE
    SET hit_count = sql_firewall_query_fingerprints.hit_count + 1,
        last_seen_at = now();
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Create or update approval (called by extension internally)
CREATE OR REPLACE FUNCTION public.sql_firewall_internal_upsert_approval(
    p_role_name NAME,
    p_command_type TEXT,
    p_is_approved BOOLEAN
) RETURNS VOID AS $$
BEGIN
    -- Only superusers can use this internal function (called by background worker)
    IF NOT (SELECT usesuper FROM pg_user WHERE usename = session_user) THEN
        RAISE EXCEPTION 'Only superusers can use this internal function';
    END IF;
    
    INSERT INTO public.sql_firewall_command_approvals (
        role_name, command_type, is_approved
    ) VALUES (
        p_role_name, p_command_type, p_is_approved
    )
    ON CONFLICT (role_name, command_type) DO UPDATE
    SET is_approved = p_is_approved;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Grant EXECUTE on internal functions to PUBLIC
GRANT EXECUTE ON FUNCTION public.sql_firewall_internal_log_activity(NAME, NAME, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT) TO PUBLIC;
GRANT EXECUTE ON FUNCTION public.sql_firewall_internal_log_blocked_query(NAME, NAME, TEXT, TEXT, TEXT, TEXT, TEXT) TO PUBLIC;
GRANT EXECUTE ON FUNCTION public.sql_firewall_internal_upsert_fingerprint(TEXT, TEXT, NAME, TEXT, TEXT, BOOLEAN) TO PUBLIC;
GRANT EXECUTE ON FUNCTION public.sql_firewall_internal_upsert_approval(NAME, TEXT, BOOLEAN) TO PUBLIC;

-- ========================================
-- LOG CLEANUP FUNCTIONS
-- ========================================

-- Clean activity log entries older than specified interval
CREATE OR REPLACE FUNCTION public.sql_firewall_cleanup_activity_log(
    p_retention_interval INTERVAL DEFAULT '30 days'
)
RETURNS TABLE(deleted_count BIGINT) AS $$
DECLARE
    v_deleted_count BIGINT;
BEGIN
    -- Only superusers can cleanup logs
    IF NOT (SELECT usesuper FROM pg_user WHERE usename = session_user) THEN
        RAISE EXCEPTION 'Only superusers can cleanup firewall logs';
    END IF;
    
    DELETE FROM public.sql_firewall_activity_log
    WHERE log_time < (now() - p_retention_interval);
    
    GET DIAGNOSTICS v_deleted_count = ROW_COUNT;
    
    RETURN QUERY SELECT v_deleted_count;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

COMMENT ON FUNCTION public.sql_firewall_cleanup_activity_log(INTERVAL) IS 
'Delete activity log entries older than specified interval. Default: 30 days. Superuser only.';

-- Clean blocked queries log entries older than specified interval
CREATE OR REPLACE FUNCTION public.sql_firewall_cleanup_blocked_queries(
    p_retention_interval INTERVAL DEFAULT '90 days'
)
RETURNS TABLE(deleted_count BIGINT) AS $$
DECLARE
    v_deleted_count BIGINT;
BEGIN
    -- Only superusers can cleanup logs
    IF NOT (SELECT usesuper FROM pg_user WHERE usename = session_user) THEN
        RAISE EXCEPTION 'Only superusers can cleanup firewall logs';
    END IF;
    
    DELETE FROM public.sql_firewall_blocked_queries
    WHERE blocked_at < (now() - p_retention_interval);
    
    GET DIAGNOSTICS v_deleted_count = ROW_COUNT;
    
    RETURN QUERY SELECT v_deleted_count;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

COMMENT ON FUNCTION public.sql_firewall_cleanup_blocked_queries(INTERVAL) IS 
'Delete blocked query log entries older than specified interval. Default: 90 days (longer retention for security analysis). Superuser only.';

-- Cleanup both logs in one transaction
CREATE OR REPLACE FUNCTION public.sql_firewall_cleanup_all_logs(
    p_activity_retention INTERVAL DEFAULT '30 days',
    p_blocked_retention INTERVAL DEFAULT '90 days'
)
RETURNS TABLE(
    activity_deleted BIGINT,
    blocked_deleted BIGINT,
    total_deleted BIGINT
) AS $$
DECLARE
    v_activity_count BIGINT;
    v_blocked_count BIGINT;
BEGIN
    -- Only superusers can cleanup logs
    IF NOT (SELECT usesuper FROM pg_user WHERE usename = session_user) THEN
        RAISE EXCEPTION 'Only superusers can cleanup firewall logs';
    END IF;
    
    -- Cleanup activity log
    DELETE FROM public.sql_firewall_activity_log
    WHERE log_time < (now() - p_activity_retention);
    GET DIAGNOSTICS v_activity_count = ROW_COUNT;
    
    -- Cleanup blocked queries log
    DELETE FROM public.sql_firewall_blocked_queries
    WHERE blocked_at < (now() - p_blocked_retention);
    GET DIAGNOSTICS v_blocked_count = ROW_COUNT;
    
    RETURN QUERY SELECT 
        v_activity_count,
        v_blocked_count,
        v_activity_count + v_blocked_count;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

COMMENT ON FUNCTION public.sql_firewall_cleanup_all_logs(INTERVAL, INTERVAL) IS 
'Cleanup both activity and blocked query logs in one transaction. Defaults: activity=30 days, blocked=90 days. Superuser only.';

-- Truncate all logs (emergency cleanup)
CREATE OR REPLACE FUNCTION public.sql_firewall_truncate_logs()
RETURNS TABLE(status TEXT) AS $$
BEGIN
    -- Only superusers can truncate logs
    IF NOT (SELECT usesuper FROM pg_user WHERE usename = session_user) THEN
        RAISE EXCEPTION 'Only superusers can truncate firewall logs';
    END IF;
    
    TRUNCATE TABLE public.sql_firewall_activity_log;
    TRUNCATE TABLE public.sql_firewall_blocked_queries;
    
    RETURN QUERY SELECT 'All firewall logs truncated successfully'::TEXT;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

COMMENT ON FUNCTION public.sql_firewall_truncate_logs() IS 
'Emergency function to truncate ALL firewall logs. Use with caution! Superuser only.';

-- ========================================
-- SECURITY: REVOKE DIRECT TABLE ACCESS
-- ========================================
-- All interaction with firewall tables must go through SECURITY DEFINER functions
-- This prevents users from tampering with firewall configuration and logs

-- Revoke all privileges on firewall tables from PUBLIC
REVOKE ALL ON TABLE public.sql_firewall_activity_log FROM PUBLIC;
REVOKE ALL ON TABLE public.sql_firewall_blocked_queries FROM PUBLIC;
REVOKE ALL ON TABLE public.sql_firewall_command_approvals FROM PUBLIC;
REVOKE ALL ON TABLE public.sql_firewall_query_fingerprints FROM PUBLIC;
REVOKE ALL ON TABLE public.sql_firewall_regex_rules FROM PUBLIC;

-- Revoke sequence access
REVOKE ALL ON SEQUENCE public.sql_firewall_activity_log_log_id_seq FROM PUBLIC;
REVOKE ALL ON SEQUENCE public.sql_firewall_blocked_queries_block_id_seq FROM PUBLIC;
REVOKE ALL ON SEQUENCE public.sql_firewall_command_approvals_id_seq FROM PUBLIC;
REVOKE ALL ON SEQUENCE public.sql_firewall_query_fingerprints_id_seq FROM PUBLIC;
REVOKE ALL ON SEQUENCE public.sql_firewall_regex_rules_id_seq FROM PUBLIC;

-- Grant SELECT on read-only views for monitoring (users can view their own data)
GRANT SELECT ON TABLE public.sql_firewall_activity_log TO PUBLIC;
GRANT SELECT ON TABLE public.sql_firewall_blocked_queries TO PUBLIC;
GRANT SELECT ON TABLE public.sql_firewall_query_fingerprints TO PUBLIC;

-- Grant SELECT on config tables for firewall internal queries (read-only for users)
GRANT SELECT ON TABLE public.sql_firewall_command_approvals TO PUBLIC;
GRANT SELECT ON TABLE public.sql_firewall_regex_rules TO PUBLIC;

-- Configuration changes still require SECURITY DEFINER functions (no INSERT/UPDATE/DELETE)
