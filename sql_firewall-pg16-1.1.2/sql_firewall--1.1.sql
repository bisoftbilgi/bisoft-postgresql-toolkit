-- sql_firewall--1.0.sql
-- ================= Tables =================

-- Activity log (C kodu INSERT: role_name, database_name, action, reason, query_text, command_type)
CREATE TABLE IF NOT EXISTS public.sql_firewall_activity_log (
    log_id          SERIAL PRIMARY KEY,
    log_time        TIMESTAMPTZ DEFAULT now() NOT NULL,
    role_name       NAME,
    database_name   NAME,
    query_text      TEXT,
    application_name TEXT,
    client_ip       TEXT,
    command_type    TEXT,
    action          TEXT,
    reason          TEXT
);

COMMENT ON TABLE  public.sql_firewall_activity_log IS 'Log of all actions performed by the SQL Firewall.';
COMMENT ON COLUMN public.sql_firewall_activity_log.action IS 'Action performed: ALLOWED, BLOCKED, LEARNED, etc.';
COMMENT ON COLUMN public.sql_firewall_activity_log.reason IS 'Reason for the action: Rate limit, Blacklisted keyword, etc.';

-- Performans için (C tarafındaki sorgulara uygun)
CREATE INDEX IF NOT EXISTS idx_sqlfw_activity_role_time
    ON public.sql_firewall_activity_log(role_name, log_time);
CREATE INDEX IF NOT EXISTS idx_sqlfw_activity_role_cmd_time
    ON public.sql_firewall_activity_log(role_name, command_type, log_time);
CREATE INDEX IF NOT EXISTS idx_sqlfw_activity_action
    ON public.sql_firewall_activity_log(action);

-- Komut onayları (C: SELECT/INSERT/UPDATE yapıyor)
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

-- Regex kuralları (C: is_active=true AND action=''BLOCK'' ve $1 ~* pattern kontrolü yapıyor)
CREATE TABLE IF NOT EXISTS public.sql_firewall_regex_rules (
    id          SERIAL PRIMARY KEY,
    pattern     TEXT    NOT NULL UNIQUE,
    description TEXT,
    action      TEXT    NOT NULL DEFAULT 'BLOCK' CHECK (action IN ('BLOCK')),
    is_active   BOOLEAN NOT NULL DEFAULT true,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

COMMENT ON TABLE  public.sql_firewall_regex_rules IS 'Regex rules used to match and block SQL queries.';
COMMENT ON COLUMN public.sql_firewall_regex_rules.pattern IS 'Regex pattern to apply on the query text.';
COMMENT ON COLUMN public.sql_firewall_regex_rules.action  IS 'Action to perform when the pattern matches.';

-- Sessiz saatler (şu an sadece metadata; C tarafı GUC ile çalışıyor)
CREATE TABLE IF NOT EXISTS public.sql_firewall_quiet_hours (
    start_time TEXT,
    end_time   TEXT
);

COMMENT ON TABLE public.sql_firewall_quiet_hours IS 'Time ranges during which queries are blocked. Format: HH24:MI';

-- Opsiyonel kara listeler (şimdilik C tarafı GUC kullanıyor; tablo istersen yönetim için hazır dursun)
CREATE TABLE IF NOT EXISTS public.sql_firewall_blocked_ips (
    ip_address TEXT PRIMARY KEY
);
CREATE TABLE IF NOT EXISTS public.sql_firewall_blocked_apps (
    application_name TEXT PRIMARY KEY
);
CREATE TABLE IF NOT EXISTS public.sql_firewall_keywords (
    keyword TEXT PRIMARY KEY
);

-- Örnek regex kuralı (idempotent)
INSERT INTO public.sql_firewall_regex_rules (pattern, description)
VALUES ('(or|--|#)\s+\d+\s*=\s*\d+', 'Block simple SQL injection pattern')
ON CONFLICT (pattern) DO NOTHING;

-- ================= C Functions =================

-- Superuser fonksiyonları (C tarafında SPI ile DELETE/UPDATE yapar)
CREATE OR REPLACE FUNCTION sql_firewall_reset_log_for_role(role_name NAME)
RETURNS BIGINT
AS '$libdir/sql_firewall', 'sql_firewall_reset_log_for_role'
LANGUAGE C STRICT;

COMMENT ON FUNCTION sql_firewall_reset_log_for_role(NAME)
IS 'Superuser only. Clears the activity log for the given role.';

CREATE OR REPLACE FUNCTION sql_firewall_approve_all_for_role(role_name NAME)
RETURNS BIGINT
AS '$libdir/sql_firewall', 'sql_firewall_approve_all_for_role'
LANGUAGE C STRICT;

COMMENT ON FUNCTION sql_firewall_approve_all_for_role(NAME)
IS 'Superuser only. Approves all pending commands for the given role.';

CREATE OR REPLACE FUNCTION sql_firewall_reject_all_for_role(role_name NAME)
RETURNS BIGINT
AS '$libdir/sql_firewall', 'sql_firewall_reject_all_for_role'
LANGUAGE C STRICT;

COMMENT ON FUNCTION sql_firewall_reject_all_for_role(NAME)
IS 'Superuser only. Rejects (unapproves) all approved commands for the given role.';

-- ================= Permissions =================
-- Not: C kodu SPI’yi mevcut kullanıcıyla çalıştırıyor; bu yüzden PUBLIC’a INSERT/USAGE veriyoruz.

-- activity_log: kullanıcılar log yazabilsin
GRANT SELECT, INSERT ON public.sql_firewall_activity_log TO PUBLIC;
GRANT USAGE, SELECT ON SEQUENCE public.sql_firewall_activity_log_log_id_seq TO PUBLIC;

-- command_approvals: LEARN modunda kullanıcı adına satır INSERT edebilmek için
GRANT SELECT, INSERT, UPDATE ON public.sql_firewall_command_approvals TO PUBLIC;
GRANT USAGE, SELECT ON SEQUENCE public.sql_firewall_command_approvals_id_seq TO PUBLIC;

-- regex kuralları ve diğer yardımcı tablolar
GRANT SELECT ON public.sql_firewall_regex_rules TO PUBLIC;
GRANT SELECT ON public.sql_firewall_quiet_hours TO PUBLIC;
GRANT SELECT ON public.sql_firewall_blocked_ips TO PUBLIC;
GRANT SELECT ON public.sql_firewall_blocked_apps TO PUBLIC;
GRANT SELECT ON public.sql_firewall_keywords TO PUBLIC;

