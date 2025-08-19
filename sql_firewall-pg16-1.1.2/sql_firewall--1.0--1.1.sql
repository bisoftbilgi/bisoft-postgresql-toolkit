-- sql_firewall--1.0--1.1.sql
-- 1.0 -> 1.1 migration (idempotent)

DO $$
BEGIN
    -- activity_log kolon adlarını 1.1 ile uyumlu hale getir (varsa)
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema='public' AND table_name='sql_firewall_activity_log'
          AND column_name='role'
    ) THEN
        EXECUTE 'ALTER TABLE public.sql_firewall_activity_log RENAME COLUMN role TO role_name';
    END IF;

    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema='public' AND table_name='sql_firewall_activity_log'
          AND column_name='db_name'
    ) THEN
        EXECUTE 'ALTER TABLE public.sql_firewall_activity_log RENAME COLUMN db_name TO database_name';
    END IF;

    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema='public' AND table_name='sql_firewall_activity_log'
          AND column_name='query'
    ) THEN
        EXECUTE 'ALTER TABLE public.sql_firewall_activity_log RENAME COLUMN query TO query_text';
    END IF;

    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema='public' AND table_name='sql_firewall_activity_log'
          AND column_name='command'
    ) THEN
        EXECUTE 'ALTER TABLE public.sql_firewall_activity_log RENAME COLUMN command TO command_type';
    END IF;

    -- sequence izinleri vb. (zaten varsa atlar)
    BEGIN
        EXECUTE 'GRANT USAGE, SELECT ON SEQUENCE public.sql_firewall_activity_log_log_id_seq TO PUBLIC';
    EXCEPTION WHEN undefined_table THEN
        -- sequence yoksa sessiz geç
        NULL;
    END;

    BEGIN
        EXECUTE 'GRANT USAGE, SELECT ON SEQUENCE public.sql_firewall_command_approvals_id_seq TO PUBLIC';
    EXCEPTION WHEN undefined_table THEN
        NULL;
    END;
END
$$;

