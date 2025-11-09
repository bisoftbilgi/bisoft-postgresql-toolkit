-- SQL Firewall Test Suite
-- Bu dosya sql_firewall_rs extension'ının temel özelliklerini test eder

\echo '=== SQL Firewall Test Suite ==='
\echo ''

-- Extension oluştur
CREATE EXTENSION IF NOT EXISTS sql_firewall_rs;

-- Gerekli tabloları oluştur
CREATE TABLE IF NOT EXISTS sql_firewall_activity_log (
    id SERIAL PRIMARY KEY,
    log_time TIMESTAMP DEFAULT now(),
    role_name NAME NOT NULL,
    database_name NAME NOT NULL,
    action TEXT NOT NULL,
    reason TEXT,
    query_text TEXT,
    command_type TEXT
);

CREATE TABLE IF NOT EXISTS sql_firewall_command_approvals (
    id SERIAL PRIMARY KEY,
    role_name NAME NOT NULL,
    command_type TEXT NOT NULL,
    is_approved BOOLEAN DEFAULT false,
    created_at TIMESTAMP DEFAULT now(),
    UNIQUE(role_name, command_type)
);

CREATE TABLE IF NOT EXISTS sql_firewall_regex_rules (
    id SERIAL PRIMARY KEY,
    pattern TEXT NOT NULL,
    action TEXT NOT NULL CHECK (action IN ('BLOCK', 'ALLOW')),
    is_active BOOLEAN DEFAULT true,
    description TEXT,
    created_at TIMESTAMP DEFAULT now()
);

\echo '=== Test 1: Extension Status ==='
SELECT sql_firewall_status();
\echo ''

\echo '=== Test 2: Configuration Settings ==='
SHOW sql_firewall.mode;
SHOW sql_firewall.enable_keyword_scan;
SHOW sql_firewall.enable_regex_scan;
SHOW sql_firewall.enable_quiet_hours;
\echo ''

\echo '=== Test 3: Basic Query Execution ==='
CREATE TABLE IF NOT EXISTS test_table (
    id SERIAL PRIMARY KEY,
    name TEXT,
    value INTEGER
);

INSERT INTO test_table (name, value) VALUES ('test1', 100);
INSERT INTO test_table (name, value) VALUES ('test2', 200);

SELECT * FROM test_table;
\echo ''

\echo '=== Test 4: Approval System (Learn Mode) ==='
SET sql_firewall.mode = 'learn';

-- Bu sorgular öğrenilmeli
SELECT COUNT(*) FROM test_table;
UPDATE test_table SET value = 150 WHERE id = 1;
DELETE FROM test_table WHERE id = 2;

-- Log'ları kontrol et
SELECT command_type, action, COUNT(*) 
FROM sql_firewall_activity_log 
GROUP BY command_type, action 
ORDER BY command_type;
\echo ''

\echo '=== Test 5: Approval Records ==='
SELECT role_name, command_type, is_approved 
FROM sql_firewall_command_approvals 
ORDER BY command_type;
\echo ''

\echo '=== Test 6: Permissive Mode ==='
SET sql_firewall.mode = 'permissive';

-- Bu sorgu onaylanmamış olsa bile geçmeli
INSERT INTO test_table (name, value) VALUES ('test3', 300);
\echo 'Permissive mode - query executed'
\echo ''

\echo '=== Test 7: Keyword Blocking ==='
SET sql_firewall.enable_keyword_scan = true;
SET sql_firewall.blacklisted_keywords = 'drop,truncate,pg_sleep';

-- Bu sorgu bloklanmalı
\echo 'Attempting blocked keyword (should fail):'
DO $$
BEGIN
    EXECUTE 'SELECT pg_sleep(1)';
EXCEPTION
    WHEN OTHERS THEN
        RAISE NOTICE 'Query blocked: %', SQLERRM;
END $$;
\echo ''

\echo '=== Test 8: Quiet Hours Configuration ==='
SET sql_firewall.enable_quiet_hours = false;
SET sql_firewall.quiet_hours_start = '22:00';
SET sql_firewall.quiet_hours_end = '06:00';

SHOW sql_firewall.quiet_hours_start;
SHOW sql_firewall.quiet_hours_end;
\echo ''

\echo '=== Test 9: Rate Limiting Configuration ==='
SET sql_firewall.enable_rate_limiting = false;
SET sql_firewall.rate_limit_count = 100;
SET sql_firewall.rate_limit_seconds = 60;
SET sql_firewall.select_limit_count = 10;
SET sql_firewall.command_limit_seconds = 60;

SHOW sql_firewall.rate_limit_count;
SHOW sql_firewall.select_limit_count;
\echo ''

\echo '=== Test 10: Regex Rules ==='
-- Tehlikeli pattern'leri blokla
INSERT INTO sql_firewall_regex_rules (pattern, action, description, is_active)
VALUES 
    ('.*;\s*DROP\s+TABLE.*', 'BLOCK', 'SQL injection: DROP TABLE', true),
    ('.*UNION\s+SELECT.*', 'BLOCK', 'SQL injection: UNION-based', true),
    ('.*--.*', 'BLOCK', 'SQL injection: comment-based', false);

SELECT id, pattern, action, is_active 
FROM sql_firewall_regex_rules 
ORDER BY id;
\echo ''

\echo '=== Test 11: Activity Log Analysis ==='
SELECT 
    command_type,
    action,
    COUNT(*) as query_count,
    COUNT(DISTINCT role_name) as unique_roles
FROM sql_firewall_activity_log
GROUP BY command_type, action
ORDER BY command_type, action;
\echo ''

\echo '=== Test 12: Recent Activity ==='
SELECT 
    log_time,
    role_name,
    command_type,
    action,
    LEFT(query_text, 50) as query_preview
FROM sql_firewall_activity_log
ORDER BY log_time DESC
LIMIT 10;
\echo ''

\echo '=== Test 13: Enforce Mode Approval Test ==='
-- Komutları onayla
UPDATE sql_firewall_command_approvals 
SET is_approved = true 
WHERE command_type IN ('SELECT', 'INSERT');

SET sql_firewall.mode = 'enforce';

-- SELECT ve INSERT onaylı olduğu için çalışmalı
SELECT COUNT(*) FROM test_table;
INSERT INTO test_table (name, value) VALUES ('test4', 400);

-- UPDATE onaylı değil, bloklanmalı
\echo 'Attempting unapproved UPDATE (should fail):'
DO $$
BEGIN
    UPDATE test_table SET value = 999 WHERE id = 1;
EXCEPTION
    WHEN OTHERS THEN
        RAISE NOTICE 'Query blocked: %', SQLERRM;
END $$;
\echo ''

\echo '=== Test 14: Performance Metrics ==='
SELECT 
    'Total Queries' as metric,
    COUNT(*) as value
FROM sql_firewall_activity_log
UNION ALL
SELECT 
    'Blocked Queries',
    COUNT(*) 
FROM sql_firewall_activity_log 
WHERE action LIKE '%BLOCKED%'
UNION ALL
SELECT 
    'Allowed Queries',
    COUNT(*) 
FROM sql_firewall_activity_log 
WHERE action LIKE '%ALLOWED%'
UNION ALL
SELECT 
    'Learned Commands',
    COUNT(*) 
FROM sql_firewall_activity_log 
WHERE action LIKE '%LEARNED%';
\echo ''

-- Temizlik
\echo '=== Cleanup ==='
SET sql_firewall.mode = 'learn';
SET sql_firewall.enable_keyword_scan = false;
\echo 'Test completed successfully!'
\echo ''
