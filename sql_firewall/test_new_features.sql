-- ============================================================================
-- SQL Firewall New Features Test Suite
-- Tests for: 
-- 1. SECURITY DEFINER enforcement (users can't approve their own commands)
-- 2. Blocked queries logging
-- 3. Dedicated blocked_queries table
-- 4. Activity logging control via GUC
-- 5. Per-user regex exemptions (allowed_roles)
-- ============================================================================

\echo '=== Setting up test environment ==='

-- Create test database and users
DROP DATABASE IF EXISTS firewall_test;
CREATE DATABASE firewall_test;
\c firewall_test

-- Load extension
CREATE EXTENSION IF NOT EXISTS sql_firewall_rs;

-- Create test users
DROP ROLE IF EXISTS test_user;
DROP ROLE IF EXISTS test_admin;
DROP ROLE IF EXISTS test_analyst;
CREATE ROLE test_user LOGIN PASSWORD 'test123';
CREATE ROLE test_admin LOGIN PASSWORD 'admin123';
CREATE ROLE test_analyst LOGIN PASSWORD 'analyst123';

-- Grant basic permissions
GRANT CONNECT ON DATABASE firewall_test TO test_user, test_admin, test_analyst;
GRANT USAGE ON SCHEMA public TO test_user, test_admin, test_analyst;

-- Create a test table for queries
CREATE TABLE test_data (id SERIAL PRIMARY KEY, value TEXT);
GRANT SELECT, INSERT, UPDATE, DELETE ON test_data TO test_user, test_admin, test_analyst;
GRANT USAGE ON SEQUENCE test_data_id_seq TO test_user, test_admin, test_analyst;

\echo ''
\echo '=== TEST 1: SECURITY DEFINER Enforcement ==='
\echo 'Test that normal users cannot directly modify firewall tables'

-- Switch to test_user
\c firewall_test test_user

\echo '--- Attempting direct INSERT to command_approvals (should fail) ---'
INSERT INTO public.sql_firewall_command_approvals (role_name, command_type, is_approved) 
VALUES ('test_user', 'SELECT', true);

\echo '--- Attempting direct UPDATE to command_approvals (should fail) ---'
UPDATE public.sql_firewall_command_approvals SET is_approved = true WHERE role_name = 'test_user';

\echo '--- Attempting direct INSERT to activity_log (should fail) ---'
INSERT INTO public.sql_firewall_activity_log (role_name, command_type, action) 
VALUES ('test_user', 'SELECT', 'ALLOWED');

\echo ''
\echo '=== TEST 2: Admin Functions Work Correctly ==='
\echo 'Test that superuser can approve commands via SECURITY DEFINER functions'

-- Switch back to superuser
\c firewall_test postgres

-- Approve SELECT for test_user
SELECT public.sql_firewall_approve_command('test_user', 'SELECT');

-- Verify approval
SELECT role_name, command_type, is_approved 
FROM public.sql_firewall_command_approvals 
WHERE role_name = 'test_user';

\echo ''
\echo '=== TEST 3: Blocked Queries Logging ==='
\echo 'Test that blocked queries are logged in enforce mode'

-- Configure firewall
ALTER SYSTEM SET sql_firewall.mode = 'enforce';
ALTER SYSTEM SET sql_firewall.enable_fingerprint_learning = false;
SELECT pg_reload_conf();

-- Wait a moment for config reload
SELECT pg_sleep(1);

-- Switch to test_admin (no approvals)
\c firewall_test test_admin

\echo '--- Attempting unapproved INSERT (should be blocked and logged) ---'
INSERT INTO test_data (value) VALUES ('test');

-- Switch back to check logs
\c firewall_test postgres

\echo '--- Checking activity_log for blocked query ---'
SELECT role_name, command_type, action, reason 
FROM public.sql_firewall_activity_log 
WHERE role_name = 'test_admin' 
ORDER BY log_time DESC LIMIT 3;

\echo ''
\echo '=== TEST 4: Dedicated Blocked Queries Table ==='
\echo 'Verify blocked queries are logged to dedicated table'

\echo '--- Checking blocked_queries table ---'
SELECT role_name, command_type, block_reason 
FROM public.sql_firewall_blocked_queries 
WHERE role_name = 'test_admin' 
ORDER BY blocked_at DESC LIMIT 3;

\echo ''
\echo '=== TEST 5: Activity Logging Control (GUC) ==='
\echo 'Test enable_activity_logging parameter'

-- Enable activity logging
ALTER SYSTEM SET sql_firewall.enable_activity_logging = true;
SELECT pg_reload_conf();
SELECT pg_sleep(1);

-- Approve INSERT for test_user
SELECT public.sql_firewall_approve_command('test_user', 'INSERT');

-- Get current log count
CREATE TEMP TABLE log_count_before AS 
SELECT COUNT(*) as count FROM public.sql_firewall_activity_log;

-- Switch to test_user and execute allowed query
\c firewall_test test_user

INSERT INTO test_data (value) VALUES ('with_logging');

-- Check that it was logged
\c firewall_test postgres

SELECT COUNT(*) as count_after_insert 
FROM public.sql_firewall_activity_log;

\echo '--- Disabling activity logging ---'
ALTER SYSTEM SET sql_firewall.enable_activity_logging = false;
SELECT pg_reload_conf();
SELECT pg_sleep(1);

-- Get new log count
CREATE TEMP TABLE log_count_middle AS 
SELECT COUNT(*) as count FROM public.sql_firewall_activity_log;

-- Execute another allowed query
\c firewall_test test_user

INSERT INTO test_data (value) VALUES ('without_logging');

-- Check that it was NOT logged
\c firewall_test postgres

\echo '--- Checking log counts (should not increase) ---'
SELECT 
    (SELECT count FROM log_count_before) as before_count,
    (SELECT count FROM log_count_middle) as middle_count,
    (SELECT COUNT(*) FROM public.sql_firewall_activity_log) as current_count;

\echo ''
\echo '=== TEST 6: Blocked Queries Always Logged (Even When Activity Logging Disabled) ==='

-- Activity logging is still disabled from previous test
\c firewall_test test_analyst

\echo '--- Attempting unapproved DELETE (should be blocked and still logged) ---'
DELETE FROM test_data WHERE id = 1;

\c firewall_test postgres

\echo '--- Checking that block was logged despite activity logging disabled ---'
SELECT role_name, command_type, action, reason 
FROM public.sql_firewall_activity_log 
WHERE role_name = 'test_analyst' 
ORDER BY log_time DESC LIMIT 2;

SELECT role_name, command_type, block_reason 
FROM public.sql_firewall_blocked_queries 
WHERE role_name = 'test_analyst' 
ORDER BY blocked_at DESC LIMIT 2;

\echo ''
\echo '=== TEST 7: Per-User Regex Exemptions (allowed_roles) ==='
\echo 'Test that regex rules can be limited to specific roles'

-- Re-enable activity logging
ALTER SYSTEM SET sql_firewall.enable_activity_logging = true;
ALTER SYSTEM SET sql_firewall.enable_regex_scan = true;
SELECT pg_reload_conf();
SELECT pg_sleep(1);

-- Add regex rule that applies to ALL roles (allowed_roles = NULL)
INSERT INTO public.sql_firewall_regex_rules (pattern, description, allowed_roles)
VALUES ('DROP\s+TABLE', 'Block DROP TABLE for all users', NULL);

-- Add regex rule that applies ONLY to test_analyst
INSERT INTO public.sql_firewall_regex_rules (pattern, description, allowed_roles)
VALUES ('UPDATE.*SET.*value.*=.*''forbidden''', 'Block forbidden updates for analysts only', ARRAY['test_analyst']);

\echo '--- Testing DROP TABLE block (applies to all) ---'
\c firewall_test test_user

CREATE TABLE temp_test (id INT);
DROP TABLE temp_test; -- Should be blocked

\c firewall_test test_analyst

CREATE TABLE temp_test2 (id INT);
DROP TABLE temp_test2; -- Should also be blocked

\c firewall_test postgres

\echo '--- Checking DROP blocks for both users ---'
SELECT role_name, command_type, action, reason 
FROM public.sql_firewall_activity_log 
WHERE query_text LIKE '%DROP TABLE%' 
ORDER BY log_time DESC LIMIT 3;

\echo '--- Testing role-specific regex rule ---'
\echo '--- test_analyst UPDATE with "forbidden" (should be blocked) ---'

-- Approve UPDATE for both users first
SELECT public.sql_firewall_approve_command('test_analyst', 'UPDATE');
SELECT public.sql_firewall_approve_command('test_user', 'UPDATE');

\c firewall_test test_analyst

UPDATE test_data SET value = 'forbidden' WHERE id = 1; -- Should be blocked by regex

\c firewall_test test_user

UPDATE test_data SET value = 'forbidden' WHERE id = 1; -- Should be ALLOWED (not in allowed_roles)

\c firewall_test postgres

\echo '--- Checking regex blocks (analyst blocked, test_user allowed) ---'
SELECT role_name, command_type, action, reason, query_text 
FROM public.sql_firewall_activity_log 
WHERE query_text LIKE '%UPDATE test_data SET value%forbidden%' 
ORDER BY log_time DESC LIMIT 3;

\echo ''
\echo '=== TEST 8: Background Worker with SECURITY DEFINER ==='
\echo 'Test that background worker uses SECURITY DEFINER function'

-- Switch to learn mode to trigger background worker
ALTER SYSTEM SET sql_firewall.mode = 'learn';
SELECT pg_reload_conf();
SELECT pg_sleep(1);

-- Clear existing approvals for test
DELETE FROM public.sql_firewall_command_approvals WHERE role_name = 'test_admin';

\c firewall_test test_admin

\echo '--- Executing query to trigger approval queue ---'
SELECT COUNT(*) FROM test_data; -- Should queue approval

-- Wait for background worker
\c firewall_test postgres
SELECT pg_sleep(2);

\echo '--- Checking that approval was recorded via SECURITY DEFINER ---'
SELECT role_name, command_type, is_approved 
FROM public.sql_firewall_command_approvals 
WHERE role_name = 'test_admin' 
ORDER BY created_at DESC LIMIT 3;

\echo ''
\echo '=== Test Summary ==='
\echo 'Checking all new tables have data:'

SELECT 'activity_log' as table_name, COUNT(*) as row_count 
FROM public.sql_firewall_activity_log
UNION ALL
SELECT 'blocked_queries', COUNT(*) 
FROM public.sql_firewall_blocked_queries
UNION ALL
SELECT 'command_approvals', COUNT(*) 
FROM public.sql_firewall_command_approvals
UNION ALL
SELECT 'regex_rules', COUNT(*) 
FROM public.sql_firewall_regex_rules;

\echo ''
\echo '=== All Tests Completed ==='
\echo 'Review the output above to verify:'
\echo '1. Users cannot directly modify firewall tables (permission denied)'
\echo '2. Blocked queries appear in activity_log'
\echo '3. Blocked queries appear in blocked_queries table'
\echo '4. Activity logging can be disabled (but blocks still logged)'
\echo '5. Regex rules respect allowed_roles column'
\echo '6. Background worker uses SECURITY DEFINER functions'

-- Cleanup
\c postgres
DROP DATABASE IF EXISTS firewall_test;
DROP ROLE IF EXISTS test_user;
DROP ROLE IF EXISTS test_admin;
DROP ROLE IF EXISTS test_analyst;

\echo ''
\echo '=== Test environment cleaned up ==='
