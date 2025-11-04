-- Test 6: Security - Permission Checks
-- ======================================

-- Setup
CREATE EXTENSION IF NOT EXISTS password_profile_pure;

-- Test 6.1: Create test users
CREATE USER sectest1 WITH PASSWORD 'TestPass123!';
CREATE USER sectest2 WITH PASSWORD 'TestPass456!';

-- Test 6.2: User tries to clear own failed login attempts (allowed)
SET ROLE sectest1;
SELECT record_failed_login('sectest1');
SELECT clear_login_attempts('sectest1');

-- Test 6.3: User tries to clear another user's attempts (denied)
SELECT clear_login_attempts('sectest2');

-- Test 6.4: Superuser can clear any user's attempts
RESET ROLE;
SELECT record_failed_login('sectest2');
SELECT clear_login_attempts('sectest2');

-- Cleanup
DROP USER IF EXISTS sectest1;
DROP USER IF EXISTS sectest2;
DELETE FROM password_profile.login_attempts WHERE username IN ('sectest1', 'sectest2');
