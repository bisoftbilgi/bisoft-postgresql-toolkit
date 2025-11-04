-- Test 3: Failed Login Lockout
-- ==============================

-- Setup
CREATE EXTENSION IF NOT EXISTS password_profile_pure;
SET password_profile.failed_login_max = 3;
SET password_profile.lockout_minutes = 5;

-- Test 3.1: User not locked initially
SELECT is_user_locked('lockoutuser');

-- Test 3.2: Record failed logins (below threshold)
SELECT record_failed_login('lockoutuser');
SELECT record_failed_login('lockoutuser');
SELECT is_user_locked('lockoutuser');

-- Test 3.3: Exceed threshold (trigger lockout)
SELECT record_failed_login('lockoutuser');
SELECT is_user_locked('lockoutuser');

-- Test 3.4: Check user access (should show locked status)
SELECT check_user_access('lockoutuser');

-- Test 3.5: Clear login attempts (superuser only)
SELECT clear_login_attempts('lockoutuser');
SELECT is_user_locked('lockoutuser');

-- Cleanup
DELETE FROM password_profile.login_attempts WHERE username = 'lockoutuser';
RESET password_profile.failed_login_max;
RESET password_profile.lockout_minutes;
