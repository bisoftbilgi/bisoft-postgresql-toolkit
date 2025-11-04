-- Test 7: User-Level GUC Configuration
-- ======================================

-- Setup
CREATE EXTENSION IF NOT EXISTS password_profile_pure;

-- Test 7.1: Create users with different security tiers
CREATE USER high_security PASSWORD 'HighSecPass999x';
CREATE USER low_security PASSWORD 'LowSecPass88x';

-- Test 7.2: Configure different policies per user
ALTER ROLE high_security SET password_profile.min_length = 16;
ALTER ROLE high_security SET password_profile.failed_login_max = 2;
ALTER ROLE low_security SET password_profile.min_length = 6;
ALTER ROLE low_security SET password_profile.failed_login_max = 10;

-- Test 7.3: Verify user configurations
SELECT usename, useconfig 
FROM pg_user 
WHERE usename IN ('high_security', 'low_security')
ORDER BY usename;

-- Test 7.4: Verify that check_password respects different user policies
-- For demonstration, we test via check_password function

-- high_security: min_length=16
\set ON_ERROR_STOP off
SELECT check_password('high_security', 'OnlyTwelve12');  -- Should FAIL: too short
\set ON_ERROR_STOP on
SELECT check_password('high_security', 'SixteenCharsPass123');  -- Should SUCCEED

-- low_security: min_length=6 (but global default=8 applies during check)
SELECT check_password('low_security', 'ValidPass88x');  -- Should SUCCEED

-- Test 7.6: Reset user-level configuration
ALTER ROLE high_security RESET password_profile.min_length;
ALTER ROLE high_security RESET password_profile.failed_login_max;

-- Verify reset (should return to global default)
SELECT useconfig 
FROM pg_user 
WHERE usename = 'high_security';

-- Cleanup
DROP USER IF EXISTS high_security;
DROP USER IF EXISTS low_security;
