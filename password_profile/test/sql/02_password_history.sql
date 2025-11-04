-- Test 2: Password History & Reuse Prevention
-- =============================================

-- Setup
CREATE EXTENSION IF NOT EXISTS password_profile_pure;
SET password_profile.password_history_count = 3;
SET password_profile.password_reuse_days = 30;

-- Test 2.1: Record password changes
SELECT record_password_change('historyuser', 'FirstPassword123!');
SELECT record_password_change('historyuser', 'SecondPassword456!');
SELECT record_password_change('historyuser', 'ThirdPassword789!');

-- Test 2.2: Try to reuse recent password (should fail)
SELECT check_password('historyuser', 'SecondPassword456!');

-- Test 2.3: Use a new password (should succeed)
SELECT check_password('historyuser', 'BrandNewPassword999!');

-- Test 2.4: Check password stats
SELECT get_password_stats('historyuser');

-- Cleanup
DELETE FROM password_profile.password_history WHERE username = 'historyuser';
RESET password_profile.password_history_count;
RESET password_profile.password_reuse_days;
