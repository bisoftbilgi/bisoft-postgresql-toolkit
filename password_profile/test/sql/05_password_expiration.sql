-- Test 5: Password Expiration
-- =============================

-- Setup
CREATE EXTENSION IF NOT EXISTS password_profile_pure;
SET password_profile.password_expiry_days = 90;
SET password_profile.password_grace_logins = 3;

-- Test 5.1: Record password change
SELECT record_password_change('expiryuser', 'InitialPassword123!');

-- Test 5.2: Check expiry (should not be expired)
SELECT check_password_expiry('expiryuser');

-- Test 5.3: Manually expire password (for testing)
UPDATE password_profile.password_expiry 
SET last_changed = now() - interval '91 days'
WHERE username = 'expiryuser';

-- Test 5.4: Check expiry (should be expired)
SELECT check_password_expiry('expiryuser');

-- Test 5.5: Record new password change (resets expiry)
SELECT record_password_change('expiryuser', 'NewPassword456!');
SELECT check_password_expiry('expiryuser');

-- Cleanup
DELETE FROM password_profile.password_expiry WHERE username = 'expiryuser';
DELETE FROM password_profile.password_history WHERE username = 'expiryuser';
RESET password_profile.password_expiry_days;
RESET password_profile.password_grace_logins;
