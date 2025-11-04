-- Test 1: Password Complexity Validation
-- =========================================

-- Setup
CREATE EXTENSION IF NOT EXISTS password_profile_pure;

-- Test 1.1: Too short password (min_length = 8)
SELECT check_password('testuser', 'short');

-- Test 1.2: Valid length password
SELECT check_password('testuser', 'LongEnough123!');

-- Test 1.3: Uppercase requirement
SET password_profile.require_uppercase = true;
SELECT check_password('testuser', 'nouppercase123!');
SELECT check_password('testuser', 'HasUpperCase123!');

-- Test 1.4: Lowercase requirement
SET password_profile.require_lowercase = true;
SELECT check_password('testuser', 'NOLOWERCASE123!');
SELECT check_password('testuser', 'HasBothCases123!');

-- Test 1.5: Digit requirement
SET password_profile.require_digit = true;
SELECT check_password('testuser', 'NoDigitsHere!');
SELECT check_password('testuser', 'HasDigit123!');

-- Test 1.6: Special character requirement
SET password_profile.require_special = true;
SELECT check_password('testuser', 'NoSpecialChar123');
SELECT check_password('testuser', 'HasSpecial123!');

-- Test 1.7: Username prevention
SET password_profile.prevent_username = true;
SELECT check_password('testuser', 'MyTestUser123!');
SELECT check_password('testuser', 'NoUsername123!');

-- Cleanup
RESET password_profile.require_uppercase;
RESET password_profile.require_lowercase;
RESET password_profile.require_digit;
RESET password_profile.require_special;
RESET password_profile.prevent_username;
