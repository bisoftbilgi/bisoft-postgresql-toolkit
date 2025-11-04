-- Test 4: Blacklist Validation
-- ==============================

-- Setup
CREATE EXTENSION IF NOT EXISTS password_profile_pure;

-- Test 4.1: Check common weak passwords (from blacklist.txt)
SELECT check_password('testuser', 'password');
SELECT check_password('testuser', '123456');
SELECT check_password('testuser', 'qwerty');

-- Test 4.2: Add custom password to database blacklist
SELECT add_to_blacklist('CompanyName2024', 'Company policy');

-- Test 4.3: Try blocked password
SELECT check_password('testuser', 'CompanyName2024');

-- Test 4.4: Valid password (not in blacklist)
SELECT check_password('testuser', 'UniqueSecure123!');

-- Test 4.5: Remove from blacklist
SELECT remove_from_blacklist('CompanyName2024');
SELECT check_password('testuser', 'CompanyName2024');

-- Cleanup
DELETE FROM password_profile.blacklist WHERE password = 'CompanyName2024';
