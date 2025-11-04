# Password Profile Pure - Complete Feature List

##  All Features Implemented and Working

### 1. Password Complexity Enforcement
Enforces configurable password strength requirements:
- **Minimum Length**: `password_profile.min_length` (default: 8)
- **Uppercase Required**: `password_profile.require_uppercase` (default: false)
- **Lowercase Required**: `password_profile.require_lowercase` (default: false)
- **Digit Required**: `password_profile.require_digit` (default: false)
- **Special Character Required**: `password_profile.require_special` (default: false)

**How it works**: Automatically validates via `check_password_hook` during `CREATE USER`, `ALTER USER`, and `\password`.

---

### 2. Username Inclusion Prevention
Blocks passwords that contain the username (case-insensitive).
- **GUC**: `password_profile.prevent_username` (default: true)

**Example**: User `john` cannot set password `john123` or `MyJohn!`.

---

### 3. Password History Tracking
Prevents reuse of the last N passwords using bcrypt hashing.
- **GUC**: `password_profile.password_history_count` (default: 5)
- **Storage**: `password_profile.password_history` table

**How it works**: 
- `record_password_change('username', 'new_password')` stores hashed password
- Hook automatically checks history during password changes

---

### 4. Reuse Interval Restriction
Disallows password reuse within a time window.
- **GUC**: `password_profile.password_reuse_days` (default: 90)

**Example**: Cannot reuse any password used in last 90 days, even if not in the "last N" list.

---

### 5. Password Expiration
Forces password change after a configurable period with grace login support.
- **GUC**: `password_profile.password_expiry_days` (default: 90)
- **Grace Logins**: `password_profile.password_grace_logins` (default: 3)
- **Storage**: `password_profile.password_expiry` table

**Functions**:
- `check_password_expiry('username')` - Check if password expired
- `record_password_change('username', 'password')` - Updates expiry timestamp

---

### 6. Failed Login Lockout (Fully Automatic)
Temporarily locks accounts after failed login attempts - **NO APPLICATION CODE REQUIRED**.

**Configuration**:
- `password_profile.failed_login_max` (default: 5 failed attempts)
- `password_profile.lockout_minutes` (default: 5 minutes)

**How it works**:
1. **Background Worker** monitors PostgreSQL log files in real-time
2. Detects failed authentication events (English + Turkish locale support)
3. Automatically records failed logins: `password_profile.login_attempts`
4. Locks account after reaching threshold
5. **Automatic cleanup**: Successful login clears failed attempt counter

**Storage**: `password_profile.login_attempts` table
```sql
CREATE TABLE password_profile.login_attempts (
    username TEXT PRIMARY KEY,
    fail_count INT DEFAULT 0,
    last_fail TIMESTAMPTZ DEFAULT now(),
    lockout_until TIMESTAMPTZ
);
```

**Manual functions** (optional):
- `record_failed_login('username')` - Manually record failure
- `clear_login_attempts('username')` - Manually clear counter
- `is_user_locked('username')` - Check lockout status
- `check_user_access('username')` - Get detailed access status

**Background Worker Configuration**:
```ini
# postgresql.conf
shared_preload_libraries = 'password_profile_pure'
password_profile.log_monitor_enabled = on
password_profile.log_directory = '/var/lib/pgsql/16/data/log'  # Optional, auto-detected
```

---

### 7. Blacklist Validation
Blocks weak or commonly used passwords using two sources:

**A. Static File** (9,789 passwords included):
- File: `blacklist.txt`
- Loaded at extension initialization
- Contains common weak passwords (e.g., "password", "123456", "qwerty")

**B. Dynamic Database Table**:
```sql
CREATE TABLE password_profile.blacklist (
    password TEXT PRIMARY KEY,
    added_at TIMESTAMPTZ DEFAULT now(),
    reason TEXT
);
```

**Functions**:
- `add_to_blacklist('password', 'reason')` - Add password to blacklist
- `remove_from_blacklist('password')` - Remove from blacklist

**Priority**: Database table overrides file blacklist.

---

### 8. Custom Validation Hook
Support for organization-specific password rules via pluggable SQL functions.

**How to use**:
1. Create a function in `password_profile` schema:
```sql
CREATE OR REPLACE FUNCTION password_profile.custom_password_check(
    username TEXT,
    password TEXT
) RETURNS TEXT AS $$
BEGIN
    -- Custom validation logic
    IF password LIKE '%2024%' THEN
        RETURN 'Password cannot contain current year';
    END IF;
    
    RETURN 'OK';  -- Password accepted
END;
$$ LANGUAGE plpgsql;
```

2. Hook automatically calls it during password validation
3. Return 'OK' to accept, or error message to reject

---

### 9. Fully Configurable via GUCs
Every rule can be changed dynamically without code changes:

```sql
-- Change settings runtime (session-level)
SET password_profile.min_length = 12;
SET password_profile.require_uppercase = true;

-- Change settings permanently (requires reload)
ALTER SYSTEM SET password_profile.failed_login_max = 3;
SELECT pg_reload_conf();
```

**All GUCs**:
```ini
# Complexity
password_profile.min_length = 8
password_profile.require_uppercase = false
password_profile.require_lowercase = false
password_profile.require_digit = false
password_profile.require_special = false
password_profile.prevent_username = true

# History
password_profile.password_history_count = 5
password_profile.password_reuse_days = 90

# Expiration
password_profile.password_expiry_days = 90
password_profile.password_grace_logins = 3

# Failed Login Lockout
password_profile.failed_login_max = 5
password_profile.lockout_minutes = 5

# Background Worker (Log Monitoring)
password_profile.log_monitor_enabled = true
password_profile.log_directory = ''  # Auto-detected if empty
```

---

##  Production-Ready Features

### Security
-  **Timing attack prevention**: Random delays on validation failures
-  **SQL injection protection**: All inputs use proper quoting/escaping
-  **bcrypt password hashing**: Secure storage in password history
-  **No plaintext storage**: Only hashed passwords stored

### Performance
-  **Minimal overhead**: Hook only runs during password changes
-  **Efficient blacklist**: In-memory HashSet for O(1) lookups
-  **Background worker**: Separate process, no impact on queries
-  **Transaction safety**: All DB operations properly committed

### Reliability
-  **No crashes**: Background worker stable under production load
-  **Automatic recovery**: Worker handles missing log directories
-  **Multi-locale support**: Works with Turkish and English PostgreSQL
-  **Log rotation**: Automatically follows newest log file

### Scalability
-  **Thousands of users**: Designed for production workloads
-  **Concurrent operations**: Thread-safe implementation
-  **Real-time monitoring**: 1-second log check interval
-  **Resource efficient**: Minimal CPU/memory usage

---

##  Testing Results

### Automatic Failed Login Tracking
```bash
# Test 1: Failed login automatically recorded
PGPASSWORD=wrong psql -U test_user -d postgres
# Result: login_attempts.fail_count = 1 

# Test 2: Multiple failures trigger lockout
# After 5 failed attempts (configurable)
# Result: lockout_until set to now() + 5 minutes 

# Test 3: Successful login clears counter
PGPASSWORD=correct psql -U test_user -d postgres
# Result: login_attempts row deleted 
```

### Background Worker Stability
- **Uptime**: Runs continuously without crashes 
- **Log Detection**: Successfully detects Turkish & English logs 
- **Transaction Management**: All operations commit successfully 
- **Error Handling**: Gracefully handles missing directories 

---

## 📦 Installation

```sql
-- 1. Configure PostgreSQL
ALTER SYSTEM SET shared_preload_libraries = 'password_profile_pure';
SELECT pg_reload_conf();

-- Restart PostgreSQL (required for shared library)
-- sudo systemctl restart postgresql-16

-- 2. Create extension
CREATE EXTENSION password_profile;

-- 3. Initialize tables
SELECT init_login_attempts_table();

-- 4. Configure rules (optional)
ALTER SYSTEM SET password_profile.min_length = 10;
ALTER SYSTEM SET password_profile.failed_login_max = 3;
SELECT pg_reload_conf();
```

---

##  Use Cases

### Enterprise Security
- Enforce company password policies automatically
- Track password change history for compliance
- Prevent account takeover via brute force

### Multi-Tenant Applications
- Per-database password rules
- Centralized security without application changes
- Audit trail of password changes

### High-Security Environments
- Defense against credential stuffing
- Automatic account lockout
- Password reuse prevention

---

##  Maintenance Functions

```sql
-- View current configuration
SELECT name, setting FROM pg_settings 
WHERE name LIKE 'password_profile.%';

-- Check user stats
SELECT get_password_stats('username');

-- Monitor failed logins
SELECT * FROM password_profile.login_attempts;

-- View password history
SELECT username, changed_at 
FROM password_profile.password_history 
ORDER BY changed_at DESC;

-- Check background worker status
SELECT pid, application_name, state 
FROM pg_stat_activity 
WHERE application_name = 'password_profile_log_monitor';
```

---

## Version

**Version**: 1.0  
**PostgreSQL**: 13, 14, 15, 16 (tested on 15, 16)  
**Note**: PostgreSQL 17 support pending pgrx 0.17.x release  
**Status**: Production-Ready   
**Last Updated**: November 4, 2025
