# User-Level GUC Configuration

## Overview

Password Profile Pure supports **user-level (role-level) GUC overrides**, allowing different password policies for different users or roles without any code changes.

This is a native PostgreSQL feature that works automatically with all `password_profile.*` GUCs.

---

## Use Cases

### 1. **Stricter Policies for Admins**

```sql
-- Admins need longer passwords and stricter lockout
ALTER ROLE admin SET password_profile.min_length = 16;
ALTER ROLE admin SET password_profile.failed_login_max = 3;
ALTER ROLE admin SET password_profile.lockout_minutes = 30;
ALTER ROLE admin SET password_profile.password_history_count = 10;
```

### 2. **Relaxed Policies for Service Accounts**

```sql
-- Service accounts don't need password expiration
ALTER ROLE app_service SET password_profile.password_expiry_days = 0;  -- Disabled
ALTER ROLE app_service SET password_profile.failed_login_max = 100;    -- More tolerant
```

### 3. **Different Complexity for Different Departments**

```sql
-- Finance department: high security
ALTER ROLE finance_user SET password_profile.require_uppercase = true;
ALTER ROLE finance_user SET password_profile.require_lowercase = true;
ALTER ROLE finance_user SET password_profile.require_digit = true;
ALTER ROLE finance_user SET password_profile.require_special = true;
ALTER ROLE finance_user SET password_profile.min_length = 14;

-- Guest users: basic security
ALTER ROLE guest SET password_profile.min_length = 8;
ALTER ROLE guest SET password_profile.require_uppercase = false;
```

### 4. **VIP Users with Instant Lockout**

```sql
-- CEO, CFO: immediate lockout after 1 failed attempt
ALTER ROLE ceo SET password_profile.failed_login_max = 1;
ALTER ROLE ceo SET password_profile.lockout_minutes = 60;
```

---

## How It Works

### Setting User-Level GUCs

```sql
-- Syntax
ALTER ROLE username SET parameter = value;

-- Examples
ALTER ROLE john SET password_profile.min_length = 12;
ALTER ROLE mary SET password_profile.password_expiry_days = 30;
```

### Viewing User-Level GUCs

```sql
-- View all user configurations
SELECT usename, useconfig 
FROM pg_user 
WHERE useconfig IS NOT NULL;

-- Example output:
  usename   |                 useconfig                  
------------+--------------------------------------------
 admin_user | {password_profile.min_length=16}
 guest_user | {password_profile.min_length=6}
 ceo        | {password_profile.failed_login_max=1}
```

### Resetting User-Level GUCs

```sql
-- Reset to global default
ALTER ROLE username RESET parameter;

-- Example
ALTER ROLE john RESET password_profile.min_length;

-- Reset all parameters for a user
ALTER ROLE john RESET ALL;
```

---

## Testing User-Level Configuration

```sql
-- 1. Create test users
CREATE USER admin_test PASSWORD 'AdminTestPass999x';
CREATE USER guest_test PASSWORD 'GuestPass123x';

-- 2. Set different policies
ALTER ROLE admin_test SET password_profile.min_length = 16;
ALTER ROLE guest_test SET password_profile.min_length = 6;

-- 3. Test as admin_test
SET ROLE admin_test;
SHOW password_profile.min_length;  -- Returns: 16
ALTER USER admin_test PASSWORD 'Short12Chars';  -- FAILS: too short

-- 4. Test as guest_test
SET ROLE guest_test;
SHOW password_profile.min_length;  -- Returns: 6
ALTER USER guest_test PASSWORD 'Ok6Char';  -- SUCCEEDS
```

---

## Precedence Order

GUC settings follow PostgreSQL's standard precedence:

1. **Session-level** (`SET password_profile.min_length = 10;`) - Highest priority
2. **User-level** (`ALTER ROLE user SET ...`) - **This feature**
3. **Database-level** (`ALTER DATABASE db SET ...`)
4. **Global** (`postgresql.conf` or `ALTER SYSTEM SET ...`) - Lowest priority

```sql
-- Example: Precedence in action
-- Global setting
ALTER SYSTEM SET password_profile.min_length = 8;

-- User-level override (takes precedence over global)
ALTER ROLE john SET password_profile.min_length = 12;

-- Session-level override (takes precedence over user-level)
SET ROLE john;
SET password_profile.min_length = 15;  -- Effective for this session only

SHOW password_profile.min_length;  -- Returns: 15 (session)
```

---

## All Supported GUC Parameters

All `password_profile.*` parameters support user-level configuration:

### Complexity
- `password_profile.min_length`
- `password_profile.require_uppercase`
- `password_profile.require_lowercase`
- `password_profile.require_digit`
- `password_profile.require_special`
- `password_profile.prevent_username`

### History & Reuse
- `password_profile.password_history_count`
- `password_profile.password_reuse_days`

### Expiration
- `password_profile.password_expiry_days`
- `password_profile.password_grace_logins`

### Failed Login Lockout
- `password_profile.failed_login_max`
- `password_profile.lockout_minutes`

### Background Worker (not user-specific, global only)
- `password_profile.log_monitor_enabled`
- `password_profile.log_directory`

---

## Production Example: Multi-Tier Security

```sql
-- Tier 1: Executive (Highest Security)
CREATE ROLE executives;
ALTER ROLE executives SET password_profile.min_length = 16;
ALTER ROLE executives SET password_profile.require_uppercase = true;
ALTER ROLE executives SET password_profile.require_lowercase = true;
ALTER ROLE executives SET password_profile.require_digit = true;
ALTER ROLE executives SET password_profile.require_special = true;
ALTER ROLE executives SET password_profile.password_history_count = 10;
ALTER ROLE executives SET password_profile.password_expiry_days = 30;
ALTER ROLE executives SET password_profile.failed_login_max = 2;
ALTER ROLE executives SET password_profile.lockout_minutes = 60;

-- Tier 2: Developers (Medium Security)
CREATE ROLE developers;
ALTER ROLE developers SET password_profile.min_length = 12;
ALTER ROLE developers SET password_profile.require_uppercase = true;
ALTER ROLE developers SET password_profile.require_digit = true;
ALTER ROLE developers SET password_profile.password_history_count = 5;
ALTER ROLE developers SET password_profile.password_expiry_days = 90;
ALTER ROLE developers SET password_profile.failed_login_max = 5;

-- Tier 3: Read-Only Users (Basic Security)
CREATE ROLE readonly_users;
ALTER ROLE readonly_users SET password_profile.min_length = 8;
ALTER ROLE readonly_users SET password_profile.password_expiry_days = 180;
ALTER ROLE readonly_users SET password_profile.failed_login_max = 10;

-- Assign users to roles
GRANT executives TO ceo, cfo;
GRANT developers TO dev1, dev2, dev3;
GRANT readonly_users TO analyst1, analyst2;
```

---

## Verification

```sql
-- Show all role configurations
SELECT 
    r.rolname,
    unnest(r.rolconfig) as config
FROM pg_roles r
WHERE r.rolconfig IS NOT NULL
ORDER BY r.rolname;

-- Example output:
   rolname    |                  config                   
--------------+-------------------------------------------
 ceo          | password_profile.failed_login_max=1
 ceo          | password_profile.lockout_minutes=60
 developers   | password_profile.min_length=12
 executives   | password_profile.min_length=16
 executives   | password_profile.password_history_count=10
```

---

## Benefits

 **No Code Changes**: Pure SQL configuration  
 **Granular Control**: Per-user or per-role policies  
 **Dynamic Updates**: Change policies without restart  
 **Inheritance**: Role membership inherits settings  
 **Audit Trail**: All changes logged in PostgreSQL logs  

---

## Limitations

 **Background Worker GUCs**: `log_monitor_enabled` and `log_directory` are global only (shared_preload_libraries context)

 **Session Overrides**: Users can temporarily override with `SET` command (session only)

---

## Best Practices

1. **Use Role-Based Policies**: Define policies on roles, grant roles to users
2. **Document Policies**: Maintain a policy document explaining each tier
3. **Test First**: Test policy changes on non-production users
4. **Audit Regularly**: Review `pg_roles.rolconfig` for compliance

---

## Migration Example

```sql
-- Before: Global policy (one-size-fits-all)
ALTER SYSTEM SET password_profile.min_length = 8;

-- After: Tiered policies
-- Keep global default for standard users
ALTER SYSTEM SET password_profile.min_length = 8;

-- Override for specific tiers
ALTER ROLE admin_tier SET password_profile.min_length = 16;
ALTER ROLE privileged_tier SET password_profile.min_length = 12;

-- No changes needed for standard users (inherit global default)
```

---

## Troubleshooting

### User reports "password too short" but global setting is 8

```sql
-- Check user-specific override
SELECT useconfig FROM pg_user WHERE usename = 'affected_user';

-- If override exists, reset it
ALTER ROLE affected_user RESET password_profile.min_length;
```

### Policy not applying

```sql
-- Verify user is connected (new session picks up role config)
\c - affected_user

-- Check effective setting
SHOW password_profile.min_length;
```

---

**Version**: 1.0  
**Feature Status**:  **FULLY SUPPORTED** (Native PostgreSQL)  
**Performance Impact**: None (native PostgreSQL feature)
