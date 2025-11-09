# SQL Firewall RS - Usage Guide

Quick reference guide for using the SQL Firewall RS extension.

## Installation

```sql
-- Install the extension in your database
CREATE EXTENSION sql_firewall_rs;

-- Verify installation
SELECT sql_firewall_status();
```

## Configuration

### Setting the Firewall Mode

```sql
-- Learn mode: Allow queries, create approval records
SET sql_firewall.mode = 'learn';

-- Enforce mode: Block unauthorized queries
SET sql_firewall.mode = 'enforce';

-- Permissive mode: Allow queries, log warnings
SET sql_firewall.mode = 'permissive';
```

### Keyword Blocking

```sql
-- Block specific SQL keywords
SET sql_firewall.blacklisted_keywords = 'drop,truncate,delete';

-- Enable keyword scanning
SET sql_firewall.enable_keyword_scan = true;

-- Disable keyword scanning
SET sql_firewall.enable_keyword_scan = false;
```

### Quiet Hours (Maintenance Windows)

```sql
-- Configure quiet hours (no queries allowed during this time)
SET sql_firewall.quiet_hours_start = '22:00';
SET sql_firewall.quiet_hours_end = '06:00';

-- All-day quiet hours (for testing)
SET sql_firewall.quiet_hours_start = '00:00';
SET sql_firewall.quiet_hours_end = '23:59';

-- Disable quiet hours
SET sql_firewall.quiet_hours_start = '';
SET sql_firewall.quiet_hours_end = '';
```

### Rate Limiting

```sql
-- Global rate limit: max 10 queries per role in 60 seconds
SET sql_firewall.rate_limit_seconds = 60;
SET sql_firewall.rate_limit_count = 10;

-- Per-command rate limit: max 5 of same command type in 30 seconds
SET sql_firewall.command_limit_seconds = 30;
SET sql_firewall.command_limit_count = 5;
```

### Regex Scanning

```sql
-- Enable/disable regex pattern matching
SET sql_firewall.enable_regex_scan = true;
SET sql_firewall.enable_regex_scan = false;
```

## Managing Regex Rules

### View Current Rules

```sql
SELECT id, pattern, description, action, is_active
FROM public.sql_firewall_regex_rules
ORDER BY id;
```

### Add New Blocking Rule

```sql
INSERT INTO public.sql_firewall_regex_rules (pattern, description, action)
VALUES ('union.*select', 'Block UNION-based SQL injection', 'BLOCK');
```

### Disable a Rule

```sql
UPDATE public.sql_firewall_regex_rules
SET is_active = false
WHERE id = 1;
```

### Delete a Rule

```sql
DELETE FROM public.sql_firewall_regex_rules
WHERE id = 2;
```

## Managing Command Approvals

### View Current Approvals

```sql
SELECT role_name, command_type, is_approved, created_at
FROM public.sql_firewall_command_approvals
ORDER BY role_name, command_type;
```

### Approve a Command for a Role

```sql
UPDATE public.sql_firewall_command_approvals
SET is_approved = true
WHERE role_name = 'myuser' AND command_type = 'SELECT';
```

### Manually Create Approval

```sql
INSERT INTO public.sql_firewall_command_approvals (role_name, command_type, is_approved)
VALUES ('myuser', 'INSERT', true)
ON CONFLICT (role_name, command_type) DO UPDATE SET is_approved = true;
```

### Revoke Approval

```sql
UPDATE public.sql_firewall_command_approvals
SET is_approved = false
WHERE role_name = 'myuser' AND command_type = 'DELETE';
```

## Viewing Activity Logs

### Recent Activity

```sql
SELECT log_time, role_name, command_type, action, reason
FROM public.sql_firewall_activity_log
ORDER BY log_time DESC
LIMIT 50;
```

### Blocked Queries

```sql
SELECT log_time, role_name, query_text, reason
FROM public.sql_firewall_activity_log
WHERE action = 'BLOCKED'
ORDER BY log_time DESC;
```

### Activity by Role

```sql
SELECT role_name, command_type, action, COUNT(*) as count
FROM public.sql_firewall_activity_log
WHERE log_time > NOW() - INTERVAL '1 hour'
GROUP BY role_name, command_type, action
ORDER BY count DESC;
```

### Activity by Time

```sql
SELECT DATE_TRUNC('hour', log_time) as hour, 
       action, 
       COUNT(*) as count
FROM public.sql_firewall_activity_log
WHERE log_time > NOW() - INTERVAL '24 hours'
GROUP BY hour, action
ORDER BY hour DESC;
```

## Common Use Cases

### 1. Learning Phase (Discover Normal Usage)

```sql
-- Set to learn mode
SET sql_firewall.mode = 'learn';
SET sql_firewall.enable_keyword_scan = true;
SET sql_firewall.enable_regex_scan = true;

-- Let application run for some time...
-- Check what was learned
SELECT DISTINCT role_name, command_type, is_approved
FROM public.sql_firewall_command_approvals
ORDER BY role_name, command_type;

-- Approve legitimate commands
UPDATE public.sql_firewall_command_approvals
SET is_approved = true
WHERE role_name = 'app_user' AND command_type IN ('SELECT', 'INSERT', 'UPDATE');
```

### 2. Production Protection

```sql
-- Switch to enforce mode
SET sql_firewall.mode = 'enforce';

-- Block dangerous operations
SET sql_firewall.blacklisted_keywords = 'drop,truncate,alter,create';

-- Enable all scanning
SET sql_firewall.enable_keyword_scan = true;
SET sql_firewall.enable_regex_scan = true;

-- Set rate limits
SET sql_firewall.rate_limit_seconds = 60;
SET sql_firewall.rate_limit_count = 100;
```

### 3. Maintenance Window

```sql
-- As superuser, configure quiet hours
ALTER SYSTEM SET sql_firewall.quiet_hours_start = '02:00';
ALTER SYSTEM SET sql_firewall.quiet_hours_end = '05:00';
SELECT pg_reload_conf();

-- During quiet hours, only superusers can execute queries
-- Non-superusers will be blocked
```

### 4. Monitoring Suspicious Activity

```sql
-- Check for repeated blocked attempts
SELECT role_name, 
       reason, 
       COUNT(*) as attempts,
       MAX(log_time) as last_attempt
FROM public.sql_firewall_activity_log
WHERE action = 'BLOCKED'
  AND log_time > NOW() - INTERVAL '1 hour'
GROUP BY role_name, reason
HAVING COUNT(*) > 5
ORDER BY attempts DESC;
```

### 5. Testing Firewall Rules

```sql
-- Create test user
CREATE ROLE testuser LOGIN PASSWORD 'test123';
GRANT CONNECT ON DATABASE mydb TO testuser;

-- Set enforce mode
SET sql_firewall.mode = 'enforce';
SET sql_firewall.blacklisted_keywords = 'drop';

-- Test as test user (in another session)
-- psql -U testuser -d mydb
-- DROP TABLE test;  -- Should be blocked

-- Check logs
SELECT log_time, role_name, query_text, reason
FROM public.sql_firewall_activity_log
WHERE role_name = 'testuser'
ORDER BY log_time DESC
LIMIT 10;
```

## Permanent Configuration

To make settings persistent across PostgreSQL restarts, add to `postgresql.conf`:

```ini
# SQL Firewall Configuration
shared_preload_libraries = 'sql_firewall_rs'

sql_firewall.mode = 'enforce'
sql_firewall.enable_keyword_scan = true
sql_firewall.enable_regex_scan = true
sql_firewall.blacklisted_keywords = 'drop,truncate,alter'
sql_firewall.rate_limit_seconds = 60
sql_firewall.rate_limit_count = 100
sql_firewall.command_limit_seconds = 30
sql_firewall.command_limit_count = 50
```

Then restart PostgreSQL:
```bash
sudo systemctl restart postgresql-16
```

## Important Notes

1. **Superusers Bypass All Rules:** Database superusers (including the postgres user) bypass all firewall restrictions.

2. **Session vs System Settings:** Use `SET` for session-level changes, `ALTER SYSTEM` for system-wide changes.

3. **Recursive Protection:** The firewall automatically skips checking its own internal queries to prevent infinite loops.

4. **Case-Insensitive Matching:** Keyword blocking is case-insensitive (`DROP`, `drop`, `Drop` all match).

5. **Regex Performance:** Complex regex rules can impact query performance. Test carefully in production.

6. **Approval Workflow:** In Learn mode, the firewall creates approval records for new command types but doesn't block them.

## Troubleshooting

### Queries Being Unexpectedly Blocked

```sql
-- Check current mode
SHOW sql_firewall.mode;

-- Check active rules
SELECT * FROM public.sql_firewall_regex_rules WHERE is_active = true;

-- Check keyword blacklist
SHOW sql_firewall.blacklisted_keywords;

-- Check recent blocks
SELECT log_time, query_text, reason
FROM public.sql_firewall_activity_log
WHERE action = 'BLOCKED'
ORDER BY log_time DESC
LIMIT 10;
```

### Cannot Access Firewall Tables

```sql
-- Firewall tables should have PUBLIC access by default
-- If issues occur, manually grant:
GRANT SELECT, INSERT, UPDATE ON public.sql_firewall_activity_log TO PUBLIC;
GRANT SELECT, INSERT, UPDATE ON public.sql_firewall_command_approvals TO PUBLIC;
GRANT SELECT, INSERT, UPDATE, DELETE ON public.sql_firewall_regex_rules TO PUBLIC;
```

### Extension Not Loading

```bash
# Check PostgreSQL logs
sudo tail -f /var/lib/pgsql/16/data/log/postgresql-*.log

# Verify extension files exist
ls -l /usr/pgsql-16/lib/libsql_firewall_rs.so
ls -l /usr/pgsql-16/share/extension/sql_firewall_rs*

# Check shared_preload_libraries
psql -U postgres -c "SHOW shared_preload_libraries;"
```

## Support

For issues, questions, or contributions:
- Check the logs in PostgreSQL log directory
- Review TEST_RESULTS.md for expected behavior
- Examine CODE_REVIEW.md for architecture details
