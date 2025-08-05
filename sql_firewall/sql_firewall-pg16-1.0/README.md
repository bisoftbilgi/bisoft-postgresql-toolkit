# SQL Firewall for PostgreSQL

`sql_firewall` is an extension for PostgreSQL that provides multi-layered protection against SQL injection, unauthorized data access, and misuse of database services.

This extension intercepts incoming SQL queries and analyzes them based on predefined rules, policies, and limits. It enhances database security by allowing only approved or safe query patterns to be executed.

---

## 🚀 Features

### Multiple Operating Modes
- **learn**: Logs all new command types to a rule table without blocking them, helping to build an initial ruleset.
- **permissive**: Logs and warns about unknown commands, blocks queries that match regex rules.
- **enforce**: Allows only previously approved commands to be executed and blocks all others.

### Command-Based Approval System
Uses command-type based rule learning and enforcement (SELECT, INSERT, etc.) per user role, instead of full query hashes.

### Regex-Based Threat Detection
Blocks queries that match regular expressions. This is effective for detecting SQL injection patterns. Case-insensitive.

### Keyword Blacklist
Blocks queries containing dangerous SQL keywords such as `DROP`, `TRUNCATE`, etc.

### Rate Limiting
Limits total queries or specific command types (e.g., SELECT) per user within a specified time window.

### Quiet Hours
Blocks query execution during specific time ranges like nighttime or maintenance windows.

### Application Blocking
Blocks connections based on the `application_name` parameter.

### Detailed Logging
Logs every allowed, blocked, or learned query with role, time, reason, and command type.

---

## 📦 Requirements

- **PostgreSQL Version**: 16
- **Build Tools**: make, gcc
- **Development Files**: postgresql-server-dev-16 or postgresql-devel

---

## ⚙️ Installation

```bash
git clone https://github.com/your_user/sql_firewall.git
cd sql_firewall
make
sudo make install
```

Edit `postgresql.conf`:

```conf
shared_preload_libraries = 'sql_firewall'
```

Restart PostgreSQL:

```bash
sudo systemctl restart postgresql-16
```

Activate the extension in your database:

```sql
CREATE EXTENSION sql_firewall;
```

---

## 🛠️ Configuration Parameters (GUCs)

| Parameter | Description | Default |
|----------|-------------|---------|
| sql_firewall.mode | Firewall mode (`learn`, `permissive`, `enforce`) | learn |
| sql_firewall.enable_regex_scan | Enable regex scan | true |
| sql_firewall.enable_keyword_scan | Enable SQL keyword block | false |
| sql_firewall.blacklisted_keywords | Comma-separated keywords | drop,truncate |
| sql_firewall.enable_quiet_hours | Enable quiet hour blocking | false |
| sql_firewall.quiet_hours_start | Quiet hours start (HH:MM) | 22:00 |
| sql_firewall.quiet_hours_end | Quiet hours end (HH:MM) | 06:00 |
| sql_firewall.enable_rate_limiting | Enable total rate limit | false |
| sql_firewall.rate_limit_count | Query limit in window | 100 |
| sql_firewall.rate_limit_seconds | Time window (seconds) | 60 |
| sql_firewall.command_limit_seconds | Per-command limit window | 60 |
| sql_firewall.select_limit_count | SELECT limit (0 = unlimited) | 0 |
| sql_firewall.insert_limit_count | INSERT limit | 0 |
| sql_firewall.update_limit_count | UPDATE limit | 0 |
| sql_firewall.delete_limit_count | DELETE limit | 0 |
| sql_firewall.enable_application_blocking | Enable app blocking | false |
| sql_firewall.blocked_applications | Comma-separated app names | '' |

Example:
```sql
ALTER SYSTEM SET sql_firewall.mode = 'enforce';
ALTER SYSTEM SET sql_firewall.enable_regex_scan = 'on';
SELECT pg_reload_conf();
```

---

## 🚦 Usage

### 1. Learn Mode
All new command types executed by a role are saved in `sql_firewall_command_approvals` with `is_approved = false`.

### 2. Approving Commands
```sql
UPDATE sql_firewall_command_approvals
SET is_approved = true
WHERE role_name = 'app_user' AND command_type = 'SELECT';
```

### 3. Regex Rules
```sql
INSERT INTO sql_firewall_regex_rules (pattern, description)
VALUES ('or\s+1\s*=\s*1', 'SQL injection attempt');
```

### 4. Enforce Mode
```sql
ALTER SYSTEM SET sql_firewall.mode = 'enforce';
SELECT pg_reload_conf();
```

### 5. Application Blocking
```sql
ALTER SYSTEM SET sql_firewall.enable_application_blocking = 'on';
ALTER SYSTEM SET sql_firewall.blocked_applications = 'pgAdmin,DBeaver';
SELECT pg_reload_conf();
```

---

## 🗃️ Tables

### `sql_firewall_command_approvals`
Command-type approval per role:
- role_name
- command_type
- is_approved
- created_at

### `sql_firewall_regex_rules`
Regex-based blocking rules:
- pattern
- description
- is_active
- created_at

### `sql_firewall_activity_log`
Query activity log:
- role_name
- database_name
- action (ALLOWED, BLOCKED, LEARNED)
- reason
- query_text
- command_type
- log_time

---

