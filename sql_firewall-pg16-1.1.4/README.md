# SQL Firewall for PostgreSQL

`sql_firewall` is a PostgreSQL extension that provides multi-layered protection against SQL injection, unauthorized data access, and misuse of database services.

It intercepts incoming SQL queries and analyzes them based on customizable rules, policies, and limits. This enhances database security by allowing only approved or safe query patterns to be executed.

---

## 🚀 Features

### Multiple Operating Modes
- **learn**: Logs all new command types (e.g., SELECT, INSERT) per user role without blocking, helping to build an initial ruleset.
- **permissive**: Logs unknown commands and blocks queries matching regex rules.
- **enforce**: Blocks any command that hasn’t been explicitly approved.

### Command-Based Approval System
Uses command-type-based rule learning and enforcement (e.g., SELECT, INSERT), per user role. Faster and more stable than hash-based fingerprinting.

### Regex-Based Threat Detection
Blocks queries that match case-insensitive regular expressions. Effective against SQL injection patterns.

### Keyword Blacklist
Blocks queries containing dangerous keywords like `DROP`, `TRUNCATE`, etc.

### Rate Limiting
Limits total queries or specific command types (e.g., SELECT) per user within a defined time window.

### Quiet Hours
Blocks all queries during configured time ranges (e.g., 22:00–06:00).

### Application Blocking
Blocks connections based on the `application_name` parameter in the client connection.

### Detailed Logging
All allowed, blocked, and learned queries are logged with metadata: user, time, reason, command type, and query.

---

## 📦 Requirements

- **PostgreSQL**: 16.x
- **Tools**: `make`, `gcc`
- **Dev Packages**: `postgresql-server-dev-16` or `postgresql-devel`

---

## ⚙️ Installation

```bash
git clone https://github.com/your_user/sql_firewall.git
cd sql_firewall
make
sudo make install
```

Enable the extension in `postgresql.conf`:

```conf
shared_preload_libraries = 'sql_firewall'
```

Restart PostgreSQL:

```bash
sudo systemctl restart postgresql-16
```

Create the extension in your database:

```sql
CREATE EXTENSION sql_firewall;
```

---

## 🛠️ Configuration Parameters (GUCs)

| Parameter | Description | Default |
|----------|-------------|---------|
| `sql_firewall.mode` | Firewall mode (`learn`, `permissive`, `enforce`) | `learn` |
| `sql_firewall.enable_regex_scan` | Enable regex blocking | `true` |
| `sql_firewall.enable_keyword_scan` | Enable keyword blocking | `false` |
| `sql_firewall.blacklisted_keywords` | Comma-separated keywords | `drop,truncate` |
| `sql_firewall.enable_quiet_hours` | Enable quiet hour blocking | `false` |
| `sql_firewall.quiet_hours_start` | Quiet hours start (`HH:MM`) | `22:00` |
| `sql_firewall.quiet_hours_end` | Quiet hours end (`HH:MM`) | `06:00` |
| `sql_firewall.enable_rate_limiting` | Enable total rate limit | `false` |
| `sql_firewall.rate_limit_count` | Max total queries in window | `100` |
| `sql_firewall.rate_limit_seconds` | Time window (seconds) | `60` |
| `sql_firewall.command_limit_seconds` | Per-command time window | `60` |
| `sql_firewall.select_limit_count` | SELECT limit (0 = unlimited) | `0` |
| `sql_firewall.insert_limit_count` | INSERT limit | `0` |
| `sql_firewall.update_limit_count` | UPDATE limit | `0` |
| `sql_firewall.delete_limit_count` | DELETE limit | `0` |
| `sql_firewall.enable_application_blocking` | Enable app blocking | `false` |
| `sql_firewall.blocked_applications` | Comma-separated app names | `''` |

### 🔧 Example
```sql
ALTER SYSTEM SET sql_firewall.mode = 'enforce';
ALTER SYSTEM SET sql_firewall.enable_regex_scan = 'on';
SELECT pg_reload_conf();
```

---

## 🚦 Usage

### 1. Learn Mode
Logs unapproved command types per role to `sql_firewall_command_approvals`:

```sql
-- This will be logged automatically if mode is 'learn':
SELECT * FROM users;
```

### 2. Approving Commands
```sql
UPDATE sql_firewall_command_approvals
SET is_approved = true
WHERE role_name = 'app_user' AND command_type = 'SELECT';
```

### 3. Adding Regex Rules
```sql
INSERT INTO sql_firewall_regex_rules (pattern, description)
VALUES ('or\s+1\s*=\s*1', 'SQL injection pattern');
```

### 4. Switching to Enforce Mode
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

## 🗃️ Internal Tables

### `sql_firewall_command_approvals`
Tracks approved command types per user role:
- `role_name`
- `command_type`
- `is_approved`
- `created_at`

### `sql_firewall_regex_rules`
Regex rules for pattern-based blocking:
- `pattern`
- `description`
- `is_active`
- `created_at`

### `sql_firewall_activity_log`
All query activities (allowed, blocked, learned):
- `log_id`
- `log_time`
- `role_name`
- `database_name`
- `query_text`
- `application_name`
- `client_ip`
- `command_type`
- `action`
