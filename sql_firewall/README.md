# SQL Firewall for PostgreSQL

`sql_firewall` is an extension for PostgreSQL that provides multi-layered protection against SQL injection, unauthorized data access, and misuse of database services.

This extension intercepts incoming SQL queries and analyzes them based on predefined rules, policies, and limits. It enhances database security by allowing only approved query patterns to be executed.

---

## 🚀 Features

- **Multiple Operating Modes:**
  - `learn`: Logs all new queries to a rule table without blocking them.
  - `permissive` (planned): Logs unknown queries but does not block them.
  - `enforce`: Allows only previously approved queries to be executed and blocks others.

- **Rule-Based Filtering:** Recognizes queries using fingerprinting and enforces per-role and per-database rules.

- **Keyword Blacklist:** Automatically blocks queries containing dangerous SQL keywords such as `DROP`, `TRUNCATE`, etc.

- **Rate Limiting:** Limits the total number of queries or query types (e.g., SELECT, UPDATE) per user in a specified time frame.

- **Quiet Hours:** Blocks query execution during specified periods, such as night hours, when database activity is not expected.

- **Application Blocking:** Blocks connections based on the `application_name` parameter.

- **Detailed Logging:** Logs every allowed, blocked, or learned query with detailed activity information.

---

## 📦 Requirements

- **PostgreSQL Version:** 9.6 or higher  
- **Build Tools:** Standard C build tools (e.g., `make`, `gcc`)  
- **PostgreSQL Development Files:** Required for compilation (e.g., `postgresql-server-dev-14` or `postgresql-devel`)

---

## ⚙️ Installation

### Clone the Repository:
```bash
git clone https://github.com/your_user/sql_firewall.git
cd sql_firewall
```

### Build and Install:
Ensure `pg_config` is available in your system `PATH`.

```bash
make
sudo make install
```

### Activate the Extension:
Connect to the target database using `psql` or any database client and run:

```sql
CREATE EXTENSION sql_firewall;
```

This will create the required tables: `sql_firewall_rules`, `sql_firewall_activity_log`.

---

## 🛠 Configuration

`sql_firewall` provides several GUC parameters configurable via `postgresql.conf` or `ALTER SYSTEM`.

| Parameter | Description | Default |
|----------|-------------|---------|
| `sql_firewall.mode` | Firewall mode (`learn`, `enforce`) | `learn` |
| `sql_firewall.enable_keyword_scan` | Enable blacklist keyword scanning | `true` |
| `sql_firewall.blacklisted_keywords` | Comma-separated keywords to block | `drop,truncate,delete` |
| `sql_firewall.enable_quiet_hours` | Enable quiet hours feature | `false` |
| `sql_firewall.quiet_hours_start` | Quiet hours start (HH:MM) | `22:00` |
| `sql_firewall.quiet_hours_end` | Quiet hours end (HH:MM) | `06:00` |
| `sql_firewall.enable_rate_limiting` | Enable general query rate limiting | `false` |
| `sql_firewall.rate_limit_count` | Max queries allowed in `rate_limit_seconds` | `100` |
| `sql_firewall.rate_limit_seconds` | Time window for rate limiting (seconds) | `60` |
| `sql_firewall.command_limit_seconds` | Time window for command-based limits (seconds) | `60` |
| `sql_firewall.select_limit_count` | SELECT query limit (0 = unlimited) | `0` |
| `sql_firewall.insert_limit_count` | INSERT query limit (0 = unlimited) | `0` |
| `sql_firewall.update_limit_count` | UPDATE query limit (0 = unlimited) | `0` |
| `sql_firewall.delete_limit_count` | DELETE query limit (0 = unlimited) | `0` |
| `sql_firewall.enable_application_blocking` | Enable blocking by application name | `false` |
| `sql_firewall.blocked_applications` | Comma-separated list of blocked `application_name`s | `''` (empty) |

### Example:
```sql
-- Set mode to 'enforce'
ALTER SYSTEM SET sql_firewall.mode = 'enforce';

-- Reload configuration
SELECT pg_reload_conf();
```

---

## 🚦 Usage

### 1. Learn Mode
When installed, the firewall defaults to `learn` mode. All unseen queries are saved in `sql_firewall_rules` with `is_approved = false`. This helps collect query fingerprints used during normal operation.

### 2. Approving Rules
After a learning period, the DBA should review and approve safe query patterns.

```sql
UPDATE sql_firewall_rules
SET is_approved = true
WHERE rule_id = 123;
```

Or approve all queries for a specific role:
```sql
UPDATE sql_firewall_rules
SET is_approved = true
WHERE role_name = 'app_user';
```

### 3. Enforce Mode
Once rules are approved, switch to `enforce` mode.

```sql
ALTER SYSTEM SET sql_firewall.mode = 'enforce';
SELECT pg_reload_conf();
```

Only queries marked `is_approved = true` will be executed. Others will be blocked and logged.

---

## 🗃️ Database Tables

### `sql_firewall_rules`
Stores learned and approved query rules.

- `rule_id`: Unique rule ID
- `role_name`: Role executing the query
- `database_name`: Database name
- `command_type`: Query type (SELECT, INSERT, etc.)
- `query_fingerprint`: Query hash
- `is_approved`: Whether the query is allowed
- `created_at`: Timestamp of rule creation

### `sql_firewall_activity_log`
Stores all firewall events.

- `log_id`: Unique log ID
- `log_time`: Timestamp
- `role_name`: Role executing the query
- `database_name`: Database
- `action`: `ALLOWED`, `BLOCKED`, or `LEARNED`
- `reason`: Explanation (e.g., “Rule not approved”, “Blacklisted keyword”)
- `query_text`: Full SQL query
- `command_type`: Type of command

---


