# sql_firewall_rs – PostgreSQL SQL Firewall

`sql_firewall_rs` is a Rust/pgrx based PostgreSQL extension that inspects every SQL command before execution and enforces configurable security policies such as learning/approval, keyword & regex screening, quiet hours, rate limiting, and detailed activity logging.

---
## Key capabilities
- **Multi-mode enforcement** – `learn`, `permissive`, `enforce` modes determine how unknown commands are handled.
- **Command learning & approvals** – first-time commands are logged to `sql_firewall_command_approvals`; DBAs grant/deny per role+command.
- **Keyword and regex filters** – case-insensitive blacklist plus regex rules stored in `sql_firewall_regex_rules`.
- **Quiet hours** – block all non-superuser traffic for configured HH:MM windows, with optional WARNING logging (`sql_firewall.quiet_hours_log`).
- **Global & per-command rate limits** – shared-memory counters enforce rolling-window limits for total queries and individual verbs.
- **Activity logging** – every allowed/blocked/learned query (outside quiet hours) is persisted in `sql_firewall_activity_log` with role, DB, reason.
- **Superuser bypass** – built-in `superuser()` check skips all enforcement for postgres/cluster admins.
- **Full test harness** – `run_tests.sh` exercises learn→enforce, approvals, regex/keyword, quiet hours, rate limits, logging, and superuser flows.

---
## Architecture overview
| Component | Description |
|-----------|-------------|
| `sql_firewall_rs/src/hooks.rs` | Installs ExecutorStart/ProcessUtility hooks and collects query text, command type, and execution context. |
| `context.rs` | Safe wrappers around `GetUserId/GetUserNameFromId` & current DB name used by logging and approvals. |
| `firewall.rs` | Top-level decision engine – quiet hours check, keyword filter, regex/rate/approval plumbing. |
| `spi_checks.rs` | Performs all SPI work (regex, rate-limit counters, approvals, activity log) using a guarded `with_spi` helper. |
| SQL schema (`firewall_schema.sql`) | Deploys activity log, command approval, and regex-rule tables with the necessary GRANTs. |
| `run_tests.sh` | End-to-end regression script covering every major feature. |

---
## Requirements
- PostgreSQL 16 (tested), compatible with 14/15 if built via pgrx 0.16.1.
- Development headers: `postgresql16-devel` (package name varies per distro).
- Rust toolchain ≥ 1.70 + `cargo-pgrx = 0.16.1`.
- Superuser access to set `shared_preload_libraries` and copy extension artifacts.

---
## Build & install
```bash
# Install cargo-pgrx once
cargo install --locked cargo-pgrx --version 0.16.1

# Point cargo-pgrx at your pg_config
cargo pgrx init --pg16 /usr/pgsql-16/bin/pg_config

# Build the extension
cd sql_firewall_rs
cargo pgrx build --release --pg-config /usr/pgsql-16/bin/pg_config

# Copy library + control/sql metadata into PostgreSQL tree
sudo cp target/release/libsql_firewall_rs.so /usr/pgsql-16/lib/
sudo cp sql_firewall_rs.control /usr/pgsql-16/share/extension/
sudo cp sql/sql_firewall_rs--*.sql /usr/pgsql-16/share/extension/

# Enable in postgresql.conf and restart
echo "shared_preload_libraries = 'sql_firewall_rs'" | sudo tee -a /var/lib/pgsql/16/data/postgresql.conf
sudo systemctl restart postgresql-16

# Create inside each database
psql -d mydb -c 'CREATE EXTENSION sql_firewall_rs;'
```

---
## Configuration (GUCs)
All runtime knobs live under `sql_firewall.*` and can be set via `ALTER SYSTEM`, `ALTER ROLE ... IN DATABASE`, or `postgresql.conf`.

| GUC | Default | Description |
|-----|---------|-------------|
| `sql_firewall.mode` | `learn` | Operating mode: learn, permissive (log + allow), enforce (block). |
| `sql_firewall.enable_keyword_scan` | `off` | Enables keyword blacklist check. |
| `sql_firewall.blacklisted_keywords` | `drop,truncate` | Comma-separated keywords (case-insensitive whole words). |
| `sql_firewall.enable_regex_scan` | `on` | Runs regex rules from `sql_firewall_regex_rules`. |
| `sql_firewall.enable_quiet_hours` | `off` | Enables quiet-hours blocking. |
| `sql_firewall.quiet_hours_start` / `end` | `22:00 / 06:00` | HH:MM window (wraps midnight if start > end). |
| `sql_firewall.quiet_hours_log` | `on` | Emits WARNING log for each quiet-hours block (no SPI logging). |
| `sql_firewall.enable_rate_limiting` | `off` | Enables global per-role limit. |
| `sql_firewall.rate_limit_count` | `100` | Max queries per `rate_limit_seconds`. |
| `sql_firewall.rate_limit_seconds` | `60` | Rolling window in seconds for global limit. |
| `sql_firewall.command_limit_seconds` | `60` | Rolling window for verb-specific limits. |
| `sql_firewall.select_limit_count` / `insert_limit_count` / ... | `0` (disabled) | Per-verb caps within the command window. |

> Note: Activity logging is always on outside quiet hours; there is no separate enable GUC.

---
## Internal tables
```sql
-- Activity log
select * from sql_firewall_activity_log order by log_time desc limit 10;
-- Columns: log_id, log_time, role_name, database_name, query_text, application_name,
--          client_ip, command_type, action, reason

-- Command approvals
select * from sql_firewall_command_approvals where role_name = 'app_user';
-- Columns: id, role_name, command_type, is_approved, created_at

-- Regex rules
select * from sql_firewall_regex_rules where is_active;
-- Columns: id, pattern, description, action ('BLOCK'), is_active, created_at
```
All three tables are granted `SELECT/INSERT/UPDATE` to PUBLIC so that non-superuser roles can record learns/logs without extra setup. Manage privileges if stricter isolation is required.

---
## Mode & workflow
1. **Learn** – unapproved commands run once but insert a row into `sql_firewall_command_approvals` with `is_approved = false`. DBAs review & set `is_approved = true`.
2. **Permissive** – unapproved commands continue to run but log “ALLOWED (PERMISSIVE)”.
3. **Enforce** – any `(role_name, command_type)` not approved causes immediate block (`ERRCODE_INSUFFICIENT_PRIVILEGE`).

Regex/keyword/quiet-hours/rate limits run before approvals, so a malicious query never reaches the learning stage.

---
## Testing
Use the bundled regression script for a full end-to-end smoke test:
```bash
cd sql_firewall_rs
chmod +x run_tests.sh
export PGPASSWORD='caghan'
./run_tests.sh
```
The script covers:
- learn → enforce → approval happy path
- regex & keyword blocking
- quiet-hours blocking + superuser bypass
- global and per-command rate limits
- activity logging
- final summary with pass/fail counts

For selective tests, see `test_full_features.sh` (quiet hours, regex, keyword, approvals) or create ad-hoc SQL snippets.

---
## Troubleshooting
| Symptom | Possible cause & fix |
|---------|----------------------|
| `FATAL: could not access file 'sql_firewall_rs'` | Ensure `libsql_firewall_rs.so` resides in PostgreSQL lib dir and `shared_preload_libraries` references the extension. |
| Quiet-hours block not logged | Set `sql_firewall.quiet_hours_log = on` and reload. |
| Learn mode never approves | Check `sql_firewall_command_approvals` for rows; ensure `INSERT` succeeded and `is_approved` was toggled. |
| Activity log empty | Quiet hours suppress logging; outside that window rows should appear. Verify table ownership/GRANTs. |
| Regex baseline misses `'1'='1'` | Use bundled SQL to insert additional patterns into `sql_firewall_regex_rules`. |
