# SQL Firewall for PostgreSQL

A production-ready SQL firewall extension for PostgreSQL 16 (compatible with 14-15). Written in Rust using pgrx, it evaluates every SQL command before execution and enforces security policies including command approvals, regex pattern blocking, rate limiting, fingerprint learning, and activity logging—all without external dependencies.

---
## 1. Architecture

| Layer | Role | Details |
|-------|------|---------|
| **Hook Layer** | `ExecutorStart_hook`, `ProcessUtility_hook` | Captures every query/utility command, collects metadata, and short-circuits execution using `ereport!` when a policy fails. |
| **Context Capture** | `sql_firewall_rs::context` | Resolves role, database, application name, client IP, and command tags for policy and logging decisions. |
| **Policy Engine** | `firewall.rs`, `spi_checks.rs` | Applies security checks with transaction-safe logging, panic-safe guards, and improved internal query detection to prevent recursive loops. All SPI use is wrapped in guards that ensure proper transaction context. |
| **Shared Memory** | `fingerprint_cache`, `rate_state` | Cross-backend caches with deadlock-free SpinLock implementation and panic safety. Tracks normalized query fingerprints (4096 entries) and rate-limit counters (512+1024 entries) without SPI overhead. |
| **Catalog Tables** | `sql_firewall_activity_log`, `sql_firewall_command_approvals`, `sql_firewall_query_fingerprints`, `sql_firewall_regex_rules` | Persist audit records, approvals, fingerprint metadata, and regex rules (installed via `sql/firewall_schema.sql`). Includes ReDoS validation trigger on regex_rules table. |
| **Alerting** | `alerts.rs` | Optional `NOTIFY` + syslog payloads whenever a block happens (regex, keyword, quiet hours, rate limit, approvals). |
| **Tooling** | `run_comprehensive_tests.sh`, `run_advanced_tests.sh` | Comprehensive test suites that provision throwaway databases and validate all features. Currently 15/15 tests passing with full coverage of security, performance, and edge cases. |

All policy decisions happen synchronously inside the backend with panic-safe guards, so blocks are atomic and crash-safe. Recent security fixes include: deadlock prevention, ReDoS timeout (100ms), transaction-safe logging, race condition fixes, and recursive loop protection.

---
## 2. Feature Summary

- **Operating modes** – `learn`, `permissive`, `enforce` determine how unknown commands are handled. Learn mode now blocks unapproved commands and requires admin approval.
- **Command approvals** – role-based authorization for command types (SELECT, INSERT, UPDATE, DELETE, DDL). Admin approval required in learn mode.
- **Adaptive fingerprints** – normalized SQL fingerprints with shared memory caching and auto-approval after threshold (configurable, default 10 hits).
- **Shared-memory rate limits** – global per-role window plus per-command budgets (SELECT/INSERT/UPDATE/DELETE) with deadlock-free SpinLock implementation.
- **Regex & keyword filters** – SQL injection pattern matching with 100ms ReDoS timeout protection. Validation trigger prevents dangerous patterns.
- **Quiet hours** – time-based access restrictions with panic-safe logging (no SPI recursion).
- **Activity logging** – transaction-safe 3-layer logging (WARNING + LOG + syslog) that survives abort scenarios.
- **Connection policies** – IP blocking, application filtering, and role-IP binding with race condition prevention.
- **Alert channels** – NOTIFY payloads + optional syslog mirroring for SIEM integration.
- **Retention jobs** – automatic pruning of activity logs and fingerprint tables.

---
## 3. Requirements

| Component | Version / Notes |
|-----------|-----------------|
| PostgreSQL | 16.x (server binaries + dev headers). Other majors supported if built with matching `pg_config`. |
| Rust | Stable 1.72+ recommended. |
| `cargo-pgrx` | 0.16.x (tested with 0.16.1). |
| Build deps | clang/llvm, make, gcc, libpq-dev, `postgresql16-devel` (distro-specific names). |

Superuser privileges are required to install the library and set `shared_preload_libraries`.

---
## 4. Installation

```bash
# 1) Install tooling (once per host)
cargo install --locked cargo-pgrx --version 0.16.1
cargo pgrx init --pg16 /usr/pgsql-16/bin/pg_config

# 2) Build the extension
git clone https://github.com/your-org/sql_firewall_rs.git
cd sql_firewall_rs
cargo pgrx build --release --pg-config /usr/pgsql-16/bin/pg_config

# 3) Deploy artifacts
sudo cp target/release/libsql_firewall_rs.so /usr/pgsql-16/lib/
sudo cp sql_firewall_rs.control /usr/pgsql-16/share/extension/
sudo cp sql/sql_firewall_rs--*.sql /usr/pgsql-16/share/extension/

# 4) Enable and create
sudo sed -i "s/^shared_preload_libraries.*/shared_preload_libraries = 'sql_firewall'/" /var/lib/pgsql/16/data/postgresql.conf
sudo systemctl restart postgresql-16
psql -d mydb -c 'CREATE EXTENSION sql_firewall;'
```

For upgrades, rebuild, copy the `.so`, and run `ALTER EXTENSION sql_firewall_rs UPDATE;` in each database.

---
## 5. Configuration (GUCs)

All knobs live under `sql_firewall.*` and may be set via `ALTER SYSTEM`, `postgresql.conf`, `ALTER DATABASE`, or `ALTER ROLE ... IN DATABASE`.

| Category | GUC | Default | Description |
|----------|-----|---------|-------------|
| **Modes** | `sql_firewall.mode` | `learn` | Choose between `learn`, `permissive`, `enforce`. |
| **Quiet Hours** | `sql_firewall.enable_quiet_hours` | `off` | Master toggle. |
| | `sql_firewall.quiet_hours_start` / `sql_firewall.quiet_hours_end` | `00:00` / `23:59` | HH:MM window; handles wrap-around. |
| | `sql_firewall.quiet_hours_log` | `on` | Emit WARNING logs instead of SPI logging (prevents recursion). |
| **Rate Limiting** | `sql_firewall.enable_rate_limiting` | `off` | Enables global per-role window. |
| | `sql_firewall.rate_limit_count` / `sql_firewall.rate_limit_seconds` | `100` / `60` | Requests allowed inside global window. |
| | `sql_firewall.command_limit_seconds` | `0` | Window for verb limits (0 disables). |
| | `sql_firewall.select_limit_count`, `insert_limit_count`, `update_limit_count`, `delete_limit_count` | `0` | Verb-specific caps per window. |
| **Approvals & Fingerprints** | `sql_firewall.enable_fingerprint_learning` | `on` | Toggle adaptive fingerprint approvals. Works in Learn and Permissive modes. |
| | `sql_firewall.fingerprint_learn_threshold` | `10` | Hits required to auto-approve a fingerprint (changed from 5 to 10). |
| | `sql_firewall.fingerprint_cache_size` | `4096` | Shared memory cache entries for fingerprints. |
| **Keyword / Regex** | `sql_firewall.enable_keyword_scan` | `off` | Keyword blacklist switch. |
| | `sql_firewall.blacklisted_keywords` | `drop,truncate` | Comma-separated list. |
| | `sql_firewall.enable_regex_scan` | `off` | Evaluate `sql_firewall_regex_rules` with 100ms timeout protection. |
| **Connection Policies** | `sql_firewall.enable_application_blocking` / `.blocked_applications` | `off` / empty | Deny by `application_name`. |
| | `sql_firewall.enable_ip_blocking` / `.blocked_ips` | `off` / empty | Deny specific client IPs. |
| | `sql_firewall.enable_role_ip_binding` / `.role_ip_bindings` | `off` / empty | Allow explicit `role@ip` pairs only. |
| **Alerts** | `sql_firewall.enable_alert_notifications` | `off` | Emit NOTIFY events for blocks. |
| | `sql_firewall.alert_channel` | `sql_firewall_alerts` | Channel name for LISTEN/NOTIFY. |
| | `sql_firewall.syslog_alerts` | `off` | Mirror alerts to syslog for SIEM. |
| **Retention** | `sql_firewall.activity_log_retention_days` | `30` | Age cutoff for log pruning. |
| | `sql_firewall.activity_log_max_rows` | `1000000` | Row count target before pruning. |

Activity logging itself is always enabled outside quiet hours; quiet-hour suppression avoids SPI recursion.

---
## 6. Operational Workflow

### 6.1 Learn → Approve → Enforce
1. **Learn** – blocks unapproved commands and logs them for review. Admin must explicitly approve via `sql_firewall_command_approvals`.
2. **Review** – admins query activity log and approval tables, verify legitimacy, and set `is_approved=true`.
3. **Enforce** – unknown or unapproved commands are blocked with `ERRCODE_INSUFFICIENT_PRIVILEGE`. `permissive` mode is available for staging: it logs violations without blocking.

### 6.2 Fingerprint Pipeline
- Every query is normalized (literals stripped, whitespace collapsed) and hashed.
- Shared-memory counters track frequency without SPI calls.
- Crossing `sql_firewall.fingerprint_learn_threshold` (default: 10) marks the fingerprint approved and writes metadata to `sql_firewall_query_fingerprints` with SELECT FOR UPDATE to prevent race conditions.
- Works in both Learn and Permissive modes for pattern discovery.

### 6.3 Quiet Hours
- Enable via `sql_firewall.enable_quiet_hours = on` and define start/end times.
- Non-superusers are blocked; superusers bypass automatically.
- Transaction-safe WARNING logging via `sql_firewall.quiet_hours_log = on` records blocks without SPI calls (prevents infinite recursion and FATAL errors discovered during testing).

### 6.4 Rate Limits
- **Global** – `rate_limit_count` queries per `rate_limit_seconds` for each role.
- **Per-command** – `command_limit_seconds` plus the `*_limit_count` knobs constrain SELECT/INSERT/UPDATE/DELETE independently.
- Counters live in shared memory (`rate_state`), so enforcement is constant-time and does not hit the catalogs.

### 6.5 Alerts & Retention
- Set `sql_firewall.enable_alert_notifications = on`, `LISTEN sql_firewall_alerts;`, and consume JSON payloads describing each block.
- Optional `sql_firewall.syslog_alerts = on` mirrors the same payload into syslog for SIEM pipelines.
- Retention knobs keep `sql_firewall_activity_log` and fingerprint tables trimmed according to compliance needs.

---
## 7. Testing & Validation

Run the comprehensive test suite:

```bash
cd sql_firewall
bash run_comprehensive_tests.sh
```

Coverage (15/15 tests passing):
- Database + extension provisioning
- Enforce mode blocking
- Learn mode workflow (block + approve)
- Permissive mode logging
- Regex filter (UNION, OR tautology patterns)
- Keyword blacklist
- Quiet hours (blocking, logging, superuser bypass)
- Global and per-command rate limits
- IP blocking and role-IP binding
- Application blocking
- Fingerprint learning and auto-approval
- Activity logging (transaction-safe)
- Superuser bypass
- Command approval workflow

Advanced tests available via `run_advanced_tests.sh` for stress testing and edge cases.

---
## 8. Troubleshooting

| Symptom | Likely cause | Fix |
|---------|--------------|-----|
| `FATAL: could not access file "sql_firewall"` | `.so` missing from PostgreSQL lib dir or typo in `shared_preload_libraries`. | Copy `libsql_firewall_rs.so` into the server lib path and double-check the conf entry, then restart PostgreSQL. |
| `DefineSavepoint` or `record_pending` FATAL error | Attempting SPI during transaction abort. | Fixed in current version. Removed problematic SPI calls, now uses 3-layer logging (WARNING + LOG + syslog). |
| Quiet hours logging causes recursion | Using SPI logging inside quiet hours. | Keep `sql_firewall.quiet_hours_log = on`; it uses elog-only logging and avoids SPI entirely. |
| Approval rows never appear | SPI insert failing or wrong column names. | Confirm `sql_firewall_command_approvals` schema is installed and that inserts use `(role_name, command_type, is_approved)`. |
| Learn mode allows unapproved commands | Old behavior from earlier versions. | Fixed: Learn mode now blocks unapproved commands and requires admin approval. |
| SpinLock deadlock or panic | Panic during lock holding in older version. | Fixed: Enhanced Drop guards with panic safety ensure locks always released. |
| ReDoS attack from user-supplied regex | No timeout protection in older versions. | Fixed: 100ms timeout + validation trigger prevents dangerous patterns. |
| Race condition on fingerprint updates | Concurrent hit_count updates lost. | Fixed: Uses SELECT FOR UPDATE to prevent race conditions. |
| Activity log empty | Quiet hours active or table privileges altered. | Disable quiet hours for the test or restore INSERT privileges on `sql_firewall_activity_log`. |
| Regex tests miss `'1'='1'` | Patterns missing quoted tautologies. | Insert additional regex rows (e.g., `(?i)or\s*'1'\s*=\s*'1'`). |

If problems persist, capture PostgreSQL logs plus `run_comprehensive_tests.sh` output when filing an issue.

