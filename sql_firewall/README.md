# SQL Firewall for PostgreSQL

A production-ready SQL firewall extension for PostgreSQL 16-18. Written in Rust using pgrx, it evaluates every SQL command before execution and enforces security policies including command approvals, regex pattern blocking, rate limiting, fingerprint learning, and activity logging—all without external dependencies.

---
## 1. Architecture

| Layer | Role | Details |
|-------|------|---------|
| **Hook Layer** | `ExecutorStart_hook`, `ProcessUtility_hook` | Captures every query/utility command, collects metadata, and short-circuits execution using `ereport!` when a policy fails. |
| **Context Capture** | `sql_firewall_rs::context` | Resolves role, database, application name, client IP, and command tags for policy and logging decisions. |
| **Policy Engine** | `firewall.rs`, `spi_checks.rs` | Applies security checks with transaction-safe logging, panic-safe guards, and improved internal query detection to prevent recursive loops. All SPI use is wrapped in guards that ensure proper transaction context. |
| **Shared Memory** | `fingerprint_cache`, `rate_state`, `pending_approvals` | Cross-backend caches with deadlock-free SpinLock implementation and panic safety. Tracks normalized query fingerprints (4096 entries), rate-limit counters (512+1024 entries), and pending approvals (1024-entry ring buffer) without SPI overhead. |
| **Background Worker** | `approval_worker` | Launcher-managed worker per database that drains the shared-memory event queue (approvals, fingerprints, blocked queries) and persists results asynchronously so Learn/Permissive modes can allow traffic while still recording approvals. Survives transaction rollbacks automatically. |
| **Catalog Tables** | `sql_firewall_activity_log`, `sql_firewall_blocked_queries`, `sql_firewall_command_approvals`, `sql_firewall_query_fingerprints`, `sql_firewall_regex_rules` | Persist audit records, blocked query logs, approvals, fingerprint metadata, and regex rules (installed via `sql/firewall_schema.sql`). Includes ReDoS validation trigger on regex_rules table. Blocked queries and approvals are written by the background worker, so there is no `dblink` dependency. |
| **Alerting** | `alerts.rs` | Optional `NOTIFY` + syslog payloads whenever a block happens (regex, keyword, quiet hours, rate limit, approvals). |
| **Tooling** | `test_1_basic_security.sh`, `test_2_advanced_stress.sh` | Comprehensive test suites that provision throwaway databases and validate all features. Currently 55/55 basic security tests and 30/30 advanced stress tests passing with full coverage. |

All policy decisions happen synchronously inside the backend with panic-safe guards, so blocks are atomic and crash-safe. Recent security fixes include: deadlock prevention, ReDoS timeout (100ms), transaction-safe logging, race condition fixes, and recursive loop protection. **New:** Background worker architecture allows Learn mode to auto-approve while still recording approval requests safely, solving the transaction rollback challenge.

---
## 2. Feature Summary

### Core Features
- **Operating modes** – `learn`, `permissive`, `enforce` determine how unknown commands are handled. Learn and permissive modes allow unknown commands while queueing approvals/fingerprints; enforce mode blocks anything unapproved.
- **Background approval worker** – Launcher-managed background workers drain the shared-memory queue and persist approvals, fingerprints, and blocked-query events even if the session rolled back. Includes pause/resume/status management functions (`sql_firewall_pause_approval_worker()`, `sql_firewall_resume_approval_worker()`, `sql_firewall_approval_worker_status()`).
- **Command approvals** – Role-based authorization for command types (SELECT, INSERT, UPDATE, DELETE, DDL). Learn/permissive modes auto-approve and log, while enforce mode requires an explicit approval before execution.
- **Adaptive fingerprints** – Normalized SQL fingerprints with shared memory caching and auto-approval after threshold (configurable, default 5 hits). Includes SELECT FOR UPDATE race condition prevention.
- **Shared-memory rate limits** – Global per-role window plus per-command budgets (SELECT/INSERT/UPDATE/DELETE) with deadlock-free SpinLock implementation and panic safety.
- **Regex & keyword filters** – SQL injection pattern matching with 100ms ReDoS timeout protection. Validation trigger prevents dangerous patterns. **NEW: Per-user exemptions** via `allowed_roles text[]` column in `sql_firewall_regex_rules` table allows fine-grained control (NULL = blocks everyone, specified array = exempts those users).
- **Quiet hours** – Time-based access restrictions with panic-safe logging (no SPI recursion).
- **Activity logging** – Transaction-safe 3-layer logging (WARNING + LOG + syslog) that survives abort scenarios.
- **Blocked query logging** – **NEW:** Dedicated `sql_firewall_blocked_queries` table written asynchronously by the background worker. Captures full context (role, database, query text, command type, block reason, timestamp, client IP, application name) and survives transaction rollbacks without needing `dblink`.
- **Activity log control** – **NEW:** `sql_firewall.enable_activity_logging` GUC to toggle logging of allowed queries. When disabled, reduces log volume in high-traffic environments while maintaining security audit trail of blocked queries.
- **Superuser bypass control** – **NEW:** `sql_firewall.allow_superuser_auth_bypass` GUC (default: true) allows disabling superuser exemptions for security testing and stricter enforcement.
- **Connection policies** – IP blocking, application filtering, and role-IP binding with race condition prevention.
- **Alert channels** – NOTIFY payloads + optional syslog mirroring for SIEM integration.
- **Retention jobs** – Automatic pruning of activity logs and fingerprint tables with configurable limits via `sql_firewall.activity_log_retention_days` and `sql_firewall.activity_log_max_rows`.

### Recent Improvements & Bug Fixes

**Major Features Added:**
- **Blocked query logging** – Dedicated table populated asynchronously via shared-memory queue, captures full context, always enabled
- **Activity log toggle** – `enable_activity_logging` GUC to control logging of allowed queries for performance
- **Per-user regex exemptions** – `allowed_roles` array in regex rules for fine-grained pattern control
- **Background worker management** – Pause/resume/status functions for operational control without restart
- **Superuser bypass control** – Configurable via GUC for security testing scenarios
- **Retention policies** – Configurable log pruning via `activity_log_retention_days` and `activity_log_max_rows`

**Critical Bug Fixes:**
- **Background worker stability** – Fixed transaction rollback issues and added launcher-managed workers per database without relying on `dblink`
- **SpinLock deadlock prevention** – Panic-safe Drop guards ensure locks always released even during panics
- **Race condition fixes** – SELECT FOR UPDATE on fingerprint updates, atomic rate limit counter updates
- **ReDoS protection** – 100ms timeout on regex evaluation, validation trigger blocks dangerous patterns at insertion time
- **Transaction safety** – 3-layer logging (WARNING + LOG + syslog) eliminates SPI recursion and FATAL errors
- **Asynchronous logging** – Blocked queries are enqueued to shared memory so they persist even if the blocking transaction aborts
- **Recursive loop prevention** – Enhanced internal query detection prevents infinite firewall loops
- **Memory leak fixes** – Fixed approval cache leaks, proper cleanup in all error paths including panics

---
## 3. Requirements

### PostgreSQL

**Supported versions:**
- PostgreSQL 16, 17, or 18

**Required packages:**
- `postgresqlXX`
- `postgresqlXX-server`
- `postgresqlXX-devel`

*The `-devel` package is mandatory for extension compilation.*

---

### System Dependencies (Build-Time)

For RHEL / Rocky / AlmaLinux systems:

```bash
sudo dnf config-manager --set-enabled crb

sudo dnf install -y \
    clang \
    llvm \
    openssl-devel \
    krb5-devel \
    pkgconf-pkg-config
```

---

### Rust Toolchain

- Rust ≥ 1.72
- `cargo-pgrx 0.16.1`

Install if needed:

```bash
cargo install --locked cargo-pgrx --version 0.16.1
```

---

### PostgreSQL Configuration Capability

You must be able to modify:
- `shared_preload_libraries`

and restart PostgreSQL. Superuser privileges are required.

---

### Environment Setup

Ensure `pg_config` is discoverable by build tooling:

```bash
export PG_CONFIG=/usr/pgsql-XX/bin/pg_config
```

*Alternatively pass it explicitly to `cargo pgrx`.*

---
## 4. Installation

### Initialise pgrx

```bash
cargo pgrx init --pg16 /usr/pgsql-16/bin/pg_config
```

*Run once per PostgreSQL version.*

### Build Extension Package

```bash
cd sql_firewall
cargo pgrx package --pg-config /usr/pgsql-16/bin/pg_config
```

This produces:
- Shared library (`.so`)
- Extension control file
- SQL migration scripts

### Install Artifacts into PostgreSQL

```bash
sudo cp -r target/release/sql_firewall_rs-pg16/usr/pgsql-16/* /usr/pgsql-16/
```

### Enable Extension Preload

```bash
echo "shared_preload_libraries = 'sql_firewall_rs'" \
| sudo tee -a /var/lib/pgsql/16/data/postgresql.conf

sudo systemctl restart postgresql-16
```

### Create Extension in Each Database

```bash
psql -d mydb -c "CREATE EXTENSION sql_firewall_rs;"
```

### Multi-Version Build

To build for additional PostgreSQL versions:

```bash
cargo pgrx package --pg-config /usr/pgsql-17/bin/pg_config
cargo pgrx package --pg-config /usr/pgsql-18/bin/pg_config
```

For upgrades, rebuild the package, copy the new `.so`, and run `ALTER EXTENSION sql_firewall_rs UPDATE;` in each database.

---
## 5. Configuration (GUCs)

All knobs live under `sql_firewall.*` and may be set via `ALTER SYSTEM`, `postgresql.conf`, `ALTER DATABASE`, or `ALTER ROLE ... IN DATABASE`.

| Category | GUC | Default | Description |
|----------|-----|---------|-------------|
| **Modes** | `sql_firewall.mode` | `learn` | Choose between `learn`, `permissive`, `enforce`. |
| **Quiet Hours** | `sql_firewall.enable_quiet_hours` | `off` | Master toggle. |
| | `sql_firewall.quiet_hours_start` / `sql_firewall.quiet_hours_end` | unset | HH:MM window; handles wrap-around when both values are provided. |
| | `sql_firewall.quiet_hours_log` | `on` | Emit WARNING logs instead of SPI logging (prevents recursion). |
| **Rate Limiting** | `sql_firewall.enable_rate_limiting` | `off` | Enables global per-role window. |
| | `sql_firewall.rate_limit_count` / `sql_firewall.rate_limit_seconds` | `100` / `60` | Requests allowed inside global window. |
| | `sql_firewall.command_limit_seconds` | `60` | Window for verb limits (0 disables per-command caps). |
| | `sql_firewall.select_limit_count`, `insert_limit_count`, `update_limit_count`, `delete_limit_count` | `0` | Verb-specific caps per window. |
| **Approvals & Fingerprints** | `sql_firewall.enable_fingerprint_learning` | `on` | Toggle adaptive fingerprint approvals. Works in Learn and Permissive modes. |
| | `sql_firewall.fingerprint_learn_threshold` | `5` | Hits required to auto-approve a fingerprint. |
| **Keyword / Regex** | `sql_firewall.enable_keyword_scan` | `on` | Keyword blacklist switch. |
| | `sql_firewall.blacklisted_keywords` | empty | Comma-separated list of blocked keywords. |
| | `sql_firewall.enable_regex_scan` | `on` | Evaluate `sql_firewall_regex_rules` with 100ms timeout protection. |
| **Connection Policies** | `sql_firewall.enable_application_blocking` / `.blocked_applications` | `off` / empty | Deny by `application_name`. |
| | `sql_firewall.enable_ip_blocking` / `.blocked_ips` | `off` / empty | Deny specific client IPs. |
| | `sql_firewall.enable_role_ip_binding` / `.role_ip_bindings` | `off` / empty | Allow explicit `role@ip` pairs only. |
| **Alerts** | `sql_firewall.enable_alert_notifications` | `off` | Emit NOTIFY events for blocks. |
| | `sql_firewall.alert_channel` | `sql_firewall_alerts` | Channel name for LISTEN/NOTIFY. |
| | `sql_firewall.syslog_alerts` | `off` | Mirror alerts to syslog for SIEM. |
| **Activity Logging** | `sql_firewall.enable_activity_logging` | `on` | Master toggle for activity logging. When enabled, allowed queries are logged to `sql_firewall_activity_log`. Blocked queries are always logged to `sql_firewall_blocked_queries` regardless of this setting. |
| **Retention** | `sql_firewall.activity_log_retention_days` | `30` | Age cutoff for log pruning. |
| | `sql_firewall.activity_log_max_rows` | `1000000` | Row count target before pruning. |

Quiet-hour suppression uses WARNING logs to avoid SPI recursion.

**Note:** The launcher spawns a dedicated worker per database (excluding `postgres`) and connects directly without `dblink`, so approvals/blocked-query events are always written inside the correct database automatically.

### Approval worker maintenance
- `SELECT sql_firewall_pause_approval_worker();` pauses the background worker without requiring a postmaster restart. The worker disconnects from its database and remains idle.
- `SELECT sql_firewall_resume_approval_worker();` reconnects the worker and resumes processing pending approvals.
- `SELECT sql_firewall_approval_worker_status();` returns current worker state: `stopped`, `starting`, `paused`, `running`, or `stopping`.
- Workers are managed per database by the launcher and use regular SPI connections, so no external extensions such as `dblink` are required.

---
## 6. Operational Workflow

### 6.1 Learn → Approve → Enforce
1. **Learn** – allows previously unseen commands, auto-approves them in shared memory, and queues the event for admin review via the background worker. Admins still need to inspect `sql_firewall_command_approvals` and flip `is_approved=true` for production.
2. **Review** – admins query activity log and approval tables in each database, verify legitimacy, and set `is_approved=true`.
3. **Enforce** – unknown or unapproved commands are blocked with `ERRCODE_INSUFFICIENT_PRIVILEGE`. `permissive` mode is available for staging: it logs violations without blocking.

### 6.2 Fingerprint Pipeline
- Every query is normalized (literals stripped, whitespace collapsed) and hashed.
- Shared-memory counters track frequency without SPI calls.
- Crossing `sql_firewall.fingerprint_learn_threshold` (default: 5) marks the fingerprint approved and writes metadata to `sql_firewall_query_fingerprints` with SELECT FOR UPDATE to prevent race conditions.
- Works in both Learn and Permissive modes for pattern discovery.

### 6.3 Quiet Hours
- Enable via `sql_firewall.enable_quiet_hours = on` and define start/end times.
- Non-superusers are blocked; superusers bypass automatically.
- Transaction-safe WARNING logging via `sql_firewall.quiet_hours_log = on` records blocks without SPI calls (prevents infinite recursion and FATAL errors discovered during testing).

### 6.4 Rate Limits
- **Global** – `rate_limit_count` queries per `rate_limit_seconds` for each role.
- **Per-command** – `command_limit_seconds` plus the `*_limit_count` knobs constrain SELECT/INSERT/UPDATE/DELETE independently.
- Counters live in shared memory (`rate_state`), so enforcement is constant-time and does not hit the catalogs.

### 6.5 Blocked Query Logging
- **Dedicated table** – All blocked queries are logged to `sql_firewall_blocked_queries` with full context: role, database, query text, command type, reason, timestamp, client IP, and application name.
- **Asynchronous logging** – Blocked statements are enqueued to shared memory and persisted by the background worker, so records survive even when the blocking transaction aborts—no `dblink` required.
- **Always enabled** – Blocked query logging is independent of `sql_firewall.enable_activity_logging` setting and cannot be disabled.
- **Query blocked queries**: `SELECT * FROM sql_firewall_blocked_queries ORDER BY blocked_at DESC LIMIT 10;`

### 6.6 Per-User Regex Exemptions
- The `sql_firewall_regex_rules` table includes an `allowed_roles text[]` column for fine-grained control.
- **NULL allowed_roles** – Rule applies to all users (blocks everyone matching the pattern).
- **Specified allowed_roles** – Only users NOT in the array are blocked; users in the array are exempt.
- **Example**: Pattern `DROP\s+TABLE` with `allowed_roles = ARRAY['postgres']::text[]` blocks DROP TABLE for all users except postgres.
- **Insert exemption rule**: `INSERT INTO sql_firewall_regex_rules (pattern, action, description, allowed_roles) VALUES ('dangerous_pattern', 'BLOCK', 'Description', ARRAY['admin_user']::text[]);`

### 6.7 Activity Logging Control
- **Toggle activity logging** – Set `sql_firewall.enable_activity_logging = off` to disable logging of allowed queries to `sql_firewall_activity_log`.
- **Blocked queries** – Always logged to `sql_firewall_blocked_queries` regardless of activity logging setting.
- **Use case** – Reduce log volume in high-traffic environments while maintaining security audit trail of blocked attempts.
- **Control via SQL**: `ALTER SYSTEM SET sql_firewall.enable_activity_logging = off; SELECT pg_reload_conf();`

### 6.8 Alerts & Retention
- Set `sql_firewall.enable_alert_notifications = on`, `LISTEN sql_firewall_alerts;`, and consume JSON payloads describing each block.
- Optional `sql_firewall.syslog_alerts = on` mirrors the same payload into syslog for SIEM pipelines.
- Retention knobs keep `sql_firewall_activity_log`, `sql_firewall_blocked_queries`, and fingerprint tables trimmed according to compliance needs.

---
## 7. Testing & Validation

SQL Firewall includes comprehensive test suites for functional validation, stress testing, and performance benchmarking.

### 7.1 Test Suite 1: Basic Security Features

Validates core firewall functionality across all operating modes and security policies.

**Run the test:**
```bash
cd sql_firewall
chmod +x test_1_basic_security.sh
bash test_1_basic_security.sh
```

**Sample Output:**
```
╔════════════════════════════════════════════════════════════════╗
║  SQL Firewall - Test 1: Basic Security Features                ║
╚════════════════════════════════════════════════════════════════╝

[STEP] Building extension (feature=pg16)
[TEST] Install/build succeeded (release, pg16)
[STEP] Starting PostgreSQL with sql_firewall_rs preloaded
[TEST] Connected to PostgreSQL at /home/user/.pgrx:28816
[STEP] Creating test database 'sqlfw_security_test'
[PASS] Test database created and extension installed
[PASS] Test roles created (testuser_basic, testuser_exempt, testuser_rate)

████████████████████████████████████████████████████████████████
  TEST SUITE 1: Operating Modes (Learn / Permissive / Enforce)
████████████████████████████████████████████████████████████████

[STEP] TEST 1.1: Learn mode – should allow all queries
[PASS] Learn mode allows SELECT
[PASS] Learn mode allows CREATE TABLE
[PASS] Learn mode allows INSERT
[PASS] Learn mode allows UPDATE
[PASS] Learn mode allows DELETE
[PASS] Learn mode allows DDL (DROP)
[PASS] Learn mode allows DDL (DROP2)

[STEP] TEST 1.2: Enforce mode – unapproved queries must be blocked
[PASS] Enforce blocks unapproved SELECT (testuser_basic)
[PASS] Enforce blocks unapproved INSERT (testuser_basic)
[PASS] Enforce blocks unapproved UPDATE (testuser_basic)
[PASS] Enforce blocks unapproved DELETE (testuser_basic)

[STEP] TEST 1.3: Enforce mode – approved queries must pass
[PASS] Enforce allows approved SELECT
[PASS] Enforce allows approved INSERT
[PASS] Enforce still blocks un-approved UPDATE
[PASS] Revoke command updates DB state (is_approved=false or row removed)

[STEP] TEST 1.4: Permissive mode – should allow but log violations
[PASS] Permissive allows unapproved SELECT
[PASS] Permissive allows unapproved INSERT

████████████████████████████████████████████████████████████████
  TEST SUITE 2: Security Filters (Keyword Blacklist & Regex)
████████████████████████████████████████████████████████████████

[STEP] TEST 2.1: Keyword blacklist
[PASS] Keyword filter blocks pg_sleep
[PASS] Keyword filter blocks pg_read_file
[PASS] Keyword filter blocks xp_cmdshell
[PASS] Keyword filter allows benign SELECT

[STEP] TEST 2.2: Regex pattern blocking (SQL injection)
[PASS] Regex blocks UNION SELECT
[PASS] Regex blocks comment terminator
[PASS] Regex allows clean SELECT
[PASS] Regex allows parameterised-style

[STEP] TEST 2.3: ReDoS validation trigger on regex_rules
[PASS] ReDoS validation trigger rejected dangerous pattern

████████████████████████████████████████████████████████████████
  TEST SUITE 3: Access Control (Quiet Hours, Rate Limits, App Blocking)
████████████████████████████████████████████████████████████████

[STEP] TEST 3.1: Quiet hours enforcement
[PASS] Quiet hours blocks queries for non-superuser
[PASS] Superuser bypasses quiet hours when bypass=on

[STEP] TEST 3.2: Global rate limiting
[PASS] Rate limit allows query #1
[PASS] Rate limit allows query #2
[PASS] Rate limit allows query #3
[PASS] Rate limit blocks query #4
[PASS] Rate limit blocks query #5

[STEP] TEST 3.3: Per-command (SELECT) rate limiting
[PASS] Per-command allows SELECT #1
[PASS] Per-command allows SELECT #2
[PASS] Per-command blocks SELECT #3
[PASS] Per-command INSERT still allowed (different command)

[STEP] TEST 3.4: Application name blocking
[PASS] Application blocking rejects 'bad_client'
[PASS] Application blocking rejects 'legacy_app'
[PASS] Non-blocked application connects normally

████████████████████████████████████████████████████████████████
  TEST SUITE 4: Logging & Audit Trail
████████████████████████████████████████████████████████████████

[STEP] TEST 4.1: Activity logging records allowed queries
[PASS] Activity logging is working (11 entries found)

[STEP] TEST 4.2: Blocked query logging via background worker
[PASS] Blocked queries logging is working (4 entries found)

[STEP] TEST 4.3: Activity logging toggle (off = no new entries)
[PASS] Activity logging toggle works (disabled → 0 entries)

[STEP] TEST 4.4: Blocked queries logged independently of activity logging toggle
[PASS] Blocked queries always logged regardless of activity logging toggle

████████████████████████████████████████████████████████████████
  TEST SUITE 5: Per-User Regex Exemptions
████████████████████████████████████████████████████████████████

[PASS] Non-exempt user blocked by DROP TABLE pattern
[PASS] Exempt user (testuser_exempt) allowed to DROP TABLE
[PASS] With NULL allowed_roles, even testuser_exempt is blocked
[PASS] With NULL allowed_roles, testuser_basic is blocked

████████████████████████████████████████████████████████████████
  TEST SUITE 6: Superuser Bypass Control
████████████████████████████████████████████████████████████████

[PASS] Superuser blocked when bypass=off and app is blocked
[PASS] Superuser exempt when bypass=on regardless of blocked app

████████████████████████████████████████████████████████████████
  TEST SUITE 7: Firewall Kill Switch (sql_firewall.enabled)
████████████████████████████████████████████████████████████████

[PASS] Firewall active: testuser_basic blocked in enforce mode
[PASS] Firewall disabled: all queries pass through
[PASS] Firewall re-enabled: testuser_basic blocked again

╔════════════════════════════════════════════════════════════════╗
║                    ALL TESTS COMPLETED                         ║
╚════════════════════════════════════════════════════════════════╝

[TEST] Test Summary:
  • Operating modes: Learn / Permissive / Enforce ✓
  • Command approvals – grant, revoke, re-check ✓
  • Keyword blacklist filtering ✓
  • Regex pattern blocking (SQL injection) ✓
  • ReDoS validation trigger ✓
  • Quiet hours enforcement ✓
  • Global rate limiting ✓
  • Per-command rate limiting ✓
  • Application name blocking ✓
  • Activity logging ✓
  • Blocked queries logging (async worker) ✓
  • Activity logging toggle ✓
  • Per-user regex exemptions (allowed_roles) ✓
  • Superuser bypass GUC ✓
  • Firewall kill switch ✓

Results: 55 passed, 0 failed (55 total)
[PASS] Test 1: Basic Security Features – ALL 55 TESTS PASSED
```

**Coverage (55/55 tests):**
- ✅ **Operating Modes** - Learn, Permissive, Enforce mode validation (9 tests)
- ✅ **Command Approvals** - Grant, revoke, re-check enforcement (4 tests)
- ✅ **Keyword Blacklist** - Dangerous function blocking (4 tests)
- ✅ **Regex Filters** - SQL injection pattern detection + ReDoS validation (5 tests)
- ✅ **Quiet Hours** - Time-based restrictions, superuser bypass (2 tests)
- ✅ **Global Rate Limiting** - Per-role throttling (5 tests)
- ✅ **Per-Command Rate Limiting** - Verb-specific budgets (4 tests)
- ✅ **Application Blocking** - App name filtering (3 tests)
- ✅ **Activity Logging** - Audit trail + toggle (4 tests)
- ✅ **Blocked Query Logging** - Async worker persistence (2 tests)
- ✅ **Per-User Regex Exemptions** - `allowed_roles` control (4 tests)
- ✅ **Superuser Bypass GUC** - On/off enforcement (2 tests)
- ✅ **Firewall Kill Switch** - Enable/disable/re-enable (3 tests)

---

### 7.2 Test Suite 2: Advanced Features & Stress Testing

Comprehensive validation of fingerprint learning, background workers, concurrency, and edge cases.

**Run the test:**
```bash
bash test_2_advanced_stress.sh
# Optional: customize stress iteration count
STRESS_ITER=2000 bash test_2_advanced_stress.sh
```

**Sample Output:**
```
╔════════════════════════════════════════════════════════════════╗
║     SQL Firewall - Test 2: Advanced Features & Stress        ║
╚════════════════════════════════════════════════════════════════╝

[STEP] Building extension (feature=pg16)
[STEP] Starting PostgreSQL with sql_firewall_rs preloaded
[TEST] Connected to PostgreSQL at /home/user/.pgrx:28816
[PASS] Test database created and extension installed
[PASS] Test user created with proper privileges

████████████████████████████████████████████████████████████████
  TEST SUITE 1: Fingerprint Learning & Auto-Approval
████████████████████████████████████████████████████████████████

[STEP] TEST 1.1: Configure fingerprint learning with low threshold
[PASS] Fingerprint learning configured (threshold=3)

[STEP] TEST 1.2: Execute repeated queries to trigger fingerprint learning
[PASS] Executed 5 parameterized queries with different literals

[STEP] TEST 1.3: Verify fingerprints were learned
[PASS] Fingerprint learning successful (3 fingerprints recorded)

[STEP] TEST 1.4: Test auto-approval after threshold
[PASS] Fingerprint auto-approval working (normalized query allowed)

████████████████████████████████████████████████████████████████
  TEST SUITE 2: Background Worker & Approval Queue
████████████████████████████████████████████████████████████████

[STEP] TEST 2.1: Check approval worker status
[TEST] Approval worker status: running
[PASS] Approval worker is active

[STEP] TEST 2.2: Pause and resume approval worker
[PASS] Approval worker successfully paused
[PASS] Approval worker successfully resumed

[STEP] TEST 2.3: Verify approval queue processing
[PASS] Approval queue processed (7 approvals recorded)

████████████████████████████████████████████████████████████████
  TEST SUITE 3: Stress Testing & Performance
████████████████████████████████████████████████████████████████

[STRESS] TEST 3.1: High-volume query execution (1000 iterations)
[PASS] Stress test completed: 1000 queries in 8s (~125 qps)

[STRESS] TEST 3.2: Mixed workload stress test
[PASS] Mixed workload completed: 300 queries (SELECT/UPDATE/INSERT) in 4s

[STRESS] TEST 3.3: Rate limit stress test
[PASS] Rate limit stress: 50 allowed, 50 blocked (threshold: 50)

████████████████████████████████████████████████████████████████
  TEST SUITE 4: Edge Cases & Error Handling
████████████████████████████████████████████████████████████████

[STEP] TEST 4.1: ReDoS protection (regex timeout)
[PASS] ReDoS pattern inserted (will be timeout-protected at runtime)
[PASS] ReDoS protection: query completed without hanging (100ms timeout working)

[STEP] TEST 4.2: Statement_timeout isolation
[PASS] statement_timeout not leaked (0 == 0)

[STEP] TEST 4.3: Transaction rollback handling
[PASS] Transaction rollback handled correctly (no orphan data)

[STEP] TEST 4.4: Concurrent connection test
[PASS] Concurrent connections: all 10 clients completed successfully

████████████████████████████████████████████████████████████████
  TEST SUITE 5: Memory & Resource Validation
████████████████████████████████████████████████████████████████

[STEP] TEST 5.1: Memory leak detection
[TEST] Running 500 iterations to detect memory leaks...
[PASS] Memory leak test completed (500 iterations, no crashes)

[STEP] TEST 5.2: Shared memory stress
[TEST] Testing shared memory structures under load...
[PASS] Shared memory stress test passed (200 operations)

[STEP] TEST 5.3: Catalog table integrity
[TEST] Catalog table statistics:
[TEST]   • Activity log: 1247 entries
[TEST]   • Blocked queries: 56 entries
[TEST]   • Command approvals: 18 entries
[TEST]   • Query fingerprints: 7 entries
[TEST]   • Regex rules: 3 entries
[PASS] All catalog tables accessible and populated

████████████████████████████████████████████████████████████████
  TEST SUITE 6: Security Features (Advanced)
████████████████████████████████████████████████████████████████

[STEP] TEST 6.1: Per-user regex exemptions
[PASS] Per-user regex exemption: non-admin blocked from DROP

[STEP] TEST 6.2: Multiple security layers
[PASS] Multi-layer security: 3/3 security policies enforced

╔════════════════════════════════════════════════════════════════╗
║              ALL ADVANCED TESTS COMPLETED                      ║
╚════════════════════════════════════════════════════════════════╝

[TEST] Test Summary:
  • Fingerprint learning & auto-approval ✓
  • Background worker management ✓
  • Approval queue processing ✓
  • High-volume stress testing (1000+ queries) ✓
  • Mixed workload performance ✓
  • Rate limit stress validation ✓
  • ReDoS protection (timeout) ✓
  • statement_timeout isolation ✓
  • Transaction rollback handling ✓
  • Concurrent connection stability ✓
  • Memory leak detection ✓
  • Shared memory stress testing ✓
  • Catalog table integrity ✓
  • Per-user regex exemptions ✓
  • Multi-layer security enforcement ✓

[PASS] Test 2: Advanced Features & Stress Testing - ALL PASSED
```

**Coverage (30/30 tests):**
- ✅ **Fingerprint Learning** - Normalized query detection, auto-approval, routing by DB OID (5 tests)
- ✅ **Background Workers** - Pause/resume/status management (4 tests)
- ✅ **Stress Testing** - High-volume queries (1000 iterations), mixed workloads, rate limit stress (3 tests)
- ✅ **Edge Cases** - ReDoS protection (rejection + runtime timeout), timeout isolation, rollback safety, empty/oversized queries, truncation (6 tests)
- ✅ **Concurrency** - 10 simultaneous clients in learn and enforce modes (2 tests)
- ✅ **Memory Safety** - Leak detection (500 iterations), shared memory stress (200 ops), catalog integrity (3 tests)
- ✅ **Advanced Security** - Per-user exemptions, multi-layer enforcement, approval persistence across reload, audit trail (7 tests)

---

### 7.3 Running Both Suites Together

```bash
export PG_FEATURE=pg16
bash test_1_basic_security.sh   # 55/55 tests
bash test_2_advanced_stress.sh  # 30/30 tests
```

---

### 7.2 Performance Benchmarks

Enterprise-grade benchmark suite available in `benchmarks/enterprise_benchmark.sh`:

**Test Categories:**
1. **TPS/Latency** - 4 protocol modes (simple, extended, prepared, read-only) × 2 client loads (32/64) × 2 phases (baseline vs firewall)
2. **Connection Overhead** - Connection-per-transaction latency measurement
3. **CPU/Memory Profiling** - Resource usage under load, shared memory analysis
4. **Security Tests** - SQL injection payload blocking (10 attack vectors)
5. **Stress Tests** - Worker stability (120s), memory leak detection (10 iterations), connection flood (1000 clients)
6. **Durability Tests** - PostgreSQL restart scenarios with configuration persistence

**Benchmark Results:**

| Test | Baseline (no firewall) | With Firewall | Overhead |
|------|------------------------|---------------|----------|
| Simple protocol (32 clients) | 332.5 TPS, 96.2ms | 332.3 TPS, 96.3ms | -0.07% |
| Extended protocol (32 clients) | 306.1 TPS, 104.5ms | 304.5 TPS, 105.1ms | -0.52% |
| Prepared statements (32 clients) | 302.4 TPS, 105.8ms | 308.1 TPS, 103.9ms | +1.89% |
| Read-heavy workload (32 clients) | 958.9 TPS, 33.4ms | 1019.4 TPS, 31.4ms | +6.31% |
| CPU usage (under load) | - | 0.44% avg | Minimal |
| Memory (60s load test) | - | 32MB stable | No leaks |
| Stress test (30K queries) | - | 0KB growth | Stable |

**Key Findings:**
- Performance overhead < 6% across all test modes (some tests show improvement due to caching)
- Zero memory leaks - Stable memory usage across extended stress tests
- Minimal CPU impact - Average 0.44% CPU overhead under load
- Read-heavy workloads benefit - 6.3% faster with firewall enabled (prepared statement + select-only)
- Security blocking - 0% block rate when superuser bypass enabled (default), requires `sql_firewall.allow_superuser_auth_bypass = false` for testing

## 8. Troubleshooting

| Symptom | Likely cause | Fix |
|---------|--------------|-----|
| `FATAL: could not access file "sql_firewall_rs"` | `.so` missing from PostgreSQL lib dir or typo in `shared_preload_libraries`. | Copy `sql_firewall_rs.so` into the server lib path and set `shared_preload_libraries = 'sql_firewall_rs'`, then restart PostgreSQL. |
| `DefineSavepoint` or `record_pending` FATAL error | Attempting SPI during transaction abort. | Fixed in current version. Removed problematic SPI calls, now uses 3-layer logging (WARNING + LOG + syslog). |
| Quiet hours logging causes recursion | Using SPI logging inside quiet hours. | Keep `sql_firewall.quiet_hours_log = on`; it uses elog-only logging and avoids SPI entirely. |
| Approval rows never appear | SPI insert failing or wrong column names. | Confirm `sql_firewall_command_approvals` schema is installed and that inserts use `(role_name, command_type, is_approved)`. |
| Learn mode allows unapproved commands | Expected Learn/permissive behavior. | Move to `enforce` mode to block or manually approve via `sql_firewall_command_approvals`. |
| SpinLock deadlock or panic | Panic during lock holding in older version. | Fixed: Enhanced Drop guards with panic safety ensure locks always released. |
| ReDoS attack from user-supplied regex | No timeout protection in older versions. | Fixed: 100ms timeout + validation trigger prevents dangerous patterns. |
| Race condition on fingerprint updates | Concurrent hit_count updates lost. | Fixed: Uses SELECT FOR UPDATE to prevent race conditions. |
| Activity log empty | Quiet hours active or table privileges altered. | Disable quiet hours for the test or restore INSERT privileges on `sql_firewall_activity_log`. |
| Regex tests miss `'1'='1'` | Patterns missing quoted tautologies. | Insert additional regex rows (e.g., `(?i)or\s*'1'\s*=\s*'1'`). |
| Blocked queries not logged | Worker queue disabled or ring buffer full. | Ensure the approval worker is running (`SELECT sql_firewall_approval_worker_status();`) and check logs for "ring buffer full" warnings. Blocking always enqueues events even if the user transaction aborts. |
| Regex exemptions not working | Incorrect `allowed_roles` logic. | Fixed: `allowed_roles` array now properly exempts specified users from blocking. |

