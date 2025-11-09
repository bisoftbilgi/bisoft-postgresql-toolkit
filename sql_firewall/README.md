# SQL Firewall (PostgreSQL 16)

`sql_firewall` is a PostgreSQL 16 extension written entirely in Rust (pgrx) that evaluates every SQL command before the backend executes it. The extension enforces least-privilege policies via multi-mode approvals, keyword and regex bans, quiet hours, shared-memory rate limiting, adaptive fingerprint learning, activity logging, and optional alerting—without any external service.

---
## 1. Architecture

| Layer | Role | Details |
|-------|------|---------|
| **Hook Layer** | `ExecutorStart_hook`, `ProcessUtility_hook` | Captures every query/utility command, collects metadata, and short-circuits execution using `ereport!` when a policy fails. |
| **Context Capture** | `sql_firewall_rs::context` | Resolves role, database, application name, client IP, and command tags for policy and logging decisions. |
| **Policy Engine** | `firewall.rs`, `spi_checks.rs` | Applies quiet hours, keyword/regex filters, connection policies, approvals, fingerprints, rate limits, and alert routing. All SPI use is wrapped in guards that ensure a transaction context. |
| **Shared Memory** | `fingerprint_cache`, `rate_state` | Cross-backend caches that track normalized query fingerprints and rate-limit counters without SPI. |
| **Catalog Tables** | `sql_firewall_activity_log`, `sql_firewall_command_approvals`, `sql_firewall_query_fingerprints`, `sql_firewall_regex_rules` | Persist audit records, approvals, fingerprint metadata, and regex rules (installed via `sql/firewall_schema.sql`). |
| **Alerting** | `alerts.rs` | Optional `NOTIFY` + syslog payloads whenever a block happens (regex, keyword, quiet hours, rate limit, approvals). |
| **Tooling** | `run_tests.sh`, `test_full_features.sh` | Idempotent test harnesses that provision a throwaway DB and validate the entire feature matrix (currently 12/12 passing). |

All policy decisions happen synchronously inside the backend, so blocks are atomic and crash-safe.

---
## 2. Feature Summary

- **Operating modes** – `learn`, `permissive`, `enforce` determine how unknown commands are handled.
- **Command approvals** – encounters of `(role_name, command_type)` create rows in `sql_firewall_command_approvals`; DBAs toggle `is_approved`.
- **Adaptive fingerprints** – normalized SQL fingerprints live in shared memory and `sql_firewall_query_fingerprints`, auto-approving patterns after a hit threshold.
- **Shared-memory rate limits** – global per-role window plus verb-specific budgets (SELECT/INSERT/UPDATE/DELETE) served from shared memory.
- **Regex & keyword filters** – case-insensitive keyword blacklist and regex patterns stored in `sql_firewall_regex_rules`.
- **Quiet hours** – blackout window for non-superusers with optional WARNING logging (no SPI) to prevent recursion loops.
- **Activity logging** – every allowed/blocked event (outside quiet hours) is written to `sql_firewall_activity_log` with role, db, query sample, reason.
- **Connection policies** – block by `application_name`, client IPs, or enforce `role@ip` bindings.
- **Alert channels** – NOTIFY payloads + optional syslog mirroring for SIEM integration.
- **Retention jobs** – background pruning keeps activity and fingerprint tables within age/row targets.

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
| **Approvals & Fingerprints** | `sql_firewall.enable_fingerprint_learning` | `on` | Toggle adaptive fingerprint approvals. |
| | `sql_firewall.fingerprint_learn_threshold` | `5` | Hits required to auto-approve a fingerprint. |
| **Keyword / Regex** | `sql_firewall.enable_keyword_scan` | `off` | Keyword blacklist switch. |
| | `sql_firewall.blacklisted_keywords` | `drop,truncate` | Comma-separated list. |
| | `sql_firewall.enable_regex_scan` | `on` | Evaluate `sql_firewall_regex_rules`. |
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
1. **Learn** – allow everything but capture `(role_name, command_type)` with `is_approved=false`.
2. **Review** – admins query `sql_firewall_command_approvals`, optionally compare against fingerprints, and flip `is_approved=true` for legitimate operations.
3. **Enforce** – unknown or unapproved commands are blocked with `ERRCODE_INSUFFICIENT_PRIVILEGE`. `permissive` mode is available for staging: it logs pending approvals but does not block.

### 6.2 Fingerprint Pipeline
- Every query is normalized (literals stripped, whitespace collapsed) and hashed.
- Shared-memory counters track frequency without SPI.
- Crossing `sql_firewall.fingerprint_learn_threshold` marks the fingerprint approved and writes metadata to `sql_firewall_query_fingerprints` so future backends also trust it.

### 6.3 Quiet Hours
- Enable via `sql_firewall.enable_quiet_hours = on` and define start/end times.
- Non-superusers are blocked; superusers bypass automatically.
- Optional WARNING logging via `sql_firewall.quiet_hours_log = on` records the role, db, command, and sample without touching SPI (prevents infinite loop bugs discovered during testing).

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

Run the bundled suite before every release:

```bash
cd sql_firewall
bash run_tests.sh
```

Coverage today (12/12):
- Database + extension provisioning
- Learn → enforce → approval path
- Regex filter against classic `'1'='1'` payloads
- Keyword blacklist toggles
- Quiet hours (blocking, logging, superuser bypass)
- Global and command-specific rate limits
- Activity logging validation
- Superuser bypass sanity

`test_full_features.sh` provides a slimmer smoke test if you only need approvals/regex/quiet hours regression. Both scripts are idempotent and safe to rerun.

---
## 8. Troubleshooting

| Symptom | Likely cause | Fix |
|---------|--------------|-----|
| `FATAL: could not access file "sql_firewall"` | `.so` missing from PostgreSQL lib dir or typo in `shared_preload_libraries`. | Copy `libsql_firewall_rs.so` into the server lib path and double-check the conf entry, then restart PostgreSQL. |
| Quiet hours logging causes recursion | Using SPI logging inside quiet hours. | Keep `sql_firewall.quiet_hours_log = on`; it uses elog-only logging and avoids SPI entirely. |
| Approval rows never appear | SPI insert failing or wrong column names. | Confirm `sql_firewall_command_approvals` schema is installed and that inserts use `(role_name, command_type, is_approved)`. |
| `approval lookup failed: SpiTupleTable positioned before the start` | SPI used outside a transaction. | Use the provided `Spi::connect` helper or wrap manual SPI in `StartTransactionCommand()` / `CommitTransactionCommand()`. |
| Activity log empty | Quiet hours active or table privileges altered. | Disable quiet hours for the test or restore INSERT privileges on `sql_firewall_activity_log`. |
| Regex tests miss `'1'='1'` | Patterns missing quoted tautologies. | Insert additional regex rows (e.g., `(?i)or\s*'1'\s*=\s*'1'`). |

If problems persist, capture PostgreSQL logs plus `run_tests.sh` output when filing an issue.

