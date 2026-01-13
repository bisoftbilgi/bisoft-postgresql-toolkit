# Password Profile

Enterprise‑grade password policy and authentication hardening for PostgreSQL.  
Built with Rust + pgrx (v0.16.1). Tested primarily on PostgreSQL 16 and compatible with 14–15.

## 1. Why This Extension?

- Enforces strong password rules (length, complexity, blacklist, username checks).
- Blocks hash‑bypass attempts (`md5...`, bcrypt, SCRAM, argon2, etc.).
- Tracks failed logins in real time, locks accounts after N attempts, and clears counters on success.
- Includes password history, expiry, and grace login support.
- Ships with a background worker, shared‑memory lock cache, and auth ring buffer to avoid nested SPI or crash scenarios.
- Designed for production: no logging of usernames/passwords, no SPI calls during `_PG_init`, and parametrised SQL everywhere.

## 2. Architecture Overview

| Component | Purpose |
|-----------|---------|
| `client_auth_hook` (C shim) | Hooks PostgreSQL authentication, inspects SQLSTATE, enqueues auth events without nested SPI. |
| Auth Event Ring (shared memory) | Lock‑free producer/consumer queue between backend and worker. |
| Background Worker (`auth_event_consumer`) | Runs SPI transactions to update tables, apply lockouts, and sync shared cache. |
| Lock Cache (shared memory) | O(1) lookups for hot lockout decisions; mirrors DB state with LRU eviction. |
| Blacklist Cache | SipHash13 over bundled/common passwords; binary search for constant latency. |
| SQL API | Functions for password checks, lock management, stats, and history. |

The extension is transparent to applications. Regular logins go through PostgreSQL as usual; policy checks and lock decisions happen behind the scenes.

## 3. Requirements

- PostgreSQL 16 (preferred), 15 or 14.
- Server compiled with development headers (`postgresqlXX-devel`).
- Rust toolchain ≥ 1.70 with `cargo-pgrx 0.16.1`.
- Ability to add the extension to `shared_preload_libraries`.

## 4. Build & Install

```bash
# Install cargo-pgrx if needed
cargo install --locked cargo-pgrx --version 0.16.1

# Initialise pgrx for your pg_config
cargo pgrx init --pg16 /usr/pgsql-16/bin/pg_config

# Package the extension
cargo pgrx package --pg-config /usr/pgsql-16/bin/pg_config

# Copy artifacts into PostgreSQL
sudo cp -r target/release/password_profile-pg16/usr/pgsql-16/* /usr/pgsql-16/

# Copy blacklist file to PGDATA directory
sudo cp blacklist.txt /var/lib/pgsql/16/data/password_profile_blacklist.txt
sudo chown postgres:postgres /var/lib/pgsql/16/data/password_profile_blacklist.txt

# Enable in postgresql.conf
echo \"shared_preload_libraries = 'password_profile'\" | sudo tee -a /var/lib/pgsql/16/data/postgresql.conf
sudo systemctl restart postgresql-16

# Create in each database where you need it
psql -d mydb -c \"CREATE EXTENSION password_profile;\"
psql -d mydb -c \"SELECT init_login_attempts_table();\"

# Load common password blacklist (10,000+ entries)
psql -d mydb -c \"SELECT load_blacklist_from_file(NULL);\"
```

Repeat for pg15/pg14 by pointing `cargo pgrx package` to the corresponding `pg_config`.

## 5. Configuration (GUCs)

All GUCs live under `password_profile.*`. They can be set globally (`postgresql.conf`, `ALTER SYSTEM`) or per role/database (`ALTER ROLE ... SET`).

| GUC | Default | Description |
|-----|---------|-------------|
| `min_length` | 8 | Minimum password length. |
| `require_uppercase` / `require_lowercase` / `require_digit` / `require_special` | false | Enable specific complexity rules. |
| `prevent_username` | true | Reject passwords containing the username (case‑insensitive). |
| `password_history_count` | 5 | Number of historical passwords to remember (0 disables). |
| `password_reuse_days` | 90 | Minimum days before reuse (0 disables). |
| `password_expiry_days` | 90 | Force change after N days (0 disables). |
| `password_grace_logins` | 3 | Allowed logins after expiry. |
| `failed_login_max` | 3 | Failed attempts before lockout. |
| `lockout_minutes` | 2 | Lock duration. |
| `bcrypt_cost` | 10 | BCrypt cost (4–31). |
| `bypass_password_profile` | false | Per‑role bypass flag (use `ALTER ROLE ... SET`). |

Changes take effect immediately; no restart is required after shared_preload_libraries is set.

## 6. SQL API Cheatsheet

| Function | Description |
|----------|-------------|
| `check_password(username, password)` | Validates password during CREATE/ALTER ROLE or manually (returns informative text). |
| `record_password_change(username, password)` | Stores bcrypt hash and updates expiry metadata. |
| `record_failed_login(username)` | Increments counters, applies lockout if needed (used by worker). |
| `clear_login_attempts(username)` | Superuser/user resets lock counters. |
| `is_user_locked(username)` | Boolean lock status. |
| `check_user_access(username)` | Returns error message if locked; otherwise “Access granted”. |
| `check_password_expiry(username)` | Indicates expiry/grace status. |
| `add_to_blacklist(password[, reason])`, `remove_from_blacklist(password)` | Manage dynamic blacklist entries. |
| `load_blacklist_from_file([file_path])` | Load common passwords from file (default: PGDATA/password_profile_blacklist.txt). |
| `get_password_stats(username)` | Aggregated history/expiry/fail info. |
| `get_lock_cache_stats()` | Shared cache metrics for monitoring. |

Tables created under `password_profile.*` keep login attempts, password history, expiry data, and admin‑managed blacklist entries.

## 7. Operations & Integration

### Common Tasks

```sql
-- Enable bypass for a maintenance account
ALTER ROLE maint SET password_profile.bypass_password_profile = true;

-- Unlock a user
SELECT clear_login_attempts('alice');

-- Audit recent failures
SELECT username, fail_count, last_fail
FROM password_profile.login_attempts
ORDER BY last_fail DESC LIMIT 20;
```

### Web UI / Control Plane Integration

Your management plane only needs to issue SQL and GUC commands:

1. Toggle policies per role/database via `ALTER ROLE ... SET password_profile.*`.
2. Expose admin actions (unlock user, set expiry) by calling the provided SQL functions.
3. Display statistics by querying `password_profile.*` tables or `get_lock_cache_stats()`.

No additional APIs are required; everything routes through standard PostgreSQL connections.

## 8. Testing & Observability

- `cargo build` ensures the Rust layer compiles and macros are generated for IDEs.
- `cargo pgrx test pg16` must run inside an environment where PostgreSQL can load the extension (shared_preload_libraries). In stripped CI containers the link step may fail because PG symbols are absent; run tests on a real PostgreSQL instance.
- Monitoring queries:
  ```sql
  SELECT * FROM get_lock_cache_stats();
  SELECT * FROM password_profile.login_attempts WHERE lockout_until > now();
  SELECT dropped FROM password_profile.auth_event_ring; -- ring buffer health
  ```
- Logs include informative `password_profile:` lines; usernames are never printed.

## 9. Troubleshooting

| Symptom | Check / Fix |
|---------|-------------|
| Extension fails to load | Ensure `.so` copied into server libdir and `shared_preload_libraries` contains `password_profile`. |
| Background worker missing | `SELECT * FROM pg_stat_activity WHERE backend_type LIKE 'password_profile%';` and confirm shared_preload_libraries + restart. |
| Auth events unprocessed | Inspect `dropped` counter in auth ring; if constantly rising, increase ring size and rebuild. |
| Lock cache misses | `get_lock_cache_stats()` – if utilisation near 100%, bump `LOCK_CACHE_SIZE` constant and recompile. |
| proc-macro errors in IDE | Run `cargo build` so `libpgrx_macros-*.so` exists in `target/debug/deps`. |
