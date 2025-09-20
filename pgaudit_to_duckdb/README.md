# pg_audit_to_duckdb 🦆

Ingest PostgreSQL **csvlog** files (with **pg_audit**) into **DuckDB**—safely, repeatedly, and fast.

- Reads completed log files from a directory (skips the newest/active file by default).
- Handles **multiline** pg_audit records via DuckDB’s CSV reader options.
- Idempotent: **ANTI JOIN** + **unique index** prevents duplicates.
- Stores per-file `(mtime, size)` to skip unchanged files.
- Runs once and exits (cron-friendly). Config + log live **next to the script**.

---

## Table of Contents

- [Quick start](#quick-start)
- [Requirements](#requirements)
- [PostgreSQL configuration](#postgresql-configuration)
- [Configuration](#configuration)
- [Usage](#usage)
  - [Directory mode](#directory-mode)
  - [Single-file mode](#single-file-mode)
- [Scheduling (cron)](#scheduling-cron)
- [How it avoids duplicates](#how-it-avoids-duplicates)
- [Change detection](#change-detection)
- [DuckDB schema](#duckdb-schema)
- [Troubleshooting](#troubleshooting)
- [Known limitations](#known-limitations)

---

## Quick start




```bash

### OS-specific notes (Rocky Linux 8)
sudo dnf install python3.12 python3.12-pip.noarch python3.12-pip-wheel.noarch

# After installing Python 3.12 to your Rocky Linux run this command
sudo alternatives --config python3 # and choose Python3.12 from the interactive prompt

# Dependencies (Python 3.9+)
pip install duckdb

# First run creates a config & a log file beside the script
python3 pg_audit_to_duckdb.py

# Edit ./pg_audit_to_duckdb.conf as needed, then run again
python3 pg_audit_to_duckdb.py
```

#### ❗Be sure to edit configuration file after the first run. 

---

## Requirements

- Python **3.9+**
- `duckdb` Python package
- PostgreSQL **csvlog** enabled and **pg_audit** producing `AUDIT:` lines
- Read access to `log_dir`; write access to `db_path` and the script directory (for config/log)

---

## PostgreSQL configuration

To make sure pg_audit events land in CSV logs the script can read, set (or confirm) the following in `postgresql.conf` and reload PostgreSQL:

```conf
# Enable CSV logging
logging_collector = on
log_destination = 'csvlog'




# Optional but recommended rotation
log_filename = 'postgresql-%Y-%m-%d'        # or include time if you prefer
log_rotation_age = '1d'                          # rotate daily
log_rotation_size = '100MB'                      # or your size threshold

# pgAudit
shared_preload_libraries = 'pgaudit'             # requires restart if changed
pgaudit.log = 'read,write,ddl,role,privilege'    # adjust to your policy
pgaudit.log_catalog = off                        # typical default

# (Optional) If there are problems with ingesting records please use this prefix
log_line_prefix = '%t [%p]: [%l-1] user=%u,db=%d,app=%a,client=%h'
```

---

## Configuration

On first run, the script creates `./pg_audit_to_duckdb.conf` next to the script.

```ini
# ./pg_audit_to_duckdb.conf
[pg_audit_to_duckdb]
db_path = /path/to/pgsql.duckdb
log_dir = /path/to/pgsql_logs
file_glob = postgresql_*.csv
skip_newest = true
force_reprocess = false
message_prefix = AUDIT:%          ; only ingest lines starting with this prefix
log_file = ./pg_audit_to_duckdb.log
log_level = INFO
```

**Key options**
- `log_dir` — directory with PostgreSQL CSV logs.
- `file_glob` — filename pattern. If rotation appends suffixes (e.g. `.1`), use `postgresql_*.csv*`.
- `skip_newest` — `true` skips the currently written file (recommended).
- `force_reprocess` — `true` deletes and re-ingests selected files (use sparingly).
- `message_prefix` — filter to pg_audit lines (default `AUDIT:%`).
- `db_path` — DuckDB database file.
- `log_file`, `log_level` — script’s own logging.

> The config parser supports inline comments (`#`, `;`) and **disables interpolation**, so `%` in `AUDIT:%` is safe.

---

## Usage

### Directory mode

Runs once and exits (ideal for cron/systemd):

```bash
python3 pg_audit_to_duckdb.py
```

What it does:
1. Ensures DuckDB schema exists.
2. Registers `log_dir` (assigns internal `log_path_id`).
3. Finds files by `file_glob`, sorts by mtime, **skips newest** (by default).
4. Skips files whose `(mtime, size)` is unchanged since the last run.
5. Reads each selected file fully and inserts only rows not already present.

### Single-file mode

Handy for ad-hoc or backfill:

```bash
python3 pg_audit_to_duckdb.py --file /path/to/postgresql_2025-08-29.csv
python3 pg_audit_to_duckdb.py --file /path/to/file.csv --db /path/to/other.duckdb --force
```

`--force` deletes existing rows for that `(log_path_id, file_name)` before ingest.

---

## Scheduling (cron)

Run every 12 hours with a simple lock:

```cron
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

# every 12 hours
0 */12 * * * flock -n /tmp/pg_audit_to_duckdb.lock \
  python3 /path/to/pg_audit_to_duckdb.py
```

The script logs to `./pg_audit_to_duckdb.log` (script directory). Adjust paths as needed.

---

## How it avoids duplicates

- Unique index on `(log_path_id, session_id, session_line_num)`:

```sql
CREATE UNIQUE INDEX IF NOT EXISTS ux_audit_unique
ON audit_logs (log_path_id, session_id, session_line_num);
```

- Each ingest uses an **ANTI JOIN** against `audit_logs` with those keys, so repeated runs are **idempotent**.

---

## Change detection

The script remembers per-file metadata in `log_summary`:

```text
(log_path_id, file_name, last_mtime, last_size)
```

If a file’s `(mtime, size)` hasn’t changed since last time, the script **skips** it entirely.

---

## DuckDB schema

```sql
-- Registered log directories
CREATE TABLE IF NOT EXISTS log_paths (
  id   INTEGER PRIMARY KEY NOT NULL DEFAULT nextval('log_path_id_seq'),
  path VARCHAR UNIQUE
);

-- Per-file change detection
CREATE TABLE IF NOT EXISTS log_summary (
  log_path_id INTEGER,
  file_name   VARCHAR,
  last_mtime  DOUBLE,
  last_size   BIGINT,
  PRIMARY KEY (log_path_id, file_name),
  FOREIGN KEY (log_path_id) REFERENCES log_paths(id)
);

-- Ingested audit events (subset of pg_audit columns)
CREATE TABLE IF NOT EXISTS audit_logs (
  log_time         TIMESTAMP,
  user_name        VARCHAR,
  database_name    VARCHAR,
  client_addr      VARCHAR,
  message          VARCHAR,
  application_name VARCHAR,
  session_id       VARCHAR,
  session_line_num INT,
  log_path_id      INTEGER,
  file_name        VARCHAR,
  FOREIGN KEY (log_path_id) REFERENCES log_paths(id)
);

CREATE UNIQUE INDEX IF NOT EXISTS ux_audit_unique
ON audit_logs (log_path_id, session_id, session_line_num);
```

---

## Troubleshooting

- **`duckdb` not installed**  
  `pip install duckdb`
  • If duckdb can't be installed please check `python3 --version && pip3 --version` and make sure it is 3.9 or newer

- **Permission errors**  
  Ensure the running user can:  
  • read `log_dir`  
  • create/write `db_path`  
  • create/write in the script directory (for the config and the log)

- **Which config/log is used?**  
  The script logs the paths at startup:
  ```
  Config file: /path/to/pg_audit_to_duckdb.conf
  Log dir    : /var/lib/pgsql/data/log
  DB Path    : /srv/samba/duck/pgsql_logs.duckdb
  ```

- **Nothing ingested**  
  - Make sure your PostgreSQL logs actually include `AUDIT:` entries (or update message_prefix). If “pgAudit Log to File” is enabled, turn it off; its output format doesn’t match the CSV schema this script expects.
  - Confirm `file_glob` matches your rotated file names.  
  - Remember the newest file is skipped by default.

---

## Known limitations

- Expects **plain CSV** files. Compressed logs are not read.
- Extremely malformed CSV lines may be skipped (`ignore_errors=TRUE` is used to keep ingestion robust).
- If `copytruncate` is used and `skip_newest=true`, the very latest tail at rotation time may be missed.

---
