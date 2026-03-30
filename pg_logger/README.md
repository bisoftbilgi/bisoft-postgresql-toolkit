# PostgreSQL Log Exporter (Parquet, PostgreSQL, MySQL, MariaDB)

This project tails PostgreSQL log files, parses log entries, and exports them in batches to:

- Parquet files
- a PostgreSQL table
- a MySQL/MariaDB table

The export target is selected from `config.toml`.

## Features

- Continuous tailing of `postgresql log` files
- Offset tracking with `sincedb` files
- Handles truncated/rotated logs
- Batch-based export (`flush_interval_secs`, `batch_size`)
- Config-driven output mode:
  - `parquet`
  - `postgresql` / `postgres`
  - `mysql` / `mariadb`
- Auto-creates destination SQL table if it does not exist
- Adds `hostname` and `ip` from config to every exported record

## Project Structure

- `src/main.rs`: Main application logic (tailing, parsing, batching, exporting)
- `config.toml`: Runtime configuration
- `sincedb/`: File offsets for each tailed log file
- `output/`: Generated parquet files (when `output_mode = "parquet"`)

## Requirements

- Rust toolchain (stable)
- Cargo
- Optional: PostgreSQL server (for `output_mode = "postgresql"`)
- Optional: MySQL or MariaDB server (for `output_mode = "mysql"` or `output_mode = "mariadb"`)

## Installation

1. Clone the repository.
2. Enter the project folder.
3. Ensure `config.toml` is configured for your environment.

## Build

```bash
cargo build --release
```

## Run

```bash
cargo run --release
```

## Docker Build and Run

Build image from project root:

```bash
docker build -t pg-log-exporter:latest .
```

Run container (mount logs, config, output, and sincedb):

```bash
docker run --rm \
  -v "$(pwd)/config.toml:/app/config.toml:ro" \
  -v "$(pwd)/sincedb:/app/sincedb" \
  -v "$(pwd)/output:/app/output" \
  -v "/var/log/postgresql:/var/log/postgresql:ro" \
  pg-log-exporter:latest
```

Windows PowerShell example:

```powershell
docker run --rm `
  -v "${PWD}/config.toml:/app/config.toml:ro" `
  -v "${PWD}/sincedb:/app/sincedb" `
  -v "${PWD}/output:/app/output" `
  -v "C:/path/to/postgresql/logs:/var/log/postgresql:ro" `
  pg-log-exporter:latest
```

Note:

- The current `Dockerfile` copies/runs a binary named `pg_rust_logger`.
- If your package binary name is different, update `COPY --from=builder ...` and `CMD` in `Dockerfile` accordingly.

## Configuration (`config.toml`)

Example:

```toml
# Export target: parquet | postgresql | mysql | mariadb
output_mode = "postgresql"

# Used when output_mode is postgresql/mysql/mariadb
db_url = "postgres://postgres:password@localhost:5432/logs_db"
db_table = "postgres_logs"
hostname = "postgres-node-1"
ip = "192.168.1.10"

# Batch settings
flush_interval_secs = 10
batch_size = 1000
```

Example MySQL/MariaDB URL:

```toml
db_url = "mysql://user:password@localhost:3306/logs_db"
```

### Fields

- `output_mode`: `parquet`, `postgresql` (`postgres`), `mysql`, or `mariadb`
- `db_url`: Database connection string (required for PostgreSQL/MySQL/MariaDB modes)
- `db_table`: Destination table name (`postgres_logs` by default)
- `hostname`: Host label added to each log record
- `ip`: IP label added to each log record
- `flush_interval_secs`: Flush interval in seconds
- `batch_size`: Number of buffered records before immediate flush

## Parsing Logic

The parser expects PostgreSQL log lines containing:

- timestamp
- `user=...`
- `db=...`
- `LOG: ...`

Multi-line log messages are merged into a single record until the next timestamp-prefixed line is seen.

## Export Logic

### Parquet mode

- Buffers records in memory
- Flushes by interval or batch size
- Writes parquet files to:
  - `./output/<year>/<month>/<day>/common_logs_<HHMMSS>.parquet`

### PostgreSQL mode

- Creates a DB pool from `db_url`
- Ensures destination table exists (`CREATE TABLE IF NOT EXISTS`)
- Inserts buffered records in a transaction
- Table columns:
  - `log_timestamp`
  - `user_name`
  - `database_name`
  - `hostname`
  - `ip_address`
  - `message`
  - `inserted_at`

### MySQL / MariaDB mode

- Creates a DB pool from `db_url`
- Ensures destination table exists (`CREATE TABLE IF NOT EXISTS`)
- Inserts buffered records in a transaction
- Table columns:
  - `log_timestamp`
  - `user_name`
  - `database_name`
  - `hostname`
  - `ip_address`
  - `message`
  - `inserted_at`

## Offset Tracking (`sincedb`)

For each tailed file, the current byte offset is stored in:

- `./sincedb/<logfilename>.offset`

On restart, reading resumes from the saved offset.
If a file is truncated, offset resets to `0`.

## Notes

- If `output_mode = "postgresql"`, `mysql`, or `mariadb` and `db_url` is missing, the app exits with an error.
- `db_table` must match `[A-Za-z_][A-Za-z0-9_]*`.
- Ensure the DB user has table create/insert permissions.
