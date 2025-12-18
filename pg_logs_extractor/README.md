# POSTGRESQL LOGS EXTRACTOR
## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [How It Works](#how-it-works)
- [Project Structure](#project-structure)
- [Prerequisites](#prerequisites)
- [PostgreSQL Log Source Setup](#postgresql-log-source-setup)
  - [1) Enable logging in `postgresql.conf`](#1-enable-logging-in-postgresqlconf)
  - [Restart PostgreSQL](#restart-postgresql)
  - [2) Path Settings](#2-path-settings)
  - [Option A: Single source (one log directory)](#option-a-single-source-one-log-directory)
  - [Option B: Folder-based multi-source (many nodes under one root)](#option-b-folder-based-multi-source-many-nodes-under-one-root)
- [Destination PostgreSQL Setup](#destination-postgresql-setup)
  - [Tables (DDL)](#tables-ddl)
- [servers.yml Mapping](#serversyml-mapping)
  - [Format](#format)
- [Environment Variables (.env)](#environment-variables-env)
  - [Log input settings](#log-input-settings)
- [Docker Compose Configuration](#docker-compose-configuration)
  - [sincedb directory permissions](#sincedb-directory-permissions)
- [Run & Monitor](#run--monitor)
- [Verification (SQL Checks)](#verification-sql-checks)
  - [Check latest inserts](#check-latest-inserts)
- [Troubleshooting](#troubleshooting)
  - [Logstash cannot read log files](#logstash-cannot-read-log-files)
  - [sincedb errors (ENOENT / permission denied)](#sincedb-errors-enoent--permission-denied)
  - [No data in tables / no new inserts](#no-data-in-tables--no-new-inserts)
  - [servers.yml not found / translate dictionary errors](#serversyml-not-found--translate-dictionary-errors)
- [Security Notes](#security-notes)
## Overview

`pg_logs_extractor` is a Logstash-based pipeline that reads PostgreSQL log files, classifies events (connection events and audit events), parses and normalizes fields, and writes the results into a destination PostgreSQL database via the JDBC output plugin.

It supports both single-source setups (one PostgreSQL instance writing logs into a single directory) and multi-source folder-based setups where each source is represented by a subfolder. In the folder-based mode, the pipeline derives a `server_id` from the log file path and enriches each event with `cluster_name`, `server_name`, and `server_ip` using a `servers.yml` mapping.

## Features

- **PostgreSQL log ingestion via Logstash**: Reads PostgreSQL log files from a mounted directory (supports glob patterns).
- **Event classification**: Routes logs into two categories:
  - `connection_logs` (connection received/authorized, disconnection, authentication failures)
  - `audit_logs` (pgAudit `AUDIT:` entries)
- **Structured parsing & normalization**: Extracts timestamps, user/db/client/app fields, and normalizes `log_time` as `timestamptz`.
- **Noise filtering**: Drops unwanted `ERROR` / `STATEMENT` lines and optional test traffic (e.g., `testuser`, `test` database) to keep datasets clean.
- **Folder-based multi-source support**: Derives `server_id` from the file path and enriches events with `cluster_name`, `server_name`, `server_ip` using `servers.yml`.
- **Config-driven deployment**: Uses `.env` for log paths, destination DB credentials, and sincedb configuration.
- **Docker-first workflow**: Runs as a containerized Logstash service with persistent sincedb state.

## How It Works

1. **File input**  
   Logstash reads PostgreSQL log files from the configured path(s) (`PG_LOG_PATHS`) using the `file` input plugin.

2. **Source identification (optional)**  
   If logs are stored under a folder structure like `/logs/<server_id>/...`, the pipeline extracts `server_id` from the file path.

3. **Metadata enrichment**  
   When `server_id` is available, the pipeline looks it up in `servers.yml` and enriches each event with:
   - `cluster_name`
   - `server_name`
   - `server_ip`

4. **Parsing & routing**  
   Each log line is parsed with `grok` and routed into one of the following:
   - **Connection events** -> `connection_logs`
   - **pgAudit events** (`AUDIT:`) -> `audit_logs`

5. **Write to destination PostgreSQL**  
   Events are inserted into the destination PostgreSQL database using Logstash’s JDBC output plugin (separate inserts per event type).

## Project Structure

```text
pg_logs_extractor/
├─ docker-compose.yml
├─ .env
├─ pipeline/
│  └─ pg.conf
├─ config/
│  └─ servers.yml
├─ sincedb/
│  └─ .gitignore
└─ README.md   
```
## Prerequisites

- **Docker** and **Docker Compose** installed on the host machine
- **Destination PostgreSQL** reachable from the Logstash container (host/network connectivity)
- **PostgreSQL logs enabled** on the source system and readable by the container user
  - The log files must be **world-readable** on the host in most setups (e.g., `chmod 644`)
- A writable local directory for **sincedb** (Logstash read offsets/state)

## PostgreSQL Log Source Setup

This section enables PostgreSQL logging and configures a predictable log format so Logstash can parse it reliably.

### 1) Enable logging in `postgresql.conf`

Edit your `postgresql.conf` (location varies by distro/installation) and set:
```conf
# Activate the built-in logging collector
logging_collector = on

# Log all new connections to the database
log_connections = on

# Log when a client disconnects
log_disconnections = on

# Store logs in the internal "log" directory
log_directory = 'log'

# Log file name pattern — daily rotation by weekday
log_filename = 'postgresql-%a.log'

# Capture all SQL statements for analysis
log_statement = 'all'

# Rotate the log file every 1 day.
log_rotation_age = 1d

# When rotating, overwrite the existing log file for that weekday.
log_truncate_on_rotation = on

# Include useful metadata in each log line
log_line_prefix = '%m [%p] user=%u,db=%d, client_ip=%h app=%a '

# Do not truncate old logs on rotation (keep history)
log_truncate_on_rotation = off

# Load pgaudit and timescaledb extensions at server startup
shared_preload_libraries = 'pgaudit,timescaledb'

# Enable full audit logging (DDL, DML, etc.)
pgaudit.log = 'all'

# Skip catalog object logging (less noise)
pgaudit.log_catalog = off
```
### Restart PostgreSQL

Restart command depends on your OS/service manager. Example (systemd):
```bash
sudo systemctl restart postgresql
```

### 2) Path Settings

This project reads PostgreSQL logs from the host machine by mounting a host directory into the container as `/logs`.

### Option A: Single source (one log directory)

If your PostgreSQL writes logs to a single directory (example: `/var/log/postgresql`), mount that directory and point Logstash to the files:

- **Host logs directory**: `/var/log/postgresql`
- **Container mount point**: `/logs`
- **Log path pattern (inside container)**: `/logs/postgresql-*.log`

### Option B: Folder-based multi-source (many nodes under one root)

If you want to represent multiple PostgreSQL sources under one root directory, use a folder-per-node layout:

```text
<HOST_PG_LOG_DIR>/
├─ pg-01/
│  └─ postgresql-*.log
├─ pg-02/
│  └─ postgresql-*.log
└─ pg-03/
   └─ postgresql-*.log
```
## Destination PostgreSQL Setup

The pipeline writes parsed events into a destination PostgreSQL database (via the Logstash JDBC output).  
Before starting the container, create the required tables on the destination database.

### Tables (DDL)

```sql
-- Connection events
CREATE TABLE IF NOT EXISTS connection_logs (
  id               BIGSERIAL PRIMARY KEY,
  log_time         TIMESTAMPTZ NOT NULL,
  username         TEXT,
  database_name    TEXT,
  client_ip        TEXT,
  action           TEXT,
  cluster_name     TEXT,
  server_name      TEXT,
  server_ip        TEXT,
  application_name TEXT
);

-- Audit events (pgAudit)
CREATE TABLE IF NOT EXISTS audit_logs (
  id               BIGSERIAL PRIMARY KEY,
  log_time         TIMESTAMPTZ NOT NULL,
  username         TEXT,
  database_name    TEXT,
  session_id       TEXT,
  statement_id     TEXT,
  audit_type       TEXT,
  statement_text   TEXT,
  command          TEXT,
  object_type      TEXT,
  object_name      TEXT,
  cluster_name     TEXT,
  server_name      TEXT,
  server_ip        TEXT,
  client_ip        TEXT,
  application_name TEXT
);
```   
## servers.yml Mapping

`config/servers.yml` is used to enrich events with `cluster_name`, `server_name`, and `server_ip` based on `server_id` derived from the log file path.

### Format

- **Key**: `server_id` (folder name, e.g. `pg-01`)
- **Value**: JSON string containing metadata fields

```yaml
pg-01: '{"cluster_name":"prod-pg","server_name":"pg-01","server_ip":"10.0.10.11"}'

# Uncomment / duplicate as needed
# pg-02: '{"cluster_name":"prod-pg","server_name":"pg-02","server_ip":"10.0.10.12"}'
# pg-03: '{"cluster_name":"prod-pg","server_name":"pg-03","server_ip":"10.0.10.13"}'

# Single-source example:
# If your logs are read from a path like /logs/postgresql/postgresql-*.log,
# you can use "postgresql" as the server_id.
postgresql: '{"cluster_name":"prod-pg","server_name":"postgresql","server_ip":"10.0.10.11"}'
```
## Environment Variables (.env)

Create a `.env` file in the project root and fill in the variables below.

### Log input settings

```dotenv
# Host directory that contains PostgreSQL logs (mounted into the container)
HOST_PG_LOG_DIR=/srv/pg-logs

# Logstash file input paths (JSON array)
# Multi-source (folder-based):
PG_LOG_PATHS=["/logs/*/postgresql-*.log"]

# Single-source example (mounted under /logs/postgresql):
# PG_LOG_PATHS=["/logs/postgresql/postgresql-*.log"]

# sincedb (state file for file input)
SINCEDB_PATH=/usr/share/logstash/sincedb/sincedb-pg
# Postgresql Destination 
PG_HOST=127.0.0.1
PG_PORT=5432
PG_DB=system_logs
PG_USER=postgres
PG_PASS=postgres

# JDBC driver path inside the container
JDBC_JAR=/usr/share/logstash/logstash-core/lib/jars/postgresql-42.7.8.jar
```
## Docker Compose Configuration

The project runs Logstash as a Docker container and mounts logs, pipeline config, sincedb state, and `servers.yml`.

```yaml
services:
  logstash:
    build: .
    image: pg_logs_extractor
    container_name: pg_logs_extractor
    env_file:
      - .env
    volumes:
      - ${HOST_PG_LOG_DIR}:/logs:ro
      - ./pipeline:/usr/share/logstash/pipeline:ro
      - ./sincedb:/usr/share/logstash/sincedb
      - ./config/servers.yml:/usr/share/logstash/extra/servers.yml:ro
    ports:
      - "5044:5044"
      - "9600:9600"
    restart: unless-stopped
```
### sincedb directory permissions

Create the sincedb directory and ensure it is writable by the container:
```bash
mkdir -p sincedb
sudo chown -R 1000:1000 sincedb
```
## Run & Monitor

Start the service:

```bash
docker compose up -d --build
```
Follow logs:
```bash
docker logs -f pg_logs_extractor
```

## Verification (SQL Checks)

Run the queries below on the **destination PostgreSQL** to confirm that the pipeline is inserting rows.

### Check latest inserts

```sql
SELECT * FROM connection_logs ORDER BY id DESC LIMIT 20;
SELECT * FROM audit_logs      ORDER BY id DESC LIMIT 20;
```

## Troubleshooting

### Logstash cannot read log files

- Ensure the host log files are readable by the container.

- Common fix (adjust the path to your setup):

```bash

sudo chmod 644 /var/log/postgresql/postgresql-\*.log
```
### sincedb errors (ENOENT / permission denied)

- Make sure the sincedb directory exists and is writable by the container:

```bash
mkdir -p sincedb
sudo chown -R 1000:1000 sincedb
```
### No data in tables / no new inserts

- Check container logs:

```bash
docker logs -f pg\_logs\_extractor
```
- Verify .env paths match the container paths:

  - PG_LOG_PATHS must reference paths inside the container (typically under /logs/...).

### servers.yml not found / translate dictionary errors

- Ensure config/servers.yml exists on the host.

- Ensure it is mounted correctly in docker-compose.yml:

```yaml
- ./config/servers.yml:/usr/share/logstash/extra/servers.yml:ro
```
## Security Notes

- **Do not commit secrets**: never push your `.env` file if it contains database credentials.
- **Limit file permissions**: make log files readable for the container, but avoid overly permissive settings beyond what is required.
- **Network exposure**: only expose required ports. If you do not need them externally, bind to localhost or remove port mappings.
- **Database permissions**: use a dedicated PostgreSQL user with the minimum required privileges (INSERT on target tables).
- **Protect `servers.yml`**: it may contain internal IPs and topology information; treat it as sensitive configuration.
