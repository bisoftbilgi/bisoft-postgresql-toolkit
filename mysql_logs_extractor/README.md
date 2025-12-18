# MySQL Logs Extractor

![Logstash](https://img.shields.io/badge/Logstash-8.x-005571?logo=elastic&logoColor=white)
![MySQL](https://img.shields.io/badge/MySQL-8.0+-4479A1?logo=mysql&logoColor=white)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-13+-336791?logo=postgresql&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?logo=docker&logoColor=white)

A production-ready pipeline that ingests **MySQL General Query Logs (Audit)** and **Slow Query Logs**, parses them with **Logstash**, enriches events with host metadata, and writes structured records into **PostgreSQL** for audit & performance analytics.

---

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Project Structure](#project-structure)
- [Prerequisites](#prerequisites)
- [MySQL Source Configuration](#mysql-source-configuration)
- [PostgreSQL Destination Setup (Tables)](#postgresql-destination-setup-tables)
- [servers.yml Mapping (Host Metadata Enrichment)](#serversyml-mapping-host-metadata-enrichment)
- [Environment Variables (.env)](#environment-variables-env)
- [Docker Compose Configuration](#docker-compose-configuration)
- [Run & Monitor](#run--monitor)
- [Verification (SQL Checks)](#verification-sql-checks)
- [Important Architecture Note (pipeline.workers=1)](#important-architecture-note-pipelineworkers1)
- [Troubleshooting](#troubleshooting)
- [Security Notes](#security-notes)

---

## Overview

This project provides a robust log pipeline for collecting, parsing, and analyzing MySQL activity:

- **General/Audit Log** → connection events, audit trail (DDL/DML/DCL/SHOW), session correlation
- **Slow Query Log** → query_time, lock_time, rows_examined-like metrics (depending on MySQL format), and slow statements

Parsed events are stored in **PostgreSQL** so you can query history, build dashboards, and do incident/performance investigations.

---

## Features

- **Full Audit Trail:** captures `Connect`, `Query`, `Quit`, `Access Denied` events
- **Session Tracking:** correlates sessions via Logstash `aggregate` filter
- **Smart Parsing:**
  - query classification (`DDL`, `DML`, `DCL`, `TCL`, `SHOW`, etc.)
  - table/object extraction where possible
  - multiline SQL normalization
- **Slow Query Metrics:** parses slow log events and extracts performance metrics
- **Environment Driven:** all runtime values configurable via `.env`
- **Docker Compose Ready:** quick deployment on any Linux host with Docker

---

## Project Structure

```text
.
├── config/
│   └── pipelines.yml        # Logstash pipeline definition
├── pipeline/
│   ├── mysql_general.conf   # General/Audit log processing logic
│   └── mysql_slow.conf      # Slow query log processing logic
├── sincedb/                 # Persistence storage for Logstash file cursor
├── .env                     # Environment variables
├── docker-compose.yml       # Docker deployment
└── README.md
```
## Prerequisites
-------------

*   Docker + Docker Compose
    
*   MySQL 8.0+ (or compatible) writing:
    
    *   General Log to file
        
    *   Slow Query Log to file
        
*   PostgreSQL 13+
    
*   Host must be able to mount MySQL log files into the Logstash container
---
## Quick Start (Docker Compose)
---

Clone repository

```bash 
git clone https://github.com/bisoftbilgi/bisoft-postgresql-toolkit.git
cd bisoft-postgresql-toolkit/mysql_logs_extractor
``` 

## MySQL Source Configuration
---

Enable file-based logging on the MySQL server. Edit your MySQL config (examples: /etc/my.cnf.d, /etc/mysql/my.cnf, /etc/mysql/mysql.conf.d/mysqld.cnf) and add:

```bash   
[mysqld]

# --- General Query Log (Audit and connection) ---
general_log = 1
general_log_file = /var/log/mysql/general-query.log

# --- Slow Query Log ---
slow_query_log = 1
slow_query_log_file = /var/log/mysql/slow-query.log
long_query_time = 2  # Minimum execution time to log. Modify according to your needs.
log_output = FILE
```

Restart MySQL:

```bash   
sudo systemctl restart mysqld
```

### File Permissions (Common Linux Issue)

Logstash container must read the mounted files.

Quick fix:

```bash   
sudo chmod 644 /var/log/mysql/general-query.log
sudo chmod 644 /var/log/mysql/slow-query.log
```
> Note: The container user is not always your host user. The simplest working approach is typically chmod 644 for log files if policy allows.

## PostgreSQL Destination Setup (Tables)
---

Create tables in your destination DB.

### 1) Connection Logs

```SQL   
CREATE TABLE IF NOT EXISTS mysql_connection_logs (
    id SERIAL PRIMARY KEY,
    log_time TIMESTAMPTZ NOT NULL,
    username VARCHAR(255),
    database_name VARCHAR(255),
    client_ip VARCHAR(50),
    action VARCHAR(50),
    cluster_name VARCHAR(100),
    server_name VARCHAR(100),
    server_ip VARCHAR(50),
    application_name VARCHAR(100)
);
```

### 2) Audit Logs

```SQL   
CREATE TABLE IF NOT EXISTS mysql_audit_logs (
    id SERIAL PRIMARY KEY,
    log_time TIMESTAMPTZ NOT NULL,
    session_id BIGINT,
    username VARCHAR(255),
    database_name VARCHAR(255),
    client_ip VARCHAR(50),
    audit_type VARCHAR(20),
    command VARCHAR(50),
    object_type VARCHAR(50),
    object_name VARCHAR(255),
    statement_text TEXT,
    cluster_name VARCHAR(100),
    server_name VARCHAR(100),
    server_ip VARCHAR(50),
    application_name VARCHAR(100)
);
```

### 3) Slow Query Logs

```SQL   
CREATE TABLE IF NOT EXISTS mysql_slowquery_logs (
    id SERIAL PRIMARY KEY,
    log_time TIMESTAMPTZ NOT NULL,
    session_id INTEGER,
    username VARCHAR(255),
    client_ip VARCHAR(50),
    query_time FLOAT,
    lock_time FLOAT,
    statement_text TEXT,
    cluster_name VARCHAR(100),
    server_name VARCHAR(100),
    server_ip VARCHAR(50),
    application_name VARCHAR(100)
);
```
## servers.yml Mapping (Host Metadata Enrichment)

This project enriches each event with:

- `cluster_name`
- `server_name`
- `server_ip`

### Format

- **Key**: `server_id` (folder name under `/logs`, e.g. `mysql-01`)
- **Value**: JSON string

```yaml
mysql-01: '{"cluster_name":"sim-mysql","server_name":"mysql-01","server_ip":"10.20.10.11"}'

# Uncomment / duplicate as needed
# mysql-02: '{"cluster_name":"sim-mysql","server_name":"mysql-02","server_ip":"10.20.10.12"}'
# mysql-03: '{"cluster_name":"sim-mysql","server_name":"mysql-03","server_ip":"10.20.10.13"}'
```
Folder layout examples
Folder-based (recommended)
Host logs:

```text
${HOST_MYSQL_LOG_DIR}/
├─ mysql-01/
│  ├─ general-query.log
│  └─ slow-query.log
└─ mysql-02/
   ├─ general-query.log
   └─ slow-query.log
```
Env globs:

```dotenv
MYSQL_GENERAL_LOG_PATH=/logs/*/general-query.log
MYSQL_SLOW_LOG_PATH=/logs/*/slow-query.log
```
Single-source (no subfolders)
If you only have:

```text
/var/log/mysql/general-query.log
/var/log/mysql/slow-query.log
```
Mount it under a named folder inside the container (example: mysql) and use that name in servers.yml:

```yaml
mysql: '{"cluster_name":"mysqlcluster","server_name":"mysql","server_ip":"10.20.10.11"}'
```
```dotenv
MYSQL_GENERAL_LOG_PATH=/logs/mysql/general-query.log
MYSQL_SLOW_LOG_PATH=/logs/mysql/slow-query.log
## Environment Variables (.env)
```
## Environment Variables (.env)
Create .env in the project root.
```bash
vi .env
```
Example:

```YAML   
# PostgreSQL Destination Config
PG_HOST=192.168.1.100
PG_PORT=5432
PG_DB_NAME=audit_db
PG_USER=postgres
PG_PASSWORD=mysecretpassword

# Host path where MySQL logs live (edit for your system)
HOST_MYSQL_LOG_DIR=/var/log/mysql

# Container globs (pipelines use these)
MYSQL_GENERAL_LOG_PATH=/logs/*/general-query.log
MYSQL_SLOW_LOG_PATH=/logs/*/slow-query.log
```

## Docker Compose Configuration
---

Your docker-compose.yml should:

*   Mount MySQL log files into the container (read-only recommended)
    
*   Mount pipeline configs
    
*   Provide .env variables to Logstash
    

Example volume mapping section:

```YAML   
services:
    mysql_logs_extractor:
      env_file:
        - .env
      volumes:
        - ${HOST_MYSQL_LOG_DIR}:/logs:ro
        - ./pipeline:/usr/share/logstash/pipeline:ro
        - ./config/pipelines.yml:/usr/share/logstash/config/pipelines.yml:ro
        - ./config/servers.yml:/usr/share/logstash/extra/servers.yml:ro
        - ./sincedb:/usr/share/logstash/sincedb

```

## Run & Monitor
---

Start:

```bash
docker compose up -d --build
```

Follow logs:

```bash   
docker logs -f mysql_logs_extractor
```

Stop:

```bash
docker compose down
```

## Verification (SQL Checks)
-------------------------

Check last audit records:

```bash   
psql -h 127.0.0.1 -U postgres -d audit_db
```
```bash
SELECT log_time, username, command, audit_type FROM mysql_audit_logs ORDER BY log_time DESC LIMIT 10;"
```

Check connection events:
```bash
SELECT log_time, username, action, client_ip  FROM mysql_connection_logs  ORDER BY log_time DESC  LIMIT 10;
```

Check slow queries:

```   
SELECT log_time, username, query_time, lock_time  FROM mysql_slowquery_logs  ORDER BY log_time DESC  LIMIT 10;
```

Important Architecture Note (pipeline.workers=1)
------------------------------------------------

This project uses Logstash **Aggregate Filter** for session tracking.

*   On **Connect**, session is stored in a map (session\_id → username/db/ip)
    
*   On **Query**, pipeline looks up the session map to enrich event
    
*   On **Quit**, session is cleared
    

For correctness, events must be processed **sequentially**.

✅ Therefore:

*   PIPELINE\_WORKERS=1 must be used for the **General/Audit** pipeline.
    

If you increase workers, events may be processed out of order and usernames/session correlation can break.

Troubleshooting
---------------

### 1) Permission denied when reading log files

**Symptom:** Logstash container shows errors like “Permission denied”.

**Fix:**

```bash   
sudo chmod 644 /var/log/mysql/general-query.log
sudo chmod 644 /var/log/mysql/slow-query.log
```

Also ensure the _directory_ is traversable:

```   
sudo chmod 755 /var/log/mysql
```

### 2) Empty username fields

**Cause:** session correlation cannot resolve user/session.

**Fix:**

*   Ensure PIPELINE\_WORKERS=1
    
*   If Logstash restarted, active sessions might not be in map; reconnect clients.
    

### 3) JDBC driver not found

**Fix:** ensure the driver exists in the container and your pipeline references it correctly:

*   Expected: /usr/share/logstash/drivers/postgresql.jar
    

Security Notes
--------------

*   Never commit .env (credentials). Add it to .gitignore.
    
*   Prefer least-privilege database user:
    
    *   grant only INSERT/SELECT on target tables (and sequence usage if needed)
        
*   Consider log retention & rotation:
    
    *   MySQL logs can grow quickly; configure rotation (logrotate) on host.
        
*   If logs contain sensitive data, treat storage and access as production data.
