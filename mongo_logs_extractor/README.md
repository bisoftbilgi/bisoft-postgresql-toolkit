MongoDB Log Extractor (Connection & Audit Logs)
===============================================
## Table of Contents

- [1. Project Overview](#1-project-overview)
- [2. What This Project Collects](#2-what-this-project-collects)
  - [2.1 Connection Events](#21-connection-events)
  - [2.2 Audit / Operational Events](#22-audit--operational-events)
- [3. Architecture Overview](#3-architecture-overview)
- [4. Repository Structure](#4-repository-structure)
- [5. Environment Configuration (.env)](#5-environment-configuration-env)
  - [Important Notes](#important-notes)
- [6. Prerequisities (Host + PostgreSQL)](#6-prerequisities-host--postgresql)
  - [6.1 MongoDB-Side Configuration](#61-mongodb-side-configuration)
  - [6.2 Required Docker Volume Mapping](#62-required-docker-volume-mapping)
- [7. PostgreSQL Schema](#7-postgresql-schema)
  - [7.1 Connection Logs Table](#71-connection-logs-table)
  - [7.2 Audit Logs Table](#72-audit-logs-table)
- [8. Noise Reduction Strategy](#8-noise-reduction-strategy)
- [9. sincedb Handling](#9-sincedb-handling)
- [10. GitHub Safety Recommendations](#10-github-safety-recommendations)
- [11. Resource Optimization Notes](#11-resource-optimization-notes)
- [12. Intended Use Cases](#12-intended-use-cases)
- [13. Final Notes](#13-final-notes)


## 1\. Project Overview
--------------------

This project is a **Logstash-based MongoDB log extraction and monitoring pipeline**.Its purpose is to collect **MongoDB connection and audit-level operational logs** from mongod.log and persist them into **PostgreSQL** for long-term storage, monitoring, and analysis.

The system is designed to be:

*   Lightweight (suitable for low-memory servers)
    
*   Containerized (Docker & Docker Compose)
    
*   Portable (environment-variable driven)
    
*   Monitoring-oriented (normalized PostgreSQL schema)
    

## 2\. What This Project Collects
------------------------------

### 2.1 Connection Events

From mongod.log, the following connection-related events are parsed and stored:

*   Successful authentications
    
*   Failed authentication attempts
    
*   Client disconnections
    
*   Connection termination events
    

These logs are useful for:

*   Security monitoring
    
*   Suspicious login detection
    
*   Connection churn analysis
    

### 2.2 Audit / Operational Events

MongoDB does not expose full SQL-style auditing like PostgreSQL, but many **DML / DDL / DQL / DCL–equivalent operations** are visible via:

*   Slow query logs
    
*   Command execution logs
    
*   Internal system operations
    

From these logs, the pipeline extracts:

*   Executed commands
    
*   Target database and object
    
*   Operation duration
    
*   Client application
    
*   Session identifiers (when available)
    

## 3\. Architecture Overview
-------------------------

High-level flow:

MongoDB (mongod.log)→ Logstash (File Input + JSON Codec)→ Logstash Filters (Normalize & Classify)→ PostgreSQL

All components run inside a **single Logstash container**.

## 4\. Repository Structure
------------------------

```plain
mongo_logs_extractor/
  │
  ├── Dockerfile
  ├── docker-compose.yml
  ├── pipeline/
  │   └── mongo.conf
  ├── config/
  │   └── pipelines.yml
  ├── sincedb/
  │   └── .gitignore
  ├── .env.example
  └── README
```

## 5\. Environment Configuration (.env)
------------------------------------

The system is fully driven by environment variables.

Create a .env file in the project root:

```bash
# --- Host Metadata ---
CLUSTER_NAME=
# SERVER_NAME and SERVER_IP can be left empty
# They will be auto-detected at runtime
SERVER_NAME=
SERVER_IP=
# --- PostgreSQL Destination ---
PG_HOST=
PG_PORT=
PG_DB_NAME=
PG_USER=
PG_PASSWORD=
```

### Important Notes

*   SERVER\_NAME and SERVER\_IP are optional.
    
*   If left empty, Logstash auto-detects:
    
    *   Hostname via system call
        
    *   First non-loopback IPv4 address
        

## 6\. Prerequisities (Host + PostgreSQL)
-------------------------------------

Before running this project, make sure the host machine and PostgreSQL destination are ready.

### Host Requirements

*   Docker Engine (recommended v20+)
    
*   Docker Compose v2 (docker compose)
    
*   Access to MongoDB log file on the host (read permissions)
    
### PostgreSQL Requirements

*   PostgreSQL must be reachable using PG\_HOST:PG\_PORT
    
*   PG\_USER must have permission to:
    
    *   CREATE TABLE (first setup) **or** tables must be created manually beforehand
        
    *   INSERT into mongo\_connection\_logs and mongo\_audit\_logs
        
### 6.1 MongoDB-Side Configuration
------------------------------

This project reads **mongod.log** and parses each line as JSON (codec => json).Because of that, MongoDB must be configured to:

1.  Write logs to a file (mongod.log)
    
2.  Produce operational/audit-like events (via profiling / slow query style logs)
    
Open /etc/mongod.conf and add this settings.

```bash
systemLog:
    destination: file
    logAppend: true
    path: /var/log/mongodb/mongod.log
operationProfiling:
    mode: all
    slowOpThresholdMs: 100
    slowOpSampleRate: 1.0
```
Important notes:

*   The pipeline assumes **JSON log format** (because codec => json is used).
    
*   Many MongoDB installations already produce JSON logs by default.
    
*   If your logs are plain-text (non-JSON), the pipeline will not parse them correctly.

*   mode: all ensures operations are visible (more complete audit trail)
    
*   slowOpThresholdMs controls what is considered "slow"
    
*   slowOpSampleRate controls sampling ratio (1.0 = capture all)
    

After updating mongod.conf, restart MongoDB:

```bash
sudo systemctl restart mongod
```

### 6.2 Required Docker Volume Mapping
----------------------------------

The container must mount the host mongod.log file as read-only.

Example:

```yml
volumes:
    - /var/log/mongodb/mongod.log:/var/log/mongodb/mongod.log:ro
    - ./pipeline:/usr/share/logstash/pipeline:ro
    - ./config/pipelines.yml:/usr/share/logstash/config/pipelines.yml:ro
    - ./sincedb:/usr/share/logstash/sincedb
```

Notes:

*   mongod.log must exist on the host before container start
    
*   The container only needs read access (:ro)
    
*   sincedb/ must be writable for Logstash to track file offsets

## 7\. PostgreSQL Schema
---------------------

### 7.1 Connection Logs Table

```SQL
CREATE TABLE IF NOT EXISTS mongo_connection_logs (
  id               BIGSERIAL PRIMARY KEY,
  log_time         TIMESTAMPTZ,
  username         TEXT,
  database_name    TEXT,
  client_ip        TEXT,
  action           TEXT,
  cluster_name     TEXT,
  server_name      TEXT,
  server_ip        TEXT,
  application_name TEXT
);
-- Useful indexes for monitoring queries
CREATE INDEX IF NOT EXISTS idx_mongo_conn_time
  ON mongo_connection_logs (log_time DESC);

CREATE INDEX IF NOT EXISTS idx_mongo_conn_action_time
  ON mongo_connection_logs (action, log_time DESC);

CREATE INDEX IF NOT EXISTS idx_mongo_conn_user_time
  ON mongo_connection_logs (username, log_time DESC);

CREATE INDEX IF NOT EXISTS idx_mongo_conn_db_time
  ON mongo_connection_logs (database_name, log_time DESC);

CREATE INDEX IF NOT EXISTS idx_mongo_conn_clientip_time
  ON mongo_connection_logs (client_ip, log_time DESC);

```
    

### 7.2 Audit Logs Table

```sql
CREATE TABLE IF NOT EXISTS mongo_audit_logs (
  id               BIGSERIAL PRIMARY KEY,
  log_time         TIMESTAMPTZ,
  username         TEXT,
  database_name    TEXT,
  session_id       TEXT,
  audit_type       TEXT,         
  statement_text   TEXT,         
  command          TEXT,       
  object_type      TEXT,         
  object_name      TEXT,        
  duration_ms      INTEGER,
  cluster_name     TEXT,
  server_name      TEXT,
  server_ip        TEXT,
  client_ip        TEXT,
  application_name TEXT
);

CREATE INDEX IF NOT EXISTS idx_mongo_audit_time
  ON mongo_audit_logs (log_time DESC);

CREATE INDEX IF NOT EXISTS idx_mongo_audit_type_time
  ON mongo_audit_logs (audit_type, log_time DESC);

CREATE INDEX IF NOT EXISTS idx_mongo_audit_db_time
  ON mongo_audit_logs (database_name, log_time DESC);

CREATE INDEX IF NOT EXISTS idx_mongo_audit_cmd_time
  ON mongo_audit_logs (command, log_time DESC);

CREATE INDEX IF NOT EXISTS idx_mongo_audit_clientip_time
  ON mongo_audit_logs (client_ip, log_time DESC);

CREATE INDEX IF NOT EXISTS idx_mongo_audit_duration_time
  ON mongo_audit_logs (duration_ms, log_time DESC);
```    

The schema is intentionally **PostgreSQL-friendly** and aligns with typical monitoring dashboards.

## 8\. Noise Reduction Strategy
----------------------------

MongoDB produces a significant amount of **internal and background traffic**, such as:

*   hello commands
    
*   Session housekeeping
    
*   Replication and config database activity
    

This project:

*   Filters non-essential events
    
*   Groups commands logically
    
*   Preserves full statement\_text for forensic use
    
*   Avoids excessive debug output
    

As a result, logs remain **actionable instead of noisy**.

## 9\. sincedb Handling
--------------------

The sincedb directory is mounted from the host:

```bash
./sincedb → /usr/share/logstash/sincedb
```

Important rules:

*   The directory must exist before starting the container
    
*   It should be writable by Docker
    
*   It must **not** be committed to Git
    

Recommended .gitignore entry:

```bash
sincedb/
```

## 10\. GitHub Safety Recommendations
----------------------------------

Never commit real credentials.

Required .gitignore entries:

```bash
.env
sincedb/
```

Recommended:

*   Commit .env.example
    
*   Let users create their own .env
    

## 11\. Resource Optimization Notes
--------------------------------

For low-memory systems:

*   Remove stdout { rubydebug } in production
    
*   Keep flush\_size low (already optimized)
    
*   Avoid parallel pipelines unless necessary
    
*   Prefer one Logstash instance per host
    

The current configuration is tested on **~3.5 GB RAM systems**.

## 12\. Intended Use Cases
-----------------------

*   MongoDB security monitoring
    
*   Audit trail persistence
    
*   Performance analysis
    
*   Centralized logging
    
*   SIEM / monitoring integrations
    

## 13\. Final Notes
----------------

This project is designed to be:

*   Predictable
    
*   Auditable
    
*   Easy to migrate
    
*   Git-friendly
    

Pipeline logic is explicit, readable, and intentionally not over-abstracted.
