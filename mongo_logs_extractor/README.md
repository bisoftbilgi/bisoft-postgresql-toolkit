MongoDB Log Extractor (Connection & Audit Logs)
===============================================

Table of Contents
-----------------

*   [1\. Project Overview](#1-project-overview)

*   [2\. Prerequisites](#2-prerequisites)
    
*   [3\. Features](#3-features)
    
*   [4\. What This Project Collects](4-what-this-project-collects)
    
    *   [4.1 Connection Events](#41-connection-events)
        
    *   [4.2 Audit / Operational Events](#42-audit--operational-events)
        
*   [5\. Architecture Overview](#5-architecture-overview)
    
*   [6\. Repository Structure](#6-repository-structure)
        
*   [7\. MongoDB Configuration](#7-mongodb-configuration)
    
    *   [7.1 Enable JSON Logging](#71-enable-json-logging)
        
    *   [7.2 Enable Operational / Slow Query Logs](#72-enable-operational--slow-query-logs)
        
*   [8\. Environment Configuration (.env)](#8-environment-configuration-env)

*   [9\. servers.yml Mapping (Host Metadata Enrichment)](#9-serversyml-mapping-host-metadata-enrichment)
    
*   [10\. Docker Compose Configuration](#10-docker-compose-configuration)
    
*   [11\. PostgreSQL Schema](#11-postgresql-schema)
    
    *   [11.1 Connection Logs Table](#111-connection-logs-table)
        
    *   [11.2 Audit Logs Table](#112-audit-logs-table)
        
*   [12\. Run & Monitor](#12-run--monitor)
    
*   [13\. Verification (SQL Checks)](#13-verification-sql-checks)
    
*   [14\. Resource Optimization Notes](#14-resource-optimization-notes)
    
*   [15\. Security Notes](#15-security-notes)
    
*   [16\. Intended Use Cases](#16-intended-use-cases)
    

## 1\. Project Overview
--------------------

This project is a **Logstash-based MongoDB log extraction and monitoring pipeline**.

Its purpose is to collect **MongoDB connection-level and audit-style operational logs** from mongod.log and persist them into **PostgreSQL** for:

*   Long-term storage
    
*   Security monitoring
    
*   Operational visibility
    
*   Performance analysis
    

The system is designed to be:

*   Lightweight (suitable for ~3–4 GB RAM servers)
    
*   Fully containerized (Docker & Docker Compose)
    
*   Portable (environment-variable driven)
    
*   Monitoring-oriented (normalized PostgreSQL schema)
    
## 2\. Prerequisites
-----------------

*   Linux-based host (Rocky Linux tested)
    
*   Docker Engine (v20+ recommended)
    
*   Docker Compose v2 (docker compose)
    
*   MongoDB 6.0+

*   PostgreSQL 14+
    
## 3\. Features
------------

*   MongoDB connection event logging
    
*   MongoDB audit / operational command capture
    
*   PostgreSQL-backed persistent storage
    
*   Noise-reduced, monitoring-friendly data model
    
*   Dockerized single-container architecture
    
*   sincedb-based offset tracking
    
*   Safe for production use on low-resource machines
    

## 4\. What This Project Collects
------------------------------

### 4.1 Connection Events

From mongod.log, the following connection-related events are parsed and stored:

*   Successful authentication attempts
    
*   Failed authentication attempts
    
*   Client disconnections
    
*   Connection termination events
    

These logs are useful for:

*   Security monitoring
    
*   Suspicious login detection
    
*   Connection churn analysis
    
*   Brute-force detection
    

### 4.2 Audit / Operational Events

MongoDB does not expose SQL-style auditing like PostgreSQL, however many **DML / DDL / DQL / DCL–equivalent operations** are visible through:

*   Slow query logs
    
*   Command execution logs
    
*   Internal command execution records
    

From these logs, the pipeline extracts:

*   Executed command
    
*   Target database and object
    
*   Operation duration
    
*   Client application name
    
*   Session identifiers (when available)
    

## 5\. Architecture Overview
-------------------------

High-level flow:

```
MongoDB (mongod.log)
          ↓
Logstash (file input + JSON codec)
          ↓
Normalization & classification filters
          ↓
PostgreSQL (connection & audit tables)
```

All components run inside a **single Logstash container**.

## 6\. Repository Structure
------------------------

```
mongo_logs_extractor/
  ├── Dockerfile
  ├── docker-compose.yml
  ├── pipeline/
  │   └── mongo.conf
  ├── config/
  │   └── servers.yml
  ├── sincedb/
  │   └── .gitignore
  └── README.md
```

## 7\. MongoDB Configuration
-------------------------

### 7.1 Enable JSON Logging

Edit /etc/mongod.conf:

```bash
systemLog:
    destination: file
    logAppend: true
    path: /var/log/mongodb/mongod.log
```

MongoDB typically logs in JSON format by default on modern versions.

### 7.2 Enable Operational / Slow Query Logs

```bash
operationProfiling:
    mode: all
    slowOpThresholdMs: 100
    slowOpSampleRate: 1.0
```

Explanation:

*   mode: all exposes operational activity
    
*   slowOpThresholdMs defines what is considered slow
    
*   slowOpSampleRate: 1.0 ensures full capture
    

Restart MongoDB:

```bash
sudo systemctl restart mongod
```

## 8\. Environment Configuration (.env)
Clone repository

```bash 
git clone https://github.com/bisoftbilgi/bisoft-postgresql-toolkit.git
cd bisoft-postgresql-toolkit/mongo_logs_extractor
```

Create a .env file in the project root:

```env
# --- PostgreSQL Destination ---
PG_HOST=
PG_PORT=
PG_DB_NAME=
PG_USER=
PG_PASSWORD=

# Host path where MongoDB logs live (edit for your system)
HOST_MONGO_LOG_DIR=/srv/mongo-logs

# Container path glob read by Logstash
MONGO_LOG_PATH=/logs/*/mongod.log
```
## 9\. servers.yml Mapping (Host Metadata Enrichment)

This project enriches each event with `cluster_name`, `server_name`, and `server_ip`.

1) Create `config/servers.yml`  
2) Add one entry per source using a `server_id` key (the folder name under `/logs`)  
3) The pipeline will extract `server_id` from the log file path and apply the mapped metadata

## 10\. Docker Compose Configuration
--------------------------------

The container mounts MongoDB logs and pipeline configuration:

```yml
volumes:
    - ${HOST_MONGO_LOG_DIR}:/logs:ro 
    - ./pipeline:/usr/share/logstash/pipeline:ro
    - ./config/pipelines.yml:/usr/share/logstash/config/pipelines.yml:ro

```

## 11\. PostgreSQL Schema
----------------------

### 11.1 Connection Logs Table

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

### 11.2 Audit Logs Table

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

## 12\. Run & Monitor
------------------

```   
docker compose up -d --build
docker logs -f mongo_logs_extractor
```

## 13\. Verification (SQL Checks)
------------------------------

```   
SELECT * FROM mongo_connection_logs ORDER BY log_time DESC LIMIT 10;
SELECT * FROM mongo_audit_logs ORDER BY duration_ms DESC LIMIT 10;
```

## 14\. Resource Optimization Notes
--------------------------------

*   Disable stdout rubydebug in production
    
*   Keep flush\_size low
    
*   Avoid parallel pipelines
    
*   One Logstash instance per host recommended
    

Tested on ~3.5 GB RAM systems.

## 15\. Security Notes
-------------------

*   Never commit .env
    
*   Logs mounted read-only
    
*   PostgreSQL credentials scoped to INSERT only
    

## 16\. Intended Use Cases
-----------------------

*   MongoDB security monitoring
    
*   Audit trail persistence
    
*   Performance diagnostics
    
*   Centralized logging
    
*   SIEM integrations
