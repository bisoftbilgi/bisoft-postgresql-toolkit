# PostgreSQL Log Extractor — Docker Deployment Guide
This folder contains the Docker configuration required to run the PostgreSQL Log Extractor in a fully isolated environment using Logstash + JDBC output.
### The container automatically:
- Parses PostgreSQL connection logs
- Parses pgaudit audit logs (if enabled on your server)
- Writes all parsed logs into your PostgreSQL database
- Uses the host’s PostgreSQL log directory via bind-mount
---
## 1. Prerequisites
### Before running the stack, ensure:
- PostgreSQL is already installed on the host
- PostgreSQL logging is enabled (log_destination = 'stderr', logging_collector = on)
- Logs are written to a directory (example):
```bash
/var/log/postgresql
```

> Your PostgreSQL user has access for Logstash to insert rows
---
## 2. Configure docker-compose.yml

### Before starting, edit the environment variables based on your system:
```bash
environment:
  PG_HOST: host.docker.internal     # Host machine
  PG_PORT: 
  PG_DB: 
  PG_USER: 
  PG_PASS: 
  PG_ADMIN_USER: 
  PG_ADMIN_PASS: 
  CLUSTER_NAME: 
  LOG_PATH:                         # Host PostgreSQL log directory
```

> Make sure these values match your local PostgreSQL configuration.

## 3. Build & Run

From the project root:
```bash
docker compose up --build -d
```
To view logs:
```bash
docker logs -f logstash
```
To enter the container:
```bash
docker exec -it logstash bash
```
---
## 4. Verify That Logs Are Being Parsed

On the host, generate some PostgreSQL activity:
```bash
psql -U youruser -d test -c "select now();"
```
Then check your database:
```bash
SELECT * FROM connection_logs ORDER BY id DESC LIMIT 20;
SELECT * FROM audit_logs ORDER BY id DESC LIMIT 20;
```

> If rows appear → system is working correctly

## 5. Stopping & Removing
```bash
docker compose down
```
To rebuild from scratch:
```bash
docker compose down -v
docker compose up --build
```
---
### Notes

The container does not include PostgreSQL itself — it connects to the host database.

The Logstash pipeline is generated dynamically at container start using the provided environment variables.

Audit logs require:
```bash
shared_preload_libraries = 'pgaudit'
pgaudit.log = 'all'
```
