## Introduction

- This repository delivers a host-based pipeline for collecting and analyzing **PostgreSQL logs** with **Logstash**.  
- It parses **connection** and **audit** events, enriches them with host metadata (`cluster_name`, `server_name`, `server_ip`), and stores structured records in **PostgreSQL / TimescaleDB** for querying and monitoring.  
- The setup targets **Rocky Linux 9** and assumes direct installation on the host.
---
# Table of Contents
- [Installation](#installation)
  - [Step 1 — Install PostgreSQL (Rocky Linux)](#step-1--install-postgresql-rocky-linux)
  - [Step 2 — TimescaleDB Setup](#step-2--timescaledb-setup)
  - [Step 3 — Configure PostgreSQL](#step-3--configure-postgresql)
  - [Step 4 — Install and Configure Logstash](#step-4--install-and-configure-logstash)
  - [Step 4.1 — Install PostgreSQL JDBC Driver](#step-41--install-postgresql-jdbc-driver)
- [Usage](#usage)
  - [Run with the Shell Script (Recommended)](#run-with-the-shell-script-recommended)
- [Verification](#verification)
- [Troubleshooting](#troubleshooting)
- [Docker Support](#docker-support)

---
## Installation
### Step 1 — Install PostgreSQL (Rocky Linux)

```bash
# 1) Install PostgreSQL server + contrib packages
sudo dnf install postgresql17-server postgresql17-contrib -y

# 2) Initialize the database cluster (creates data dir, default configs)
sudo /usr/pgsql-17/bin/postgresql-17-setup initdb

# 3) Enable and start the service on boot
sudo systemctl enable --now postgresql-17

# 4) Quick health check
systemctl --no-pager status postgresql-17
psql --version  # verify client installed (optional)
```
### Step 2 — TimescaleDB Setup  
To optimize storage and queries for time-series log data, you can enable TimescaleDB.

Install the TimescaleDB package (example for Rocky Linux 9 / PostgreSQL 17):

```bash
sudo tee /etc/yum.repos.d/timescaledb.repo <<EOF
[timescaledb]
name=timescaledb
baseurl=https://packagecloud.io/timescale/timescaledb/el/9/x86_64
repo_gpgcheck=1
enabled=1
gpgkey=https://packagecloud.io/timescale/timescaledb/gpgkey
sslverify=1
sslcacert=/etc/pki/tls/certs/ca-bundle.crt
metadata_expire=300
EOF
```
```bash
sudo dnf install -y timescaledb-2-postgresql-17
```
### Step 3 — Configure PostgreSQL
Goal: Enable detailed connection and audit logging in PostgreSQL by adjusting key parameters in `postgresql.conf`.  
- This step ensures that both standard activity logs and audit trails are captured for Logstash.
---
Open the main configuration file:

```bash
# Open postgresql.conf inside the data directory
sudo vi /var/lib/pgsql/17/data/postgresql.conf
```
Below are the recommended settings for comprehensive logging and auditing.
```bash
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
Then restart PostgreSQL to apply the changes:
```bash
sudo systemctl restart postgresql-17
```
### Step 4 — Install and Configure Logstash
Goal: Install Logstash on the host system, enable it as a service, and prepare the directory structure for pipeline configuration.

---
> ⚠️ **Permission Warning**
>
> Make sure the user running **Logstash** has:
> - **Read access** to PostgreSQL log files under `/var/lib/pgsql/17/data/log/`
> - **Write access** to the target PostgreSQL database  
>
> If permission errors occur during parsing or JDBC output,  
> temporarily run Logstash with **root privileges**:
>
> ```bash
> sudo systemctl restart logstash
> ```
>
> This ensures the service can both read log files and insert records into database tables.
---
### Install Logstash

Add Elastic’s official repository and install Logstash:

```bash
# Import Elastic GPG key
sudo rpm --import https://artifacts.elastic.co/GPG-KEY-elasticsearch

# Create the YUM repo definition
sudo tee /etc/yum.repos.d/logstash.repo > /dev/null <<'EOF'
[logstash-8.x]
name=Elastic repository for 8.x packages
baseurl=https://artifacts.elastic.co/packages/8.x/yum
gpgcheck=1
enabled=1
autorefresh=1
type=rpm-md
EOF

# Install Logstash package
sudo dnf install logstash -y

# Enable Logstash to start automatically at boot
sudo systemctl enable logstash
```
### Step 4.1 — Install PostgreSQL JDBC Driver

Goal: Allow Logstash to connect to PostgreSQL using the JDBC output plugin.

Logstash requires a PostgreSQL JDBC driver (`.jar`) file to write data into the database.  
Follow these steps to install it manually.

```bash
# Navigate to the Logstash JDBC library directory
cd /usr/share/logstash/logstash-core/lib/jars/

# Download the official PostgreSQL JDBC driver
sudo wget https://jdbc.postgresql.org/download/postgresql-42.7.8.jar

# Verify the file is present
ls -l postgresql-*.jar
```
> The version number (e.g., 42.7.8) may change depending on the latest release.
> You can find the most recent version at:
> https://jdbc.postgresql.org/download/

## Usage

> After completing the installation and configuration steps,  
> you can start the entire pipeline using the provided shell script  
> or run it manually through Logstash.

---

### Run with the Shell Script (Recommended)

The easiest way to start and maintain the pipeline is by using the **`setup-logstash.sh`** script.  
This script automatically performs all necessary setup tasks.

```bash
cd scripts/
sudo bash setup-logstash.sh
```
> 💡 **Note**
>
> If you experience any issues, open the example configuration file  
> provided in this repository and update it according to your environment.
>
> The file can be found under:
> ```
> /etc/logstash/conf.d/logstash.conf
> ```
---
## Verification

After running the setup script, verify that the pipeline is correctly configured and Logstash is actively sending data to PostgreSQL.

### Check Logstash Service Status
Ensure Logstash is running properly:
```bash
sudo systemctl status logstash --no-pager
```
If the service is active, you should see:
> Active: active (running)

### Validate Logstash Configuration
Manually test the configuration file to confirm there are no syntax errors:
```bash
sudo /usr/share/logstash/bin/logstash -t -f /etc/logstash/conf.d/logstash.conf
```
If successful, the output will include:
> Configuration OK

### Verify Database Tables

Run the following commands to confirm that new data is being inserted into the target tables:
```bash
# Check latest connection logs
psql -h <host> -p <port> -U <admin_user> -d <database> \
     -c "SELECT log_time, username, client_ip, action FROM connection_logs ORDER BY log_time DESC LIMIT 10;"

# Check latest audit logs
psql -h <host> -p <port> -U <admin_user> -d <database> \
     -c "SELECT log_time, username, audit_type, command, application_name FROM audit_logs ORDER BY log_time DESC LIMIT 10;"
```
If both queries return rows, the setup is complete and operational.

## Troubleshooting
---
Below are some common issues you may encounter during setup or runtime,
along with their possible causes and recommended solutions.

| **Issue** | **Possible Cause** | **Solution** |
|------------|--------------------|---------------|
| **Logstash pipeline failed to start** | Configuration syntax error in the `.conf` file | Run:<br>`sudo /usr/share/logstash/bin/logstash -t -f /etc/logstash/conf.d/main.conf`<br>to validate and locate the issue. |
| **No data written to PostgreSQL tables** | Incorrect credentials or database permissions | Check the JDBC section in your config:<br>`username`, `password`, and `connection_string` must match your PostgreSQL setup. |
| **Permission denied errors** | Insufficient access to Logstash directories | Fix permissions:<br>`sudo chown -R logstash:logstash /var/lib/logstash /etc/logstash` |
| **psql: connection refused** | Wrong host, port, or PostgreSQL service not running | Test connection manually:<br>`psql -h <host> -p <port> -U <user> -d <database>` |

> 💡 **Tip:**  
> If the issue persists, check the Logstash logs for detailed errors:  
> ```bash
> sudo tail -f /var/log/logstash/logstash-plain.log
> ```  
> and review `/tmp/logstash-test.log` if a configuration test fails.
---

## Docker Support

If you prefer to run this setup inside a containerized environment,  
see [Docker README](https://github.com/bisoft-postgresql-toolkit/tree/main/pg_logs_extractor/docker/README.md) for Docker Compose examples  
and container-based Logstash + PostgreSQL configuration.
