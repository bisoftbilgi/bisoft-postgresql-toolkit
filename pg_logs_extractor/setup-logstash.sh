#!/bin/bash

################################################################################
# Logstash PostgreSQL Audit & Connection Logger Setup Script
# 
# Usage: ./setup-logstash.sh [OPTIONS]
# 
# Options:
#   --pg-host         PostgreSQL host (default: localhost)
#   --pg-port         PostgreSQL port (default: 5432)
#   --pg-database     PostgreSQL database (default: postgres)
#   --pg-user         PostgreSQL user for Logstash (default: logstash_writer)
#   --pg-password     PostgreSQL password for Logstash (required)
#   --pg-admin-user   PostgreSQL admin user for setup (default: postgres)
#   --pg-admin-pass   PostgreSQL admin password (optional)
#   --log-path        PostgreSQL log directory (default: /var/log/postgresql)
#   --cluster-name    Cluster name (default: postgrescluster)
#   --server-name     Server name (default: auto-detect)
#   --server-ip       Server IP (default: auto-detect)
#   --jdbc-jar        JDBC driver path (default: /usr/share/logstash/logstash-core/lib/jars/postgresql-42.7.8.jar)
#   --config-path     Logstash config path (default: /etc/logstash/conf.d/logstash.conf)
#   --sincedb-path    Sincedb path (default: /var/lib/logstash/sincedb-combined-logs)
#   --help            Show this help message
################################################################################

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default values
PG_HOST="localhost"
PG_PORT="5432"
PG_DATABASE="postgres"
PG_USER="logstash_writer"
PG_PASSWORD=""
PG_ADMIN_USER="postgres"
PG_ADMIN_PASS=""
LOG_PATH="/var/log/postgresql"
CLUSTER_NAME="postgrescluster"
SERVER_NAME=""
SERVER_IP=""
JDBC_JAR="/usr/share/logstash/logstash-core/lib/jars/postgresql-42.7.8.jar"
CONFIG_PATH="/etc/logstash/conf.d/logstash.conf"
SINCEDB_PATH="/var/lib/logstash/sincedb-combined-logs"

# Functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_step() {
    echo -e "${BLUE}[STEP]${NC} $1"
}

show_help() {
    grep "^#" "$0" | grep -v "^#!/" | sed 's/^# //' | sed 's/^#//'
    exit 0
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --pg-host)
            PG_HOST="$2"
            shift 2
            ;;
        --pg-port)
            PG_PORT="$2"
            shift 2
            ;;
        --pg-database)
            PG_DATABASE="$2"
            shift 2
            ;;
        --pg-user)
            PG_USER="$2"
            shift 2
            ;;
        --pg-password)
            PG_PASSWORD="$2"
            shift 2
            ;;
        --pg-admin-user)
            PG_ADMIN_USER="$2"
            shift 2
            ;;
        --pg-admin-pass)
            PG_ADMIN_PASS="$2"
            shift 2
            ;;
        --log-path)
            LOG_PATH="$2"
            shift 2
            ;;
        --cluster-name)
            CLUSTER_NAME="$2"
            shift 2
            ;;
        --server-name)
            SERVER_NAME="$2"
            shift 2
            ;;
        --server-ip)
            SERVER_IP="$2"
            shift 2
            ;;
        --jdbc-jar)
            JDBC_JAR="$2"
            shift 2
            ;;
        --config-path)
            CONFIG_PATH="$2"
            shift 2
            ;;
        --sincedb-path)
            SINCEDB_PATH="$2"
            shift 2
            ;;
        --help)
            show_help
            ;;
        *)
            log_error "Unknown option: $1"
            show_help
            ;;
    esac
done

# Auto-detect server info if not provided
if [ -z "$SERVER_NAME" ]; then
    SERVER_NAME=$(hostname)
    log_info "Auto-detected server name: $SERVER_NAME"
fi

if [ -z "$SERVER_IP" ]; then
    SERVER_IP=$(ip -4 addr show 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | grep -v '127.0.0.1' | head -1)
    if [ -z "$SERVER_IP" ]; then
        SERVER_IP="127.0.0.1"
    fi
    log_info "Auto-detected server IP: $SERVER_IP"
fi

# Validate required parameters
if [ -z "$PG_PASSWORD" ]; then
    log_error "PostgreSQL password is required. Use --pg-password"
    exit 1
fi

# Check if log path exists
if [ ! -d "$LOG_PATH" ]; then
    log_error "PostgreSQL log directory does not exist: $LOG_PATH"
    exit 1
fi

echo ""
log_info "========================================"
log_info "Logstash PostgreSQL Setup"
log_info "========================================"
log_info "PostgreSQL Host: $PG_HOST:$PG_PORT"
log_info "PostgreSQL Database: $PG_DATABASE"
log_info "PostgreSQL User: $PG_USER"
log_info "Log Path: $LOG_PATH"
log_info "Cluster Name: $CLUSTER_NAME"
log_info "Server Name: $SERVER_NAME"
log_info "Server IP: $SERVER_IP"
log_info "JDBC JAR: $JDBC_JAR"
log_info "Config Path: $CONFIG_PATH"
log_info "Sincedb Path: $SINCEDB_PATH"
log_info "========================================"
echo ""

# Create PostgreSQL connection string for admin
if [ -n "$PG_ADMIN_PASS" ]; then
    export PGPASSWORD="$PG_ADMIN_PASS"
fi

# Test PostgreSQL connection
log_step "Step 1: Testing PostgreSQL connection..."
if ! psql -h "$PG_HOST" -p "$PG_PORT" -U "$PG_ADMIN_USER" -d "$PG_DATABASE" -c "SELECT 1" > /dev/null 2>&1; then
    log_error "Cannot connect to PostgreSQL. Please check credentials."
    exit 1
fi
log_info "? PostgreSQL connection successful"
echo ""

# Create logstash user if not exists
log_step "Step 2: Creating PostgreSQL user: $PG_USER"
psql -h "$PG_HOST" -p "$PG_PORT" -U "$PG_ADMIN_USER" -d "$PG_DATABASE" > /dev/null 2>&1 <<EOF
DO \$\$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = '$PG_USER') THEN
        CREATE USER $PG_USER WITH PASSWORD '$PG_PASSWORD';
        RAISE NOTICE 'User created: $PG_USER';
    ELSE
        ALTER USER $PG_USER WITH PASSWORD '$PG_PASSWORD';
        RAISE NOTICE 'User updated: $PG_USER';
    END IF;
END
\$\$;
EOF
log_info "? User $PG_USER configured"
echo ""

# Create tables if not exist
log_step "Step 3: Creating connection_logs table..."
psql -h "$PG_HOST" -p "$PG_PORT" -U "$PG_ADMIN_USER" -d "$PG_DATABASE" > /dev/null 2>&1 <<EOF
CREATE TABLE IF NOT EXISTS connection_logs (
    id SERIAL PRIMARY KEY,
    log_time TIMESTAMPTZ NOT NULL,
    username TEXT,
    database_name TEXT,
    client_ip TEXT,
    action TEXT,
    cluster_name TEXT,
    server_name TEXT,
    server_ip TEXT,
    application_name TEXT
);


CREATE INDEX IF NOT EXISTS idx_connection_logs_log_time ON connection_logs(log_time);
CREATE INDEX IF NOT EXISTS idx_connection_logs_username ON connection_logs(username);
CREATE INDEX IF NOT EXISTS idx_connection_logs_cluster ON connection_logs(cluster_name);
CREATE INDEX IF NOT EXISTS idx_connection_logs_server ON connection_logs(server_name);
CREATE INDEX IF NOT EXISTS idx_connection_logs_app_name ON connection_logs(application_name);

GRANT INSERT, SELECT ON connection_logs TO $PG_USER;
EOF
log_info "? Table connection_logs created/verified"

log_step "Step 4: Creating audit_logs table..."
psql -h "$PG_HOST" -p "$PG_PORT" -U "$PG_ADMIN_USER" -d "$PG_DATABASE" > /dev/null 2>&1 <<EOF
CREATE TABLE IF NOT EXISTS audit_logs (
    id SERIAL PRIMARY KEY,
    log_time TIMESTAMPTZ NOT NULL,
    username TEXT,
    database_name TEXT,
    session_id TEXT,
    statement_id TEXT,
    audit_type TEXT,
    statement_text TEXT,
    command TEXT,
    object_type TEXT,
    object_name TEXT,
    cluster_name TEXT,
    server_name TEXT,
    server_ip TEXT,
    client_ip TEXT,
    application_name TEXT
);


CREATE INDEX IF NOT EXISTS idx_audit_logs_log_time ON audit_logs(log_time);
CREATE INDEX IF NOT EXISTS idx_audit_logs_username ON audit_logs(username);
CREATE INDEX IF NOT EXISTS idx_audit_logs_audit_type ON audit_logs(audit_type);
CREATE INDEX IF NOT EXISTS idx_audit_logs_cluster ON audit_logs(cluster_name);
CREATE INDEX IF NOT EXISTS idx_audit_logs_server ON audit_logs(server_name);
CREATE INDEX IF NOT EXISTS idx_audit_logs_client_ip ON audit_logs(client_ip);
CREATE INDEX IF NOT EXISTS idx_audit_logs_app_name ON audit_logs(application_name);

GRANT INSERT, SELECT ON audit_logs TO $PG_USER;
EOF
log_info "? Table audit_logs created/verified"
echo ""

log_info "? Database setup completed"
echo ""

log_step "Step 5: Enabling TimescaleDB extension..."
psql -h "$PG_HOST" -p "$PG_PORT" -U "$PG_ADMIN_USER" -d "$PG_DATABASE" > /dev/null 2>&1 <<EOF
CREATE EXTENSION IF NOT EXISTS timescaledb;
EOF

if [ $? -eq 0 ]; then
    log_info "✓ TimescaleDB extension enabled successfully"
else
    log_warn "TimescaleDB extension could not be enabled. Please verify shared_preload_libraries includes 'timescaledb'"
fi

log_step "Step 6: Converting tables to hypertables..."
psql -h "$PG_HOST" -p "$PG_PORT" -U "$PG_ADMIN_USER" -d "$PG_DATABASE" > /dev/null 2>&1 <<EOF
SELECT create_hypertable('connection_logs', 'log_time', if_not_exists => TRUE);
SELECT create_hypertable('audit_logs', 'log_time', if_not_exists => TRUE);
EOF

if [ $? -eq 0 ]; then
    log_info "✓ Tables successfully converted to hypertables"
else
    log_warn "Hypertable conversion skipped or failed (TimescaleDB may not be active)"
fi

# Download JDBC driver if not exists
log_step "Step 7: Checking JDBC driver..."
if [ ! -f "$JDBC_JAR" ]; then
    log_info "Downloading PostgreSQL JDBC driver..."
    JDBC_DIR=$(dirname "$JDBC_JAR")
    mkdir -p "$JDBC_DIR"
    wget -q https://jdbc.postgresql.org/download/postgresql-42.7.8.jar -O "$JDBC_JAR"
    log_info "? JDBC driver downloaded"
else
    log_info "? JDBC driver already exists"
fi
echo ""

# Create Logstash configuration
log_step "Step 8: Creating Logstash configuration..."

# Create config directory if not exists
mkdir -p "$(dirname "$CONFIG_PATH")"

# Write configuration using the working config
cat > "$CONFIG_PATH" <<'EOF'
input {
  file {
    path              => "LOG_PATH_PLACEHOLDER/postgresql-*.log"
    start_position    => "beginning"
    sincedb_path      => "SINCEDB_PATH_PLACEHOLDER"
    discover_interval => 1
    stat_interval     => 0.5
    close_older       => 300
    ignore_older      => 0
  }
}

filter {
  # Add server metadata - can be set via environment variables or defaults
  mutate {
    add_field => {
      "cluster_name" => "${CLUSTER_NAME:CLUSTER_NAME_PLACEHOLDER}"
      "server_name" => "${SERVER_NAME:SERVER_NAME_PLACEHOLDER}"
      "server_ip" => "${SERVER_IP:SERVER_IP_PLACEHOLDER}"
    }
  }

  # Auto-detect server_name (hostname) if not set
  if [server_name] == "" {
    ruby {
      code => "
        require 'socket'
        event.set('server_name', Socket.gethostname)
      "
    }
  }

  # Auto-detect server_ip if not set
  if [server_ip] == "" {
    ruby {
      code => "
        require 'socket'
        begin
          hostname = Socket.gethostname
          ip_address = Socket.ip_address_list.detect{|intf| intf.ipv4? && !intf.ipv4_loopback?}
          event.set('server_ip', ip_address ? ip_address.ip_address : '127.0.0.1')
        rescue
          event.set('server_ip', '127.0.0.1')
        end
      "
    }
  }

  # Drop ERROR and STATEMENT lines (noise)
  if [message] =~ /^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d+\s+\w+\s+\[\d+\]\s+user=.*\s+(ERROR|STATEMENT):/ {
    drop { }
  }

  # Parse main PostgreSQL log structure (UTC timezone format)
  grok {
    match => {
      "message" => [
        '^%{TIMESTAMP_ISO8601:log_time}\s+(?<tz>(?:[+-]\d{2}(?::?\d{2})?|UTC))\s+\[%{NUMBER:pid}\]\s+user=%{DATA:username},db=%{DATA:database_name}, client_ip=%{DATA:client_ip}\s+app=%{DATA:application_name}\s+LOG:\s+%{GREEDYDATA:pg_message}$'
      ]
    }
    tag_on_failure => ["_grokparsefailure"]
  }

  if [pg_message] =~ /application_name=/ {
    grok {
      match => {
        "pg_message" => 'application_name=%{GREEDYDATA:application_name}$'
      }
      overwrite => ["application_name"]
    }
    mutate {
      strip => ["application_name"]
    }
  }

  # Only process if main grok succeeded
  if "_grokparsefailure" not in [tags] {

    # Combine timestamp with timezone (UTC handling)
    if [tz] == "UTC" {
      mutate { add_field => { "log_time_full" => "%{log_time} +00:00" } }
    } else {
      mutate { add_field => { "log_time_full" => "%{log_time} %{tz}" } }
    }

    date {
      match  => ["log_time_full", "YYYY-MM-dd HH:mm:ss.SSS Z", "YYYY-MM-dd HH:mm:ss.SSS"]
      target => "log_time"
      timezone => "UTC"
    }

    # Route 1: Connection/Disconnection logs
    if [pg_message] =~ /^connection received:|^connection authorized:|^disconnection:/ {

      if [pg_message] =~ /^connection received:/ {
        mutate { add_field => { "action" => "connection_received" } }
      } else if [pg_message] =~ /^connection authorized:/ {
        mutate { add_field => { "action" => "connection" } }
      } else if [pg_message] =~ /^disconnection:/ {
        mutate { add_field => { "action" => "disconnection" } }
      }

      # Clean up fields for connection logs
      mutate {
        strip => ["username", "database_name", "client_ip", "action", "cluster_name", "server_name", "server_ip", "application_name"]
        remove_field => ["log_time_full", "tz", "pid", "pg_message", "@version", "host", "event", "log", "message"]
      }

      # Tag for routing to connection_logs table
      mutate { add_tag => ["connection_log"] }
    }

    # Route 2: Audit logs
    else if [pg_message] =~ /^AUDIT:/ {

      # Parse AUDIT details
      grok {
        match => {
          "pg_message" => "AUDIT:\s+SESSION,%{NUMBER:session_id},%{NUMBER:statement_id},%{WORD:audit_type},%{GREEDYDATA:statement_details}"
        }
      }

      # Parse statement_details: command,object_type,object_name,statement_text
      grok {
        match => {
          "statement_details" => "(?<command>[^,]*),(?<object_type>[^,]*),(?<object_name>[^,]*),%{GREEDYDATA:statement_text}"
        }
        overwrite => ["command", "object_type", "object_name", "statement_text"]
      }

      # Clean up statement_text
      mutate {
        gsub => [
          "statement_text", ",<not logged>", "",
          "statement_text", "^\"|\"$", ""
        ]
      }

      # Handle empty object_type and object_name
      if [object_type] == "," or [object_type] == "" {
        mutate { replace => { "object_type" => "" } }
      }
      if [object_name] == "," or [object_name] == "" {
        mutate { replace => { "object_name" => "" } }
      }

      # Clean up fields for audit logs (keep client_ip for audit_logs now)
      mutate {
        strip => ["username", "session_id", "statement_id", "audit_type", "statement_text", "command", "object_type", "object_name", "cluster_name", "server_name", "server_ip", "client_ip", "application_name"]
        remove_field => ["statement_details", "tz", "pid", "pg_message", "log_time_full", "@version", "host", "event", "log", "message", "database_name"]
      }

      # Tag for routing to audit_logs table
      mutate { add_tag => ["audit_log"] }
    }

    # Drop all other logs
    else {
      drop { }
    }
  }
  # Drop logs that failed main grok parsing
  else {
    drop { }
  }
}

output {
  # Output for connection logs
  if "connection_log" in [tags] {
    jdbc {
      connection_string => "jdbc:postgresql://PG_HOST_PLACEHOLDER:PG_PORT_PLACEHOLDER/PG_DATABASE_PLACEHOLDER"
      driver_class      => "org.postgresql.Driver"
      driver_jar_path   => "JDBC_JAR_PLACEHOLDER"
      username          => "PG_USER_PLACEHOLDER"
      password          => "PG_PASSWORD_PLACEHOLDER"
      statement => [
        "INSERT INTO connection_logs (log_time, username, database_name, client_ip, action, cluster_name, server_name, server_ip, application_name) VALUES (?::timestamptz, ?, ?, ?, ?, ?, ?, ?, ?)",
        "log_time", "username", "database_name", "client_ip", "action", "cluster_name", "server_name", "server_ip", "application_name"
      ]
      flush_size    => 1
      max_pool_size => 5
    }
  }

  # Output for audit logs (now includes client_ip and application_name)
  if "audit_log" in [tags] {
    jdbc {
      connection_string => "jdbc:postgresql://PG_HOST_PLACEHOLDER:PG_PORT_PLACEHOLDER/PG_DATABASE_PLACEHOLDER"
      driver_class      => "org.postgresql.Driver"
      driver_jar_path   => "JDBC_JAR_PLACEHOLDER"
      username          => "PG_USER_PLACEHOLDER"
      password          => "PG_PASSWORD_PLACEHOLDER"
      statement => [
        "INSERT INTO audit_logs (log_time, username, database_name, session_id, statement_id, audit_type, statement_text, command, object_type, object_name, cluster_name, server_name, server_ip, client_ip, application_name) VALUES (?::timestamptz, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        "log_time", "username", "database_name","session_id", "statement_id", "audit_type", "statement_text", "command", "object_type", "object_name", "cluster_name", "server_name", "server_ip", "client_ip", "application_name"
      ]
      flush_size    => 1
      max_pool_size => 5
    }
  }

  # Optional: Debug output (uncomment for troubleshooting)
  # stdout { codec => rubydebug }
}
EOF

# Replace placeholders
sed -i "s|LOG_PATH_PLACEHOLDER|$LOG_PATH|g" "$CONFIG_PATH"
sed -i "s|SINCEDB_PATH_PLACEHOLDER|$SINCEDB_PATH|g" "$CONFIG_PATH"
sed -i "s|CLUSTER_NAME_PLACEHOLDER|$CLUSTER_NAME|g" "$CONFIG_PATH"
sed -i "s|SERVER_NAME_PLACEHOLDER|$SERVER_NAME|g" "$CONFIG_PATH"
sed -i "s|SERVER_IP_PLACEHOLDER|$SERVER_IP|g" "$CONFIG_PATH"
sed -i "s|PG_HOST_PLACEHOLDER|$PG_HOST|g" "$CONFIG_PATH"
sed -i "s|PG_PORT_PLACEHOLDER|$PG_PORT|g" "$CONFIG_PATH"
sed -i "s|PG_DATABASE_PLACEHOLDER|$PG_DATABASE|g" "$CONFIG_PATH"
sed -i "s|PG_USER_PLACEHOLDER|$PG_USER|g" "$CONFIG_PATH"
sed -i "s|PG_PASSWORD_PLACEHOLDER|$PG_PASSWORD|g" "$CONFIG_PATH"
sed -i "s|JDBC_JAR_PLACEHOLDER|$JDBC_JAR|g" "$CONFIG_PATH"

log_info "? Logstash configuration created: $CONFIG_PATH"
echo ""

# Create sincedb directory if not exists
log_step "Step 9: Setting up sincedb directory..."
SINCEDB_DIR=$(dirname "$SINCEDB_PATH")
if [ ! -d "$SINCEDB_DIR" ]; then
    log_info "Creating sincedb directory: $SINCEDB_DIR"
    mkdir -p "$SINCEDB_DIR"
fi

# Set proper ownership
if id "logstash" &>/dev/null; then
    chown -R logstash:logstash "$SINCEDB_DIR" 2>/dev/null || true
    log_info "? Sincedb directory configured"
else
    log_warn "logstash user not found, skipping ownership change"
fi
echo ""

# Test Logstash configuration
log_step "Step 10: Testing Logstash configuration..."
if /usr/share/logstash/bin/logstash -t -f "$CONFIG_PATH" > /tmp/logstash-test.log 2>&1; then
    log_info "? Logstash configuration test passed"
else
    log_error "Logstash configuration test failed. Check /tmp/logstash-test.log for details"
    cat /tmp/logstash-test.log
    exit 1
fi
echo ""

# Restart Logstash
log_step "Step 11: Restarting Logstash service..."
if systemctl is-active --quiet logstash; then
    systemctl restart logstash
    log_info "? Logstash service restarted"
else
    systemctl start logstash
    log_info "? Logstash service started"
fi

# Wait a bit for Logstash to start
sleep 3

# Check Logstash status
if systemctl is-active --quiet logstash; then
    log_info "? Logstash is running"
else
    log_warn "Logstash service may not be running properly"
fi
echo ""

echo ""
log_info "========================================"
log_info "Setup completed successfully!"
log_info "========================================"
echo ""
log_info "Configuration Details:"
log_info "  Config file: $CONFIG_PATH"
log_info "  Cluster name: $CLUSTER_NAME"
log_info "  Server name: $SERVER_NAME"
log_info "  Server IP: $SERVER_IP"
echo ""
