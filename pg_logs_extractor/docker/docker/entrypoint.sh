#!/bin/bash
set -e

echo "============================================"
echo "🚀 PostgreSQL + Logstash auto setup starting"
echo "============================================"

PG_HOST=${PG_HOST:-host.docker.internal}
PG_PORT=${PG_PORT:-5432}
PG_DB=${PG_DB:-postgres}
PG_USER=${PG_USER:-logstash_writer}
PG_PASS=${PG_PASS:-logstash_writer_pw}
PG_ADMIN_USER=${PG_ADMIN_USER:-postgres}
PG_ADMIN_PASS=${PG_ADMIN_PASS:-postgres}
CLUSTER_NAME=${CLUSTER_NAME:-pgcluster}
LOG_PATH=${LOG_PATH:-/var/log/postgresql}
SINCEDB_PATH=${SINCEDB_PATH:-/usr/share/logstash/data/sincedb-combined-logs}
CONFIG_PATH=${CONFIG_PATH:-/usr/share/logstash/pipeline/logstash.conf}
JDBC_JAR="/usr/share/logstash/logstash-core/lib/jars/postgresql-42.7.8.jar"

# PostgreSQL bağlantısını test et
echo "🔍 Testing PostgreSQL connection..."
PGPASSWORD="$PG_ADMIN_PASS" psql -h "$PG_HOST" -p "$PG_PORT" -U "$PG_ADMIN_USER" -d "$PG_DB" -c "SELECT 1;" >/dev/null 2>&1 || {
  echo "❌ PostgreSQL connection failed"
  exit 1
}
echo "✅ PostgreSQL reachable"

# Kullanıcı ve tabloları oluştur
echo "🔧 Creating user and tables..."
PGPASSWORD="$PG_ADMIN_PASS" psql -h "$PG_HOST" -p "$PG_PORT" -U "$PG_ADMIN_USER" -d "$PG_DB" <<EOF
DO \$\$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = '$PG_USER') THEN
        CREATE USER $PG_USER WITH PASSWORD '$PG_PASS';
    ELSE
        ALTER USER $PG_USER WITH PASSWORD '$PG_PASS';
    END IF;
END
\$\$;

CREATE TABLE IF NOT EXISTS connection_logs (
    id SERIAL PRIMARY KEY,
    log_time timestamptz,
    username text,
    database_name text,
    client_ip text,
    action text,
    cluster_name text,
    server_name text,
    server_ip text,
    application_name text
);

CREATE TABLE IF NOT EXISTS audit_logs (
    id SERIAL PRIMARY KEY,
    log_time timestamptz,
    username text,
    database_name text,
    session_id text,
    statement_id text,
    audit_type text,
    statement_text text,
    command text,
    object_type text,
    object_name text,
    cluster_name text,
    server_name text,
    server_ip text,
    client_ip text,
    application_name text
);

GRANT INSERT, SELECT ON connection_logs, audit_logs TO $PG_USER;
GRANT USAGE, SELECT ON SEQUENCE audit_logs_id_seq TO $PG_USER;
CREATE EXTENSION IF NOT EXISTS pgaudit;
EOF
echo "✅ Tables ready."

# Pipeline oluştur
echo "🧩 Creating Logstash pipeline..."
cat > "$CONFIG_PATH" <<EOF
input {
  file {
    path              => "$LOG_PATH/postgresql-*.log"
    start_position    => "beginning"
    sincedb_path      => "$SINCEDB_PATH"
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
      "cluster_name" => "$CLUSTER_NAME"
      "server_name" => "$SERVER_NAME"
      "server_ip" => "$SERVER_IP"
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
        '^%{TIMESTAMP_ISO8601:log_time}\s+(?<tz>(?:[+-]\d{2}(?::?\d{2})?|UTC))\s+\[%{NUMBER:pid}\]\s+user=%{DATA:username},db=%{DATA:database_name}, client_ip=%{DATA:client_ip}\s+app=%{DATA:application_name}\s*(?:LOG|ERROR|FATAL|DETAIL|STATEMENT):\s+%{GREEDYDATA:pg_message}$'
      ]
    }
    tag_on_failure => ["_grokparsefailure"]
  }
  if [username] == "testuser" {
    drop { }
  }
  if [database_name] == "test" {
    drop { }
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

      mutate {
        strip => ["username", "database_name", "client_ip", "action", "cluster_name", "server_name", "server_ip", "application_name"]
        remove_field => ["log_time_full", "tz", "pid", "pg_message", "@version", "host", "event", "log", "message"]
      }

      mutate { add_tag => ["connection_log"] }
    }
    else if [pg_message] =~ /password authentication failed/ {

      mutate { add_field => { "action" => "connection_failed" } }
      mutate {
        strip => ["username", "database_name", "client_ip", "action", "cluster_name", "server_name", "server_ip", "application_name"]
        remove_field => ["log_time_full", "tz", "pid", "pg_message", "@version", "host", "event", "log", "message"]
      }
      mutate { add_tag => ["connection_log"] }

    }
    # Route 2: Audit logs
    else if [pg_message] =~ /^AUDIT:/ {

      grok {
        match => {
          "pg_message" => "AUDIT:\s+SESSION,%{NUMBER:session_id},%{NUMBER:statement_id},%{WORD:audit_type},%{GREEDYDATA:statement_details}"
        }
      }

      grok {
        match => {
          "statement_details" => "(?<command>[^,]*),(?<object_type>[^,]*),(?<object_name>[^,]*),%{GREEDYDATA:statement_text}"
        }
        overwrite => ["command", "object_type", "object_name", "statement_text"]
      }

      mutate {
        gsub => [
          "statement_text", ",<not logged>", "",
          "statement_text", "^\"|\"$", ""          
        ]
        strip => ["statement_text", "database_name"]
      }

      if [object_type] == "," or [object_type] == "" {
        mutate { replace => { "object_type" => "" } }
      }
      if [object_name] == "," or [object_name] == "" {
        mutate { replace => { "object_name" => "" } }
      }

      mutate {
        strip => ["username", "session_id", "statement_id", "audit_type", "statement_text", "command", "object_type", "object_name", "cluster_name", "server_name", "server_ip", "client_ip", "application_name"]
        remove_field => ["statement_details", "tz", "pid", "pg_message", "log_time_full", "@version", "host", "event", "log", "message"]
      }

      mutate { add_tag => ["audit_log"] }
    }

    else {
      drop { }
    }
  } else {
    drop { }
  }
}

output {
  if "connection_log" in [tags] {
    jdbc {
      connection_string => "jdbc:postgresql://$PG_HOST:$PG_PORT/$PG_DB"
      driver_class      => "org.postgresql.Driver"
      driver_jar_path   => "$JDBC_JAR"
      username          => "$PG_USER"
      password          => "$PG_PASS"
      statement => [
        "INSERT INTO connection_logs (log_time, username, database_name, client_ip, action, cluster_name, server_name, server_ip, application_name) VALUES (?::timestamptz, ?, ?, ?, ?, ?, ?, ?, ?)",
        "log_time","username","database_name","client_ip","action","cluster_name","server_name","server_ip","application_name"
      ]
      flush_size => 1
      max_pool_size => 5
    }
  }

  if "audit_log" in [tags] {
    jdbc {
      connection_string => "jdbc:postgresql://$PG_HOST:$PG_PORT/$PG_DB"
      driver_class      => "org.postgresql.Driver"
      driver_jar_path   => "$JDBC_JAR"
      username          => "$PG_USER"
      password          => "$PG_PASS"
      statement => [
        "INSERT INTO audit_logs (log_time, username, database_name, session_id, statement_id, audit_type, statement_text, command, object_type, object_name, cluster_name, server_name, server_ip, client_ip, application_name) VALUES (?::timestamptz, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        "log_time","username","database_name","session_id","statement_id","audit_type","statement_text","command","object_type","object_name","cluster_name","server_name","server_ip","client_ip","application_name"
      ]
      flush_size => 1
      max_pool_size => 5
    }
  }
  stdout { codec => rubydebug }
}
EOF
echo "✅ Pipeline written to $CONFIG_PATH"

if /usr/share/logstash/bin/logstash --path.settings /usr/share/logstash/config -t -f "$CONFIG_PATH" > /tmp/logstash-test.log 2>&1; then
    echo "✅ Configuration test passed."
    
else
    echo "❌ Configuration test failed. Showing details:"
    cat /tmp/logstash-test.log
    exit 1
fi
echo ""
echo "🚀 Starting Logstash..."
exec /usr/share/logstash/bin/logstash --path.settings /usr/share/logstash/config -f "$CONFIG_PATH"
