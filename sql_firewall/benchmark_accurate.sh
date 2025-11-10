#!/bin/bash
# More accurate benchmark with database restart between phases

set -e

DB="benchmark_firewall_db"
USER="postgres"
PGPASSWORD="caghan"
export PGPASSWORD

echo "========================================="
echo "SQL Firewall Accurate Performance Test"
echo "========================================="
echo ""

cleanup() {
    psql -U $USER -d postgres -c "DROP DATABASE IF EXISTS $DB;" 2>/dev/null || true
}

trap cleanup EXIT

# Function to restart PostgreSQL and clear caches
restart_postgres() {
    echo "Restarting PostgreSQL to clear caches..."
    sudo systemctl restart postgresql-16
    sleep 3
    echo "PostgreSQL restarted."
}

# Setup database
setup_db() {
    echo "Setting up test database..."
    psql -U $USER -d postgres -c "DROP DATABASE IF EXISTS $DB;" 2>/dev/null || true
    psql -U $USER -d postgres -c "CREATE DATABASE $DB;"
    
    psql -U $USER -d $DB <<EOF
CREATE TABLE benchmark_test (
    id SERIAL PRIMARY KEY,
    name TEXT,
    value INTEGER,
    created_at TIMESTAMP DEFAULT NOW()
);

INSERT INTO benchmark_test (name, value)
SELECT 'test_' || generate_series, (random() * 1000)::INTEGER
FROM generate_series(1, 10000);

ANALYZE benchmark_test;
EOF
}

# Benchmark script
cat > /tmp/bench_script.sql <<EOF
\set id random(1, 10000)
SELECT * FROM benchmark_test WHERE id = :id;
INSERT INTO benchmark_test (name, value) VALUES ('bench_' || :id, :id);
UPDATE benchmark_test SET value = value + 1 WHERE id = :id;
EOF

echo ""
echo "========================================="
echo "TEST 1: NO FIREWALL (Fresh Start)"
echo "========================================="
restart_postgres
setup_db
echo "Running benchmark..."
pgbench -U $USER -d $DB -c 10 -j 2 -t 500 -f /tmp/bench_script.sql -n 2>&1 | tee /tmp/bench_no_firewall.txt
BASELINE_TPS=$(cat /tmp/bench_no_firewall.txt | grep "tps =" | awk '{print $3}')
BASELINE_LAT=$(cat /tmp/bench_no_firewall.txt | grep "latency average" | awk '{print $4}')

echo ""
echo "========================================="
echo "TEST 2: FIREWALL PERMISSIVE (Fresh Start)"
echo "========================================="
restart_postgres
setup_db
psql -U $USER -d $DB -c "CREATE EXTENSION sql_firewall_rs;"
psql -U $USER -d $DB <<EOF
ALTER SYSTEM SET sql_firewall.mode = 'permissive';
ALTER SYSTEM SET sql_firewall.enable_fingerprint_learning = true;
ALTER SYSTEM SET sql_firewall.enable_regex_scan = false;
SELECT pg_reload_conf();

INSERT INTO sql_firewall_command_approvals (role_name, command_type, is_approved)
VALUES 
    ('$USER', 'SELECT', true),
    ('$USER', 'INSERT', true),
    ('$USER', 'UPDATE', true)
ON CONFLICT (role_name, command_type) DO UPDATE SET is_approved = true;
EOF
echo "Running benchmark..."
pgbench -U $USER -d $DB -c 10 -j 2 -t 500 -f /tmp/bench_script.sql -n 2>&1 | tee /tmp/bench_permissive.txt
PERMISSIVE_TPS=$(cat /tmp/bench_permissive.txt | grep "tps =" | awk '{print $3}')
PERMISSIVE_LAT=$(cat /tmp/bench_permissive.txt | grep "latency average" | awk '{print $4}')

echo ""
echo "========================================="
echo "TEST 3: FIREWALL ENFORCE + REGEX (Fresh Start)"
echo "========================================="
restart_postgres
setup_db
psql -U $USER -d $DB -c "CREATE EXTENSION sql_firewall_rs;"
psql -U $USER -d $DB <<EOF
ALTER SYSTEM SET sql_firewall.mode = 'enforce';
ALTER SYSTEM SET sql_firewall.enable_fingerprint_learning = true;
ALTER SYSTEM SET sql_firewall.enable_regex_scan = true;
SELECT pg_reload_conf();

INSERT INTO sql_firewall_command_approvals (role_name, command_type, is_approved)
VALUES 
    ('$USER', 'SELECT', true),
    ('$USER', 'INSERT', true),
    ('$USER', 'UPDATE', true)
ON CONFLICT (role_name, command_type) DO UPDATE SET is_approved = true;

INSERT INTO sql_firewall_regex_rules (pattern, description, is_active) VALUES
    ('.*UNION.*SELECT.*', 'UNION injection', true),
    ('.*OR.*1.*=.*1.*', 'OR tautology', true),
    ('.*;.*--.*', 'Comment injection', true);
EOF
echo "Running benchmark..."
pgbench -U $USER -d $DB -c 10 -j 2 -t 500 -f /tmp/bench_script.sql -n 2>&1 | tee /tmp/bench_enforce.txt
ENFORCE_TPS=$(cat /tmp/bench_enforce.txt | grep "tps =" | awk '{print $3}')
ENFORCE_LAT=$(cat /tmp/bench_enforce.txt | grep "latency average" | awk '{print $4}')

echo ""
echo "========================================="
echo "ACCURATE RESULTS"
echo "========================================="
echo ""
printf "%-30s %12s %15s\n" "Configuration" "TPS" "Avg Latency"
echo "------------------------------------------------------------"
printf "%-30s %12.2f %15s ms\n" "Baseline (No Firewall)" "$BASELINE_TPS" "$BASELINE_LAT"
printf "%-30s %12.2f %15s ms\n" "Firewall (Permissive)" "$PERMISSIVE_TPS" "$PERMISSIVE_LAT"
printf "%-30s %12.2f %15s ms\n" "Firewall (Enforce + Regex)" "$ENFORCE_TPS" "$ENFORCE_LAT"
echo ""

OVERHEAD_PERM=$(echo "scale=2; (($PERMISSIVE_TPS - $BASELINE_TPS) / $BASELINE_TPS) * 100" | bc)
OVERHEAD_ENF=$(echo "scale=2; (($ENFORCE_TPS - $BASELINE_TPS) / $BASELINE_TPS) * 100" | bc)

echo "Performance Impact:"
echo "  Permissive Mode: ${OVERHEAD_PERM}%"
echo "  Enforce + Regex: ${OVERHEAD_ENF}%"
echo ""
echo "Note: Each test ran with fresh PostgreSQL restart to eliminate cache effects."

rm -f /tmp/bench_script.sql
