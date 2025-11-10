#!/bin/bash
# SQL Firewall Performance Benchmark
# Compares firewall OFF vs ON performance

set -e

DB="benchmark_firewall_db"
USER="postgres"
PGPASSWORD="caghan"
export PGPASSWORD

echo "========================================="
echo "SQL Firewall Performance Benchmark"
echo "========================================="
echo ""

# Cleanup function
cleanup() {
    echo "Cleaning up..."
    psql -U $USER -d postgres -c "DROP DATABASE IF EXISTS $DB;" 2>/dev/null || true
}

trap cleanup EXIT

# Create test database
echo "1. Creating test database..."
psql -U $USER -d postgres -c "DROP DATABASE IF EXISTS $DB;" 2>/dev/null || true
psql -U $USER -d postgres -c "CREATE DATABASE $DB;"

# Create test table
echo "2. Creating test table with sample data..."
psql -U $USER -d $DB <<EOF
CREATE TABLE benchmark_test (
    id SERIAL PRIMARY KEY,
    name TEXT,
    value INTEGER,
    created_at TIMESTAMP DEFAULT NOW()
);

-- Insert 10000 rows
INSERT INTO benchmark_test (name, value)
SELECT 
    'test_' || generate_series,
    (random() * 1000)::INTEGER
FROM generate_series(1, 10000);

ANALYZE benchmark_test;
EOF

echo ""
echo "========================================="
echo "PHASE 1: Baseline (NO FIREWALL)"
echo "========================================="
echo ""

# Run pgbench without firewall
echo "Running pgbench with custom script (10 clients, 1000 transactions)..."
cat > /tmp/bench_script.sql <<EOF
\set id random(1, 10000)
SELECT * FROM benchmark_test WHERE id = :id;
INSERT INTO benchmark_test (name, value) VALUES ('bench_' || :id, :id);
UPDATE benchmark_test SET value = value + 1 WHERE id = :id;
DELETE FROM benchmark_test WHERE id > 9000 AND value < 100;
EOF

pgbench -U $USER -d $DB -c 10 -j 2 -t 1000 -f /tmp/bench_script.sql -n > /tmp/bench_no_firewall.txt 2>&1

echo "Results (NO FIREWALL):"
cat /tmp/bench_no_firewall.txt | grep -E "(tps|latency average|initial connection)"
BASELINE_TPS=$(cat /tmp/bench_no_firewall.txt | grep "tps =" | awk '{print $3}')

echo ""
echo "========================================="
echo "PHASE 2: Installing Firewall"
echo "========================================="
echo ""

# Install firewall
echo "Installing SQL Firewall extension..."
psql -U $USER -d $DB -c "CREATE EXTENSION IF NOT EXISTS sql_firewall_rs;"

# Configure firewall in permissive mode
echo "Configuring firewall (permissive mode)..."
psql -U $USER -d $DB <<EOF
ALTER SYSTEM SET sql_firewall.mode = 'permissive';
ALTER SYSTEM SET sql_firewall.enable_fingerprint_learning = true;
ALTER SYSTEM SET sql_firewall.fingerprint_learn_threshold = 5;
ALTER SYSTEM SET sql_firewall.enable_regex_scan = false;
ALTER SYSTEM SET sql_firewall.enable_rate_limiting = false;
SELECT pg_reload_conf();

-- Approve all commands for benchmark user
INSERT INTO sql_firewall_command_approvals (role_name, command_type, is_approved)
VALUES 
    ('$USER', 'SELECT', true),
    ('$USER', 'INSERT', true),
    ('$USER', 'UPDATE', true),
    ('$USER', 'DELETE', true)
ON CONFLICT (role_name, command_type) DO UPDATE SET is_approved = true;
EOF

echo ""
echo "========================================="
echo "PHASE 3: With Firewall (Permissive Mode)"
echo "========================================="
echo ""

# Run same benchmark with firewall
echo "Running pgbench with firewall enabled..."
pgbench -U $USER -d $DB -c 10 -j 2 -t 1000 -f /tmp/bench_script.sql -n > /tmp/bench_with_firewall_permissive.txt 2>&1

echo "Results (FIREWALL - Permissive Mode):"
cat /tmp/bench_with_firewall_permissive.txt | grep -E "(tps|latency average|initial connection)"
FIREWALL_TPS_PERMISSIVE=$(cat /tmp/bench_with_firewall_permissive.txt | grep "tps =" | awk '{print $3}')

echo ""
echo "========================================="
echo "PHASE 4: With Firewall (Enforce Mode + Regex)"
echo "========================================="
echo ""

# Enable enforce mode with regex
psql -U $USER -d $DB <<EOF
ALTER SYSTEM SET sql_firewall.mode = 'enforce';
ALTER SYSTEM SET sql_firewall.enable_regex_scan = true;
SELECT pg_reload_conf();

-- Add some regex patterns
INSERT INTO sql_firewall_regex_rules (pattern, description, is_active) VALUES
    ('.*UNION.*SELECT.*', 'SQL Injection: UNION', true),
    ('.*OR.*1.*=.*1.*', 'SQL Injection: OR tautology', true),
    ('.*;.*--.*', 'SQL Injection: comment', true);
EOF

echo "Running pgbench with full firewall protection..."
pgbench -U $USER -d $DB -c 10 -j 2 -t 1000 -f /tmp/bench_script.sql -n > /tmp/bench_with_firewall_enforce.txt 2>&1

echo "Results (FIREWALL - Enforce Mode + Regex):"
cat /tmp/bench_with_firewall_enforce.txt | grep -E "(tps|latency average|initial connection)"
FIREWALL_TPS_ENFORCE=$(cat /tmp/bench_with_firewall_enforce.txt | grep "tps =" | awk '{print $3}')

echo ""
echo "========================================="
echo "PHASE 5: Cache Statistics"
echo "========================================="
echo ""

psql -U $USER -d $DB <<EOF
SELECT 
    COUNT(*) as total_fingerprints,
    COUNT(*) FILTER (WHERE is_approved) as approved_count,
    AVG(hit_count) as avg_hits,
    MAX(hit_count) as max_hits
FROM sql_firewall_query_fingerprints;

SELECT 
    COUNT(*) as total_activity_logs,
    COUNT(*) FILTER (WHERE action LIKE '%ALLOWED%') as allowed_count,
    COUNT(*) FILTER (WHERE action LIKE '%BLOCKED%') as blocked_count
FROM sql_firewall_activity_log;
EOF

echo ""
echo "========================================="
echo "SUMMARY"
echo "========================================="
echo ""

# Calculate overhead
OVERHEAD_PERMISSIVE=$(echo "scale=2; (($BASELINE_TPS - $FIREWALL_TPS_PERMISSIVE) / $BASELINE_TPS) * 100" | bc)
OVERHEAD_ENFORCE=$(echo "scale=2; (($BASELINE_TPS - $FIREWALL_TPS_ENFORCE) / $BASELINE_TPS) * 100" | bc)

echo "Baseline (No Firewall):           $BASELINE_TPS tps"
echo "Permissive Mode:                  $FIREWALL_TPS_PERMISSIVE tps (${OVERHEAD_PERMISSIVE}% overhead)"
echo "Enforce Mode + Regex:             $FIREWALL_TPS_ENFORCE tps (${OVERHEAD_ENFORCE}% overhead)"
echo ""
echo "Test configuration:"
echo "  - 10 concurrent clients"
echo "  - 1000 transactions per client"
echo "  - Mixed workload: SELECT, INSERT, UPDATE, DELETE"
echo "  - 10,000 rows in test table"
echo ""
echo "Firewall configuration:"
echo "  - Permissive: All checks enabled, no blocking"
echo "  - Enforce: Full protection + 3 regex patterns"
echo "  - Fingerprint cache: 4096 entries"
echo "  - Learn threshold: 5 hits"
echo ""

# Full results
echo "Full benchmark results saved to:"
echo "  - /tmp/bench_no_firewall.txt"
echo "  - /tmp/bench_with_firewall_permissive.txt"
echo "  - /tmp/bench_with_firewall_enforce.txt"
echo ""

# Cleanup temp files
rm -f /tmp/bench_script.sql

echo "Benchmark complete!"
