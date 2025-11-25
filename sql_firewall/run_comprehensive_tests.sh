#!/bin/bash
# ========================================================================
# SQL Firewall RS - Comprehensive Feature Test Suite
# ========================================================================
# Tests ALL features: Learn/Permissive/Enforce, IP blocking, App blocking,
# Quiet hours, Rate limiting, Fingerprints, Regex, Keywords, Role-IP binding

# set -e removed to allow tests to continue on errors

DB="test_firewall_db"
ADMIN="postgres"
ADMIN_PASS="caghan"
USER="user1"
USER_PASS="123"
PGHOST="127.0.0.1"
PGPORT="5432"
LOGFILE="comprehensive_test.log"

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'

info() { echo -e "${BLUE}ℹ $*${NC}"; echo "[INFO] $*" >> $LOGFILE; }
ok() { echo -e "${GREEN}✓ $*${NC}"; echo "[OK] $*" >> $LOGFILE; }
err() { echo -e "${RED}✗ $*${NC}"; echo "[ERR] $*" >> $LOGFILE; }
warn() { echo -e "${YELLOW}⚠ $*${NC}"; echo "[WARN] $*" >> $LOGFILE; }

psql_postgres() { PGPASSWORD="$ADMIN_PASS" psql -h "$PGHOST" -p "$PGPORT" -U "$ADMIN" -d postgres -At -q -c "$*" 2>&1 || true; }
psql_admin() { PGPASSWORD="$ADMIN_PASS" psql -h "$PGHOST" -p "$PGPORT" -U "$ADMIN" -d "$DB" -At -q -c "$*" 2>&1 || true; }
psql_user() { PGPASSWORD="$USER_PASS" psql -h "$PGHOST" -p "$PGPORT" -U "$USER" -d "$DB" -At -q -c "$*" 2>&1 || true; }

PASSED=0
FAILED=0

# Cleanup
rm -f $LOGFILE
echo "=== SQL Firewall Comprehensive Test - $(date) ===" > $LOGFILE

info "🔧 Initializing test environment..."

# Create test database and user
info "Creating test database and user..."
psql_postgres "DROP DATABASE IF EXISTS $DB;" >/dev/null 2>&1
psql_postgres "DROP ROLE IF EXISTS $USER;" >/dev/null 2>&1
psql_postgres "CREATE DATABASE $DB;" >/dev/null 2>&1
psql_postgres "CREATE ROLE $USER WITH LOGIN PASSWORD '$USER_PASS';" >/dev/null 2>&1

# Wait for database to be ready
sleep 1

# Create extension and tables in test database
info "Setting up test database..."
psql_admin "CREATE EXTENSION IF NOT EXISTS sql_firewall_rs;" >/dev/null 2>&1
psql_admin "CREATE TABLE IF NOT EXISTS test_table (id SERIAL PRIMARY KEY, data TEXT);" >/dev/null 2>&1
psql_admin "GRANT ALL ON test_table TO $USER;" >/dev/null 2>&1
psql_admin "GRANT ALL ON SEQUENCE test_table_id_seq TO $USER;" >/dev/null 2>&1

# Cleanup existing data
psql_admin "TRUNCATE sql_firewall_activity_log RESTART IDENTITY CASCADE;" >/dev/null 2>&1
psql_admin "TRUNCATE sql_firewall_command_approvals RESTART IDENTITY CASCADE;" >/dev/null 2>&1
psql_admin "TRUNCATE sql_firewall_query_fingerprints RESTART IDENTITY CASCADE;" >/dev/null 2>&1
psql_admin "DELETE FROM sql_firewall_regex_rules WHERE description LIKE 'Test%';" >/dev/null 2>&1
psql_admin "TRUNCATE test_table RESTART IDENTITY CASCADE;" >/dev/null 2>&1

# Reset all GUCs to defaults - each in separate command for proper effect
psql_admin "ALTER SYSTEM SET sql_firewall.mode='enforce';" >/dev/null 2>&1
psql_admin "ALTER SYSTEM SET sql_firewall.enable_keyword_scan=false;" >/dev/null 2>&1
psql_admin "ALTER SYSTEM SET sql_firewall.enable_regex_scan=false;" >/dev/null 2>&1
psql_admin "ALTER SYSTEM SET sql_firewall.enable_quiet_hours=false;" >/dev/null 2>&1
psql_admin "ALTER SYSTEM SET sql_firewall.enable_rate_limiting=false;" >/dev/null 2>&1
psql_admin "ALTER SYSTEM SET sql_firewall.enable_application_blocking=false;" >/dev/null 2>&1
psql_admin "ALTER SYSTEM SET sql_firewall.enable_ip_blocking=false;" >/dev/null 2>&1
psql_admin "ALTER SYSTEM SET sql_firewall.enable_role_ip_binding=false;" >/dev/null 2>&1
psql_admin "ALTER SYSTEM SET sql_firewall.enable_fingerprint_learning=true;" >/dev/null 2>&1
psql_admin "SELECT pg_reload_conf();" >/dev/null 2>&1
sleep 2

echo ""
info "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
info "TEST 1: ENFORCE MODE - Block unapproved commands"
info "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

psql_admin "ALTER SYSTEM SET sql_firewall.mode='enforce';" >/dev/null 2>&1
psql_admin "SELECT pg_reload_conf();" >/dev/null 2>&1
sleep 1
out=$(psql_user "INSERT INTO test_table VALUES (1, 'test');" 2>&1)
if echo "$out" | grep -qi "sql_firewall\|hata\|error"; then
    ok "Enforce mode blocked unapproved INSERT"
    ((PASSED++))
else
    err "Enforce mode did not block! Output: $out"
    ((FAILED++))
fi

echo ""
info "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
info "TEST 2: LEARN MODE - Block and record"
info "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

psql_admin "ALTER SYSTEM SET sql_firewall.mode='learn';" >/dev/null 2>&1
psql_admin "SELECT pg_reload_conf();" >/dev/null 2>&1
sleep 1
out=$(psql_user "SELECT * FROM test_table LIMIT 1;" 2>&1)
if echo "$out" | grep -qi "sql_firewall\|hata"; then
    ok "Learn mode blocked unapproved SELECT"
    ((PASSED++))
else
    err "Learn mode did not block! Output: $out"
    ((FAILED++))
fi

# Approve SELECT
psql_admin "INSERT INTO sql_firewall_command_approvals (role_name, command_type, is_approved) VALUES ('$USER', 'SELECT', true) ON CONFLICT (role_name, command_type) DO UPDATE SET is_approved=true;" >/dev/null 2>&1
sleep 1

out=$(psql_user "SELECT * FROM test_table LIMIT 1;" 2>&1)
if echo "$out" | grep -qi "sql_firewall\|hata"; then
    err "SELECT still blocked after approval!"
    ((FAILED++))
else
    ok "SELECT allowed after approval"
    ((PASSED++))
fi

echo ""
info "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
info "TEST 3: PERMISSIVE MODE - Allow but log"
info "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

psql_admin "ALTER SYSTEM SET sql_firewall.mode='permissive';" >/dev/null 2>&1
psql_admin "ALTER SYSTEM SET sql_firewall.enable_fingerprint_learning=false;" >/dev/null 2>&1
psql_admin "SELECT pg_reload_conf();" >/dev/null 2>&1
sleep 2

# Insert a test row first
psql_admin "INSERT INTO test_table VALUES (999, 'to_delete');" >/dev/null 2>&1

out=$(psql_user "DELETE FROM test_table WHERE id=999;" 2>&1)
exit_code=$?
if [ $exit_code -eq 0 ] && ! echo "$out" | grep -qi "hata\|error"; then
    ok "Permissive mode allowed unapproved DELETE"
    ((PASSED++))
else
    err "Permissive mode blocked (should allow)! Output: $out"
    ((FAILED++))
fi

# Check log
cnt=$(psql_admin "SELECT count(*) FROM sql_firewall_activity_log WHERE role_name='$USER' AND action LIKE '%PERMISSIVE%';" 2>/dev/null || echo 0)
if [ "$cnt" -gt 0 ]; then
    ok "Permissive action logged ($cnt entries)"
    ((PASSED++))
else
    warn "No permissive log found"
    ((FAILED++))
fi

echo ""
info "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
info "TEST 4: KEYWORD BLACKLIST - Block dangerous keywords"
info "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

psql_admin "ALTER SYSTEM SET sql_firewall.mode='permissive';"
psql_admin "ALTER SYSTEM SET sql_firewall.enable_keyword_scan=true;"
psql_admin "ALTER SYSTEM SET sql_firewall.blacklisted_keywords='DROP,TRUNCATE,DELETE';"
psql_admin "SELECT pg_reload_conf();" >/dev/null
sleep 1

out=$(psql_user "DROP TABLE test_table;" 2>&1)
if echo "$out" | grep -qi "blacklisted keyword"; then
    ok "Keyword blacklist blocked DROP"
    ((PASSED++))
else
    err "Keyword blacklist failed! Output: $out"
    ((FAILED++))
fi

# Reset
psql_admin "ALTER SYSTEM SET sql_firewall.enable_keyword_scan=false;" >/dev/null 2>&1
psql_admin "SELECT pg_reload_conf();" >/dev/null 2>&1

echo ""
info "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
info "TEST 5: REGEX RULES - Pattern matching"
info "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

psql_admin "INSERT INTO sql_firewall_regex_rules (pattern, description, is_active) VALUES ('.*UNION.*SELECT.*', 'Test SQL injection', true) ON CONFLICT (pattern) DO UPDATE SET is_active=true;" >/dev/null
psql_admin "ALTER SYSTEM SET sql_firewall.enable_regex_scan=true;" >/dev/null 2>&1
psql_admin "SELECT pg_reload_conf();" >/dev/null 2>&1
sleep 1
    psql_admin "SELECT pg_reload_conf();" >/dev/null
sleep 1

out=$(psql_user "SELECT * FROM test_table UNION SELECT * FROM test_table;" 2>&1)
if echo "$out" | grep -qi "regex\|pattern"; then
    ok "Regex rule blocked UNION attack"
    ((PASSED++))
else
    warn "Regex rule might not have triggered. Output: $out"
    ((FAILED++))
fi

# Cleanup
psql_admin "DELETE FROM sql_firewall_regex_rules WHERE description='Test SQL injection';" >/dev/null
psql_admin "ALTER SYSTEM SET sql_firewall.enable_regex_scan=false;" >/dev/null 2>&1
    psql_admin "SELECT pg_reload_conf();" >/dev/null 2>&1
    psql_admin "SELECT pg_reload_conf();" >/dev/null

echo ""
info "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
info "TEST 6: QUIET HOURS - Time-based blocking"
info "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Set quiet hours to current time (will block immediately)
current_hour=$(date +%H)
current_min=$(date +%M)
next_min=$((current_min + 1))
if [ $next_min -ge 60 ]; then next_min=0; fi

quiet_start="${current_hour}:${current_min}"
quiet_end="${current_hour}:${next_min}"

psql_admin "ALTER SYSTEM SET sql_firewall.enable_quiet_hours=true;"
psql_admin "ALTER SYSTEM SET sql_firewall.quiet_hours_start='${quiet_start}';"
psql_admin "ALTER SYSTEM SET sql_firewall.quiet_hours_end='${quiet_end}';"
psql_admin "SELECT pg_reload_conf();" >/dev/null
sleep 1

out=$(psql_user "SELECT 1;" 2>&1)
if echo "$out" | grep -qi "quiet hours"; then
    ok "Quiet hours blocked query"
    ((PASSED++))
else
    warn "Quiet hours might not be active. Output: $out"
    ((FAILED++))
fi

# Reset
psql_admin "ALTER SYSTEM SET sql_firewall.enable_quiet_hours=false;" >/dev/null 2>&1
    psql_admin "SELECT pg_reload_conf();" >/dev/null 2>&1
    psql_admin "SELECT pg_reload_conf();" >/dev/null

echo ""
info "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
info "TEST 7: RATE LIMITING - Query throttling"
info "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

psql_admin "ALTER SYSTEM SET sql_firewall.enable_rate_limiting=true;"
psql_admin "ALTER SYSTEM SET sql_firewall.rate_limit_count=3;"
psql_admin "ALTER SYSTEM SET sql_firewall.rate_limit_seconds=5;"
psql_admin "SELECT pg_reload_conf();" >/dev/null
sleep 1

# Run 5 queries rapidly
blocked=0
for i in {1..5}; do
    out=$(psql_user "SELECT $i;" 2>&1)
    if echo "$out" | grep -qi "rate limit"; then
        ((blocked++))
    fi
done

if [ $blocked -gt 0 ]; then
    ok "Rate limiting blocked $blocked out of 5 queries"
    ((PASSED++))
else
    warn "Rate limiting did not trigger"
    ((FAILED++))
fi

# Reset
psql_admin "ALTER SYSTEM SET sql_firewall.enable_rate_limiting=false;" >/dev/null 2>&1
    psql_admin "SELECT pg_reload_conf();" >/dev/null 2>&1
    psql_admin "SELECT pg_reload_conf();" >/dev/null
sleep 6  # Wait for rate limit window to expire

echo ""
info "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
info "TEST 8: APPLICATION BLOCKING - Block specific apps"
info "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

psql_admin "ALTER SYSTEM SET sql_firewall.enable_application_blocking=true;"
psql_admin "ALTER SYSTEM SET sql_firewall.blocked_applications='evil_app,malware';"
psql_admin "SELECT pg_reload_conf();" >/dev/null
sleep 1

out=$(PGPASSWORD="$USER_PASS" PGAPPNAME="evil_app" psql -h "$PGHOST" -p "$PGPORT" -U "$USER" -d "$DB" -At -c "SELECT 1;" 2>&1)
if echo "$out" | grep -qi "application"; then
    ok "Application blocking works"
    ((PASSED++))
else
    warn "Application blocking might not have triggered. Output: $out"
    ((FAILED++))
fi

# Reset
psql_admin "ALTER SYSTEM SET sql_firewall.enable_application_blocking=false;" >/dev/null 2>&1
    psql_admin "SELECT pg_reload_conf();" >/dev/null 2>&1
    psql_admin "SELECT pg_reload_conf();" >/dev/null

echo ""
info "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
info "TEST 9: IP BLOCKING - Block specific IPs"
info "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

psql_admin "ALTER SYSTEM SET sql_firewall.enable_ip_blocking=true;"
psql_admin "ALTER SYSTEM SET sql_firewall.blocked_ips='192.168.99.99,10.0.0.1';"
psql_admin "SELECT pg_reload_conf();" >/dev/null
sleep 1

# Our test IP (127.0.0.1) should not be blocked
out=$(psql_user "SELECT 1;" 2>&1)
if echo "$out" | grep -qi "1"; then
    ok "IP blocking allows non-blocked IPs"
    ((PASSED++))
else
    err "IP blocking blocked legitimate IP!"
    ((FAILED++))
fi

# Reset
psql_admin "ALTER SYSTEM SET sql_firewall.enable_ip_blocking=false;" >/dev/null 2>&1
    psql_admin "SELECT pg_reload_conf();" >/dev/null 2>&1
    psql_admin "SELECT pg_reload_conf();" >/dev/null

echo ""
info "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
info "TEST 10: ROLE-IP BINDING - Restrict role to specific IP"
info "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

psql_admin "ALTER SYSTEM SET sql_firewall.enable_role_ip_binding=true;"
psql_admin "ALTER SYSTEM SET sql_firewall.role_ip_bindings='${USER}@192.168.1.100,admin@10.0.0.1';"
psql_admin "SELECT pg_reload_conf();" >/dev/null
sleep 1

# user1 from 127.0.0.1 should be blocked (bound to 192.168.1.100)
out=$(psql_user "SELECT 1;" 2>&1)
if echo "$out" | grep -qi "ip.*binding\|role.*ip"; then
    ok "Role-IP binding blocked wrong IP"
    ((PASSED++))
else
    warn "Role-IP binding might not have triggered. Output: $out"
    ((FAILED++))
fi

# Reset
psql_admin "ALTER SYSTEM SET sql_firewall.enable_role_ip_binding=false;" >/dev/null 2>&1
    psql_admin "SELECT pg_reload_conf();" >/dev/null 2>&1
    psql_admin "SELECT pg_reload_conf();" >/dev/null

echo ""
info "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
info "TEST 11: FINGERPRINT LEARNING - Auto-approve patterns"
info "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Clean slate
psql_admin "DELETE FROM sql_firewall_query_fingerprints WHERE role_name='$USER';" >/dev/null 2>&1
psql_admin "DELETE FROM sql_firewall_command_approvals WHERE role_name='$USER' AND command_type='UPDATE';" >/dev/null 2>&1

# Configure fingerprint learning - use Permissive mode so queries execute while learning
psql_admin "ALTER SYSTEM SET sql_firewall.mode='permissive';" >/dev/null 2>&1
psql_admin "ALTER SYSTEM SET sql_firewall.enable_fingerprint_learning=true;" >/dev/null 2>&1
psql_admin "ALTER SYSTEM SET sql_firewall.fingerprint_learn_threshold=3;" >/dev/null 2>&1
psql_admin "SELECT pg_reload_conf();" >/dev/null 2>&1
sleep 2

# Insert test data
psql_admin "INSERT INTO test_table (id, data) VALUES (1, 'initial') ON CONFLICT (id) DO UPDATE SET data='initial';" >/dev/null 2>&1

# Run same UPDATE query 4 times - should auto-approve after threshold
for i in {1..4}; do
    psql_user "UPDATE test_table SET data='test$i' WHERE id=1;" 2>&1 >/dev/null
done

# Check if fingerprint was auto-approved
fp_cnt=$(psql_admin "SELECT count(*) FROM sql_firewall_query_fingerprints WHERE role_name='$USER' AND is_approved=true;" 2>/dev/null || echo 0)
total_fps=$(psql_admin "SELECT count(*) FROM sql_firewall_query_fingerprints WHERE role_name='$USER';" 2>/dev/null || echo 0)
hit_cnt=$(psql_admin "SELECT MAX(hit_count) FROM sql_firewall_query_fingerprints WHERE role_name='$USER';" 2>/dev/null || echo 0)

if [ "$fp_cnt" -gt 0 ] && [ "$hit_cnt" -ge 3 ]; then
    ok "Fingerprint learning auto-approved pattern (approved=$fp_cnt, total=$total_fps, max_hits=$hit_cnt)"
    ((PASSED++))
else
    warn "Fingerprint learning: approved=$fp_cnt, total=$total_fps, max_hits=$hit_cnt (expected >=3)"
    ((FAILED++))
fi

echo ""
info "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
info "TEST 12: SUPERUSER BYPASS"
info "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

psql_admin "ALTER SYSTEM SET sql_firewall.mode='enforce';"
psql_admin "ALTER SYSTEM SET sql_firewall.allow_superuser_auth_bypass=true;"
psql_admin "SELECT pg_reload_conf();" >/dev/null

# Superuser should bypass firewall
out=$(psql_admin "DELETE FROM test_table WHERE id=1;" 2>&1)
if echo "$out" | grep -qi "sql_firewall\|hata\|error"; then
    err "Superuser was blocked (should bypass)!"
    ((FAILED++))
else
    ok "Superuser bypass works"
    ((PASSED++))
fi

echo ""
info "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
info "TEST 13: ACTIVITY LOG - Verify logging"
info "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

log_cnt=$(psql_admin "SELECT count(*) FROM sql_firewall_activity_log WHERE role_name='$USER';" 2>/dev/null || echo 0)
if [ "$log_cnt" -gt 3 ]; then
    ok "Activity log has $log_cnt entries for user"
    ((PASSED++))
else
    warn "Activity log might not be working properly ($log_cnt entries, expected >3)"
    ((FAILED++))
fi

echo ""
info "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "${GREEN}=====================================${NC}"
echo -e "${GREEN}   COMPREHENSIVE TEST SUMMARY${NC}"
echo -e "${GREEN}=====================================${NC}"
echo -e "Total Tests: $((PASSED + FAILED))"
echo -e "${GREEN}Passed: $PASSED${NC}"
echo -e "${RED}Failed: $FAILED${NC}"
if [ $FAILED -eq 0 ]; then
    echo -e "${GREEN}✓ ALL TESTS PASSED!${NC}"
else
    echo -e "${YELLOW}⚠ Some tests failed. Check $LOGFILE for details.${NC}"
fi
echo ""
info "Detailed results saved to: $LOGFILE"
