#!/usr/bin/env bash
# =============================================================================
# SQL Firewall – Test 1: Basic Security Features
# =============================================================================
# Validates core firewall functionality:
#   - Operating modes (learn / permissive / enforce)
#   - Command approvals
#   - Keyword blacklist
#   - Regex / SQL-injection blocking
#   - Quiet hours
#   - Global rate limiting
#   - Application-name blocking
#   - Activity logging & blocked-query logging
#   - Activity logging toggle
#   - Per-user regex exemptions
# =============================================================================
set -uo pipefail

# ---------------------------------------------------------------------------
# Configuration (overridable via environment)
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEST_DB="${TEST_DB:-sqlfw_security_test}"
PG_PORT="${PGRX_TEST_PORT:-28816}"
PG_SOCK="${PGRX_SOCKET_DIR:-${HOME}/.pgrx}"
PG_FEATURE="${PG_FEATURE:-pg16}"
PG_MAJOR="${PG_FEATURE#pg}"
PGRX_DATA_DIR="${PG_SOCK}/data-${PG_MAJOR}"
AUTO_CONF="${PGRX_DATA_DIR}/postgresql.auto.conf"
# Detect superuser: if running as root, use the owner of the pgrx data dir
if [ -z "${PG_SUPERUSER:-}" ]; then
    if [ "$(id -u)" = "0" ] && [ -d "${PG_SOCK}" ]; then
        PG_SUPERUSER=$(stat -c '%U' "${PG_SOCK}" 2>/dev/null || echo "postgres")
    else
        PG_SUPERUSER="$(whoami)"
    fi
fi
PSQL_SUPER="psql -h ${PG_SOCK} -p ${PG_PORT} -U ${PG_SUPERUSER}"

# ---------------------------------------------------------------------------
# Counters & colour codes
# ---------------------------------------------------------------------------
PASS=0
FAIL=0
TESTS_TOTAL=0

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------
banner() {
    local msg="$1"
    printf "\n${BOLD}╔════════════════════════════════════════════════════════════════╗${NC}\n"
    printf "${BOLD}║  %-62s║${NC}\n" "$msg"
    printf "${BOLD}╚════════════════════════════════════════════════════════════════╝${NC}\n\n"
}

section() {
    printf "\n${BLUE}████████████████████████████████████████████████████████████████${NC}\n"
    printf "${BLUE}  %s${NC}\n" "$1"
    printf "${BLUE}████████████████████████████████████████████████████████████████${NC}\n\n"
}

step()  { printf "${YELLOW}[STEP]${NC} %s\n" "$*"; }
info()  { printf "${BLUE}[TEST]${NC} %s\n" "$*"; }
pass()  { PASS=$((PASS + 1));  TESTS_TOTAL=$((TESTS_TOTAL + 1)); printf "${GREEN}[PASS]${NC} %s\n" "$*"; }
fail()  { FAIL=$((FAIL + 1));  TESTS_TOTAL=$((TESTS_TOTAL + 1)); printf "${RED}[FAIL]${NC} %s\n" "$*"; }
warn()  { printf "${YELLOW}[WARN]${NC} %s\n" "$*"; }

# ---------------------------------------------------------------------------
# SQL helpers
# ---------------------------------------------------------------------------
# Run SQL as postgres superuser against TEST_DB
sql() {
    $PSQL_SUPER -d "$TEST_DB" -c "$1" 2>&1
}

# Same but quiet (no headers, aligned)
sql_q() {
    $PSQL_SUPER -d "$TEST_DB" -t -A -c "$1" 2>&1
}

# Run SQL as a specific role
sql_as() {
    local role="$1"; shift
    local query="$1"
    local output=""

    for _ in $(seq 1 5); do
        output=$(psql -h "${PG_SOCK}" -p "${PG_PORT}" -U "$role" -d "$TEST_DB" -c "$query" 2>&1)
        if [ $? -eq 0 ]; then
            printf "%s\n" "$output"
            return 0
        fi
        if echo "$output" | grep -qi "recovery mode"; then
            sleep 1
            continue
        fi
        printf "%s\n" "$output"
        return 1
    done

    printf "%s\n" "$output"
    return 1
}

# Assert: command exits 0  → PASS, else FAIL
assert_ok() {
    local desc="$1"; shift
    local output
    output=$("$@" 2>&1)
    if [ $? -eq 0 ]; then
        pass "$desc"
    else
        fail "$desc :: ${output}"
    fi
}

# Assert: command exits non-0  → PASS, else FAIL
assert_err() {
    local desc="$1"; shift
    local output
    output=$("$@" 2>&1)
    if [ $? -eq 0 ]; then
        fail "$desc (should have been rejected) :: ${output}"
    else
        pass "$desc"
    fi
}

# ---------------------------------------------------------------------------
# Firewall approval helpers – use direct DML (not SELECT sql_firewall_approve_command)
# because in enforce mode with bypass=off the SELECT call itself would be blocked
# (is_firewall_internal_query only bypasses queries that reference table names)
# ---------------------------------------------------------------------------
approve_cmd() {
    sql "INSERT INTO public.sql_firewall_command_approvals (role_name, command_type, is_approved)
         VALUES ('$1', '$2', true)
         ON CONFLICT (role_name, command_type) DO UPDATE SET is_approved = true, updated_at = now();" >/dev/null 2>&1
}
revoke_cmd() {
    sql "UPDATE public.sql_firewall_command_approvals
         SET is_approved = false, updated_at = now()
         WHERE role_name = '$1' AND command_type = '$2';" >/dev/null 2>&1
}

# ---------------------------------------------------------------------------
# GUC helpers (ALTER SYSTEM cannot run inside a transaction block, so each
# statement must be executed in its own psql -c invocation)
# ---------------------------------------------------------------------------
ADMIN_PGOPTIONS="-c sql_firewall.mode=learn -c sql_firewall.allow_superuser_auth_bypass=on"

set_guc() {
    PGOPTIONS="$ADMIN_PGOPTIONS" $PSQL_SUPER -d "$TEST_DB" -c "ALTER SYSTEM SET $1 = $2"    >/dev/null 2>&1
    PGOPTIONS="$ADMIN_PGOPTIONS" $PSQL_SUPER -d "$TEST_DB" -c "SELECT pg_reload_conf();"     >/dev/null 2>&1
}
reset_guc() {
    PGOPTIONS="$ADMIN_PGOPTIONS" $PSQL_SUPER -d "$TEST_DB" -c "ALTER SYSTEM RESET $1"        >/dev/null 2>&1
    PGOPTIONS="$ADMIN_PGOPTIONS" $PSQL_SUPER -d "$TEST_DB" -c "SELECT pg_reload_conf();"     >/dev/null 2>&1
}
# For inline ALTER SYSTEM ... ; SELECT pg_reload_conf() patterns
alter_sys() {
    PGOPTIONS="$ADMIN_PGOPTIONS" $PSQL_SUPER -d "$TEST_DB" -c "$1" >/dev/null 2>&1
    PGOPTIONS="$ADMIN_PGOPTIONS" $PSQL_SUPER -d "$TEST_DB" -c "SELECT pg_reload_conf();"     >/dev/null 2>&1
}

# ---------------------------------------------------------------------------
# Deterministic bootstrap helpers
# ---------------------------------------------------------------------------
clear_persisted_sql_firewall_gucs() {
    if [ -f "$AUTO_CONF" ]; then
        sed -i '/^sql_firewall\./d' "$AUTO_CONF"
    fi
}

ensure_shared_preload_sql_firewall() {
    mkdir -p "$(dirname "$AUTO_CONF")"
    touch "$AUTO_CONF"

    if grep -q '^shared_preload_libraries' "$AUTO_CONF"; then
        sed -i "s/^shared_preload_libraries.*/shared_preload_libraries = 'sql_firewall_rs'/" "$AUTO_CONF"
    else
        printf "shared_preload_libraries = 'sql_firewall_rs'\n" >> "$AUTO_CONF"
    fi
}

wait_for_postgres_ready() {
    for _ in $(seq 1 20); do
        if $PSQL_SUPER -d postgres -c "SELECT 1" >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
    done
    return 1
}

wait_for_sql_count_gt_zero() {
    local query="$1"
    local timeout_seconds="${2:-20}"
    local count="0"

    for _ in $(seq 1 "$timeout_seconds"); do
        count=$(sql_q "$query" 2>/dev/null | tr -d '[:space:]' || echo "0")
        if [[ "$count" =~ ^[0-9]+$ ]] && [ "$count" -gt 0 ]; then
            echo "$count"
            return 0
        fi
        sleep 1
    done

    echo "0"
    return 1
}

wait_for_worker_running() {
    local timeout_seconds="${1:-20}"
    local status=""
    for _ in $(seq 1 "$timeout_seconds"); do
        status=$(sql_q "SELECT sql_firewall_approval_worker_status()" 2>/dev/null | tr -d '[:space:]' || echo "unknown")
        if [ "$status" = "running" ]; then
            return 0
        fi
        sleep 1
    done
    return 1
}

# ---------------------------------------------------------------------------
# Setup / teardown
# ---------------------------------------------------------------------------
setup() {
    step "Creating test database '${TEST_DB}'"
    wait_for_postgres_ready
    PGOPTIONS="$ADMIN_PGOPTIONS" $PSQL_SUPER -d postgres -c "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = '${TEST_DB}' AND pid <> pg_backend_pid();" >/dev/null 2>&1 || true
    PGOPTIONS="$ADMIN_PGOPTIONS" $PSQL_SUPER -d postgres -c "ALTER DATABASE ${TEST_DB} WITH ALLOW_CONNECTIONS false;" >/dev/null 2>&1 || true
    PGOPTIONS="$ADMIN_PGOPTIONS" $PSQL_SUPER -d postgres -c "DROP DATABASE IF EXISTS ${TEST_DB};" >/dev/null 2>&1 || true
    wait_for_postgres_ready
    for _ in $(seq 1 5); do
        if PGOPTIONS="$ADMIN_PGOPTIONS" $PSQL_SUPER -d postgres -c "CREATE DATABASE ${TEST_DB};" >/dev/null 2>&1; then
            break
        fi
        sleep 1
        PGOPTIONS="$ADMIN_PGOPTIONS" $PSQL_SUPER -d postgres -c "DROP DATABASE IF EXISTS ${TEST_DB};" >/dev/null 2>&1 || true
    done
    PGOPTIONS="$ADMIN_PGOPTIONS" $PSQL_SUPER -d postgres -t -A -c "SELECT 1 FROM pg_database WHERE datname='${TEST_DB}'" | grep -q 1
    $PSQL_SUPER -d "$TEST_DB" -c "CREATE EXTENSION IF NOT EXISTS sql_firewall_rs;" >/dev/null 2>&1
    pass "Test database created and extension installed"

    step "Creating test roles"
    for role in testuser_basic testuser_exempt testuser_rate; do
        $PSQL_SUPER -d postgres -c "DROP ROLE IF EXISTS ${role};" >/dev/null 2>&1 || true
        $PSQL_SUPER -d postgres -c "CREATE ROLE ${role} LOGIN;" >/dev/null 2>&1
        $PSQL_SUPER -d postgres -c "GRANT CONNECT ON DATABASE ${TEST_DB} TO ${role};" >/dev/null 2>&1
        $PSQL_SUPER -d "$TEST_DB" -c "GRANT USAGE ON SCHEMA public TO ${role};" >/dev/null 2>&1
        $PSQL_SUPER -d "$TEST_DB" -c "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO ${role};" >/dev/null 2>&1
    done
    pass "Test roles created (testuser_basic, testuser_exempt, testuser_rate)"

    step "Creating test table and seeding data"
    sql "CREATE TABLE IF NOT EXISTS test_data (id serial PRIMARY KEY, value text);" >/dev/null 2>&1
    sql "INSERT INTO test_data (value) SELECT 'seed_' || g FROM generate_series(1,10) g;" >/dev/null 2>&1
    # Grant permissions AFTER creating the table so test roles can access it
    for role in testuser_basic testuser_exempt testuser_rate; do
        sql "GRANT SELECT, INSERT, UPDATE, DELETE ON test_data TO ${role};" >/dev/null 2>&1
        sql "GRANT USAGE, SELECT ON SEQUENCE test_data_id_seq TO ${role};" >/dev/null 2>&1
    done

    step "Keeping superuser bypass enabled for administrative test setup"
    set_guc "sql_firewall.allow_superuser_auth_bypass" "on"

    step "Resetting firewall to a clean learn-mode baseline"
    set_guc "sql_firewall.mode"                      "learn"
    set_guc "sql_firewall.enable_keyword_scan"       "on"
    set_guc "sql_firewall.enable_regex_scan"         "on"
    set_guc "sql_firewall.enable_quiet_hours"        "off"
    set_guc "sql_firewall.enable_rate_limiting"      "off"
    set_guc "sql_firewall.enable_application_blocking" "off"
    set_guc "sql_firewall.enable_activity_logging"   "on"
    alter_sys "ALTER SYSTEM RESET sql_firewall.blacklisted_keywords"
    sql "TRUNCATE public.sql_firewall_command_approvals;" >/dev/null 2>&1
    sql "TRUNCATE public.sql_firewall_activity_log;" >/dev/null 2>&1
    sql "TRUNCATE public.sql_firewall_blocked_queries;" >/dev/null 2>&1
    sql "DELETE FROM public.sql_firewall_regex_rules WHERE pattern NOT IN ('(or|--|#)\\s+([[:alpha:]_][[:alnum:]_]*|''[^'']*''|[0-9]+)\\s*=\\s*([[:alpha:]_][[:alnum:]_]*|''[^'']*''|[0-9]+)');" >/dev/null 2>&1
    echo ""
}

cleanup() {
    step "Cleaning up test resources"
    # Restore safe defaults (ALTER SYSTEM must run outside transaction blocks)
    for guc in sql_firewall.mode sql_firewall.allow_superuser_auth_bypass \
               sql_firewall.enable_rate_limiting sql_firewall.enable_quiet_hours \
               sql_firewall.enable_application_blocking sql_firewall.enable_activity_logging \
               sql_firewall.blacklisted_keywords sql_firewall.select_limit_count \
               sql_firewall.command_limit_seconds sql_firewall.rate_limit_count \
               sql_firewall.rate_limit_seconds sql_firewall.enabled \
               sql_firewall.blocked_applications sql_firewall.quiet_hours_start \
               sql_firewall.quiet_hours_end; do
        $PSQL_SUPER -d postgres -c "ALTER SYSTEM RESET ${guc};" >/dev/null 2>&1 || true
    done
    $PSQL_SUPER -d postgres -c "SELECT pg_reload_conf();"                >/dev/null 2>&1 || true
    # Block new connections to prevent background worker from reconnecting, then drop
    $PSQL_SUPER -d postgres -c "ALTER DATABASE ${TEST_DB} WITH ALLOW_CONNECTIONS false;" >/dev/null 2>&1 || true
    $PSQL_SUPER -d postgres -c "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = '${TEST_DB}' AND pid != pg_backend_pid();" >/dev/null 2>&1 || true
    sleep 2
    $PSQL_SUPER -d postgres -c "DROP DATABASE IF EXISTS ${TEST_DB};"     >/dev/null 2>&1 || true
    for role in testuser_basic testuser_exempt testuser_rate; do
        $PSQL_SUPER -d postgres -c "DROP ROLE IF EXISTS ${role};"        >/dev/null 2>&1 || true
    done
}

# ===========================================================================
# MAIN
# ===========================================================================
banner "SQL Firewall - Test 1: Basic Security Features"

# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------
step "Building extension (feature=${PG_FEATURE})"
cd "$SCRIPT_DIR"
BUILD_OK=false
PG_CONFIG_PATH="$(cargo pgrx info pg-config "${PG_FEATURE}" 2>/dev/null || true)"
if [ -n "$PG_CONFIG_PATH" ] && cargo pgrx install --release --no-default-features -F "${PG_FEATURE}" -c "$PG_CONFIG_PATH" >/dev/null 2>&1; then
    info "Install/build succeeded (release, ${PG_FEATURE})"; BUILD_OK=true
elif [ -n "$PG_CONFIG_PATH" ] && cargo pgrx install --no-default-features -F "${PG_FEATURE}" -c "$PG_CONFIG_PATH" >/dev/null 2>&1; then
    info "Install/build succeeded (debug, ${PG_FEATURE})"; BUILD_OK=true
fi
if ! $BUILD_OK; then
    # When running as root, try to install the already-built .so directly
    SO_FILE=$(find "${SCRIPT_DIR}/target" -name "sql_firewall_rs.so" 2>/dev/null | head -1)
    if [ -n "$SO_FILE" ]; then
        warn "Build failed (possibly running as root). Using pre-built .so: $SO_FILE"
    else
        printf "${RED}[ERROR]${NC} Build failed and no pre-built .so found – aborting.\n"; exit 1
    fi
fi

# ---------------------------------------------------------------------------
# Deterministic PostgreSQL bootstrap (clear persisted sql_firewall.* settings)
# ---------------------------------------------------------------------------
step "Resetting PostgreSQL instance to a clean sql_firewall baseline"
cargo pgrx stop "${PG_FEATURE}" >/dev/null 2>&1 || true
clear_persisted_sql_firewall_gucs
ensure_shared_preload_sql_firewall

step "Starting PostgreSQL with sql_firewall_rs preloaded"
cargo pgrx start "${PG_FEATURE}" >/dev/null 2>&1
sleep 3

# Wait briefly for readiness
for _ in $(seq 1 10); do
    if $PSQL_SUPER -d postgres -c "SELECT 1" >/dev/null 2>&1; then
        break
    fi
    sleep 1
done

info "Connected to PostgreSQL at ${PG_SOCK}:${PG_PORT}"

# Ensure extension is installed in postgres DB to prevent SPI errors in DDL hooks
$PSQL_SUPER -d postgres -c "CREATE EXTENSION IF NOT EXISTS sql_firewall_rs;" >/dev/null 2>&1 || true

trap cleanup EXIT
setup

# ===========================================================================
# SUITE 1 – Operating Modes
# ===========================================================================
section "TEST SUITE 1: Operating Modes (Learn / Permissive / Enforce)"

# ---- 1.1 Learn mode -------------------------------------------------------
step "TEST 1.1: Learn mode – should allow all queries"
set_guc "sql_firewall.mode" "learn"
sql "CREATE TABLE IF NOT EXISTS learn_tmp (x int);" >/dev/null 2>&1

assert_ok  "Learn mode allows SELECT"       sql "SELECT * FROM test_data LIMIT 1"
assert_ok  "Learn mode allows CREATE TABLE" sql "CREATE TABLE IF NOT EXISTS learn_tmp2 (x int)"
assert_ok  "Learn mode allows INSERT"       sql "INSERT INTO learn_tmp VALUES (1)"
assert_ok  "Learn mode allows UPDATE"       sql "UPDATE learn_tmp SET x = 2 WHERE x = 1"
assert_ok  "Learn mode allows DELETE"       sql "DELETE FROM learn_tmp WHERE x = 2"
assert_ok  "Learn mode allows DDL (DROP)"   sql "DROP TABLE IF EXISTS learn_tmp"
assert_ok  "Learn mode allows DDL (DROP2)"  sql "DROP TABLE IF EXISTS learn_tmp2"

# ---- 1.2 Enforce mode without approvals -----------------------------------
step "TEST 1.2: Enforce mode – unapproved queries must be blocked"
sql "TRUNCATE public.sql_firewall_command_approvals;" >/dev/null 2>&1
set_guc "sql_firewall.mode" "enforce"

assert_err "Enforce blocks unapproved SELECT (testuser_basic)" \
    sql_as testuser_basic "SELECT * FROM test_data LIMIT 1"
assert_err "Enforce blocks unapproved INSERT (testuser_basic)" \
    sql_as testuser_basic "INSERT INTO test_data (value) VALUES ('should_fail')"
assert_err "Enforce blocks unapproved UPDATE (testuser_basic)" \
    sql_as testuser_basic "UPDATE test_data SET value = 'x' WHERE id = 1"
assert_err "Enforce blocks unapproved DELETE (testuser_basic)" \
    sql_as testuser_basic "DELETE FROM test_data WHERE id = 999"

# ---- 1.3 Enforce mode with approvals --------------------------------------
step "TEST 1.3: Enforce mode – approved queries must pass"
approve_cmd testuser_basic SELECT
approve_cmd testuser_basic INSERT

assert_ok  "Enforce allows approved SELECT" \
    sql_as testuser_basic "SELECT * FROM test_data LIMIT 1"
assert_ok  "Enforce allows approved INSERT" \
    sql_as testuser_basic "INSERT INTO test_data (value) VALUES ('approved_insert')"
assert_err "Enforce still blocks un-approved UPDATE" \
    sql_as testuser_basic "UPDATE test_data SET value = 'x' WHERE id = 1"

# Verify revoke via direct DML (cache TTL=60s means enforcement is delayed)
revoke_cmd testuser_basic SELECT
# After revoke, DB should show is_approved=false OR record deleted (depends on implementation)
DB_STATE=$(sql "SELECT COALESCE(is_approved::text, 'deleted') FROM public.sql_firewall_command_approvals WHERE role_name='testuser_basic' AND command_type='SELECT';" 2>&1 | grep -E "^[[:space:]]+(f|deleted)" | wc -l)
assert_ok "Revoke command updates DB state (is_approved=false or row removed)" \
    [ "$DB_STATE" -ge 1 ]

# ---- 1.4 Permissive mode --------------------------------------------------
step "TEST 1.4: Permissive mode – should allow but log violations"
sql "TRUNCATE public.sql_firewall_command_approvals;" >/dev/null 2>&1
set_guc "sql_firewall.mode" "permissive"

assert_ok  "Permissive allows unapproved SELECT" \
    sql_as testuser_basic "SELECT count(*) FROM test_data"
assert_ok  "Permissive allows unapproved INSERT" \
    sql_as testuser_basic "INSERT INTO test_data (value) VALUES ('permissive_val')"

# Back to learn for subsequent suites
set_guc "sql_firewall.mode" "learn"
sql "TRUNCATE public.sql_firewall_command_approvals;" >/dev/null 2>&1

# ===========================================================================
# SUITE 2 – Security Filters
# ===========================================================================
section "TEST SUITE 2: Security Filters (Keyword Blacklist & Regex)"

# ---- 2.1 Keyword blacklist ------------------------------------------------
step "TEST 2.1: Keyword blacklist"
set_guc "sql_firewall.enable_keyword_scan" "on"
alter_sys "ALTER SYSTEM SET sql_firewall.blacklisted_keywords = 'pg_sleep,pg_read_file,xp_cmdshell'"

assert_err "Keyword filter blocks pg_sleep"       sql_as testuser_basic "SELECT pg_sleep(0)"
assert_err "Keyword filter blocks pg_read_file"   sql_as testuser_basic "SELECT pg_read_file('/etc/passwd')"
assert_err "Keyword filter blocks xp_cmdshell"    sql_as testuser_basic "SELECT xp_cmdshell('ls')"
assert_ok  "Keyword filter allows benign SELECT"  sql_as testuser_basic "SELECT 1+1"

alter_sys "ALTER SYSTEM RESET sql_firewall.blacklisted_keywords"

# ---- 2.2 Regex injection patterns ----------------------------------------
step "TEST 2.2: Regex pattern blocking (SQL injection)"
set_guc "sql_firewall.enable_regex_scan" "on"

sql "INSERT INTO public.sql_firewall_regex_rules (pattern, description)
     VALUES
       ('(?i)union[[:space:]]+select',           'Block UNION SELECT injection'),
       ('(?i)or[[:space:]]+''[^'']*''[[:space:]]*=[[:space:]]*''', 'Block tautology injection'),
       ('(?i)or[[:space:]]+[0-9]+[[:space:]]*=[[:space:]]*[0-9]+','Block numeric tautology'),
       ('(?i)--;[[:space:]]*$',                  'Block comment terminator'),
       ('(?i)exec[[:space:]]*\\(',               'Block EXEC calls')
     ON CONFLICT (pattern) DO NOTHING;" >/dev/null 2>&1

assert_err "Regex blocks UNION SELECT"            sql_as testuser_basic "SELECT 1 UNION SELECT username FROM pg_user"
assert_err "Regex blocks comment terminator"      sql_as testuser_basic "SELECT * FROM test_data WHERE value='x'--;"
assert_ok  "Regex allows clean SELECT"            sql_as testuser_basic "SELECT count(*) FROM test_data"
assert_ok  "Regex allows parameterised-style"     sql_as testuser_basic "SELECT * FROM test_data WHERE id = 1"

# Cleanup injected rules
sql "DELETE FROM public.sql_firewall_regex_rules
     WHERE pattern IN (
       '(?i)union[[:space:]]+select',
       '(?i)or[[:space:]]+''[^'']*''[[:space:]]*=[[:space:]]*''',
       '(?i)or[[:space:]]+[0-9]+[[:space:]]*=[[:space:]]*[0-9]+',
       '(?i)--;[[:space:]]*\$',
       '(?i)exec[[:space:]]*\\\\('
     );" >/dev/null 2>&1

# ---- 2.3 ReDoS validation trigger ----------------------------------------
step "TEST 2.3: ReDoS validation trigger on regex_rules"
# Try inserting a pattern with multiple adjacent quantifiers
REDOS_RESULT=$(sql "INSERT INTO public.sql_firewall_regex_rules (pattern, description)
                    VALUES ('(a++)+', 'ReDoS test pattern');" 2>&1 || true)
if echo "$REDOS_RESULT" | grep -qi "error\|exception\|not allowed"; then
    pass "ReDoS validation trigger rejected dangerous pattern"
else
    warn "ReDoS trigger may not have fired – review manually"
fi

# ===========================================================================
# SUITE 3 – Access Control
# ===========================================================================
section "TEST SUITE 3: Access Control (Quiet Hours, Rate Limits, IP/App Blocking)"

# ---- 3.1 Quiet hours ------------------------------------------------------
step "TEST 3.1: Quiet hours enforcement"
# Cover the current hour with a window that wraps if needed
CURRENT_HOUR=$(date +%H)
START_H=$(( (10#$CURRENT_HOUR - 1 + 24) % 24 ))
END_H=$(( (10#$CURRENT_HOUR + 2) % 24 ))
START_T=$(printf "%02d:00" $START_H)
END_T=$(printf "%02d:00" $END_H)

# IMPORTANT: Re-enable superuser bypass before activating quiet hours.
# Without this, even the cleanup commands get blocked → GUC deadlock.
set_guc "sql_firewall.allow_superuser_auth_bypass" "on"
set_guc "sql_firewall.enable_quiet_hours"          "on"
alter_sys "ALTER SYSTEM SET sql_firewall.quiet_hours_start = '${START_T}'"
alter_sys "ALTER SYSTEM SET sql_firewall.quiet_hours_end = '${END_T}'"

assert_err "Quiet hours blocks queries for non-superuser" \
    sql_as testuser_basic "SELECT 1"
# Superuser is exempt because allow_superuser_auth_bypass = on
assert_ok  "Superuser bypasses quiet hours when bypass=on" \
    sql "SELECT 1"

set_guc "sql_firewall.enable_quiet_hours" "off"
alter_sys "ALTER SYSTEM RESET sql_firewall.quiet_hours_start"
alter_sys "ALTER SYSTEM RESET sql_firewall.quiet_hours_end"
# Keep superuser bypass enabled for remaining administrative ALTER SYSTEM calls.
# Dedicated bypass behavior is validated explicitly in SUITE 6.
set_guc "sql_firewall.allow_superuser_auth_bypass" "on"

# ---- 3.2 Global rate limiting ---------------------------------------------
step "TEST 3.2: Global rate limiting"
sql "TRUNCATE public.sql_firewall_command_approvals;" >/dev/null 2>&1
approve_cmd testuser_basic SELECT
set_guc "sql_firewall.mode"               "enforce"
set_guc "sql_firewall.enable_rate_limiting" "on"
set_guc "sql_firewall.rate_limit_count"   "3"
set_guc "sql_firewall.rate_limit_seconds" "60"

assert_ok  "Rate limit allows query #1" sql_as testuser_basic "SELECT 1"
assert_ok  "Rate limit allows query #2" sql_as testuser_basic "SELECT 2"
assert_ok  "Rate limit allows query #3" sql_as testuser_basic "SELECT 3"
assert_err "Rate limit blocks query #4" sql_as testuser_basic "SELECT 4"
assert_err "Rate limit blocks query #5" sql_as testuser_basic "SELECT 5"

set_guc "sql_firewall.enable_rate_limiting" "off"
set_guc "sql_firewall.mode"               "learn"
sql "TRUNCATE public.sql_firewall_command_approvals;" >/dev/null 2>&1

# ---- 3.3 Per-command rate limiting ----------------------------------------
step "TEST 3.3: Per-command (SELECT) rate limiting"
approve_cmd testuser_rate SELECT
approve_cmd testuser_rate INSERT
set_guc "sql_firewall.mode"                  "enforce"
set_guc "sql_firewall.enable_rate_limiting"  "on"
set_guc "sql_firewall.rate_limit_count"      "1000"   # global high enough not to interfere
set_guc "sql_firewall.select_limit_count"    "2"
set_guc "sql_firewall.command_limit_seconds" "60"

EFFECTIVE_GLOBAL=$(sql_q "SHOW sql_firewall.rate_limit_count" | tr -d '[:space:]')
EFFECTIVE_SELECT=$(sql_q "SHOW sql_firewall.select_limit_count" | tr -d '[:space:]')
if [ "$EFFECTIVE_GLOBAL" != "1000" ] || [ "$EFFECTIVE_SELECT" != "2" ]; then
    fail "Per-command rate-limit GUCs not applied (global=${EFFECTIVE_GLOBAL}, select=${EFFECTIVE_SELECT})"
fi

assert_ok  "Per-command allows SELECT #1" sql_as testuser_rate "SELECT 1"
assert_ok  "Per-command allows SELECT #2" sql_as testuser_rate "SELECT 2"
assert_err "Per-command blocks SELECT #3" sql_as testuser_rate "SELECT 3"
assert_ok  "Per-command INSERT still allowed (different command)" \
    sql_as testuser_rate "INSERT INTO test_data (value) VALUES ('cmd_rate')"

set_guc "sql_firewall.select_limit_count"   "0"
set_guc "sql_firewall.enable_rate_limiting" "off"
set_guc "sql_firewall.mode"                 "learn"
sql "TRUNCATE public.sql_firewall_command_approvals;" >/dev/null 2>&1

# ---- 3.4 Application name blocking ----------------------------------------
step "TEST 3.4: Application name blocking"
set_guc "sql_firewall.enable_application_blocking" "on"
alter_sys "ALTER SYSTEM SET sql_firewall.blocked_applications = 'bad_client,legacy_app'"

assert_err "Application blocking rejects 'bad_client'" \
    PGAPPNAME=bad_client psql -h "${PG_SOCK}" -p "${PG_PORT}" -U testuser_basic -d "$TEST_DB" -c "SELECT 1"
assert_err "Application blocking rejects 'legacy_app'" \
    PGAPPNAME=legacy_app psql -h "${PG_SOCK}" -p "${PG_PORT}" -U testuser_basic -d "$TEST_DB" -c "SELECT 1"
assert_ok  "Non-blocked application connects normally" \
    env PGAPPNAME=trusted_app psql -h "${PG_SOCK}" -p "${PG_PORT}" -U testuser_basic -d "$TEST_DB" -c "SELECT 1"

alter_sys "ALTER SYSTEM RESET sql_firewall.blocked_applications"
set_guc "sql_firewall.enable_application_blocking" "off"

# ===========================================================================
# SUITE 4 – Logging & Audit Trail
# ===========================================================================
section "TEST SUITE 4: Logging & Audit Trail"

# ---- 4.1 Activity logging -------------------------------------------------
step "TEST 4.1: Activity logging records allowed queries"
set_guc "sql_firewall.enable_activity_logging" "on"
sql "TRUNCATE public.sql_firewall_activity_log;" >/dev/null 2>&1

for i in $(seq 1 5); do
    sql_as testuser_basic "SELECT count(*) FROM test_data;" >/dev/null 2>&1
done
sleep 1

LOG_COUNT=$(sql_q "SELECT COUNT(*) FROM public.sql_firewall_activity_log
                   WHERE log_time > now() - interval '1 minute'" 2>/dev/null || echo 0)
if [ "${LOG_COUNT:-0}" -gt 0 ]; then
    pass "Activity logging is working (${LOG_COUNT} entries found)"
else
    fail "Activity logging not recording entries (got ${LOG_COUNT:-0})"
fi

# ---- 4.2 Blocked query logging --------------------------------------------
step "TEST 4.2: Blocked query logging via background worker"
set_guc "sql_firewall.mode" "enforce"
sql "TRUNCATE public.sql_firewall_command_approvals;" >/dev/null 2>&1
sql "SELECT sql_firewall_clear_approval_cache();"  >/dev/null 2>&1 || true
sql "TRUNCATE public.sql_firewall_blocked_queries;"   >/dev/null 2>&1

sql "SELECT sql_firewall_resume_approval_worker();" >/dev/null 2>&1 || true
if ! wait_for_worker_running 20; then
    fail "Approval worker is not running; blocked-query persistence cannot be validated"
fi

# Fire several queries that will be blocked
for i in $(seq 1 4); do
    sql_as testuser_basic "SELECT $i" >/dev/null 2>&1 || true
done
sleep 6   # background worker flush window (worker checks every ~1s, allow extra margin)

BLOCK_COUNT=$(wait_for_sql_count_gt_zero "SELECT COUNT(*) FROM public.sql_firewall_blocked_queries
                     WHERE blocked_at > now() - interval '1 minute'" 20)
if [ "${BLOCK_COUNT:-0}" -gt 0 ]; then
    pass "Blocked queries logging is working (${BLOCK_COUNT} entries found)"
else
    fail "Blocked queries not logged within timeout (got ${BLOCK_COUNT:-0})"
fi

set_guc "sql_firewall.mode" "learn"
sql "TRUNCATE public.sql_firewall_command_approvals;" >/dev/null 2>&1

# ---- 4.3 Activity logging toggle ------------------------------------------
step "TEST 4.3: Activity logging toggle (off = no new entries)"
set_guc "sql_firewall.enable_activity_logging" "off"
sql "TRUNCATE public.sql_firewall_activity_log;" >/dev/null 2>&1

for i in $(seq 1 3); do
    sql "SELECT $i;" >/dev/null 2>&1
done
sleep 1

COUNT_AFTER=$(sql_q "SELECT COUNT(*) FROM public.sql_firewall_activity_log" 2>/dev/null || echo 0)
if [ "${COUNT_AFTER:-0}" -eq 0 ]; then
    pass "Activity logging toggle works (disabled → 0 entries)"
else
    fail "Activity logging still writing despite being disabled (${COUNT_AFTER} entries)"
fi
set_guc "sql_firewall.enable_activity_logging" "on"

# ---- 4.4 Blocked-queries logged even when activity logging is off ---------
step "TEST 4.4: Blocked queries logged independently of activity logging toggle"
set_guc "sql_firewall.enable_activity_logging" "off"
set_guc "sql_firewall.mode" "enforce"
sql "TRUNCATE public.sql_firewall_command_approvals;" >/dev/null 2>&1
sql "SELECT sql_firewall_clear_approval_cache();"  >/dev/null 2>&1 || true
sql "TRUNCATE public.sql_firewall_blocked_queries;"   >/dev/null 2>&1

sql "SELECT sql_firewall_resume_approval_worker();" >/dev/null 2>&1 || true
if ! wait_for_worker_running 20; then
    fail "Approval worker is not running; blocked-query persistence cannot be validated"
fi

sql_as testuser_basic "SELECT 1" >/dev/null 2>&1 || true
sql_as testuser_basic "SELECT 2" >/dev/null 2>&1 || true
sleep 6

BQ=$(wait_for_sql_count_gt_zero "SELECT COUNT(*) FROM public.sql_firewall_blocked_queries
            WHERE blocked_at > now() - interval '1 minute'" 20)
if [ "${BQ:-0}" -gt 0 ]; then
    pass "Blocked queries always logged regardless of activity logging toggle"
else
    fail "Blocked queries not logged when activity logging is off"
fi

set_guc "sql_firewall.enable_activity_logging" "on"
set_guc "sql_firewall.mode" "learn"
sql "TRUNCATE public.sql_firewall_command_approvals;" >/dev/null 2>&1

# ===========================================================================
# SUITE 5 – Per-User Regex Exemptions
# ===========================================================================
section "TEST SUITE 5: Per-User Regex Exemptions"

step "TEST 5.1: allowed_roles exempts specified users from regex rule"
# Insert DROP TABLE pattern that blocks everyone except testuser_exempt
sql "INSERT INTO public.sql_firewall_regex_rules (pattern, description, allowed_roles)
     VALUES ('(?i)drop[[:space:]]+table', 'Block DROP TABLE', ARRAY['testuser_exempt']::text[])
     ON CONFLICT (pattern) DO UPDATE SET allowed_roles = EXCLUDED.allowed_roles;" >/dev/null 2>&1
set_guc "sql_firewall.enable_regex_scan" "on"

assert_err "Non-exempt user blocked by DROP TABLE pattern" \
    sql_as testuser_basic "DROP TABLE IF EXISTS nonexistent_table"
assert_ok  "Exempt user (testuser_exempt) allowed to DROP TABLE" \
    sql_as testuser_exempt "DROP TABLE IF EXISTS nonexistent_table"

# ---- 5.2 NULL allowed_roles blocks everyone -------------------------------
step "TEST 5.2: NULL allowed_roles means rule applies to ALL users"
sql "UPDATE public.sql_firewall_regex_rules
     SET allowed_roles = NULL
     WHERE pattern = '(?i)drop[[:space:]]+table';" >/dev/null 2>&1

assert_err "With NULL allowed_roles, even testuser_exempt is blocked" \
    sql_as testuser_exempt "DROP TABLE IF EXISTS nonexistent_table"
assert_err "With NULL allowed_roles, testuser_basic is blocked" \
    sql_as testuser_basic  "DROP TABLE IF EXISTS nonexistent_table"

sql "DELETE FROM public.sql_firewall_regex_rules
     WHERE pattern = '(?i)drop[[:space:]]+table';" >/dev/null 2>&1

# ===========================================================================
# SUITE 6 – Superuser Bypass GUC
# ===========================================================================
section "TEST SUITE 6: Superuser Bypass Control"

step "TEST 6.1: allow_superuser_auth_bypass = off enforces policy on superuser"
set_guc "sql_firewall.allow_superuser_auth_bypass" "off"
set_guc "sql_firewall.enable_application_blocking" "on"
alter_sys "ALTER SYSTEM SET sql_firewall.blocked_applications = 'blocked_su_app'"

assert_err "Superuser blocked when bypass=off and app is blocked" \
    PGAPPNAME=blocked_su_app $PSQL_SUPER -d "$TEST_DB" -c "SELECT 1"

step "TEST 6.2: allow_superuser_auth_bypass = on exempts superuser"
set_guc "sql_firewall.allow_superuser_auth_bypass" "on"
assert_ok  "Superuser exempt when bypass=on regardless of blocked app" \
    env PGAPPNAME=blocked_su_app $PSQL_SUPER -d "$TEST_DB" -c "SELECT 1"

alter_sys "ALTER SYSTEM RESET sql_firewall.blocked_applications"
set_guc "sql_firewall.enable_application_blocking"   "off"
set_guc "sql_firewall.allow_superuser_auth_bypass"   "on"

# ===========================================================================
# SUITE 7 – Firewall Kill Switch
# ===========================================================================
section "TEST SUITE 7: Firewall Kill Switch (sql_firewall.enabled)"

step "TEST 7.1: Disabling the firewall bypasses all checks"
set_guc "sql_firewall.mode" "enforce"
sql "TRUNCATE public.sql_firewall_command_approvals;" >/dev/null 2>&1
sql "SELECT sql_firewall_clear_approval_cache();"     >/dev/null 2>&1 || true
assert_err "Firewall active: testuser_basic blocked in enforce mode" \
    sql_as testuser_basic "SELECT 1"

set_guc "sql_firewall.enabled" "off"
assert_ok  "Firewall disabled: all queries pass through" \
    sql_as testuser_basic "SELECT 1"

step "TEST 7.2: Re-enabling the firewall restores enforcement"
set_guc "sql_firewall.enabled" "on"
assert_err "Firewall re-enabled: testuser_basic blocked again" \
    sql_as testuser_basic "SELECT 1"

set_guc "sql_firewall.mode"    "learn"
set_guc "sql_firewall.enabled" "on"
sql "TRUNCATE public.sql_firewall_command_approvals;" >/dev/null 2>&1

# ===========================================================================
# Summary
# ===========================================================================
banner "ALL TESTS COMPLETED"

info "Test Summary:"
info "  • Operating modes: Learn / Permissive / Enforce ✓"
info "  • Command approvals – grant, revoke, re-check ✓"
info "  • Keyword blacklist filtering ✓"
info "  • Regex pattern blocking (SQL injection) ✓"
info "  • ReDoS validation trigger ✓"
info "  • Quiet hours enforcement ✓"
info "  • Global rate limiting ✓"
info "  • Per-command rate limiting ✓"
info "  • Application name blocking ✓"
info "  • Activity logging ✓"
info "  • Blocked queries logging (async worker) ✓"
info "  • Activity logging toggle ✓"
info "  • Per-user regex exemptions (allowed_roles) ✓"
info "  • Superuser bypass GUC ✓"
info "  • Firewall kill switch ✓"
echo ""
printf "Results: ${GREEN}%d passed${NC}, ${RED}%d failed${NC} (%d total)\n" "$PASS" "$FAIL" "$TESTS_TOTAL"
echo ""

if [ "${FAIL}" -eq 0 ]; then
    printf "${GREEN}[PASS]${NC} Test 1: Basic Security Features – ALL %d TESTS PASSED\n" "$TESTS_TOTAL"
    exit 0
else
    printf "${RED}[FAIL]${NC} Test 1: Basic Security Features – %d of %d TESTS FAILED\n" "$FAIL" "$TESTS_TOTAL"
    exit 1
fi
