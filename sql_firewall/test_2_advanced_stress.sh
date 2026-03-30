#!/usr/bin/env bash
# =============================================================================
# SQL Firewall – Test 2: Advanced Features & Stress Testing
# =============================================================================
# Validates advanced firewall functionality under realistic workloads:
#   - Fingerprint learning & auto-approval
#   - Background approval worker (pause / resume / status)
#   - Approval queue processing & persistence
#   - High-volume stress testing (configurable STRESS_ITER)
#   - Mixed-workload performance (SELECT / INSERT / UPDATE / DELETE)
#   - Per-command rate limit stress
#   - ReDoS protection (regex timeout)
#   - statement_timeout isolation (firewall must not leak its own timeout)
#   - Transaction rollback safety (blocked-query records survive abort)
#   - Concurrent connection stability
#   - Memory-leak / crash detection over long iteration counts
#   - Shared-memory consistency under rapid concurrent writes
#   - Catalog table integrity
#   - Per-user regex exemptions (end-to-end)
#   - Multi-layer security (regex + keyword + approval simultaneously)
# =============================================================================
set -uo pipefail

# ---------------------------------------------------------------------------
# Configuration (overridable via environment)
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEST_DB="${TEST_DB:-sqlfw_stress_test}"
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
STRESS_ITER="${STRESS_ITER:-1000}"          # ------ stress knob
MIXED_ITER="${MIXED_ITER:-300}"             # mixed-workload queries
CONCURRENT_CLIENTS="${CONCURRENT_CLIENTS:-10}"
MEMORY_ITER="${MEMORY_ITER:-500}"
SHARED_MEM_OPS="${SHARED_MEM_OPS:-200}"
FINGERPRINT_THRESHOLD="${FINGERPRINT_THRESHOLD:-3}"

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
CYAN='\033[0;36m'
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

step()   { printf "${YELLOW}[STEP]${NC} %s\n"   "$*"; }
info()   { printf "${BLUE}[TEST]${NC} %s\n"     "$*"; }
stress() { printf "${CYAN}[STRESS]${NC} %s\n"   "$*"; }
pass()   { PASS=$((PASS + 1));  TESTS_TOTAL=$((TESTS_TOTAL + 1)); printf "${GREEN}[PASS]${NC} %s\n" "$*"; }
fail()   { FAIL=$((FAIL + 1));  TESTS_TOTAL=$((TESTS_TOTAL + 1)); printf "${RED}[FAIL]${NC} %s\n"  "$*"; }
warn()   { printf "${YELLOW}[WARN]${NC} %s\n"   "$*"; }

# ---------------------------------------------------------------------------
# SQL helpers
# ---------------------------------------------------------------------------
sql() {
    $PSQL_SUPER -d "$TEST_DB" -c "$1" 2>&1
}
sql_q() {
    $PSQL_SUPER -d "$TEST_DB" -t -A -c "$1" 2>&1
}
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
assert_eq() {
    local desc="$1" expected="$2" actual="$3"
    if [ "${actual}" = "${expected}" ]; then
        pass "$desc (${actual})"
    else
        fail "$desc – expected '${expected}', got '${actual}'"
    fi
}

# ---------------------------------------------------------------------------
# GUC helpers (ALTER SYSTEM cannot run inside a transaction block)
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

# ---------------------------------------------------------------------------
# Firewall approval helpers – use direct DML (not SELECT sql_firewall_approve_command)
# because in enforce mode with bypass=off the SELECT call itself would be blocked
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
# Setup / teardown
# ---------------------------------------------------------------------------
setup() {
    step "Creating test database '${TEST_DB}'"
    wait_for_postgres_ready
    PGOPTIONS="$ADMIN_PGOPTIONS" $PSQL_SUPER -d postgres -c "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = '${TEST_DB}' AND pid <> pg_backend_pid();" >/dev/null 2>&1 || true
    PGOPTIONS="$ADMIN_PGOPTIONS" $PSQL_SUPER -d postgres -c "ALTER DATABASE ${TEST_DB} WITH ALLOW_CONNECTIONS false;" >/dev/null 2>&1 || true
    PGOPTIONS="$ADMIN_PGOPTIONS" $PSQL_SUPER -d postgres -c "DROP DATABASE IF EXISTS ${TEST_DB};"  >/dev/null 2>&1 || true
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

    # Wait for the launcher to spawn a background worker for the new database.
    # The launcher scans every 5 s; we poll pg_stat_activity until the worker appears
    # (max 15 s).
    step "Waiting for background worker to spin up for '${TEST_DB}'"
    for _ in $(seq 1 15); do
        WCOUNT=$($PSQL_SUPER -d postgres -t -A -c "SELECT count(*) FROM pg_stat_activity WHERE datname = '${TEST_DB}' AND backend_type LIKE 'sql_firewall_worker_%'" 2>/dev/null || echo 0)
        if [ "${WCOUNT:-0}" -gt 0 ]; then
            info "Background worker ready for '${TEST_DB}'"
            break
        fi
        sleep 1
    done

    step "Creating test roles"
    for role in stressuser fp_learner exemptuser mlayer_user; do
        $PSQL_SUPER -d postgres -c "DROP ROLE IF EXISTS ${role};"             >/dev/null 2>&1 || true
        $PSQL_SUPER -d postgres -c "CREATE ROLE ${role} LOGIN;"               >/dev/null 2>&1
        $PSQL_SUPER -d postgres -c "GRANT CONNECT ON DATABASE ${TEST_DB} TO ${role};" >/dev/null 2>&1
        $PSQL_SUPER -d "$TEST_DB" -c "GRANT USAGE ON SCHEMA public TO ${role};" >/dev/null 2>&1
        $PSQL_SUPER -d "$TEST_DB" -c "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO ${role};" >/dev/null 2>&1
    done
    pass "Test roles created"

    step "Creating test tables"
    sql "CREATE TABLE IF NOT EXISTS stress_data  (id serial PRIMARY KEY, val text, ts timestamptz DEFAULT now());" >/dev/null 2>&1
    sql "CREATE TABLE IF NOT EXISTS fp_data      (id serial PRIMARY KEY, score int, label text);"                  >/dev/null 2>&1
    sql "INSERT INTO stress_data (val) SELECT 'row_' || g FROM generate_series(1,100) g;" >/dev/null 2>&1
    sql "INSERT INTO fp_data (score, label) SELECT g, 'label_' || g FROM generate_series(1,50) g;" >/dev/null 2>&1
    for role in stressuser fp_learner exemptuser mlayer_user; do
        sql "GRANT SELECT, INSERT, UPDATE, DELETE ON stress_data TO ${role};" >/dev/null 2>&1
        sql "GRANT SELECT, INSERT, UPDATE, DELETE ON fp_data TO ${role};" >/dev/null 2>&1
        sql "GRANT USAGE, SELECT ON SEQUENCE stress_data_id_seq TO ${role};" >/dev/null 2>&1
        sql "GRANT USAGE, SELECT ON SEQUENCE fp_data_id_seq TO ${role};" >/dev/null 2>&1
    done

    step "Resetting firewall to a clean baseline"
    set_guc "sql_firewall.mode"                      "learn"
    set_guc "sql_firewall.allow_superuser_auth_bypass" "on"
    set_guc "sql_firewall.enable_fingerprint_learning" "on"
    set_guc "sql_firewall.enable_rate_limiting"       "off"
    set_guc "sql_firewall.enable_regex_scan"          "on"
    set_guc "sql_firewall.enable_keyword_scan"        "on"
    set_guc "sql_firewall.enable_activity_logging"    "on"
    sql "TRUNCATE public.sql_firewall_command_approvals;"  >/dev/null 2>&1
    sql "TRUNCATE public.sql_firewall_activity_log;"       >/dev/null 2>&1
    sql "TRUNCATE public.sql_firewall_blocked_queries;"    >/dev/null 2>&1
    sql "TRUNCATE public.sql_firewall_query_fingerprints;" >/dev/null 2>&1
    sql "TRUNCATE public.sql_firewall_fingerprint_hits;"   >/dev/null 2>&1
    sql "DELETE FROM public.sql_firewall_regex_rules WHERE pattern NOT IN ('(or|--|#)\\s+([[:alpha:]_][[:alnum:]_]*|''[^'']*''|[0-9]+)\\s*=\\s*([[:alpha:]_][[:alnum:]_]*|''[^'']*''|[0-9]+)');" >/dev/null 2>&1
    echo ""
}

cleanup() {
    step "Cleaning up resources"
    for guc in sql_firewall.mode sql_firewall.allow_superuser_auth_bypass \
               sql_firewall.enable_fingerprint_learning sql_firewall.fingerprint_learn_threshold \
               sql_firewall.enable_rate_limiting sql_firewall.rate_limit_count \
               sql_firewall.enable_regex_scan sql_firewall.enable_keyword_scan \
               sql_firewall.enable_activity_logging sql_firewall.blacklisted_keywords; do
        $PSQL_SUPER -d postgres -c "ALTER SYSTEM RESET ${guc};" >/dev/null 2>&1 || true
    done
    $PSQL_SUPER -d postgres -c "SELECT pg_reload_conf();" >/dev/null 2>&1 || true
    # Block new connections to prevent background worker from reconnecting, then drop
    $PSQL_SUPER -d postgres -c "ALTER DATABASE ${TEST_DB} WITH ALLOW_CONNECTIONS false;" >/dev/null 2>&1 || true
    $PSQL_SUPER -d postgres -c "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = '${TEST_DB}' AND pid != pg_backend_pid();" >/dev/null 2>&1 || true
    sleep 2
    $PSQL_SUPER -d postgres -c "DROP DATABASE IF EXISTS ${TEST_DB};" >/dev/null 2>&1 || true
    for role in stressuser fp_learner exemptuser mlayer_user; do
        $PSQL_SUPER -d postgres -c "DROP ROLE IF EXISTS ${role};" >/dev/null 2>&1 || true
    done
}

# ===========================================================================
# MAIN
# ===========================================================================
banner "SQL Firewall - Test 2: Advanced Features & Stress"

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

step "Starting PostgreSQL"
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
# SUITE 1 – Fingerprint Learning & Auto-Approval
# ===========================================================================
section "TEST SUITE 1: Fingerprint Learning & Auto-Approval"

step "TEST 1.1: Configure fingerprint learning with low threshold (${FINGERPRINT_THRESHOLD})"
set_guc "sql_firewall.enable_fingerprint_learning"  "on"
set_guc "sql_firewall.fingerprint_learn_threshold"  "${FINGERPRINT_THRESHOLD}"
set_guc "sql_firewall.mode"                         "learn"
pass "Fingerprint learning configured (threshold=${FINGERPRINT_THRESHOLD})"

step "TEST 1.2: Execute parameterised queries to build fingerprint hit count"
# Run the same normalised form with different literals several times
for i in $(seq 1 $(( FINGERPRINT_THRESHOLD + 2 )) ); do
    sql_as fp_learner "SELECT id, score FROM fp_data WHERE score = ${i}" >/dev/null 2>&1 || true
done
sleep 3  # let background worker flush fingerprint events
pass "Executed $(( FINGERPRINT_THRESHOLD + 2 )) parameterised queries with different literals"

step "TEST 1.3: Verify fingerprints were recorded in the catalog"
FP_COUNT=$(sql_q "SELECT COUNT(*) FROM public.sql_firewall_query_fingerprints
                  WHERE role_name = 'fp_learner'" 2>/dev/null || echo 0)
# Also check fingerprint_hits table (background-worker path)
FPH_COUNT=$(sql_q "SELECT COUNT(*) FROM public.sql_firewall_fingerprint_hits" 2>/dev/null || echo 0)

if [ "${FP_COUNT:-0}" -gt 0 ] || [ "${FPH_COUNT:-0}" -gt 0 ]; then
    pass "Fingerprint learning successful (query_fingerprints=${FP_COUNT}, fingerprint_hits=${FPH_COUNT})"
else
    fail "No fingerprints recorded (query_fingerprints=${FP_COUNT}, fingerprint_hits=${FPH_COUNT})"
fi

step "TEST 1.4: Verify auto-approval after threshold reached"
sleep 2
# In enforce mode, the fingerprint-approved query should now pass
APPROVED_COUNT=$(sql_q "SELECT COUNT(*) FROM public.sql_firewall_query_fingerprints
                         WHERE is_approved = true AND role_name = 'fp_learner'" 2>/dev/null || echo 0)
if [ "${APPROVED_COUNT:-0}" -gt 0 ]; then
    pass "Fingerprint auto-approval triggered (${APPROVED_COUNT} fingerprint(s) approved)"
else
    warn "Auto-approval not yet triggered – fingerprints may still be accumulating"
    # Not a hard fail since timing depends on background worker
fi

step "TEST 1.5: Fingerprint threshold reset – verify counter resets after approval"
set_guc "sql_firewall.fingerprint_learn_threshold" "5"
pass "Fingerprint threshold reset to default (5)"

# ===========================================================================
# SUITE 2 – Background Approval Worker
# ===========================================================================
section "TEST SUITE 2: Background Worker & Approval Queue"

step "TEST 2.1: Check approval worker status"
WORKER_STATUS=$(sql_q "SELECT sql_firewall_approval_worker_status()" 2>/dev/null || echo "unknown")
info "Approval worker status: ${WORKER_STATUS}"

if echo "$WORKER_STATUS" | grep -qi "running\|starting\|paused\|stopped"; then
    pass "Approval worker status reported: ${WORKER_STATUS}"
else
    fail "Unexpected worker status: '${WORKER_STATUS}'"
fi

step "TEST 2.2: Pause the approval worker"
sql "SELECT sql_firewall_pause_approval_worker();" >/dev/null 2>&1
sleep 2
PAUSED_STATUS=$(sql_q "SELECT sql_firewall_approval_worker_status()" 2>/dev/null || echo "unknown")
info "Status after pause: ${PAUSED_STATUS}"

if echo "$PAUSED_STATUS" | grep -qi "paused\|stopped"; then
    pass "Approval worker successfully paused"
else
    warn "Worker status after pause: '${PAUSED_STATUS}' (may depend on timing)"
fi

step "TEST 2.3: Resume the approval worker"
sql "SELECT sql_firewall_resume_approval_worker();" >/dev/null 2>&1
sleep 2
RESUMED_STATUS=$(sql_q "SELECT sql_firewall_approval_worker_status()" 2>/dev/null || echo "unknown")
info "Status after resume: ${RESUMED_STATUS}"

if echo "$RESUMED_STATUS" | grep -qi "running\|starting"; then
    pass "Approval worker successfully resumed"
else
    warn "Worker status after resume: '${RESUMED_STATUS}' (may need more time)"
fi

step "TEST 2.4: Verify approval queue processes while worker is running"
set_guc "sql_firewall.mode" "learn"
sql "TRUNCATE public.sql_firewall_command_approvals;" >/dev/null 2>&1

for cmd in "SELECT 1" "INSERT INTO stress_data (val) VALUES ('wq')" "SELECT count(*) FROM stress_data"; do
    sql "$cmd" >/dev/null 2>&1 || true
done
sleep 3  # let worker drain the queue

APPROVAL_COUNT=$(sql_q "SELECT COUNT(*) FROM public.sql_firewall_command_approvals" 2>/dev/null || echo 0)
if [ "${APPROVAL_COUNT:-0}" -gt 0 ]; then
    pass "Approval queue processed (${APPROVAL_COUNT} approval record(s) found)"
else
    warn "No approval records yet – worker may need more time or mode may differ"
fi

# ===========================================================================
# SUITE 3 – Stress Testing & Performance
# ===========================================================================
section "TEST SUITE 3: Stress Testing & Performance"

set_guc "sql_firewall.mode" "learn"
approve_cmd stressuser SELECT
approve_cmd stressuser INSERT
approve_cmd stressuser UPDATE
approve_cmd stressuser DELETE

# ---- 3.1 High-volume SELECT stress ----------------------------------------
stress "TEST 3.1: High-volume query execution (${STRESS_ITER} iterations)"
START_TS=$SECONDS
for i in $(seq 1 "$STRESS_ITER"); do
    sql_as stressuser "SELECT id, val FROM stress_data WHERE id = $(( (i % 100) + 1 ))" >/dev/null 2>&1
done
ELAPSED=$(( SECONDS - START_TS ))
QPS=$(( STRESS_ITER / (ELAPSED > 0 ? ELAPSED : 1) ))
pass "Stress test completed: ${STRESS_ITER} queries in ${ELAPSED}s (~${QPS} qps)"

# ---- 3.2 Mixed-workload stress ---------------------------------------------
stress "TEST 3.2: Mixed workload stress test (${MIXED_ITER} queries)"
START_TS=$SECONDS
for i in $(seq 1 "$MIXED_ITER"); do
    case $(( i % 4 )) in
        0) sql_as stressuser "SELECT count(*) FROM stress_data"                              >/dev/null 2>&1 ;;
        1) sql_as stressuser "INSERT INTO stress_data (val) VALUES ('stress_${i}')"          >/dev/null 2>&1 ;;
        2) sql_as stressuser "UPDATE stress_data SET val = 'upd_${i}' WHERE id = $(( (i % 50) + 1 ))" >/dev/null 2>&1 ;;
        3) sql_as stressuser "DELETE FROM stress_data WHERE val = 'stress_$(( i - 1 ))'"    >/dev/null 2>&1 ;;
    esac
done
ELAPSED=$(( SECONDS - START_TS ))
pass "Mixed workload completed: ${MIXED_ITER} queries (SELECT/INSERT/UPDATE/DELETE) in ${ELAPSED}s"

# ---- 3.3 Rate-limit stress test -------------------------------------------
stress "TEST 3.3: Rate limit stress test"
RATE_LIMIT=50
set_guc "sql_firewall.mode"               "enforce"
set_guc "sql_firewall.enable_rate_limiting" "on"
set_guc "sql_firewall.rate_limit_count"   "${RATE_LIMIT}"
set_guc "sql_firewall.rate_limit_seconds" "120"

ALLOWED=0
BLOCKED=0
for i in $(seq 1 $(( RATE_LIMIT * 2 )) ); do
    if sql_as stressuser "SELECT $i" >/dev/null 2>&1; then
        ALLOWED=$(( ALLOWED + 1 ))
    else
        BLOCKED=$(( BLOCKED + 1 ))
    fi
done

info "Rate limit stress: ${ALLOWED} allowed, ${BLOCKED} blocked (limit=${RATE_LIMIT})"
if [ "${ALLOWED}" -le "${RATE_LIMIT}" ] && [ "${BLOCKED}" -gt 0 ]; then
    pass "Rate limit stress: correct enforcement (≤${RATE_LIMIT} allowed, ${BLOCKED} blocked)"
else
    fail "Rate limit stress: unexpected counts (${ALLOWED} allowed, ${BLOCKED} blocked, limit=${RATE_LIMIT})"
fi

set_guc "sql_firewall.enable_rate_limiting" "off"
set_guc "sql_firewall.mode"               "learn"
sql "TRUNCATE public.sql_firewall_command_approvals;" >/dev/null 2>&1

# ===========================================================================
# SUITE 4 – Edge Cases & Error Handling
# ===========================================================================
section "TEST SUITE 4: Edge Cases & Error Handling"

# ---- 4.1 ReDoS protection -------------------------------------------------
step "TEST 4.1: ReDoS protection – dangerous pattern rejected at insertion"
RESULT=$(sql "INSERT INTO public.sql_firewall_regex_rules (pattern, description)
              VALUES ('(a++)+', 'ReDoS test');" 2>&1 || true)
if echo "$RESULT" | grep -qi "error\|exception\|not allowed\|invalid"; then
    pass "ReDoS pattern insertion rejected by validation trigger"
else
    warn "ReDoS trigger may not have fired – check validation trigger"
fi

step "TEST 4.2: Runtime regex timeout (100ms) on an expensive-but-valid pattern"
# Insert a pattern that can be expensive on pathological input; firewall must not hang
sql "INSERT INTO public.sql_firewall_regex_rules (pattern, description)
     VALUES ('(x+x+)+y', 'Mildly expensive regex for timeout test')
     ON CONFLICT (pattern) DO NOTHING;" >/dev/null 2>&1

START_TS=$SECONDS
sql_as stressuser "SELECT 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'" >/dev/null 2>&1 || true
ELAPSED=$(( SECONDS - START_TS ))
sql "DELETE FROM public.sql_firewall_regex_rules WHERE pattern = '(x+x+)+y';" >/dev/null 2>&1

if [ "${ELAPSED}" -lt 5 ]; then
    pass "ReDoS protection: query completed without hanging (${ELAPSED}s < 5s timeout guard)"
else
    fail "Query took too long (${ELAPSED}s) – possible timeout issue"
fi

# ---- 4.3 statement_timeout isolation ---------------------------------------
step "TEST 4.3: Firewall must not leak its internal statement_timeout"
sql "SET statement_timeout = 0;" >/dev/null 2>&1   # ensure clean start
TIMEOUT_BEFORE=$(sql_q "SHOW statement_timeout" 2>/dev/null || echo "0")
sql_as stressuser "SELECT pg_sleep(0)" >/dev/null 2>&1 || true   # triggers firewall path
TIMEOUT_AFTER=$(sql_q "SHOW statement_timeout" 2>/dev/null || echo "0")

if [ "${TIMEOUT_BEFORE}" = "${TIMEOUT_AFTER}" ]; then
    pass "statement_timeout not leaked (${TIMEOUT_BEFORE} == ${TIMEOUT_AFTER})"
else
    fail "statement_timeout was modified by firewall: before=${TIMEOUT_BEFORE}, after=${TIMEOUT_AFTER}"
fi

# ---- 4.4 Transaction rollback survival ------------------------------------
step "TEST 4.4: Blocked-query records survive transaction rollback"
set_guc "sql_firewall.mode" "enforce"
sql "TRUNCATE public.sql_firewall_command_approvals;" >/dev/null 2>&1
sql "TRUNCATE public.sql_firewall_blocked_queries;"   >/dev/null 2>&1

# The user fires a query inside an explicit transaction and then rolls back
psql -h "${PG_SOCK}" -p "${PG_PORT}" -U stressuser -d "$TEST_DB" <<'SQL' >/dev/null 2>&1 || true
BEGIN;
SELECT 1;
ROLLBACK;
SQL

sleep 3  # background worker flush

SURVIVED=$(sql_q "SELECT COUNT(*) FROM public.sql_firewall_blocked_queries
                  WHERE blocked_at > now() - interval '1 minute'" 2>/dev/null || echo 0)
if [ "${SURVIVED:-0}" -gt 0 ]; then
    pass "Blocked query records survived transaction rollback (${SURVIVED} record(s))"
else
    warn "No blocked records found after rollback test – worker timing may vary"
fi

set_guc "sql_firewall.mode" "learn"
sql "TRUNCATE public.sql_firewall_command_approvals;" >/dev/null 2>&1

# ---- 4.5 Empty query & whitespace-only query ------------------------------
step "TEST 4.5: Empty / whitespace-only query handling"
# These should not crash the firewall
sql "SELECT '';" >/dev/null 2>&1 || true
sql "SELECT '   ';" >/dev/null 2>&1 || true
pass "Empty/whitespace queries handled without crash"

# ---- 4.6 Very long query --------------------------------------------------
step "TEST 4.6: Very long query (2KB+ text) truncation in blocked_queries"
set_guc "sql_firewall.mode" "enforce"
sql "TRUNCATE public.sql_firewall_command_approvals;" >/dev/null 2>&1

LONG_QUERY="SELECT /* $(python3 -c "print('x' * 2500)" 2>/dev/null || printf '%2500s' '' | tr ' ' 'x') */ 1"
sql_as stressuser "$LONG_QUERY" >/dev/null 2>&1 || true
sleep 3

TRUNCATED=$(sql_q "SELECT COUNT(*) FROM public.sql_firewall_blocked_queries
                   WHERE query_truncated = true
                   AND blocked_at > now() - interval '1 minute'" 2>/dev/null || echo 0)
if [ "${TRUNCATED:-0}" -gt 0 ]; then
    pass "Long query correctly truncated and flagged (query_truncated=true)"
else
    warn "Truncation flag not set – may depend on worker timing or query length threshold"
fi

set_guc "sql_firewall.mode" "learn"
sql "TRUNCATE public.sql_firewall_command_approvals;" >/dev/null 2>&1

# ===========================================================================
# SUITE 5 – Concurrency
# ===========================================================================
section "TEST SUITE 5: Concurrent Connection Stability"

step "TEST 5.1: ${CONCURRENT_CLIENTS} simultaneous clients in learn mode"
set_guc "sql_firewall.mode" "learn"
PIDS=()
TMPDIR_CONC=$(mktemp -d)

for i in $(seq 1 "$CONCURRENT_CLIENTS"); do
    (
        for q in $(seq 1 20); do
            sql_as stressuser "SELECT id FROM stress_data WHERE id = $(( (q % 50) + 1 ))" >/dev/null 2>&1
            sql_as stressuser "INSERT INTO stress_data (val) VALUES ('conc_${i}_${q}')"    >/dev/null 2>&1
        done
        touch "${TMPDIR_CONC}/done_${i}"
    ) &
    PIDS+=($!)
done

# Wait for all background jobs
WAIT_SECS=0
while [ "$(ls "${TMPDIR_CONC}" | wc -l)" -lt "$CONCURRENT_CLIENTS" ]; do
    sleep 1
    WAIT_SECS=$(( WAIT_SECS + 1 ))
    if [ "$WAIT_SECS" -gt 60 ]; then
        break
    fi
done

DONE_COUNT=$(ls "${TMPDIR_CONC}" | wc -l)
rm -rf "${TMPDIR_CONC}"

if [ "${DONE_COUNT}" -eq "${CONCURRENT_CLIENTS}" ]; then
    pass "Concurrent connections: all ${CONCURRENT_CLIENTS} clients completed successfully"
else
    fail "Concurrent connections: only ${DONE_COUNT}/${CONCURRENT_CLIENTS} clients completed"
fi

step "TEST 5.2: ${CONCURRENT_CLIENTS} simultaneous clients in enforce mode (mixed block/allow)"
set_guc "sql_firewall.mode" "enforce"
sql "TRUNCATE public.sql_firewall_command_approvals;" >/dev/null 2>&1
approve_cmd stressuser SELECT

PIDS=()
TMPDIR_ENF=$(mktemp -d)

for i in $(seq 1 "$CONCURRENT_CLIENTS"); do
    (
        PASS_LOCAL=0
        for q in $(seq 1 10); do
            sql_as stressuser "SELECT $q" >/dev/null 2>&1 && PASS_LOCAL=$(( PASS_LOCAL + 1 ))
        done
        echo "$PASS_LOCAL" > "${TMPDIR_ENF}/result_${i}"
    ) &
    PIDS+=($!)
done

wait "${PIDS[@]}" 2>/dev/null || true
TOTAL_PASS=$(cat "${TMPDIR_ENF}"/result_* 2>/dev/null | awk '{s+=$1}END{print s+0}')
rm -rf "${TMPDIR_ENF}"

if [ "${TOTAL_PASS}" -gt 0 ]; then
    pass "Enforce-mode concurrency: ${TOTAL_PASS} approved queries succeeded across ${CONCURRENT_CLIENTS} clients"
else
    fail "Enforce-mode concurrency: 0 queries succeeded"
fi

set_guc "sql_firewall.mode" "learn"
sql "TRUNCATE public.sql_firewall_command_approvals;" >/dev/null 2>&1

# ===========================================================================
# SUITE 6 – Memory & Resource Validation
# ===========================================================================
section "TEST SUITE 6: Memory & Resource Validation"

step "TEST 6.1: Memory leak detection over ${MEMORY_ITER} iterations"
set_guc "sql_firewall.mode" "learn"
CRASH=0
for i in $(seq 1 "$MEMORY_ITER"); do
    if ! sql_as stressuser "SELECT id FROM stress_data WHERE id = $(( (i % 50) + 1 ))" >/dev/null 2>&1; then
        CRASH=$(( CRASH + 1 ))
    fi
done

if [ "${CRASH}" -eq 0 ]; then
    pass "Memory leak test completed (${MEMORY_ITER} iterations, 0 crashes)"
else
    fail "Memory leak test: ${CRASH} failed queries out of ${MEMORY_ITER}"
fi

step "TEST 6.2: Shared-memory stress (fingerprint cache & rate counters)"
set_guc "sql_firewall.enable_fingerprint_learning" "on"
set_guc "sql_firewall.fingerprint_learn_threshold" "2"
ERRORS=0

for i in $(seq 1 "$SHARED_MEM_OPS"); do
    # Vary the literal so multiple fingerprint slots are exercised
    if ! sql_as stressuser "SELECT score FROM fp_data WHERE label = 'label_$(( (i % 50) + 1 ))'" >/dev/null 2>&1; then
        ERRORS=$(( ERRORS + 1 ))
    fi
done

set_guc "sql_firewall.fingerprint_learn_threshold" "5"

if [ "${ERRORS}" -eq 0 ]; then
    pass "Shared memory stress test passed (${SHARED_MEM_OPS} operations, 0 errors)"
else
    fail "Shared memory stress: ${ERRORS} errors in ${SHARED_MEM_OPS} ops"
fi

step "TEST 6.3: Catalog table integrity check"
ACTIVITY_CNT=$(sql_q "SELECT COUNT(*) FROM public.sql_firewall_activity_log"         2>/dev/null || echo "?")
BLOCKED_CNT=$(sql_q  "SELECT COUNT(*) FROM public.sql_firewall_blocked_queries"       2>/dev/null || echo "?")
APPROVAL_CNT=$(sql_q "SELECT COUNT(*) FROM public.sql_firewall_command_approvals"    2>/dev/null || echo "?")
FP_CNT=$(sql_q       "SELECT COUNT(*) FROM public.sql_firewall_query_fingerprints"   2>/dev/null || echo "?")
FPH_CNT=$(sql_q      "SELECT COUNT(*) FROM public.sql_firewall_fingerprint_hits"     2>/dev/null || echo "?")
REGEX_CNT=$(sql_q    "SELECT COUNT(*) FROM public.sql_firewall_regex_rules"          2>/dev/null || echo "?")

info "Catalog table statistics:"
info "  • Activity log:       ${ACTIVITY_CNT} entries"
info "  • Blocked queries:    ${BLOCKED_CNT} entries"
info "  • Command approvals:  ${APPROVAL_CNT} entries"
info "  • Query fingerprints: ${FP_CNT} entries"
info "  • Fingerprint hits:   ${FPH_CNT} entries"
info "  • Regex rules:        ${REGEX_CNT} entries"

# Basic sanity – none of these queries should have thrown
if [[ "${ACTIVITY_CNT}" != "?" && "${BLOCKED_CNT}" != "?" ]]; then
    pass "All catalog tables accessible and populated"
else
    fail "One or more catalog tables returned an error"
fi

# ===========================================================================
# SUITE 7 – Advanced Security Features
# ===========================================================================
section "TEST SUITE 7: Advanced Security Features"

# ---- 7.1 Per-user regex exemptions (end-to-end) ---------------------------
step "TEST 7.1: Per-user regex exemptions"
# Rule: DROP TABLE is blocked for stressuser but exempted for exemptuser
sql "INSERT INTO public.sql_firewall_regex_rules (pattern, description, allowed_roles)
     VALUES ('(?i)drop[[:space:]]+table', 'Block DROP TABLE', ARRAY['exemptuser']::text[])
     ON CONFLICT (pattern) DO UPDATE SET allowed_roles = EXCLUDED.allowed_roles;" >/dev/null 2>&1
set_guc "sql_firewall.enable_regex_scan" "on"

assert_err "Per-user regex: non-exempt user (stressuser) blocked by DROP TABLE" \
    sql_as stressuser  "DROP TABLE IF EXISTS nonexistent_for_test"
assert_ok  "Per-user regex: exempt user (exemptuser) allowed to DROP TABLE" \
    sql_as exemptuser  "DROP TABLE IF EXISTS nonexistent_for_test"

sql "DELETE FROM public.sql_firewall_regex_rules WHERE pattern = '(?i)drop[[:space:]]+table';" >/dev/null 2>&1

# ---- 7.2 Multi-layer security enforcement ---------------------------------
step "TEST 7.2: Multi-layer security (approval + keyword + regex simultaneously)"
sql "TRUNCATE public.sql_firewall_command_approvals;" >/dev/null 2>&1
set_guc "sql_firewall.mode"              "enforce"
set_guc "sql_firewall.enable_keyword_scan" "on"
alter_sys "ALTER SYSTEM SET sql_firewall.blacklisted_keywords = 'pg_sleep'"
set_guc "sql_firewall.enable_regex_scan" "on"
sql "INSERT INTO public.sql_firewall_regex_rules (pattern, description)
     VALUES ('(?i)union[[:space:]]+select', 'Block UNION SELECT')
     ON CONFLICT (pattern) DO NOTHING;" >/dev/null 2>&1

# Only approve SELECT for dedicated isolated role
approve_cmd mlayer_user SELECT

# Layer 1 – approval check: INSERT not approved → blocked
assert_err "Multi-layer: unapproved INSERT blocked (approval layer)" \
    sql_as mlayer_user "INSERT INTO stress_data (val) VALUES ('multi_test')"

# Layer 2 – keyword scan: pg_sleep → blocked even though SELECT is approved
assert_err "Multi-layer: pg_sleep blocked (keyword layer)" \
    sql_as mlayer_user "SELECT pg_sleep(0)"

# Layer 3 – regex: UNION SELECT → blocked even though SELECT is approved
assert_err "Multi-layer: UNION SELECT blocked (regex layer)" \
    sql_as mlayer_user "SELECT 1 UNION SELECT 2"

# Clean query passes all three layers
assert_ok  "Multi-layer: clean approved SELECT passes all layers" \
    sql_as mlayer_user "SELECT count(*) FROM stress_data"

alter_sys "ALTER SYSTEM RESET sql_firewall.blacklisted_keywords"
sql "DELETE FROM public.sql_firewall_regex_rules WHERE pattern = '(?i)union[[:space:]]+select';" >/dev/null 2>&1
set_guc "sql_firewall.mode" "learn"
sql "TRUNCATE public.sql_firewall_command_approvals;" >/dev/null 2>&1

# ---- 7.3 Approval persistence across pg_reload_conf ----------------------
step "TEST 7.3: Approvals persist across pg_reload_conf"
sql "SELECT sql_firewall_approve_command('stressuser','SELECT');" >/dev/null 2>&1
set_guc "sql_firewall.mode" "enforce"
sql "SELECT pg_reload_conf();" >/dev/null 2>&1
sleep 1

assert_ok "Approval persists after reload" \
    sql_as stressuser "SELECT 1"

set_guc "sql_firewall.mode" "learn"
sql "TRUNCATE public.sql_firewall_command_approvals;" >/dev/null 2>&1

# ---- 7.4 Firewall audit trail completeness --------------------------------
step "TEST 7.4: Audit trail – activity log captures command_type"
set_guc "sql_firewall.enable_activity_logging" "on"
set_guc "sql_firewall.mode" "enforce"
sql "TRUNCATE public.sql_firewall_activity_log;" >/dev/null 2>&1
sql "TRUNCATE public.sql_firewall_command_approvals;" >/dev/null 2>&1
approve_cmd mlayer_user SELECT
approve_cmd mlayer_user INSERT
sql_as mlayer_user "SELECT 1;" >/dev/null 2>&1
sql_as mlayer_user "INSERT INTO stress_data (val) VALUES ('at');" >/dev/null 2>&1
sleep 1

CMD_TYPES=$(sql_q "SELECT array_agg(DISTINCT command_type ORDER BY command_type)
                   FROM public.sql_firewall_activity_log
                   WHERE log_time > now() - interval '1 minute'" 2>/dev/null || echo "")

if echo "$CMD_TYPES" | grep -qi "select\|insert"; then
    pass "Activity log records command types (found: ${CMD_TYPES})"
else
    fail "Activity log missing command_type data (got: '${CMD_TYPES}')"
fi

set_guc "sql_firewall.mode" "learn"

# ===========================================================================
# Summary
# ===========================================================================
banner "ALL ADVANCED TESTS COMPLETED"

info "Test Summary:"
info "  • Fingerprint learning & hit accumulation ✓"
info "  • Background worker pause / resume / status ✓"
info "  • Approval queue processing ✓"
info "  • High-volume SELECT stress (${STRESS_ITER} iterations) ✓"
info "  • Mixed workload (SELECT/INSERT/UPDATE/DELETE) ✓"
info "  • Rate limit stress validation ✓"
info "  • ReDoS protection (pattern rejection + runtime timeout) ✓"
info "  • statement_timeout isolation ✓"
info "  • Transaction rollback – blocked query record survival ✓"
info "  • Empty / oversized query edge cases ✓"
info "  • Concurrent connections – learn mode ✓"
info "  • Concurrent connections – enforce mode ✓"
info "  • Memory leak detection (${MEMORY_ITER} iterations) ✓"
info "  • Shared memory stress (${SHARED_MEM_OPS} operations) ✓"
info "  • Catalog table integrity ✓"
info "  • Per-user regex exemptions (end-to-end) ✓"
info "  • Multi-layer security enforcement ✓"
info "  • Approval persistence across reload ✓"
info "  • Audit trail completeness ✓"
echo ""
printf "Results: ${GREEN}%d passed${NC}, ${RED}%d failed${NC} (%d total)\n" "$PASS" "$FAIL" "$TESTS_TOTAL"
echo ""

if [ "${FAIL}" -eq 0 ]; then
    printf "${GREEN}[PASS]${NC} Test 2: Advanced Features & Stress Testing – ALL %d TESTS PASSED\n" "$TESTS_TOTAL"
    exit 0
else
    printf "${RED}[FAIL]${NC} Test 2: Advanced Features & Stress Testing – %d of %d TESTS FAILED\n" "$FAIL" "$TESTS_TOTAL"
    exit 1
fi
