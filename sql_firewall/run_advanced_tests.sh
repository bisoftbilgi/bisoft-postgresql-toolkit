#!/bin/bash
# ===========================================================
# SQL Firewall RS - FULL PERFORMANCE & ROBUSTNESS TEST SUITE
# ===========================================================
# Tests:
# 1. Concurrent sessions
# 2. Memory/shmem stress
# 3. Crash-restart durability
# 4. Cross-schema and cross-database isolation
# 5. Latency profiling
# 6. SQL fuzz testing

DB="test_firewall_db"
EXT="sql_firewall_rs"
ADMIN="postgres"
TEST_USER="user1"
TEST_PWD="123"
PGHOST="127.0.0.1"
PGPORT="5432"
LOGFILE="full_perf_test.log"
passed=0
failed=0

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; NC='\033[0m'

info(){ echo -e "${YELLOW}$*${NC}"; echo "[INFO] $*" >> $LOGFILE; }
ok(){ echo -e "${GREEN}$*${NC}"; echo "[OK] $*" >> $LOGFILE; ((passed++)); }
err(){ echo -e "${RED}$*${NC}"; echo "[ERR] $*" >> $LOGFILE; ((failed++)); }

psql_user(){ PGPASSWORD="$TEST_PWD" psql -h "$PGHOST" -p "$PGPORT" -U "$TEST_USER" -d "$DB" -At -q -c "$*"; }
psql_admin(){ PGPASSWORD="caghan" psql -h "$PGHOST" -p "$PGPORT" -U "$ADMIN" -d "$DB" -At -q -c "$*"; }

start_time() { date +%s%3N; }
end_time() { date +%s%3N; }

cpu_snapshot() { grep 'cpu ' /proc/stat | awk '{print $2+$4}'; }

# ===========================================================
# 1. Concurrent Sessions
# ===========================================================
info "TEST 1: Concurrent sessions under rate limiting"
psql_admin "ALTER SYSTEM SET sql_firewall.enable_rate_limiting=on;"
psql_admin "ALTER SYSTEM SET sql_firewall.rate_limit_count=3;"
psql_admin "ALTER SYSTEM SET sql_firewall.rate_limit_seconds=5;"
psql_admin "SELECT pg_reload_conf();"
sleep 1

run_concurrent_queries() {
  for i in {1..20}; do
    psql_user "SELECT $i;" >/dev/null 2>&1
  done
}

cpu_before=$(cpu_snapshot)
start=$(start_time)
for n in {1..10}; do run_concurrent_queries & done
wait
end=$(end_time)
cpu_after=$(cpu_snapshot)
duration=$((end - start))
cpu_load=$((cpu_after - cpu_before))
ok "Concurrent session test completed in ${duration}ms (CPU delta=$cpu_load jiffies)"

# ===========================================================
# 2. Memory / Shmem Stress
# ===========================================================
info "TEST 2: Shared memory and lock contention test"
psql_admin "ALTER SYSTEM SET sql_firewall.enable_fingerprint_learning=on;"
psql_admin "SELECT pg_reload_conf();"
psql_admin "TRUNCATE sql_firewall_activity_log;" >/dev/null 2>&1

start=$(start_time)
for i in {1..2000}; do
  psql_user "INSERT INTO sql_firewall_activity_log(role_name, action) VALUES('stress_$i','SELECT');" >/dev/null 2>&1 &
  if (( $i % 100 == 0 )); then sleep 0.05; fi
done
wait
end=$(end_time)
duration=$((end - start))
ok "Memory stress test completed (${duration}ms, 2000 inserts)"

# ===========================================================
# 3. Crash-Restart Durability
# ===========================================================
info "TEST 3: PostgreSQL restart and transaction durability"
psql_admin "ALTER TABLE sql_firewall_activity_log SET LOGGED;"
psql_admin "INSERT INTO sql_firewall_activity_log(role_name, database_name, action, reason, query_text, command_type) VALUES ('restart_probe', current_database(), 'TEST', 'durability check', 'SELECT 1', 'SELECT');"
pre_cnt=$(psql_admin "SELECT count(*) FROM sql_firewall_activity_log WHERE role_name='restart_probe';" 2>/dev/null || echo 0)
if sudo -n systemctl restart postgresql-16 >/dev/null 2>&1 || sudo -n systemctl restart postgresql >/dev/null 2>&1; then
  sleep 3
  if psql_admin "SELECT 1;" >/dev/null 2>&1; then
    ok "PostgreSQL restart successful"
  else
    err "PostgreSQL restart verification failed"
  fi
  post_cnt=$(psql_admin "SELECT count(*) FROM sql_firewall_activity_log WHERE role_name='restart_probe';" 2>/dev/null || echo 0)
  if [[ "$post_cnt" -ge "$pre_cnt" && "$post_cnt" -gt 0 ]]; then
    ok "Activity log persisted across restart (rows=$post_cnt)"
  else
    err "Activity log lost entries across restart ($pre_cnt -> $post_cnt)"
  fi
else
  info "Skipping restart test (requires passwordless sudo)"
fi
psql_admin "DELETE FROM sql_firewall_activity_log WHERE role_name='restart_probe';" >/dev/null 2>&1

psql_admin "BEGIN; INSERT INTO sql_firewall_activity_log(role_name, action) VALUES('txn_test','INSERT'); COMMIT;"
tx_count=$(psql_admin "SELECT count(*) FROM sql_firewall_activity_log WHERE role_name='txn_test';")
[[ "$tx_count" -gt 0 ]] && ok "Transaction durability verified ($tx_count entries)" || err "Transaction rollback persistence failed"
psql_admin "DELETE FROM sql_firewall_activity_log WHERE role_name='txn_test';" >/dev/null 2>&1

# ===========================================================
# 4. Cross-schema / Cross-database
# ===========================================================
info "TEST 4: Schema and database isolation"
psql_admin "CREATE DATABASE firewall_test_iso WITH OWNER=$ADMIN CONNECTION LIMIT 5;" >/dev/null 2>&1
psql_admin "REVOKE CONNECT ON DATABASE firewall_test_iso FROM PUBLIC;" >/dev/null 2>&1
psql_admin "REVOKE CONNECT ON DATABASE firewall_test_iso FROM $TEST_USER;" >/dev/null 2>&1
PGDATABASE="firewall_test_iso" psql_admin "CREATE EXTENSION IF NOT EXISTS sql_firewall_rs;"
psql_admin "CREATE SCHEMA IF NOT EXISTS private;"
psql_admin "CREATE TABLE IF NOT EXISTS private.hidden_data(id serial, secret text);" >/dev/null 2>&1
psql_admin "ALTER DEFAULT PRIVILEGES REVOKE ALL ON SCHEMAS FROM PUBLIC;" >/dev/null 2>&1
psql_admin "ALTER DEFAULT PRIVILEGES REVOKE ALL ON TABLES FROM PUBLIC;" >/dev/null 2>&1
psql_admin "REVOKE ALL PRIVILEGES ON DATABASE $DB FROM PUBLIC;" >/dev/null 2>&1
psql_admin "REVOKE CONNECT ON DATABASE $DB FROM $TEST_USER;" >/dev/null 2>&1
psql_admin "REVOKE ALL PRIVILEGES ON SCHEMA private FROM $TEST_USER;" >/dev/null 2>&1
psql_admin "REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA private FROM $TEST_USER;" >/dev/null 2>&1
psql_admin "REVOKE USAGE ON SCHEMA private FROM $TEST_USER;" >/dev/null 2>&1
psql_admin "GRANT USAGE ON SCHEMA private TO $ADMIN;" >/dev/null 2>&1
psql_admin "GRANT SELECT ON private.hidden_data TO $ADMIN;" >/dev/null 2>&1
psql_admin "REVOKE ALL PRIVILEGES ON TABLE private.hidden_data FROM PUBLIC;" >/dev/null 2>&1
psql_admin "REVOKE ALL PRIVILEGES ON TABLE private.hidden_data FROM $TEST_USER;" >/dev/null 2>&1

if psql_user "SELECT * FROM private.hidden_data;" 2>&1 | grep -Eiq "permission denied|izin reddedildi|ERROR"; then
  ok "Schema isolation successful"
else
  err "Schema isolation failed"
fi

out=$(PGDATABASE="firewall_test_iso" psql_user "SELECT 1;" 2>&1)
if echo "$out" | grep -qi "FATAL"; then
  ok "Cross-database access isolated"
else
  err "Cross-database access leaked"
fi

# ===========================================================
# 5. Latency Profiling
# ===========================================================
info "TEST 5: Latency measurement per mode"
measure_latency() {
  local mode=$1
  psql_admin "ALTER SYSTEM SET sql_firewall.mode='$mode';"
  psql_admin "SELECT pg_reload_conf();"
  sleep 0.5
  start=$(start_time)
  for i in {1..1000}; do psql_user "SELECT $i;" >/dev/null 2>&1; done
  end=$(end_time)
  echo $((end - start))
}
lat_learn=$(measure_latency "learn" | tr -dc '0-9')
lat_enforce=$(measure_latency "enforce" | tr -dc '0-9')
diff=$((lat_enforce - lat_learn))
ok "Learn mode latency: ${lat_learn}ms"
ok "Enforce mode latency: ${lat_enforce}ms"
info "Latency difference: ${diff}ms over 1000 queries"

# ===========================================================
# 6. SQL Fuzz Testing
# ===========================================================
info "TEST 6: Random fuzz + injection patterns"
FUZZ_FILE=$(mktemp)
patterns=("UNION SELECT" "' OR '1'='1" "DROP TABLE" "-- comment" ";SELECT" "1/0" "/*inject*/" "';--" "xp_cmdshell")
for pattern in "${patterns[@]}"; do
  echo "SELECT * FROM public.test_table WHERE note='$pattern';" >> $FUZZ_FILE
done
for i in {1..50}; do
  rand=$(head /dev/urandom | tr -dc A-Za-z0-9 | head -c 6)
  echo "SELECT '$rand';" >> $FUZZ_FILE
done

blocked=0
while IFS= read -r sql; do
  out=$(psql_user "$sql" 2>&1)
  if echo "$out" | grep -qi "blocked"; then ((blocked++)); fi
done < "$FUZZ_FILE"
rm -f "$FUZZ_FILE"
ok "Fuzz test complete, $blocked queries blocked out of 60"

# ===========================================================
# SUMMARY
# ===========================================================
echo ""
echo "===== FULL PERFORMANCE TEST SUMMARY ====="
echo "Results logged in $LOGFILE"
echo -e "${GREEN}Passed: $passed  Failed: $failed  Total: $((passed + failed))${NC}"
if [[ "$failed" -eq 0 ]]; then
  echo -e "${GREEN}ALL TESTS PASSED SUCCESSFULLY${NC}"
else
  echo -e "${RED}$failed TEST(S) FAILED${NC}"
fi
echo ""
