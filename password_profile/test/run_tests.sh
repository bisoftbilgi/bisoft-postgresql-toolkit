#!/bin/bash
# Password Profile Pure - Test Suite Runner
# ==========================================

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

TESTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SQL_DIR="$TESTS_DIR/sql"
EXPECTED_DIR="$TESTS_DIR/expected"
RESULTS_DIR="$TESTS_DIR/results"

# PostgreSQL connection settings
PGDATABASE="${PGDATABASE:-postgres}"
PGHOST="${PGHOST:-localhost}"
PGPORT="${PGPORT:-5432}"
PGUSER="${PGUSER:-postgres}"

echo "=========================================="
echo "Password Profile Pure - Test Suite"
echo "=========================================="
echo "Database: $PGDATABASE"
echo "Host: $PGHOST:$PGPORT"
echo "User: $PGUSER"
echo ""

# Create results directory
mkdir -p "$RESULTS_DIR"

# Function to run a single test
run_test() {
    local test_file="$1"
    local test_name=$(basename "$test_file" .sql)
    local result_file="$RESULTS_DIR/${test_name}.out"
    local expected_file="$EXPECTED_DIR/${test_name}.out"
    
    echo -n "Running test: $test_name ... "
    
    # Run the test and capture output
    if psql -h "$PGHOST" -p "$PGPORT" -U "$PGUSER" -d "$PGDATABASE" \
         -f "$test_file" > "$result_file" 2>&1; then
        
        # Check if expected output exists
        if [ -f "$expected_file" ]; then
            # Compare output with expected
            if diff -u "$expected_file" "$result_file" > /dev/null 2>&1; then
                echo -e "${GREEN}PASS${NC}"
                return 0
            else
                echo -e "${RED}FAIL${NC} (output mismatch)"
                echo "  Run: diff -u $expected_file $result_file"
                return 1
            fi
        else
            echo -e "${YELLOW}SKIP${NC} (no expected output, creating baseline)"
            cp "$result_file" "$expected_file"
            return 0
        fi
    else
        echo -e "${RED}ERROR${NC}"
        cat "$result_file"
        return 1
    fi
}

# Run all tests
PASS=0
FAIL=0
SKIP=0

for test_file in "$SQL_DIR"/*.sql; do
    if [ -f "$test_file" ]; then
        if run_test "$test_file"; then
            ((PASS++))
        else
            ((FAIL++))
        fi
    fi
done

echo ""
echo "=========================================="
echo "Test Results:"
echo "  ${GREEN}Passed: $PASS${NC}"
echo "  ${RED}Failed: $FAIL${NC}"
echo "=========================================="

# Exit with appropriate code
if [ $FAIL -eq 0 ]; then
    echo -e "${GREEN}All tests passed!${NC}"
    exit 0
else
    echo -e "${RED}Some tests failed!${NC}"
    exit 1
fi
