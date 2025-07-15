#!/bin/bash
set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test counters
TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

# Helper functions
info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

run_test() {
    local test_name=$1
    local cmd=$2
    local expected_pattern=$3
    
    TESTS_RUN=$((TESTS_RUN + 1))
    echo -n "Running: $test_name... "
    
    if output=$($cmd 2>&1); then
        if echo "$output" | grep -q "$expected_pattern"; then
            echo -e "${GREEN}PASSED${NC}"
            TESTS_PASSED=$((TESTS_PASSED + 1))
        else
            echo -e "${RED}FAILED${NC}"
            echo "Expected pattern: $expected_pattern"
            echo "Got output: $output"
            TESTS_FAILED=$((TESTS_FAILED + 1))
        fi
    else
        echo -e "${RED}FAILED${NC} (command failed)"
        echo "Error: $output"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi
}

run_test_expect_failure() {
    local test_name=$1
    local cmd=$2
    local expected_pattern=$3
    
    TESTS_RUN=$((TESTS_RUN + 1))
    echo -n "Running: $test_name... "
    
    if output=$($cmd 2>&1); then
        echo -e "${RED}FAILED${NC} (expected command to fail)"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    else
        if echo "$output" | grep -q "$expected_pattern"; then
            echo -e "${GREEN}PASSED${NC}"
            TESTS_PASSED=$((TESTS_PASSED + 1))
        else
            echo -e "${RED}FAILED${NC}"
            echo "Expected error pattern: $expected_pattern"
            echo "Got output: $output"
            TESTS_FAILED=$((TESTS_FAILED + 1))
        fi
    fi
}

# Build the binary
info "Building guardrail..."
go build -o guardrail ./cmd/guardrail

# Start integration tests
info "Starting integration tests..."

# Test help commands
run_test "Help command" "./guardrail --help" "Available Commands:"
run_test "Validate help" "./guardrail validate --help" "Validate RBAC manifests"
run_test "Analyze help" "./guardrail analyze --help" "Analyze RBAC permissions"

# Test validate command
info "Testing validate command..."
run_test "Validate good role" "./guardrail validate -f testdata/good-role.yaml" "No violations found"
run_test "Validate wildcard role" "./guardrail validate -f testdata/role-with-wildcard.yaml" "RBAC001"
run_test "Validate secrets access" "./guardrail validate -f testdata/role-secrets-access.yaml" "RBAC003"
run_test "Validate cluster admin" "./guardrail validate -f testdata/clusterrolebinding-admin.yaml" "RBAC002"
run_test "Validate directory" "./guardrail validate -d testdata/" "violations found"

# Test output formats
info "Testing output formats..."
run_test "JSON output" "./guardrail validate -f testdata/role-with-wildcard.yaml -o json" '"severity":"High"'
run_test "SARIF output" "./guardrail validate -f testdata/role-with-wildcard.yaml -o sarif" '"version":"2.1.0"'

# Test analyze command
info "Testing analyze command..."
run_test "Analyze complex RBAC" "./guardrail analyze -f testdata/complex-rbac.yaml" "Subject Permissions"
run_test "Analyze with roles" "./guardrail analyze -f testdata/complex-rbac.yaml --show-roles" "Role Details"
run_test "Analyze directory" "./guardrail analyze -d testdata/" "permissions analyzed"

# Test filtering
info "Testing filtering options..."
run_test "Filter by risk level" "./guardrail analyze -f testdata/complex-rbac.yaml --risk-level critical" "Critical"
run_test "Filter by subject" "./guardrail analyze -f testdata/complex-rbac.yaml --subject admin" "admin"

# Test error cases
info "Testing error handling..."
run_test_expect_failure "Missing file" "./guardrail validate -f nonexistent.yaml" "no such file"
run_test_expect_failure "Invalid output format" "./guardrail validate -f testdata/good-role.yaml -o invalid" "unsupported output format"
run_test_expect_failure "No input specified" "./guardrail validate" "must specify"

# If kubectl is available and we're in CI, test cluster integration
if command -v kubectl &> /dev/null && [ "${CI:-false}" = "true" ]; then
    info "Testing cluster integration..."
    run_test "Analyze cluster" "./guardrail analyze --cluster" "Subject Permissions"
    run_test "Analyze cluster with filter" "./guardrail analyze --cluster --risk-level high" "Risk Level"
fi

# Summary
echo
echo "================================"
echo "Integration Test Summary"
echo "================================"
echo -e "Tests run:    ${TESTS_RUN}"
echo -e "Tests passed: ${GREEN}${TESTS_PASSED}${NC}"
echo -e "Tests failed: ${RED}${TESTS_FAILED}${NC}"
echo "================================"

if [ $TESTS_FAILED -gt 0 ]; then
    error "Integration tests failed!"
    exit 1
else
    info "All integration tests passed!"
fi