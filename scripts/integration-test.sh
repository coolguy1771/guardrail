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
    
    # Run command and capture output, ignoring exit code
    output=$($cmd 2>&1) || true
    
    if echo "$output" | grep -q "$expected_pattern"; then
        echo -e "${GREEN}PASSED${NC}"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        echo -e "${RED}FAILED${NC}"
        echo "Expected pattern: $expected_pattern"
        echo "Got first 500 chars of output: $(echo "$output" | head -c 500)"
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

# Determine the binary path
if [ -f "./guardrail" ]; then
    BINARY="./guardrail"
elif [ -f "./build/guardrail" ]; then
    BINARY="./build/guardrail"
elif [ -f "./guardrail-linux-amd64" ]; then
    BINARY="./guardrail-linux-amd64"
else
    info "Building guardrail..."
    go build -o guardrail ./cmd/guardrail
    BINARY="./guardrail"
fi

info "Using binary: $BINARY"

# Start integration tests
info "Starting integration tests..."

# Test help commands
run_test "Help command" "$BINARY --help" "Available Commands:"
run_test "Validate help" "$BINARY validate --help" "Validate Kubernetes RBAC manifests"
run_test "Analyze help" "$BINARY analyze --help" "Analyze RoleBindings and ClusterRoleBindings"

# Test validate command
info "Testing validate command..."
run_test "Validate good role" "$BINARY validate -f testdata/good-role.yaml" "No issues found"
run_test "Validate wildcard role" "$BINARY validate -f testdata/role-with-wildcard.yaml" "RBAC001"
run_test "Validate secrets access" "$BINARY validate -f testdata/role-secrets-access.yaml" "RBAC003"
run_test "Validate cluster admin" "$BINARY validate -f testdata/clusterrolebinding-admin.yaml" "RBAC002"
run_test "Validate directory" "$BINARY validate -d testdata/" "issue(s)"

# Test output formats
info "Testing output formats..."
run_test "JSON output" "$BINARY validate -f testdata/role-with-wildcard.yaml -o json" '"Severity": "HIGH"'
run_test "SARIF output" "$BINARY validate -f testdata/role-with-wildcard.yaml -o sarif" '"version": "2.1.0"'

# Test analyze command
info "Testing analyze command..."
run_test "Analyze complex RBAC" "$BINARY analyze -f testdata/complex-rbac.yaml" "Risk Level"
run_test "Analyze with roles" "$BINARY analyze -f testdata/complex-rbac.yaml --show-roles" "Detailed Permissions"
run_test "Analyze directory" "$BINARY analyze -d testdata/" "Risk Level"

# Test filtering
info "Testing filtering options..."
run_test "Filter by risk level" "$BINARY analyze -f testdata/complex-rbac.yaml --risk-level high" "Risk Level: HIGH"
run_test "Filter by subject" "$BINARY analyze -f testdata/complex-rbac.yaml --subject admin@company.com" "admin@company.com"

# Test error cases
info "Testing error handling..."
run_test_expect_failure "Missing file" "$BINARY validate -f nonexistent.yaml" "no such file"
run_test "Invalid output format defaults to text" "$BINARY validate -f testdata/good-role.yaml -o invalid" "No issues found"
run_test_expect_failure "No input specified" "$BINARY validate" "either --file or --dir must be specified"

# Test cluster integration only if explicitly enabled or if we can verify cluster access
if [ "${ENABLE_CLUSTER_TESTS:-false}" = "true" ]; then
    info "Cluster tests explicitly enabled via ENABLE_CLUSTER_TESTS=true"
    info "Testing cluster integration..."
    run_test "Analyze cluster" "$BINARY analyze --cluster" "Subject Permissions"
    run_test "Analyze cluster with filter" "$BINARY analyze --cluster --risk-level high" "Risk Level"
elif command -v kubectl &> /dev/null && kubectl get nodes &> /dev/null 2>&1; then
    info "Cluster detected, running cluster integration tests..."
    run_test "Analyze cluster" "$BINARY analyze --cluster" "Subject Permissions"
    run_test "Analyze cluster with filter" "$BINARY analyze --cluster --risk-level high" "Risk Level"
else
    info "Skipping cluster integration tests (no cluster access detected)"
    if command -v kubectl &> /dev/null; then
        warn "kubectl is available but cluster access failed"
    fi
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