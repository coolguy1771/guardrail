# Testing Guide

This document describes the testing infrastructure and best practices for the Guardrail project.

## Test Structure

### Unit Tests
Each package has comprehensive unit tests located alongside the source code:
- `pkg/analyzer/analyzer_test.go` - Analyzer unit tests
- `pkg/validator/validator_test.go` - Validator unit tests
- `pkg/parser/parser_test.go` - Parser unit tests
- `pkg/reporter/reporter_test.go` - Reporter unit tests
- `pkg/kubernetes/client_test.go` - Kubernetes client unit tests

### Integration Tests
Integration tests are located in:
- `scripts/integration-test.sh` - Shell script for end-to-end testing
- CI workflow runs integration tests against multiple Kubernetes versions

### Benchmark Tests
Performance benchmarks are available:
- `pkg/analyzer/analyzer_bench_test.go` - Analyzer benchmarks
- `pkg/validator/validator_bench_test.go` - Validator benchmarks

## Running Tests

### Basic Commands

```bash
# Run all tests
make test

# Run tests with coverage
make test-coverage

# Check coverage with cov (70% threshold)
make cov

# Check PR coverage with cov (80% threshold)
make cov-pr

# Run integration tests
make test-integration

# Run benchmarks
make test-bench

# Run tests for specific package
make test-pkg PKG=analyzer
```

### Advanced Testing

```bash
# Run tests with race detection
go test -race ./...

# Run specific test
go test -v -run TestAnalyzePermissions ./pkg/analyzer

# Run benchmarks with memory profiling
go test -bench=. -benchmem ./pkg/analyzer

# Generate coverage report
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out -o coverage.html

# Install cov locally
go install github.com/PaloAltoNetworks/cov@latest

# Use cov directly
cov --threshold 70 coverage.out
cov --branch main --threshold 80 coverage.out  # For PR coverage
```

## CI/CD Testing

### Test Matrix
- **Operating Systems**: Ubuntu, macOS, Windows
- **Go Versions**: 1.23, 1.24
- **Kubernetes Versions**: 1.30, 1.31, 1.32

### CI Jobs
1. **Lint** - Code quality checks with golangci-lint
2. **Test** - Unit tests with race detection and coverage (uses Cov for coverage checking)
3. **Build** - Cross-platform builds
4. **Integration Test** - End-to-end tests with Kind clusters
5. **Benchmark** - Performance regression testing (PRs only)
6. **Security Scan** - Vulnerability scanning with Trivy

### PR Validation
- Semantic PR title validation
- Commit message linting
- PR size labeling
- Changed package testing
- Test data validation

## Test Utilities

The `internal/testutil` package provides helpers for testing:

```go
// Create test RBAC objects
role := testutil.NewTestRole("test-role", "default")
testutil.AddRule(role, rbacv1.PolicyRule{
    APIGroups: []string{""},
    Resources: []string{"pods"},
    Verbs:     []string{"get", "list"},
})

// Assertions
testutil.AssertEqual(t, expected, actual, "values should match")
testutil.AssertContains(t, slice, value, "slice should contain value")
```

## Test Data

Test YAML files are located in `testdata/`:
- `good-role.yaml` - Valid RBAC configuration
- `role-with-wildcard.yaml` - Role with wildcard permissions
- `role-secrets-access.yaml` - Role with secrets access
- `clusterrolebinding-admin.yaml` - Cluster admin binding
- `complex-rbac.yaml` - Complex multi-object RBAC
- `namespace-admin.yaml` - Namespace-scoped admin role
- `dev-team-rbac.yaml` - Developer team RBAC setup

## Coverage Requirements

Using [Cov](https://github.com/PaloAltoNetworks/cov) for coverage checking:

- **Overall Coverage**: 70% minimum (enforced in CI)
- **PR Coverage**: 80% minimum (enforced for changed code)
- **Package Coverage Goals**:
  - `pkg/reporter`: 100% ✓
  - `pkg/validator`: 100% ✓
  - `pkg/parser`: 97.6% ✓
  - `pkg/analyzer`: 80.0% ✓
  - `pkg/kubernetes`: 54.9% (mocked client)

### Coverage Reports

Cov generates a tree view showing which packages meet the coverage threshold. Coverage status is reported as a GitHub status check on PRs.

### Ignoring Files

Files excluded from coverage via `.covignore`:
- Test files (`**/*_test.go`)
- Test utilities (`internal/testutil/*`)
- Test data (`testdata/*`)
- Generated code (`*.pb.go`, `mock_*.go`)

## Best Practices

1. **Table-Driven Tests**: Use table-driven tests for comprehensive coverage
2. **Test Helpers**: Use `testutil` package for common test operations
3. **Parallel Tests**: Mark independent tests with `t.Parallel()`
4. **Error Cases**: Always test error conditions and edge cases
5. **Benchmarks**: Add benchmarks for performance-critical code
6. **Integration Tests**: Test real-world scenarios with actual YAML files

## Debugging Tests

```bash
# Run tests with verbose output
go test -v ./pkg/analyzer

# Run with specific test filter
go test -v -run "TestAnalyze.*Critical" ./pkg/analyzer

# Debug with delve
dlv test ./pkg/analyzer

# Check test coverage for specific functions
go test -coverprofile=coverage.out ./pkg/analyzer
go tool cover -func=coverage.out | grep functionName
```

## Contributing Tests

When adding new features:
1. Write unit tests first (TDD approach)
2. Add integration test cases
3. Include benchmark if performance-critical
4. Update test data if needed
5. Ensure coverage doesn't decrease
6. Run `make pre-commit` before pushing