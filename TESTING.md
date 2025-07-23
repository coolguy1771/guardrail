# Testing Guide for Guardrail

This document provides guidance on running and writing tests for the Guardrail project.

## Running Tests

### Run all tests
```bash
go test ./...
```

### Run tests with coverage
```bash
make test-coverage
```

### Run specific package tests
```bash
go test ./pkg/validator
go test ./pkg/analyzer
go test ./pkg/kubernetes
go test ./pkg/parser
go test ./pkg/reporter
```

### Run tests with verbose output
```bash
go test -v ./...
```

### Run a specific test
```bash
go test -v -run TestValidateWildcardPermissions ./pkg/validator
```

## Test Structure

The project follows Go testing conventions with tests located alongside the code they test:

```
pkg/
├── analyzer/
│   ├── analyzer.go
│   ├── analyzer_test.go
│   ├── mapper.go
│   └── mapper_test.go
├── kubernetes/
│   ├── client.go
│   └── client_test.go
├── parser/
│   ├── parser.go
│   └── parser_test.go
├── reporter/
│   ├── reporter.go
│   └── reporter_test.go
└── validator/
    ├── validator.go
    └── validator_test.go
```

## Test Utilities

Test utilities are provided in `internal/testutil/testutil.go`:

- `NewTestRole()` - Creates test Role objects
- `NewTestClusterRole()` - Creates test ClusterRole objects
- `NewTestRoleBinding()` - Creates test RoleBinding objects
- `NewTestClusterRoleBinding()` - Creates test ClusterRoleBinding objects
- `AssertEqual()` - Simple equality assertion
- `AssertNotNil()` - Nil check assertion
- `AssertNil()` - Not nil check assertion
- `AssertContains()` - String slice contains assertion
- `AssertLen()` - Slice length assertion

## Writing Tests

### Table-Driven Tests

The project uses table-driven tests extensively:

```go
func TestValidateWildcardPermissions(t *testing.T) {
    tests := []struct {
        name          string
        object        runtime.Object
        expectedCount int
        expectedMsg   string
    }{
        {
            name: "wildcard in all fields",
            object: &rbacv1.Role{
                ObjectMeta: metav1.ObjectMeta{Name: "wildcard-all", Namespace: "default"},
                Rules: []rbacv1.PolicyRule{
                    {
                        APIGroups: []string{"*"},
                        Resources: []string{"*"},
                        Verbs:     []string{"*"},
                    },
                },
            },
            expectedCount: 3,
            expectedMsg:   "Wildcard",
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            findings := validateWildcardPermissions(tt.object)
            testutil.AssertEqual(t, tt.expectedCount, len(findings), "unexpected number of findings")
        })
    }
}
```

### Mocking

For testing the Kubernetes client, use the fake clientset:

```go
import "k8s.io/client-go/kubernetes/fake"

clientset := fake.NewSimpleClientset(role1, role2)
client := &Client{clientset: clientset}
```

### Testing Commands

Command tests require special setup due to Cobra's structure:

```go
// Re-initialize commands for each test
rootCmd = &cobra.Command{
    Use:   "guardrail",
    Short: "A Kubernetes RBAC validation tool",
}

// Add the command with flags
validateCmd = &cobra.Command{
    Use:   "validate",
    Short: "Validate RBAC manifests",
    RunE:  runValidate,
}
validateCmd.Flags().StringVarP(&file, "file", "f", "", "Path to a single RBAC manifest file")
rootCmd.AddCommand(validateCmd)

// Execute
err := rootCmd.Execute()
```

## Common Test Patterns

### Testing Error Cases
```go
t.Run("error case", func(t *testing.T) {
    _, err := FunctionThatShouldError()
    testutil.AssertNotNil(t, err, "expected error")
    if err != nil && !strings.Contains(err.Error(), "expected message") {
        t.Errorf("expected error to contain 'expected message', got: %v", err)
    }
})
```

### Testing File Operations
```go
// Create temporary test files
tmpDir, err := os.MkdirTemp("", "test-*")
if err != nil {
    t.Fatal(err)
}
defer os.RemoveAll(tmpDir)

// Write test content
testFile := filepath.Join(tmpDir, "test.yaml")
if err := os.WriteFile(testFile, []byte(content), 0644); err != nil {
    t.Fatal(err)
}
```

### Testing JSON Output
```go
var result map[string]interface{}
if err := json.Unmarshal(output, &result); err != nil {
    t.Errorf("expected valid JSON, got error: %v", err)
}
// Check specific fields
if _, ok := result["findings"]; !ok {
    t.Error("expected 'findings' field in JSON")
}
```

## CI/CD Integration

Tests are automatically run in CI on:
- Every push to main
- Every pull request
- Multiple OS (Linux, macOS, Windows)
- Multiple Go versions (1.23, 1.24)

The CI configuration enables race detection by default.