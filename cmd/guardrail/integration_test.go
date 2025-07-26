//go:build integration
// +build integration

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// TestIntegrationCommands runs integration tests for the guardrail CLI
func TestIntegrationCommands(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration tests in short mode")
	}

	// Build the binary once for all tests
	binary := buildBinary(t)

	// Get the project root directory
	projectRoot := getProjectRoot(t)

	tests := []struct {
		name       string
		args       []string
		wantErr    bool
		contains   []string
		excludes   []string
		skipReason string
	}{
		// Help commands
		{
			name:     "help command",
			args:     []string{"--help"},
			contains: []string{"Available Commands:", "validate", "analyze"},
		},
		{
			name:     "validate help",
			args:     []string{"validate", "--help"},
			contains: []string{"Validate Kubernetes RBAC manifests", "--file", "--dir"},
		},
		{
			name:     "analyze help",
			args:     []string{"analyze", "--help"},
			contains: []string{"Analyze RoleBindings and ClusterRoleBindings", "--subject", "--risk-level"},
		},

		// Validate commands - positive cases
		{
			name:     "validate good role",
			args:     []string{"validate", "-f", filepath.Join(projectRoot, "testdata", "good-role.yaml")},
			contains: []string{"No issues found"},
			excludes: []string{"RBAC001", "RBAC002", "RBAC003"},
		},
		{
			name:     "validate wildcard role",
			args:     []string{"validate", "-f", filepath.Join(projectRoot, "testdata", "role-with-wildcard.yaml")},
			wantErr:  true, // validation should fail with high severity issues
			contains: []string{"RBAC001", "HIGH", "Wildcard"},
		},
		{
			name:     "validate secrets access",
			args:     []string{"validate", "-f", filepath.Join(projectRoot, "testdata", "role-secrets-access.yaml")},
			wantErr:  false, // MEDIUM severity doesn't cause exit error
			contains: []string{"RBAC003", "MEDIUM", "Direct read access to secrets"},
		},
		{
			name:     "validate cluster admin",
			args:     []string{"validate", "-f", filepath.Join(projectRoot, "testdata", "clusterrolebinding-admin.yaml")},
			wantErr:  true, // validation exits with error when issues found
			contains: []string{"RBAC002", "HIGH", "cluster-admin"},
		},
		{
			name:     "validate directory",
			args:     []string{"validate", "-d", filepath.Join(projectRoot, "testdata")},
			wantErr:  true, // validation exits with error when issues found
			contains: []string{"Found", "issue"},
		},
		{
			name:     "validate multiple files",
			args:     []string{"validate", "-f", filepath.Join(projectRoot, "testdata", "role-with-wildcard.yaml"), "-f", filepath.Join(projectRoot, "testdata", "role-secrets-access.yaml")},
			wantErr:  true,                           // validation exits with error when HIGH severity issues found
			contains: []string{"RBAC001", "RBAC003"}, // Should find issues from both files
		},

		// Output formats
		{
			name:     "JSON output",
			args:     []string{"validate", "-f", filepath.Join(projectRoot, "testdata", "role-with-wildcard.yaml"), "-o", "json"},
			wantErr:  true, // validation exits with error when issues found
			contains: []string{`"Severity": "HIGH"`, `"RuleID": "RBAC001"`, `"Resource":`},
		},
		{
			name:     "SARIF output",
			args:     []string{"validate", "-f", filepath.Join(projectRoot, "testdata", "role-with-wildcard.yaml"), "-o", "sarif"},
			wantErr:  true, // validation exits with error when issues found
			contains: []string{`"version": "2.1.0"`, `"$schema"`, `"runs":`},
		},
		{
			name:     "Text output format explicit",
			args:     []string{"validate", "-f", filepath.Join(projectRoot, "testdata", "role-with-wildcard.yaml"), "-o", "text"},
			wantErr:  true, // validation exits with error when issues found
			contains: []string{"RBAC001", "HIGH"},
		},

		// Analyze commands
		{
			name:     "analyze complex RBAC",
			args:     []string{"analyze", "-f", filepath.Join(projectRoot, "testdata", "complex-rbac.yaml")},
			contains: []string{"📊 RBAC Analysis Summary", "Risk Level", "Total Subjects:"},
		},
		{
			name:     "analyze with detailed roles",
			args:     []string{"analyze", "-f", filepath.Join(projectRoot, "testdata", "complex-rbac.yaml"), "--show-roles"},
			contains: []string{"Detailed Permissions", "Risk Level", "Actions allowed:"},
		},
		{
			name:     "analyze directory",
			args:     []string{"analyze", "-d", filepath.Join(projectRoot, "testdata")},
			contains: []string{"Risk Level", "📊 RBAC Analysis Summary"},
		},
		{
			name:     "analyze JSON output",
			args:     []string{"analyze", "-f", filepath.Join(projectRoot, "testdata", "complex-rbac.yaml"), "-o", "json"},
			contains: []string{`"subjects":`, `"summary":`, `"total_subjects":`},
		},

		// Filtering options
		{
			name:     "filter by high risk level",
			args:     []string{"analyze", "-f", filepath.Join(projectRoot, "testdata", "complex-rbac.yaml"), "--risk-level", "high"},
			contains: []string{"Risk Level: HIGH"},
			excludes: []string{"Risk Level: LOW", "Risk Level: MEDIUM"},
		},
		{
			name:     "filter by critical risk level",
			args:     []string{"analyze", "-f", filepath.Join(projectRoot, "testdata", "complex-rbac.yaml"), "--risk-level", "critical"},
			contains: []string{"No RBAC permissions found matching the criteria"},
		},
		{
			name:     "filter by subject",
			args:     []string{"analyze", "-f", filepath.Join(projectRoot, "testdata", "complex-rbac.yaml"), "--subject", "admin@company.com"},
			contains: []string{"admin@company.com"},
			excludes: []string{"developer@company.com", "service-account@company.com"},
		},
		{
			name:     "filter by non-existent subject",
			args:     []string{"analyze", "-f", filepath.Join(projectRoot, "testdata", "complex-rbac.yaml"), "--subject", "nonexistent@company.com"},
			contains: []string{"No RBAC permissions found matching the criteria"},
		},

		// Error cases
		{
			name:     "missing file",
			args:     []string{"validate", "-f", "nonexistent.yaml"},
			wantErr:  true,
			contains: []string{"no such file"},
		},
		{
			name:     "invalid YAML file",
			args:     []string{"validate", "-f", "README.md"},
			wantErr:  true,
			contains: []string{"failed to decode YAML"},
		},
		{
			name:     "no input specified for validate",
			args:     []string{"validate"},
			wantErr:  true,
			contains: []string{"either --file or --dir must be specified"},
		},
		{
			name:     "no input specified for analyze",
			args:     []string{"analyze"},
			wantErr:  true,
			contains: []string{"must specify one of --file, --dir, or --cluster"},
		},
		{
			name:     "multiple input sources",
			args:     []string{"analyze", "-f", filepath.Join(projectRoot, "testdata", "good-role.yaml"), "-d", filepath.Join(projectRoot, "testdata")},
			wantErr:  true,
			contains: []string{"cannot specify multiple input sources"},
		},
		{
			name:     "invalid output format defaults to text",
			args:     []string{"validate", "-f", filepath.Join(projectRoot, "testdata", "good-role.yaml"), "-o", "invalid"},
			contains: []string{"No issues found"},
		},
		{
			name:     "invalid risk level",
			args:     []string{"analyze", "-f", filepath.Join(projectRoot, "testdata", "complex-rbac.yaml"), "--risk-level", "invalid"},
			contains: []string{"No RBAC permissions found matching the criteria"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.skipReason != "" {
				t.Skip(tt.skipReason)
			}

			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			cmd := exec.CommandContext(ctx, binary, tt.args...)
			cmd.Dir = projectRoot // Run from project root so relative paths work
			var stdout, stderr bytes.Buffer
			cmd.Stdout = &stdout
			cmd.Stderr = &stderr

			err := cmd.Run()
			if (err != nil) != tt.wantErr {
				t.Errorf("unexpected error: wantErr=%v, got=%v\nstderr: %s", tt.wantErr, err, stderr.String())
			}

			output := stdout.String() + stderr.String()

			// Check for expected strings
			for _, want := range tt.contains {
				if !strings.Contains(output, want) {
					t.Errorf("output missing expected string %q\nGot output:\n%s", want, truncateOutput(output))
				}
			}

			// Check for excluded strings
			for _, exclude := range tt.excludes {
				if strings.Contains(output, exclude) {
					t.Errorf("output contains unexpected string %q\nGot output:\n%s", exclude, truncateOutput(output))
				}
			}
		})
	}
}

// TestIntegrationCluster runs cluster-specific integration tests
func TestIntegrationCluster(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping cluster integration tests in short mode")
	}

	// Get the project root directory
	projectRoot := getProjectRoot(t)

	// Check if cluster tests are enabled
	if os.Getenv("ENABLE_CLUSTER_TESTS") != "true" {
		// Try to detect if a cluster is available
		cmd := exec.Command("kubectl", "get", "nodes")
		cmd.Dir = projectRoot
		if err := cmd.Run(); err != nil {
			t.Skip("Skipping cluster tests: no cluster access detected (set ENABLE_CLUSTER_TESTS=true to force)")
		}
	}

	binary := buildBinary(t)

	// Apply test resources using Kustomize
	t.Log("Applying test resources using Kustomize...")
	applyCmd := exec.Command("kubectl", "apply", "-k", filepath.Join(projectRoot, "testdata"))
	applyCmd.Dir = projectRoot
	if output, err := applyCmd.CombinedOutput(); err != nil {
		t.Logf("Warning: Failed to apply test resources: %v\nOutput: %s", err, output)
	}

	// Clean up resources after tests
	t.Cleanup(func() {
		t.Log("Cleaning up test RBAC resources...")
		// Use label selector to delete all test resources
		deleteCmd := exec.Command("kubectl", "delete", "all,namespaces,clusterroles,clusterrolebindings,roles,rolebindings",
			"-l", "test-suite=guardrail-integration", "--ignore-not-found=true")
		deleteCmd.Dir = projectRoot
		if output, err := deleteCmd.CombinedOutput(); err != nil {
			t.Logf("Warning: Failed to clean up test resources: %v\nOutput: %s", err, output)
		}
	})

	tests := []struct {
		name     string
		args     []string
		contains []string
		setup    func(t *testing.T)
	}{
		{
			name:     "analyze cluster basic",
			args:     []string{"analyze", "--cluster"},
			contains: []string{"📊 RBAC Analysis Summary", "Total Subjects:", "Risk Distribution:"},
		},
		{
			name:     "analyze cluster with high risk filter",
			args:     []string{"analyze", "--cluster", "--risk-level", "high"},
			contains: []string{"Risk Level"},
		},
		{
			name:     "analyze cluster with subject filter",
			args:     []string{"analyze", "--cluster", "--subject", "system:masters"},
			contains: []string{"system:masters"},
		},
		{
			name:     "analyze cluster JSON output",
			args:     []string{"analyze", "--cluster", "-o", "json"},
			contains: []string{`"subjects":`, `"summary":`},
		},
		{
			name:     "analyze cluster with context",
			args:     []string{"analyze", "--cluster", "--context", getCurrentContext(t)},
			contains: []string{"📊 RBAC Analysis Summary"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.setup != nil {
				tt.setup(t)
			}

			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()

			cmd := exec.CommandContext(ctx, binary, tt.args...)
			cmd.Dir = projectRoot
			output, err := cmd.CombinedOutput()

			// For cluster tests, we're more lenient with errors
			// as the cluster might not have any RBAC resources matching filters
			if err != nil && !strings.Contains(string(output), "No RBAC permissions found") {
				t.Logf("Command failed (might be expected): %v\nOutput: %s", err, truncateOutput(string(output)))
			}

			for _, want := range tt.contains {
				if !strings.Contains(string(output), want) {
					t.Errorf("output missing expected string %q\nGot output:\n%s", want, truncateOutput(string(output)))
				}
			}
		})
	}
}

// TestIntegrationPerformance runs performance benchmarks as integration tests
func TestIntegrationPerformance(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping performance tests in short mode")
	}

	binary := buildBinary(t)

	// Get the project root directory
	projectRoot := getProjectRoot(t)

	tests := []struct {
		name        string
		args        []string
		maxDuration time.Duration
	}{
		{
			name:        "validate large directory performance",
			args:        []string{"validate", "-d", filepath.Join(projectRoot, "testdata")},
			maxDuration: 5 * time.Second,
		},
		{
			name:        "analyze complex RBAC performance",
			args:        []string{"analyze", "-f", filepath.Join(projectRoot, "testdata", "complex-rbac.yaml")},
			maxDuration: 2 * time.Second,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			start := time.Now()
			cmd := exec.Command(binary, tt.args...)
			cmd.Dir = projectRoot

			if err := cmd.Run(); err != nil {
				// For validate commands, error is expected when issues are found
				if !strings.Contains(tt.name, "validate") {
					t.Fatalf("Command failed: %v", err)
				}
			}

			duration := time.Since(start)
			if duration > tt.maxDuration {
				t.Errorf("Command took too long: %v > %v", duration, tt.maxDuration)
			}
			t.Logf("Command completed in %v", duration)
		})
	}
}

// TestIntegrationValidateJSON validates that JSON output is parseable
func TestIntegrationValidateJSON(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping JSON validation tests in short mode")
	}

	binary := buildBinary(t)

	// Get the project root directory
	projectRoot := getProjectRoot(t)

	tests := []struct {
		name string
		args []string
	}{
		{
			name: "validate JSON output",
			args: []string{"validate", "-f", filepath.Join(projectRoot, "testdata", "role-with-wildcard.yaml"), "-o", "json"},
		},
		{
			name: "analyze JSON output",
			args: []string{"analyze", "-f", filepath.Join(projectRoot, "testdata", "complex-rbac.yaml"), "-o", "json"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := exec.Command(binary, tt.args...)
			cmd.Dir = projectRoot
			output, err := cmd.CombinedOutput()
			// For JSON output tests, we expect validation to fail but still produce valid JSON
			if err != nil && !strings.Contains(tt.name, "validate") {
				t.Fatalf("Command failed: %v", err)
			}

			// For validate commands with JSON output, extract only the JSON part (before error message)
			jsonOutput := output
			if strings.Contains(tt.name, "validate") && bytes.Contains(output, []byte("Error:")) {
				// Find the end of JSON (last closing brace before "Error:")
				if idx := bytes.LastIndex(output, []byte("}")); idx != -1 {
					jsonOutput = output[:idx+1]
				}
			}

			// Validate JSON is parseable
			var result interface{}
			if err := json.Unmarshal(jsonOutput, &result); err != nil {
				t.Errorf("Invalid JSON output: %v\nOutput: %s", err, truncateOutput(string(jsonOutput)))
			}
		})
	}
}

// Helper functions

// buildBinary builds the guardrail binary and returns its path
func buildBinary(t *testing.T) string {
	t.Helper()

	// Use a shared binary for all tests in the same test run
	binaryName := fmt.Sprintf("guardrail-test-%d", os.Getpid())
	if runtime.GOOS == "windows" {
		binaryName += ".exe"
	}

	binaryPath := filepath.Join(os.TempDir(), binaryName)

	// Check if binary already exists
	if _, err := os.Stat(binaryPath); err == nil {
		return binaryPath
	}

	t.Logf("Building binary to %s", binaryPath)

	// Find the repository root dynamically
	repoRoot := findRepositoryRoot(t)

	cmd := exec.Command("go", "build", "-o", binaryPath, "./cmd/guardrail")
	cmd.Dir = repoRoot

	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("Failed to build binary: %v\nOutput: %s", err, output)
	}

	// Clean up binary after all tests
	t.Cleanup(func() {
		os.Remove(binaryPath)
	})

	return binaryPath
}

// truncateOutput truncates long output for better test readability
func truncateOutput(output string) string {
	const maxLen = 1000
	if len(output) <= maxLen {
		return output
	}
	return output[:maxLen] + "\n... (truncated)"
}

// getCurrentContext gets the current kubectl context
func getCurrentContext(t *testing.T) string {
	t.Helper()
	projectRoot := getProjectRoot(t)
	cmd := exec.Command("kubectl", "config", "current-context")
	cmd.Dir = projectRoot
	output, err := cmd.Output()
	if err != nil {
		t.Fatalf("Failed to get current context: %v", err)
	}
	return strings.TrimSpace(string(output))
}

// getProjectRoot returns the absolute path to the project root directory
func getProjectRoot(t *testing.T) string {
	t.Helper()
	return findRepositoryRoot(t)
}

// findRepositoryRoot walks up the directory tree looking for go.mod file
func findRepositoryRoot(t *testing.T) string {
	t.Helper()

	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Failed to get working directory: %v", err)
	}

	// Walk up the directory tree until we find go.mod
	for {
		goModPath := filepath.Join(dir, "go.mod")
		if _, err := os.Stat(goModPath); err == nil {
			return dir
		}

		parent := filepath.Dir(dir)
		if parent == dir {
			// Reached root of filesystem without finding go.mod
			t.Fatalf("Could not find go.mod in any parent directory")
		}
		dir = parent
	}
}
