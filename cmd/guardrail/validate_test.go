package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/coolguy1771/guardrail/internal/testutil"
)

// validateTestFiles holds paths to test files.
type validateTestFiles struct {
	validFile   string
	multiFile   string
	nonRBACFile string
	invalidFile string
	tmpDir      string
}

// setupValidateTestFiles creates test YAML files for validation tests.
func setupValidateTestFiles(t *testing.T) validateTestFiles {
	tmpDir := t.TempDir()

	// Create test YAML files
	validRoleYAML := `
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: test-role
  namespace: default
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["*"]  # This should trigger RBAC001
`

	validFile := filepath.Join(tmpDir, "valid.yaml")
	if err := os.WriteFile(validFile, []byte(validRoleYAML), 0o644); err != nil {
		t.Fatal(err)
	}

	multiDocYAML := `
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: test-role1
  namespace: default
rules:
- apiGroups: [""]
  resources: ["secrets"]
  verbs: ["get", "list"]  # This should trigger RBAC003
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: admin-binding
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cluster-admin  # This should trigger RBAC002
subjects:
- kind: User
  name: admin
`

	multiFile := filepath.Join(tmpDir, "multi.yaml")
	if err := os.WriteFile(multiFile, []byte(multiDocYAML), 0o644); err != nil {
		t.Fatal(err)
	}

	// Create a non-RBAC YAML file
	nonRBACYAML := `
apiVersion: v1
kind: ConfigMap
metadata:
  name: test-config
data:
  key: value
`

	nonRBACFile := filepath.Join(tmpDir, "config.yaml")
	if err := os.WriteFile(nonRBACFile, []byte(nonRBACYAML), 0o644); err != nil {
		t.Fatal(err)
	}

	// Create invalid YAML file
	invalidYAML := `
this is not valid YAML
`

	invalidFile := filepath.Join(tmpDir, "invalid.yaml")
	if err := os.WriteFile(invalidFile, []byte(invalidYAML), 0o644); err != nil {
		t.Fatal(err)
	}

	return validateTestFiles{
		validFile:   validFile,
		multiFile:   multiFile,
		nonRBACFile: nonRBACFile,
		invalidFile: invalidFile,
		tmpDir:      tmpDir,
	}
}

// validateTestCase represents a test case for the validate command.
type validateTestCase struct {
	name        string
	args        []string
	expectError bool
	checkOutput func(t *testing.T, output string)
}

// getValidateTestCases returns all test cases for validation.
func getValidateTestCases(files validateTestFiles) []validateTestCase {
	return []validateTestCase{
		{
			name:        "missing file and dir flags",
			args:        []string{"guardrail", "validate"},
			expectError: true,
			checkOutput: nil,
		},
		{
			name:        "both file and dir flags",
			args:        []string{"guardrail", "validate", "--file", files.validFile, "--dir", files.tmpDir},
			expectError: true,
			checkOutput: nil,
		},
		{
			name:        "validate single file",
			args:        []string{"guardrail", "validate", "--file", files.validFile},
			expectError: true, // High severity findings cause error
			checkOutput: checkValidateSingleFile,
		},
		{
			name:        "validate directory",
			args:        []string{"guardrail", "validate", "--dir", files.tmpDir},
			expectError: true, // High severity findings cause error
			checkOutput: checkValidateDirectory,
		},
		{
			name:        "non-existent file",
			args:        []string{"guardrail", "validate", "--file", "/non/existent/file.yaml"},
			expectError: true,
			checkOutput: nil,
		},
		{
			name:        "non-existent directory",
			args:        []string{"guardrail", "validate", "--dir", "/non/existent/dir"},
			expectError: true,
			checkOutput: nil,
		},
		{
			name:        "json output format",
			args:        []string{"guardrail", "validate", "--file", files.validFile, "--output", "json"},
			expectError: true, // High severity findings cause error
			checkOutput: checkJSONValidateOutput,
		},
	}
}

// checkValidateSingleFile checks output for single file validation.
func checkValidateSingleFile(t *testing.T, output string) {
	if !strings.Contains(output, "RBAC001") {
		t.Errorf("expected to find RBAC001 violation, got: %s", output)
	}
}

// checkValidateDirectory checks output for directory validation.
func checkValidateDirectory(t *testing.T, output string) {
	// Should find violations from multiple files
	if !strings.Contains(output, "RBAC001") {
		t.Errorf("expected to find RBAC001 violation, got: %s", output)
	}
	if !strings.Contains(output, "RBAC002") {
		t.Errorf("expected to find RBAC002 violation, got: %s", output)
	}
	if !strings.Contains(output, "RBAC003") {
		t.Errorf("expected to find RBAC003 violation, got: %s", output)
	}
}

// checkJSONValidateOutput checks JSON output format.
func checkJSONValidateOutput(t *testing.T, output string) {
	// Check for valid JSON structure - the JSON should be present even if there's an error
	if !strings.Contains(output, `"RuleID": "RBAC001"`) {
		t.Errorf("expected JSON output with RBAC001, got: %s", output)
	}
	if !strings.Contains(output, `"findings"`) {
		t.Errorf("expected JSON to contain findings array, got: %s", output)
	}
}

func TestValidateCommand(t *testing.T) {
	// Save original args
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }() //nolint:reassign // Required for testing

	// Create test files
	files := setupValidateTestFiles(t)

	// Get test cases
	tests := getValidateTestCases(files)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			executeValidateCommandTest(t, tt)
		})
	}
}

// resetValidateFlags resets validate command flags.
func resetValidateFlags() {
	files = []string{}
	directory = ""
}

// setupValidateCommand creates and configures the validate command for testing.
func setupValidateCommand(buf *bytes.Buffer) {
	rootCmd = &cobra.Command{
		Use:   "guardrail",
		Short: "A Kubernetes RBAC validation tool",
	}
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)

	validateCmd = &cobra.Command{
		Use:   "validate",
		Short: "Validate RBAC manifests",
		RunE:  runValidate,
	}

	// Register all flags for validate command
	validateCmd.Flags().
		StringSliceVarP(&files, "file", "f", []string{}, "Path to RBAC manifest file(s) (can be specified multiple times)")
	validateCmd.Flags().StringVarP(&directory, "dir", "d", "", "Path to a directory containing RBAC manifests")

	// Add output flag to root command
	rootCmd.PersistentFlags().StringP("output", "o", "text", "Output format (text, json, sarif)")

	// Bind flags to viper
	_ = viper.BindPFlag("files", validateCmd.Flags().Lookup("file"))
	_ = viper.BindPFlag("directory", validateCmd.Flags().Lookup("dir"))
	_ = viper.BindPFlag("output", rootCmd.PersistentFlags().Lookup("output"))

	rootCmd.AddCommand(validateCmd)
}

// executeValidateCommandTest executes a single validate command test.
func executeValidateCommandTest(t *testing.T, tt validateTestCase) {
	// Reset viper for each test
	viper.Reset()
	resetValidateFlags()

	// Capture output
	var buf bytes.Buffer

	// Setup command
	setupValidateCommand(&buf)

	// Set command line arguments (skip the first arg which is the binary name)
	rootCmd.SetArgs(tt.args[1:])

	// Execute
	execErr := rootCmd.Execute()

	if tt.expectError {
		testutil.AssertNotNil(t, execErr, "expected error")
	} else {
		testutil.AssertNil(t, execErr, "unexpected error")
	}

	if tt.checkOutput != nil {
		tt.checkOutput(t, buf.String())
	}
}

func TestRunValidate_DirectoryWithNoYAML(t *testing.T) {
	// Create empty directory
	tmpDir := t.TempDir()

	// Reset viper
	viper.Reset()
	viper.Set("directory", tmpDir)

	err := runValidate(nil, nil)
	testutil.AssertNotNil(t, err, "should error when no YAML files found")
	if err != nil && !strings.Contains(err.Error(), "no YAML files found") {
		t.Errorf("expected 'no YAML files found' error, got: %v", err)
	}
}

func TestRunValidate_AllNonRBACFiles(t *testing.T) {
	// Create directory with only non-RBAC YAML
	tmpDir := t.TempDir()

	nonRBACYAML := `
apiVersion: v1
kind: ConfigMap
metadata:
  name: test-config
data:
  key: value
`

	configFile := filepath.Join(tmpDir, "config.yaml")
	if err := os.WriteFile(configFile, []byte(nonRBACYAML), 0o644); err != nil {
		t.Fatal(err)
	}

	// Reset viper
	viper.Reset()
	viper.Set("directory", tmpDir)

	err := runValidate(nil, nil)
	testutil.AssertNotNil(t, err, "should error when no RBAC resources found")
	if err != nil && !strings.Contains(err.Error(), "no valid RBAC resources found") {
		t.Errorf("expected 'no valid RBAC resources found' error, got: %v", err)
	}
}

// createTestRoleFile creates a test role file with wildcard permissions.
func createTestRoleFile(t *testing.T) string {
	tmpDir := t.TempDir()

	roleYAML := `
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: test-role
  namespace: default
rules:
- apiGroups: ["*"]
  resources: ["*"]
  verbs: ["*"]
`

	roleFile := filepath.Join(tmpDir, "role.yaml")
	if err := os.WriteFile(roleFile, []byte(roleYAML), 0o644); err != nil {
		t.Fatal(err)
	}
	return roleFile
}

// captureOutput captures stdout during function execution.
// Uses a goroutine to read from the pipe to prevent blocking on Windows.
func captureOutput(fn func() error) (string, error) {
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w //nolint:reassign // Required for capturing stdout in tests

	// Start reading from pipe in a goroutine to prevent blocking.
	// This is essential for Windows compatibility where pipes can block
	// if the buffer fills up before being read.
	outputChan := make(chan string)
	go func() {
		buf := new(bytes.Buffer)
		_, _ = buf.ReadFrom(r)
		outputChan <- buf.String()
	}()

	// Run the function
	runErr := fn()

	// Close writer and restore stdout
	w.Close()
	os.Stdout = oldStdout //nolint:reassign // Restore stdout after test

	// Wait for reader to finish
	output := <-outputChan
	return output, runErr
}

// validateOutputFormat checks if output matches expected format.
func validateOutputFormat(t *testing.T, output string, format string) {
	switch format {
	case "json":
		if !strings.Contains(output, `"findings"`) {
			t.Error("expected JSON format with 'findings' field")
		}
	case "sarif":
		if !strings.Contains(output, `"version":"2.1.0"`) && !strings.Contains(output, `"version": "2.1.0"`) {
			t.Errorf("expected SARIF format with version 2.1.0, got: %s", output)
		}
	case "text":
		if !strings.Contains(output, "RBAC001") {
			t.Error("expected text format with rule ID")
		}
	}
}

func TestRunValidate_OutputFormats(t *testing.T) {
	roleFile := createTestRoleFile(t)
	formats := []string{"text", "json", "sarif"}

	for _, format := range formats {
		t.Run(format+" format", func(t *testing.T) {
			// Reset viper
			viper.Reset()
			viper.Set("file", roleFile)
			viper.Set("output", format)

			// Capture output
			output, runErr := captureOutput(func() error {
				return runValidate(nil, nil)
			})

			// Check for high severity finding (now returns error instead of os.Exit)
			testutil.AssertNotNil(t, runErr, "runValidate should return error for high severity findings")
			if runErr != nil && !strings.Contains(runErr.Error(), "validation failed") {
				t.Errorf("expected validation failed error, got: %v", runErr)
			}

			// Verify output format
			validateOutputFormat(t, output, format)
		})
	}
}
