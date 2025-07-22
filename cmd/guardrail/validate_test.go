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

func TestValidateCommand(t *testing.T) {
	// Save original args
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()

	// Create temporary directory for test files
	tmpDir, err := os.MkdirTemp("", "validate-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

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
	if err := os.WriteFile(validFile, []byte(validRoleYAML), 0644); err != nil {
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
	if err := os.WriteFile(multiFile, []byte(multiDocYAML), 0644); err != nil {
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
	if err := os.WriteFile(nonRBACFile, []byte(nonRBACYAML), 0644); err != nil {
		t.Fatal(err)
	}

	// Create invalid YAML file
	invalidYAML := `
this is not valid YAML
`

	invalidFile := filepath.Join(tmpDir, "invalid.yaml")
	if err := os.WriteFile(invalidFile, []byte(invalidYAML), 0644); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name        string
		args        []string
		expectError bool
		checkOutput func(t *testing.T, output string)
	}{
		{
			name:        "missing file and dir flags",
			args:        []string{"guardrail", "validate"},
			expectError: true,
		},
		{
			name:        "both file and dir flags",
			args:        []string{"guardrail", "validate", "--file", validFile, "--dir", tmpDir},
			expectError: true,
		},
		{
			name: "validate single file",
			args: []string{"guardrail", "validate", "--file", validFile},
			expectError: true, // High severity findings cause error
			checkOutput: func(t *testing.T, output string) {
				if !strings.Contains(output, "RBAC001") {
					t.Errorf("expected to find RBAC001 violation, got: %s", output)
				}
			},
		},
		{
			name: "validate directory",
			args: []string{"guardrail", "validate", "--dir", tmpDir},
			expectError: true, // High severity findings cause error
			checkOutput: func(t *testing.T, output string) {
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
			},
		},
		{
			name:        "non-existent file",
			args:        []string{"guardrail", "validate", "--file", "/non/existent/file.yaml"},
			expectError: true,
		},
		{
			name:        "non-existent directory",
			args:        []string{"guardrail", "validate", "--dir", "/non/existent/dir"},
			expectError: true,
		},
		{
			name: "json output format",
			args: []string{"guardrail", "validate", "--file", validFile, "--output", "json"},
			expectError: true, // High severity findings cause error
			checkOutput: func(t *testing.T, output string) {
				// Check for valid JSON structure - the JSON should be present even if there's an error
				if !strings.Contains(output, `"RuleID": "RBAC001"`) {
					t.Errorf("expected JSON output with RBAC001, got: %s", output)
				}
				if !strings.Contains(output, `"findings"`) {
					t.Errorf("expected JSON to contain findings array, got: %s", output)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset viper for each test
			viper.Reset()

			// Reset flag values
			file = ""
			directory = ""

			// Capture output
			var buf bytes.Buffer

			// Re-initialize commands
			rootCmd = &cobra.Command{
				Use:   "guardrail",
				Short: "A Kubernetes RBAC validation tool",
			}
			rootCmd.SetOut(&buf)
			rootCmd.SetErr(&buf)
			// Add the validate command with all its flags
			validateCmd = &cobra.Command{
				Use:   "validate",
				Short: "Validate RBAC manifests",
				RunE:  runValidate,
			}
			
			// Register all flags for validate command
			validateCmd.Flags().StringVarP(&file, "file", "f", "", "Path to a single RBAC manifest file")
			validateCmd.Flags().StringVarP(&directory, "dir", "d", "", "Path to a directory containing RBAC manifests")
			
			// Add output flag to root command
			rootCmd.PersistentFlags().StringP("output", "o", "text", "Output format (text, json, sarif)")
			
			// Bind flags to viper
			_ = viper.BindPFlag("file", validateCmd.Flags().Lookup("file"))
			_ = viper.BindPFlag("directory", validateCmd.Flags().Lookup("dir"))
			_ = viper.BindPFlag("output", rootCmd.PersistentFlags().Lookup("output"))
			
			rootCmd.AddCommand(validateCmd)

			// Set command line arguments (skip the first arg which is the binary name)
			rootCmd.SetArgs(tt.args[1:])

			// Execute
			err := rootCmd.Execute()

			if tt.expectError {
				testutil.AssertNotNil(t, err, "expected error")
			} else {
				testutil.AssertNil(t, err, "unexpected error")
			}

			if tt.checkOutput != nil {
				tt.checkOutput(t, buf.String())
			}
		})
	}
}

func TestRunValidate_DirectoryWithNoYAML(t *testing.T) {
	// Create empty directory
	tmpDir, err := os.MkdirTemp("", "empty-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	// Reset viper
	viper.Reset()
	viper.Set("directory", tmpDir)

	err = runValidate(nil, nil)
	testutil.AssertNotNil(t, err, "should error when no YAML files found")
	if err != nil && !strings.Contains(err.Error(), "no YAML files found") {
		t.Errorf("expected 'no YAML files found' error, got: %v", err)
	}
}

func TestRunValidate_AllNonRBACFiles(t *testing.T) {
	// Create directory with only non-RBAC YAML
	tmpDir, err := os.MkdirTemp("", "non-rbac-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	nonRBACYAML := `
apiVersion: v1
kind: ConfigMap
metadata:
  name: test-config
data:
  key: value
`

	configFile := filepath.Join(tmpDir, "config.yaml")
	if err := os.WriteFile(configFile, []byte(nonRBACYAML), 0644); err != nil {
		t.Fatal(err)
	}

	// Reset viper
	viper.Reset()
	viper.Set("directory", tmpDir)

	err = runValidate(nil, nil)
	testutil.AssertNotNil(t, err, "should error when no RBAC resources found")
	if err != nil && !strings.Contains(err.Error(), "no valid RBAC resources found") {
		t.Errorf("expected 'no valid RBAC resources found' error, got: %v", err)
	}
}

func TestRunValidate_OutputFormats(t *testing.T) {
	// Create test file
	tmpDir, err := os.MkdirTemp("", "format-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

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
	if err := os.WriteFile(roleFile, []byte(roleYAML), 0644); err != nil {
		t.Fatal(err)
	}

	formats := []string{"text", "json", "sarif"}

	for _, format := range formats {
		t.Run(format+" format", func(t *testing.T) {
			// Reset viper
			viper.Reset()
			viper.Set("file", roleFile)
			viper.Set("output", format)

			// Capture output
			oldStdout := os.Stdout
			r, w, _ := os.Pipe()
			os.Stdout = w

			err := runValidate(nil, nil)

			// Restore stdout
			w.Close()
			os.Stdout = oldStdout

			// Read output
			buf := new(bytes.Buffer)
			buf.ReadFrom(r)
			output := buf.String()

			// Check for high severity finding (should exit with code 1)
			// Note: In real execution, os.Exit(1) would be called
			// For testing, we just check the error is nil (findings were processed)
			testutil.AssertNil(t, err, "runValidate should not return error")

			// Verify output format
			switch format {
			case "json":
				if !strings.Contains(output, `"findings"`) {
					t.Error("expected JSON format with 'findings' field")
				}
			case "sarif":
				if !strings.Contains(output, `"version":"2.1.0"`) {
					t.Error("expected SARIF format with version 2.1.0")
				}
			case "text":
				if !strings.Contains(output, "RBAC001") {
					t.Error("expected text format with rule ID")
				}
			}
		})
	}
}