package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	rbacv1 "k8s.io/api/rbac/v1"

	"github.com/coolguy1771/guardrail/internal/testutil"
	"github.com/coolguy1771/guardrail/pkg/analyzer"
)

func TestAnalyzeCommand(t *testing.T) {
	// Save original args
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()

	// Create temporary directory for test files
	tmpDir, err := os.MkdirTemp("", "analyze-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	// Create test YAML files
	roleYAML := `
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: pod-reader
  namespace: default
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "list", "watch"]
`

	roleFile := filepath.Join(tmpDir, "role.yaml")
	if err := os.WriteFile(roleFile, []byte(roleYAML), 0644); err != nil {
		t.Fatal(err)
	}

	roleBindingYAML := `
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: read-pods
  namespace: default
subjects:
- kind: User
  name: alice
  apiGroup: rbac.authorization.k8s.io
- kind: ServiceAccount
  name: default
  namespace: default
roleRef:
  kind: Role
  name: pod-reader
  apiGroup: rbac.authorization.k8s.io
`

	bindingFile := filepath.Join(tmpDir, "binding.yaml")
	if err := os.WriteFile(bindingFile, []byte(roleBindingYAML), 0644); err != nil {
		t.Fatal(err)
	}

	// Create a high-risk role and binding
	adminRoleYAML := `
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: dangerous-role
rules:
- apiGroups: ["*"]
  resources: ["*"]
  verbs: ["*"]
`

	adminRoleFile := filepath.Join(tmpDir, "admin-role.yaml")
	if err := os.WriteFile(adminRoleFile, []byte(adminRoleYAML), 0644); err != nil {
		t.Fatal(err)
	}

	adminBindingYAML := `
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: dangerous-binding
subjects:
- kind: User
  name: admin
  apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: ClusterRole
  name: dangerous-role
  apiGroup: rbac.authorization.k8s.io
`

	adminBindingFile := filepath.Join(tmpDir, "admin-binding.yaml")
	if err := os.WriteFile(adminBindingFile, []byte(adminBindingYAML), 0644); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name        string
		args        []string
		expectError bool
		checkOutput func(t *testing.T, output string)
	}{
		{
			name:        "missing input source",
			args:        []string{"guardrail", "analyze"},
			expectError: true,
		},
		{
			name:        "multiple input sources",
			args:        []string{"guardrail", "analyze", "--file", roleFile, "--dir", tmpDir},
			expectError: true,
		},
		{
			name: "analyze single file",
			args: []string{"guardrail", "analyze", "--file", bindingFile},
			checkOutput: func(t *testing.T, output string) {
				// Should show permissions for alice
				if !strings.Contains(output, "alice") {
					t.Error("expected to find user alice in output")
				}
				// Should show pod-reader role
				if !strings.Contains(output, "pod-reader") {
					t.Error("expected to find pod-reader role")
				}
			},
		},
		{
			name: "analyze directory",
			args: []string{"guardrail", "analyze", "--dir", tmpDir},
			checkOutput: func(t *testing.T, output string) {
				// Should find both alice and admin
				if !strings.Contains(output, "alice") {
					t.Error("expected to find user alice")
				}
				if !strings.Contains(output, "admin") {
					t.Error("expected to find user admin")
				}
				// Should show risk levels
				if !strings.Contains(output, "Risk Level:") {
					t.Error("expected to find risk level")
				}
			},
		},
		{
			name: "filter by subject",
			args: []string{"guardrail", "analyze", "--dir", tmpDir, "--subject", "alice"},
			checkOutput: func(t *testing.T, output string) {
				if !strings.Contains(output, "alice") {
					t.Error("expected to find alice")
				}
				if strings.Contains(output, "admin") {
					t.Error("should not find admin when filtering for alice")
				}
			},
		},
		{
			name: "filter by risk level",
			args: []string{"guardrail", "analyze", "--dir", tmpDir, "--risk-level", "critical"},
			checkOutput: func(t *testing.T, output string) {
				// Only admin should have critical risk
				if !strings.Contains(output, "admin") {
					t.Error("expected to find admin with critical risk")
				}
				if strings.Contains(output, "alice") {
					t.Error("alice should not have critical risk")
				}
			},
		},
		{
			name: "show roles detail",
			args: []string{"guardrail", "analyze", "--dir", tmpDir, "--show-roles"},
			checkOutput: func(t *testing.T, output string) {
				// Should show detailed permissions
				if !strings.Contains(output, "Detailed Permissions:") {
					t.Error("expected detailed permissions section")
				}
			},
		},
		{
			name: "json output",
			args: []string{"guardrail", "analyze", "--dir", tmpDir, "--output", "json"},
			checkOutput: func(t *testing.T, output string) {
				// Should be valid JSON
				var result map[string]interface{}
				if err := json.Unmarshal([]byte(output), &result); err != nil {
					t.Errorf("expected valid JSON output, got error: %v", err)
				}
				// Should have subjects array
				if _, ok := result["subjects"]; !ok {
					t.Error("expected 'subjects' field in JSON output")
				}
			},
		},
		{
			name: "no color output",
			args: []string{"guardrail", "analyze", "--dir", tmpDir, "--no-color"},
			checkOutput: func(t *testing.T, output string) {
				// Should not contain ANSI color codes
				if strings.Contains(output, "\033[") {
					t.Error("expected no ANSI color codes with --no-color")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset viper for each test
			viper.Reset()

			// Capture output
			var buf bytes.Buffer
			rootCmd.SetOut(&buf)
			rootCmd.SetErr(&buf)

			// Set args
			os.Args = tt.args

			// Re-initialize commands by creating new instances
			// Note: We can't call init() directly, so we need to set up the command structure manually
			rootCmd = &cobra.Command{
				Use:   "guardrail",
				Short: "A Kubernetes RBAC validation tool",
			}
			// Add the analyze command with all its flags
			analyzeCmd = &cobra.Command{
				Use:   "analyze",
				Short: "Analyze RBAC permissions and explain what subjects can do",
				RunE:  runAnalyze,
			}
			
			// Register all flags for analyze command
			analyzeCmd.Flags().StringVarP(&analyzeFile, "file", "f", "", "Path to a single RBAC manifest file")
			analyzeCmd.Flags().StringVarP(&analyzeDirectory, "dir", "d", "", "Path to a directory containing RBAC manifests")
			analyzeCmd.Flags().BoolVarP(&analyzeCluster, "cluster", "c", false, "Analyze live cluster RBAC")
			analyzeCmd.Flags().StringVar(&kubeconfig, "kubeconfig", "", "Path to kubeconfig file")
			analyzeCmd.Flags().StringVar(&kubectx, "context", "", "Kubernetes context to use")
			analyzeCmd.Flags().StringVarP(&subject, "subject", "s", "", "Filter by subject name")
			analyzeCmd.Flags().BoolVar(&showRoles, "show-roles", false, "Show detailed role information")
			analyzeCmd.Flags().StringVar(&riskLevel, "risk-level", "", "Filter by risk level")
			analyzeCmd.Flags().BoolVar(&noColor, "no-color", false, "Disable colored output")
			
			// Add output flag to root command
			rootCmd.PersistentFlags().StringP("output", "o", "text", "Output format (text, json, sarif)")
			
			rootCmd.AddCommand(analyzeCmd)

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

func TestRunAnalyze_NoPermissions(t *testing.T) {
	// Create a role without any bindings
	tmpDir, err := os.MkdirTemp("", "no-perms-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	roleYAML := `
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: orphan-role
  namespace: default
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get"]
`

	roleFile := filepath.Join(tmpDir, "role.yaml")
	if err := os.WriteFile(roleFile, []byte(roleYAML), 0644); err != nil {
		t.Fatal(err)
	}

	// Reset viper
	viper.Reset()
	viper.Set("analyze.file", roleFile)

	// Create command with output buffer
	cmd := &cobra.Command{}
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)

	err = runAnalyze(cmd, nil)
	output := buf.String()

	testutil.AssertNil(t, err, "runAnalyze should not return error")
	
	// Should indicate no permissions found
	if !strings.Contains(output, "No RBAC permissions found") {
		t.Error("expected message about no permissions found")
	}
}

func TestGetSummary(t *testing.T) {
	// Create test data with different risk levels
	permissions := []analyzer.SubjectPermissions{
		{RiskLevel: analyzer.RiskLevelCritical},
		{RiskLevel: analyzer.RiskLevelCritical},
		{RiskLevel: analyzer.RiskLevelHigh},
		{RiskLevel: analyzer.RiskLevelMedium},
		{RiskLevel: analyzer.RiskLevelMedium},
		{RiskLevel: analyzer.RiskLevelMedium},
		{RiskLevel: analyzer.RiskLevelLow},
	}

	summary := getSummary(permissions)

	testutil.AssertEqual(t, 7, summary.TotalSubjects, "total subjects")
	testutil.AssertEqual(t, 2, summary.CriticalRisk, "critical risk count")
	testutil.AssertEqual(t, 1, summary.HighRisk, "high risk count")
	testutil.AssertEqual(t, 3, summary.MediumRisk, "medium risk count")
	testutil.AssertEqual(t, 1, summary.LowRisk, "low risk count")
}

func TestFilterPermissions(t *testing.T) {
	permissions := []analyzer.SubjectPermissions{
		{
			Subject: rbacv1.Subject{Name: "alice"},
			RiskLevel: analyzer.RiskLevelLow,
		},
		{
			Subject: rbacv1.Subject{Name: "bob"},
			RiskLevel: analyzer.RiskLevelHigh,
		},
		{
			Subject: rbacv1.Subject{Name: "charlie"},
			RiskLevel: analyzer.RiskLevelMedium,
		},
	}

	tests := []struct {
		name         string
		subjectFilter string
		riskFilter   string
		expectedLen  int
	}{
		{
			name:         "no filters",
			subjectFilter: "",
			riskFilter:   "",
			expectedLen:  3,
		},
		{
			name:         "filter by subject",
			subjectFilter: "alice",
			riskFilter:   "",
			expectedLen:  1,
		},
		{
			name:         "filter by risk",
			subjectFilter: "",
			riskFilter:   "high",
			expectedLen:  1,
		},
		{
			name:         "filter by both",
			subjectFilter: "bob",
			riskFilter:   "high",
			expectedLen:  1,
		},
		{
			name:         "no match",
			subjectFilter: "alice",
			riskFilter:   "high",
			expectedLen:  0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filtered := filterPermissions(permissions, tt.subjectFilter, tt.riskFilter)
			testutil.AssertEqual(t, tt.expectedLen, len(filtered), "filtered length")
		})
	}
}

func TestColorFunctions(t *testing.T) {
	// Test with color disabled
	noColor = true
	defer func() { noColor = false }()

	if isColorSupported() {
		t.Error("color should not be supported when noColor is true")
	}

	if getColorForRisk("critical") != "" {
		t.Error("expected empty string for color when disabled")
	}

	if resetColor() != "" {
		t.Error("expected empty string for reset when disabled")
	}

	// Test with NO_COLOR env var
	noColor = false
	os.Setenv("NO_COLOR", "1")
	defer os.Unsetenv("NO_COLOR")

	if isColorSupported() {
		t.Error("color should not be supported with NO_COLOR env var")
	}
}

func TestRiskIcon(t *testing.T) {
	tests := []struct {
		level    analyzer.RiskLevel
		expected string
	}{
		{analyzer.RiskLevelCritical, "🔴"},
		{analyzer.RiskLevelHigh, "🟠"},
		{analyzer.RiskLevelMedium, "🟡"},
		{analyzer.RiskLevelLow, "🟢"},
		{analyzer.RiskLevel("unknown"), "⚪"},
	}

	for _, tt := range tests {
		t.Run(string(tt.level), func(t *testing.T) {
			icon := getRiskIcon(tt.level)
			testutil.AssertEqual(t, tt.expected, icon, "risk icon")
		})
	}
}

// Add missing imports
func TestAnalyze_Imports(t *testing.T) {
	// Import check for rbacv1
	subject := rbacv1.Subject{
		Kind: "User",
		Name: "test",
	}
	testutil.AssertEqual(t, "User", subject.Kind, "rbacv1 import should work")

	// Import check for analyzer types
	perm := analyzer.SubjectPermissions{
		Subject:   subject,
		RiskLevel: analyzer.RiskLevelLow,
	}
	testutil.AssertEqual(t, analyzer.RiskLevelLow, perm.RiskLevel, "analyzer types should work")
}