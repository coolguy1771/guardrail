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

// setupAnalyzeTestFiles creates test YAML files in a temporary directory.
func setupAnalyzeTestFiles(t *testing.T) (string, string, string, string, string) {
	tmpDir := t.TempDir()

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
	if err := os.WriteFile(roleFile, []byte(roleYAML), 0o644); err != nil {
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
	if err := os.WriteFile(bindingFile, []byte(roleBindingYAML), 0o644); err != nil {
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
	if err := os.WriteFile(adminRoleFile, []byte(adminRoleYAML), 0o644); err != nil {
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
	if err := os.WriteFile(adminBindingFile, []byte(adminBindingYAML), 0o644); err != nil {
		t.Fatal(err)
	}

	return tmpDir, roleFile, bindingFile, adminRoleFile, adminBindingFile
}

// analyzeTestCase represents a test case for the analyze command.
type analyzeTestCase struct {
	name        string
	args        []string
	expectError bool
	checkOutput func(t *testing.T, output string)
}

// getAnalyzeTestCases returns all test cases for the analyze command.
func getAnalyzeTestCases(tmpDir, roleFile, bindingFile string) []analyzeTestCase {
	return []analyzeTestCase{
		{
			name:        "missing input source",
			args:        []string{"guardrail", "analyze"},
			expectError: true,
			checkOutput: nil,
		},
		{
			name:        "multiple input sources",
			args:        []string{"guardrail", "analyze", "--file", roleFile, "--dir", tmpDir},
			expectError: true,
			checkOutput: nil,
		},
		{
			name:        "analyze single file",
			args:        []string{"guardrail", "analyze", "--file", bindingFile},
			expectError: false,
			checkOutput: checkAnalyzeSingleFile,
		},
		{
			name:        "analyze directory",
			args:        []string{"guardrail", "analyze", "--dir", tmpDir},
			expectError: false,
			checkOutput: checkAnalyzeDirectory,
		},
		{
			name:        "filter by subject",
			args:        []string{"guardrail", "analyze", "--dir", tmpDir, "--subject", "alice"},
			expectError: false,
			checkOutput: checkFilterBySubject,
		},
		{
			name:        "filter by risk level",
			args:        []string{"guardrail", "analyze", "--dir", tmpDir, "--risk-level", "critical"},
			expectError: false,
			checkOutput: checkFilterByRiskLevel,
		},
		{
			name:        "show roles detail",
			args:        []string{"guardrail", "analyze", "--dir", tmpDir, "--show-roles"},
			expectError: false,
			checkOutput: checkShowRolesDetail,
		},
		{
			name:        "json output",
			args:        []string{"guardrail", "analyze", "--dir", tmpDir, "--output", "json"},
			expectError: false,
			checkOutput: checkJSONOutput,
		},
		{
			name:        "no color output",
			args:        []string{"guardrail", "analyze", "--dir", tmpDir, "--no-color"},
			expectError: false,
			checkOutput: checkNoColorOutput,
		},
	}
}

// checkAnalyzeSingleFile validates output for single file analysis.
func checkAnalyzeSingleFile(t *testing.T, output string) {
	if !strings.Contains(output, "User: alice") {
		t.Errorf("expected to find user alice in output, got: %s", output)
	}
	if !strings.Contains(output, "read-pods") {
		t.Errorf("expected to find read-pods binding, got: %s", output)
	}
}

// checkAnalyzeDirectory validates output for directory analysis.
func checkAnalyzeDirectory(t *testing.T, output string) {
	if !strings.Contains(output, "User: alice") {
		t.Errorf("expected to find user alice, got: %s", output)
	}
	if !strings.Contains(output, "User: admin") {
		t.Errorf("expected to find user admin, got: %s", output)
	}
	if !strings.Contains(output, "Risk Level:") {
		t.Errorf("expected to find risk level, got: %s", output)
	}
}

// checkFilterBySubject validates subject filtering.
func checkFilterBySubject(t *testing.T, output string) {
	if !strings.Contains(output, "User: alice") {
		t.Errorf("expected to find alice, got: %s", output)
	}
	if strings.Contains(output, "admin") {
		t.Error("should not find admin when filtering for alice")
	}
}

// checkFilterByRiskLevel validates risk level filtering.
func checkFilterByRiskLevel(t *testing.T, output string) {
	if !strings.Contains(output, "User: admin") {
		t.Errorf("expected to find admin with critical risk, got: %s", output)
	}
	if strings.Contains(output, "alice") {
		t.Error("alice should not have critical risk")
	}
}

// checkShowRolesDetail validates detailed role output.
func checkShowRolesDetail(t *testing.T, output string) {
	if !strings.Contains(output, "🔍 Detailed Permissions:") {
		t.Errorf("expected detailed permissions section, got: %s", output)
	}
}

// checkJSONOutput validates JSON output format.
func checkJSONOutput(t *testing.T, output string) {
	var result map[string]any
	if unmarshalErr := json.Unmarshal([]byte(output), &result); unmarshalErr != nil {
		t.Errorf("expected valid JSON output, got error: %v, output: %s", unmarshalErr, output)
		return
	}
	if _, ok := result["subjects"]; !ok {
		t.Errorf("expected 'subjects' field in JSON output, got: %v", result)
	}
}

// checkNoColorOutput validates no color codes in output.
func checkNoColorOutput(t *testing.T, output string) {
	if strings.Contains(output, "\033[") {
		t.Error("expected no ANSI color codes with --no-color")
	}
}

// resetAnalyzeFlags resets all analyze command flags to their default values.
func resetAnalyzeFlags() {
	analyzeFile = ""
	analyzeDirectory = ""
	analyzeCluster = false
	kubeconfig = ""
	kubectx = ""
	subject = ""
	showRoles = false
	riskLevel = ""
	noColor = false
}

// setupAnalyzeCommand creates and configures the analyze command for testing.
func setupAnalyzeCommand(outBuf, errBuf *bytes.Buffer) {
	rootCmd = &cobra.Command{
		Use:   "guardrail",
		Short: "A Kubernetes RBAC validation tool",
	}
	rootCmd.SetOut(outBuf)
	rootCmd.SetErr(errBuf)

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

	// Bind flags to viper
	_ = viper.BindPFlag("analyze.file", analyzeCmd.Flags().Lookup("file"))
	_ = viper.BindPFlag("analyze.directory", analyzeCmd.Flags().Lookup("dir"))
	_ = viper.BindPFlag("analyze.cluster", analyzeCmd.Flags().Lookup("cluster"))
	_ = viper.BindPFlag("analyze.kubeconfig", analyzeCmd.Flags().Lookup("kubeconfig"))
	_ = viper.BindPFlag("analyze.context", analyzeCmd.Flags().Lookup("context"))
	_ = viper.BindPFlag("analyze.subject", analyzeCmd.Flags().Lookup("subject"))
	_ = viper.BindPFlag("analyze.show-roles", analyzeCmd.Flags().Lookup("show-roles"))
	_ = viper.BindPFlag("analyze.risk-level", analyzeCmd.Flags().Lookup("risk-level"))
	_ = viper.BindPFlag("analyze.no-color", analyzeCmd.Flags().Lookup("no-color"))
	_ = viper.BindPFlag("output", rootCmd.PersistentFlags().Lookup("output"))

	rootCmd.AddCommand(analyzeCmd)
}

// executeAnalyzeCommandTest executes a single analyze command test case.
func executeAnalyzeCommandTest(t *testing.T, tt analyzeTestCase) {
	// Reset viper for each test
	viper.Reset()
	resetAnalyzeFlags()

	// Capture output
	var outBuf bytes.Buffer
	var errBuf bytes.Buffer

	// Setup command
	setupAnalyzeCommand(&outBuf, &errBuf)

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
		output := outBuf.String()
		if output == "" {
			output = errBuf.String()
		}
		tt.checkOutput(t, output)
	}
}

func TestAnalyzeCommand(t *testing.T) {
	// Save original args
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }() //nolint:reassign // Required for testing

	// Create test files
	tmpDir, roleFile, bindingFile, _, _ := setupAnalyzeTestFiles(t)

	// Get test cases
	tests := getAnalyzeTestCases(tmpDir, roleFile, bindingFile)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			executeAnalyzeCommandTest(t, tt)
		})
	}
}

func TestRunAnalyze_NoPermissions(t *testing.T) {
	// Create a role without any bindings
	tmpDir := t.TempDir()

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
	if err := os.WriteFile(roleFile, []byte(roleYAML), 0o644); err != nil {
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

	err := runAnalyze(cmd, nil)
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
		{Subject: rbacv1.Subject{}, Permissions: nil, RiskLevel: analyzer.RiskLevelCritical},
		{Subject: rbacv1.Subject{}, Permissions: nil, RiskLevel: analyzer.RiskLevelCritical},
		{Subject: rbacv1.Subject{}, Permissions: nil, RiskLevel: analyzer.RiskLevelHigh},
		{Subject: rbacv1.Subject{}, Permissions: nil, RiskLevel: analyzer.RiskLevelMedium},
		{Subject: rbacv1.Subject{}, Permissions: nil, RiskLevel: analyzer.RiskLevelMedium},
		{Subject: rbacv1.Subject{}, Permissions: nil, RiskLevel: analyzer.RiskLevelMedium},
		{Subject: rbacv1.Subject{}, Permissions: nil, RiskLevel: analyzer.RiskLevelLow},
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
			Subject:     rbacv1.Subject{Kind: "", APIGroup: "", Name: "alice", Namespace: ""},
			Permissions: nil,
			RiskLevel:   analyzer.RiskLevelLow,
		},
		{
			Subject:     rbacv1.Subject{Kind: "", APIGroup: "", Name: "bob", Namespace: ""},
			Permissions: nil,
			RiskLevel:   analyzer.RiskLevelHigh,
		},
		{
			Subject:     rbacv1.Subject{Kind: "", APIGroup: "", Name: "charlie", Namespace: ""},
			Permissions: nil,
			RiskLevel:   analyzer.RiskLevelMedium,
		},
	}

	tests := []struct {
		name          string
		subjectFilter string
		riskFilter    string
		expectedLen   int
	}{
		{
			name:          "no filters",
			subjectFilter: "",
			riskFilter:    "",
			expectedLen:   3,
		},
		{
			name:          "filter by subject",
			subjectFilter: "alice",
			riskFilter:    "",
			expectedLen:   1,
		},
		{
			name:          "filter by risk",
			subjectFilter: "",
			riskFilter:    "high",
			expectedLen:   1,
		},
		{
			name:          "filter by both",
			subjectFilter: "bob",
			riskFilter:    "high",
			expectedLen:   1,
		},
		{
			name:          "no match",
			subjectFilter: "alice",
			riskFilter:    "high",
			expectedLen:   0,
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
	t.Setenv("NO_COLOR", "1")

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

// Add missing imports.
func TestAnalyze_Imports(t *testing.T) {
	// Import check for rbacv1
	subject := rbacv1.Subject{
		Kind:      "User",
		APIGroup:  "",
		Name:      "test",
		Namespace: "",
	}
	testutil.AssertEqual(t, "User", subject.Kind, "rbacv1 import should work")

	// Import check for analyzer types
	perm := analyzer.SubjectPermissions{
		Subject:     subject,
		Permissions: []analyzer.PermissionGrant{},
		RiskLevel:   analyzer.RiskLevelLow,
	}
	testutil.AssertEqual(t, analyzer.RiskLevelLow, perm.RiskLevel, "analyzer types should work")
	testutil.AssertEqual(t, "test", perm.Subject.Name, "subject should be set correctly")
	testutil.AssertEqual(t, 0, len(perm.Permissions), "permissions should be empty")
}
