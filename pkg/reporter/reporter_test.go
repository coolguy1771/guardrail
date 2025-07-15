package reporter

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/coolguy1771/guardrail/internal/testutil"
	"github.com/coolguy1771/guardrail/pkg/validator"
)

func createTestFindings() []validator.Finding {
	return []validator.Finding{
		{
			RuleID:      "RBAC001",
			RuleName:    "Avoid Wildcard Permissions",
			Severity:    validator.SeverityHigh,
			Message:     "Wildcard verb '*' found in Role",
			Resource:    "admin-role",
			Namespace:   "default",
			Kind:        "Role",
			Remediation: "Replace wildcard verb with specific verbs",
		},
		{
			RuleID:      "RBAC002",
			RuleName:    "Avoid Cluster-Admin Binding",
			Severity:    validator.SeverityHigh,
			Message:     "ClusterRoleBinding references cluster-admin role",
			Resource:    "admin-binding",
			Namespace:   "",
			Kind:        "ClusterRoleBinding",
			Remediation: "Create a custom ClusterRole with limited permissions",
		},
		{
			RuleID:      "RBAC003",
			RuleName:    "Avoid Secrets Access",
			Severity:    validator.SeverityMedium,
			Message:     "Direct read access to secrets found in Role",
			Resource:    "secret-reader",
			Namespace:   "kube-system",
			Kind:        "Role",
			Remediation: "Limit secrets access to specific named resources",
		},
		{
			RuleID:    "RBAC004",
			RuleName:  "Prefer Namespaced Roles",
			Severity:  validator.SeverityLow,
			Message:   "ClusterRole only contains namespace-scoped resources",
			Resource:  "namespaced-cr",
			Namespace: "",
			Kind:      "ClusterRole",
			Remediation: "Consider using a Role instead",
		},
		{
			RuleID:    "RBAC005",
			RuleName:  "Info Check",
			Severity:  validator.SeverityInfo,
			Message:   "Informational finding",
			Resource:  "info-resource",
			Namespace: "default",
			Kind:      "Role",
		},
	}
}

func TestNew(t *testing.T) {
	tests := []struct {
		name     string
		format   Format
		expected string
	}{
		{
			name:     "text format",
			format:   FormatText,
			expected: "*TextReporter",
		},
		{
			name:     "json format",
			format:   FormatJSON,
			expected: "*JSONReporter",
		},
		{
			name:     "sarif format",
			format:   FormatSARIF,
			expected: "*SARIFReporter",
		},
		{
			name:     "unknown format defaults to text",
			format:   Format("unknown"),
			expected: "*TextReporter",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reporter := New(tt.format)
			testutil.AssertNotNil(t, reporter, "New should return non-nil reporter")
			
			// Check the type - include package name in comparison
			typeName := fmt.Sprintf("%T", reporter)
			expectedWithPackage := fmt.Sprintf("*reporter.%s", strings.TrimPrefix(tt.expected, "*"))
			if typeName != expectedWithPackage {
				t.Errorf("expected reporter type %s, got %s", expectedWithPackage, typeName)
			}
		})
	}
}

func TestTextReporter_Report(t *testing.T) {
	reporter := &TextReporter{}
	
	t.Run("no findings", func(t *testing.T) {
		var buf bytes.Buffer
		err := reporter.Report([]validator.Finding{}, &buf)
		testutil.AssertNil(t, err, "Report should not return error")
		
		output := buf.String()
		if !strings.Contains(output, "✅ No issues found!") {
			t.Errorf("expected success message, got: %s", output)
		}
	})
	
	t.Run("with findings", func(t *testing.T) {
		findings := createTestFindings()
		var buf bytes.Buffer
		err := reporter.Report(findings, &buf)
		testutil.AssertNil(t, err, "Report should not return error")
		
		output := buf.String()
		
		// Check summary
		if !strings.Contains(output, "Found 5 issue(s)") {
			t.Errorf("expected summary with 5 issues, got: %s", output)
		}
		
		// Check severity sections
		expectedSeverities := []string{
			"🔴 HIGH (2)",
			"🟡 MEDIUM (1)",
			"🔵 LOW (1)",
			"ℹ️ INFO (1)",
		}
		
		for _, expected := range expectedSeverities {
			if !strings.Contains(output, expected) {
				t.Errorf("expected to find '%s' in output", expected)
			}
		}
		
		// Check specific findings
		if !strings.Contains(output, "RBAC001") {
			t.Error("expected to find RBAC001 in output")
		}
		if !strings.Contains(output, "admin-role") {
			t.Error("expected to find resource name in output")
		}
		if !strings.Contains(output, "namespace: default") {
			t.Error("expected to find namespace in output")
		}
		if !strings.Contains(output, "Replace wildcard verb with specific verbs") {
			t.Error("expected to find remediation in output")
		}
	})
}

func TestJSONReporter_Report(t *testing.T) {
	reporter := &JSONReporter{}
	
	t.Run("no findings", func(t *testing.T) {
		var buf bytes.Buffer
		err := reporter.Report([]validator.Finding{}, &buf)
		testutil.AssertNil(t, err, "Report should not return error")
		
		var report JSONReport
		err = json.Unmarshal(buf.Bytes(), &report)
		testutil.AssertNil(t, err, "should unmarshal JSON")
		
		testutil.AssertEqual(t, 0, report.Summary.Total, "total findings")
		testutil.AssertEqual(t, 0, len(report.Findings), "findings array length")
	})
	
	t.Run("with findings", func(t *testing.T) {
		findings := createTestFindings()
		var buf bytes.Buffer
		err := reporter.Report(findings, &buf)
		testutil.AssertNil(t, err, "Report should not return error")
		
		var report JSONReport
		err = json.Unmarshal(buf.Bytes(), &report)
		testutil.AssertNil(t, err, "should unmarshal JSON")
		
		// Check summary
		testutil.AssertEqual(t, 5, report.Summary.Total, "total findings")
		testutil.AssertEqual(t, 2, report.Summary.BySeverity["HIGH"], "high severity count")
		testutil.AssertEqual(t, 1, report.Summary.BySeverity["MEDIUM"], "medium severity count")
		testutil.AssertEqual(t, 1, report.Summary.BySeverity["LOW"], "low severity count")
		testutil.AssertEqual(t, 1, report.Summary.BySeverity["INFO"], "info severity count")
		
		// Check timestamp
		_, err = time.Parse(time.RFC3339, report.Timestamp)
		testutil.AssertNil(t, err, "timestamp should be valid RFC3339")
		
		// Check findings
		testutil.AssertEqual(t, 5, len(report.Findings), "findings array length")
		testutil.AssertEqual(t, "RBAC001", report.Findings[0].RuleID, "first finding rule ID")
	})
}

func TestSARIFReporter_Report(t *testing.T) {
	reporter := &SARIFReporter{}
	findings := createTestFindings()
	
	var buf bytes.Buffer
	err := reporter.Report(findings, &buf)
	testutil.AssertNil(t, err, "Report should not return error")
	
	var sarif SARIF
	err = json.Unmarshal(buf.Bytes(), &sarif)
	testutil.AssertNil(t, err, "should unmarshal SARIF JSON")
	
	// Check SARIF structure
	testutil.AssertEqual(t, "2.1.0", sarif.Version, "SARIF version")
	testutil.AssertEqual(t, "https://json.schemastore.org/sarif-2.1.0.json", sarif.Schema, "SARIF schema")
	testutil.AssertEqual(t, 1, len(sarif.Runs), "SARIF runs count")
	
	run := sarif.Runs[0]
	testutil.AssertEqual(t, "guardrail", run.Tool.Driver.Name, "tool name")
	testutil.AssertEqual(t, "1.0.0", run.Tool.Driver.Version, "tool version")
	testutil.AssertEqual(t, "https://github.com/coolguy1771/guardrail", run.Tool.Driver.InformationURI, "tool URI")
	
	// Check rules (should be deduplicated)
	// We have 5 findings but only 5 unique rules in our test data
	testutil.AssertEqual(t, 5, len(run.Tool.Driver.Rules), "unique rules count")
	
	// Check results
	testutil.AssertEqual(t, 5, len(run.Results), "results count")
	
	// Check first result
	firstResult := run.Results[0]
	testutil.AssertEqual(t, "RBAC001", firstResult.RuleID, "first result rule ID")
	testutil.AssertEqual(t, "error", firstResult.Level, "first result level (HIGH -> error)")
	testutil.AssertEqual(t, "Wildcard verb '*' found in Role", firstResult.Message.Text, "first result message")
	
	// Check location
	testutil.AssertEqual(t, 1, len(firstResult.Locations), "locations count")
	expectedURI := "namespace/default/Role/admin-role"
	testutil.AssertEqual(t, expectedURI, firstResult.Locations[0].PhysicalLocation.ArtifactLocation.URI, "location URI")
	
	// Check a cluster-scoped resource
	for _, result := range run.Results {
		if result.RuleID == "RBAC002" {
			expectedURI := "ClusterRoleBinding/admin-binding"
			testutil.AssertEqual(t, expectedURI, result.Locations[0].PhysicalLocation.ArtifactLocation.URI, "cluster-scoped URI")
			break
		}
	}
}

func TestGroupBySeverity(t *testing.T) {
	findings := createTestFindings()
	grouped := groupBySeverity(findings)
	
	testutil.AssertEqual(t, 2, len(grouped[validator.SeverityHigh]), "high severity count")
	testutil.AssertEqual(t, 1, len(grouped[validator.SeverityMedium]), "medium severity count")
	testutil.AssertEqual(t, 1, len(grouped[validator.SeverityLow]), "low severity count")
	testutil.AssertEqual(t, 1, len(grouped[validator.SeverityInfo]), "info severity count")
}

func TestGetSeverityIcon(t *testing.T) {
	tests := []struct {
		severity validator.Severity
		expected string
	}{
		{validator.SeverityHigh, "🔴"},
		{validator.SeverityMedium, "🟡"},
		{validator.SeverityLow, "🔵"},
		{validator.SeverityInfo, "ℹ️"},
		{validator.Severity("unknown"), "•"},
	}
	
	for _, tt := range tests {
		t.Run(string(tt.severity), func(t *testing.T) {
			icon := getSeverityIcon(tt.severity)
			testutil.AssertEqual(t, tt.expected, icon, "severity icon")
		})
	}
}

func TestSeverityToSARIFLevel(t *testing.T) {
	tests := []struct {
		severity validator.Severity
		expected string
	}{
		{validator.SeverityHigh, "error"},
		{validator.SeverityMedium, "warning"},
		{validator.SeverityLow, "note"},
		{validator.SeverityInfo, "note"},
		{validator.Severity("unknown"), "none"},
	}
	
	for _, tt := range tests {
		t.Run(string(tt.severity), func(t *testing.T) {
			level := severityToSARIFLevel(tt.severity)
			testutil.AssertEqual(t, tt.expected, level, "SARIF level")
		})
	}
}

func TestReportToFile(t *testing.T) {
	findings := createTestFindings()
	
	// Create temporary file
	tmpfile, err := os.CreateTemp("", "test-report-*.json")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpfile.Name())
	tmpfile.Close()
	
	// Write report to file
	err = ReportToFile(findings, FormatJSON, tmpfile.Name())
	testutil.AssertNil(t, err, "ReportToFile should not return error")
	
	// Read and verify the file
	data, err := os.ReadFile(tmpfile.Name())
	testutil.AssertNil(t, err, "should read file")
	
	var report JSONReport
	err = json.Unmarshal(data, &report)
	testutil.AssertNil(t, err, "should unmarshal JSON from file")
	
	testutil.AssertEqual(t, 5, report.Summary.Total, "total findings in file")
}

func TestReportToFile_Error(t *testing.T) {
	findings := createTestFindings()
	
	// Try to write to an invalid path
	err := ReportToFile(findings, FormatJSON, "/invalid/path/file.json")
	testutil.AssertNotNil(t, err, "ReportToFile should return error for invalid path")
	if err != nil && !strings.Contains(err.Error(), "failed to create file") {
		t.Errorf("expected error to contain 'failed to create file', got: %v", err)
	}
}

func TestTextReporter_FormattingDetails(t *testing.T) {
	reporter := &TextReporter{}
	
	// Test with a finding that has no remediation
	findings := []validator.Finding{
		{
			RuleID:    "TEST001",
			RuleName:  "Test Rule",
			Severity:  validator.SeverityHigh,
			Message:   "Test message",
			Resource:  "test-resource",
			Namespace: "",  // No namespace
			Kind:      "ClusterRole",
			// No remediation
		},
	}
	
	var buf bytes.Buffer
	err := reporter.Report(findings, &buf)
	testutil.AssertNil(t, err, "Report should not return error")
	
	output := buf.String()
	
	// Should not show namespace for cluster-scoped resources
	if strings.Contains(output, "namespace:") {
		t.Error("should not show namespace for cluster-scoped resource")
	}
	
	// Should not show remediation section when not provided
	if strings.Contains(output, "Remediation:") {
		t.Error("should not show remediation when not provided")
	}
}

func TestJSONReporter_EmptySeverity(t *testing.T) {
	reporter := &JSONReporter{}
	
	// Test with findings that don't cover all severities
	findings := []validator.Finding{
		{
			RuleID:   "TEST001",
			Severity: validator.SeverityHigh,
		},
	}
	
	var buf bytes.Buffer
	err := reporter.Report(findings, &buf)
	testutil.AssertNil(t, err, "Report should not return error")
	
	var report JSONReport
	err = json.Unmarshal(buf.Bytes(), &report)
	testutil.AssertNil(t, err, "should unmarshal JSON")
	
	// Check that only HIGH severity is in the map
	testutil.AssertEqual(t, 1, len(report.Summary.BySeverity), "severity map should only contain present severities")
	testutil.AssertEqual(t, 1, report.Summary.BySeverity["HIGH"], "high severity count")
}

// Add missing import
func TestReporter_Imports(t *testing.T) {
	// This test ensures the fmt import is used
	output := fmt.Sprintf("test %d", 1)
	testutil.AssertEqual(t, "test 1", output, "fmt should work")
}