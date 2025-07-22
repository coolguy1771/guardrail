package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/coolguy1771/guardrail/pkg/analyzer"
	"github.com/coolguy1771/guardrail/pkg/kubernetes"
	"github.com/coolguy1771/guardrail/pkg/parser"
)

const outputSeparatorLength = 80

//nolint:gochecknoglobals // CLI flags need to be global for Cobra
var (
	analyzeFile      string
	analyzeDirectory string
	analyzeCluster   bool
	kubeconfig       string
	kubectx          string
	subject          string
	showRoles        bool
	riskLevel        string
	noColor          bool
)

//nolint:gochecknoglobals // Cobra commands must be global
var analyzeCmd = &cobra.Command{
	Use:   "analyze",
	Short: "Analyze RBAC permissions and explain what subjects can do",
	Long: `Analyze RoleBindings and ClusterRoleBindings to understand what permissions
are granted to users, service accounts, and groups. Provides plain English
explanations of what each permission allows.`,
	RunE: runAnalyze,
}

// init registers the 'analyze' CLI command and its flags, and binds them to Viper configuration keys for RBAC permission analysis.
//
//nolint:gochecknoinits // Cobra requires init for command registration
func init() {
	rootCmd.AddCommand(analyzeCmd)

	analyzeCmd.Flags().StringVarP(&analyzeFile, "file", "f", "", "Path to a single RBAC manifest file")
	analyzeCmd.Flags().StringVarP(&analyzeDirectory, "dir", "d", "", "Path to a directory containing RBAC manifests")
	analyzeCmd.Flags().BoolVarP(&analyzeCluster, "cluster", "c", false, "Analyze live cluster RBAC")
	analyzeCmd.Flags().StringVar(&kubeconfig, "kubeconfig", "", "Path to kubeconfig file")
	analyzeCmd.Flags().StringVar(&kubectx, "context", "", "Kubernetes context to use")
	analyzeCmd.Flags().
		StringVarP(&subject, "subject", "s", "", "Filter by subject name (user, group, or service account)")
	analyzeCmd.Flags().BoolVar(&showRoles, "show-roles", false, "Show detailed role information")
	analyzeCmd.Flags().StringVar(&riskLevel, "risk-level", "", "Filter by risk level (low, medium, high, critical)")
	analyzeCmd.Flags().BoolVar(&noColor, "no-color", false, "Disable colored output")

	_ = viper.BindPFlag("analyze.file", analyzeCmd.Flags().Lookup("file"))
	_ = viper.BindPFlag("analyze.directory", analyzeCmd.Flags().Lookup("dir"))
	_ = viper.BindPFlag("analyze.cluster", analyzeCmd.Flags().Lookup("cluster"))
	_ = viper.BindPFlag("analyze.kubeconfig", analyzeCmd.Flags().Lookup("kubeconfig"))
	_ = viper.BindPFlag("analyze.context", analyzeCmd.Flags().Lookup("context"))
	_ = viper.BindPFlag("analyze.subject", analyzeCmd.Flags().Lookup("subject"))
	_ = viper.BindPFlag("analyze.show-roles", analyzeCmd.Flags().Lookup("show-roles"))
	_ = viper.BindPFlag("analyze.risk-level", analyzeCmd.Flags().Lookup("risk-level"))
	_ = viper.BindPFlag("analyze.no-color", analyzeCmd.Flags().Lookup("no-color"))
}

// runAnalyze executes the RBAC analysis command, processing input from a file, directory, or live Kubernetes cluster, and outputs permission analysis results in the specified format.
// It validates input options, initializes the analyzer, performs permission analysis, applies subject and risk level filters, and outputs results as JSON or human-readable text.
// Returns an error if input validation, parsing, analysis, or output fails.
func runAnalyze(cmd *cobra.Command, _ []string) error {
	fileArg := viper.GetString("analyze.file")
	directoryArg := viper.GetString("analyze.directory")
	clusterArg := viper.GetBool("analyze.cluster")
	kubeconfigArg := viper.GetString("analyze.kubeconfig")
	kubectxArg := viper.GetString("analyze.context")
	subjectArg := viper.GetString("analyze.subject")
	showRolesArg := viper.GetBool("analyze.show-roles")
	riskLevelArg := viper.GetString("analyze.risk-level")
	outputFormat := viper.GetString("output")

	// Validate input options
	inputCount := 0
	if fileArg != "" {
		inputCount++
	}
	if directoryArg != "" {
		inputCount++
	}
	if clusterArg {
		inputCount++
	}

	if inputCount == 0 {
		return errors.New("must specify one of --file, --dir, or --cluster")
	}
	if inputCount > 1 {
		return errors.New("cannot specify multiple input sources")
	}

	var a *analyzer.Analyzer
	var err error

	if clusterArg {
		// Analyze live cluster
		a, err = createClusterAnalyzer(kubeconfigArg, kubectxArg)
		if err != nil {
			return err
		}
	} else {
		// Analyze files
		a, err = createFileAnalyzer(fileArg, directoryArg)
		if err != nil {
			return err
		}
	}

	// Analyze permissions
	ctx := context.Background()
	// Note: The kubectx flag value is already passed to kubernetes.NewClient() above,
	// which handles context switching internally. This block is kept for potential
	// future use where we might need to pass context-specific options.

	permissions, err := a.AnalyzePermissions(ctx)
	if err != nil {
		return fmt.Errorf("failed to analyze permissions: %w", err)
	}

	// Apply filters
	permissions = filterPermissions(permissions, subjectArg, riskLevelArg)

	// Output results
	var writer io.Writer = os.Stdout
	if cmd != nil {
		writer = cmd.OutOrStdout()
	}
	
	switch outputFormat {
	case "json":
		return outputJSON(permissions, writer)
	default:
		return outputHumanReadable(permissions, showRolesArg, writer)
	}
}

// createClusterAnalyzer creates an analyzer for live cluster analysis.
func createClusterAnalyzer(kubeconfigArg, kubectxArg string) (*analyzer.Analyzer, error) {
	client, err := kubernetes.NewClient(kubeconfigArg, kubectxArg)
	if err != nil {
		return nil, fmt.Errorf("failed to create kubernetes client: %w", err)
	}
	return analyzer.NewAnalyzer(client.GetRBACReader()), nil
}

// createFileAnalyzer creates an analyzer for file-based analysis.
func createFileAnalyzer(fileArg, directoryArg string) (*analyzer.Analyzer, error) {
	var objects []runtime.Object
	var err error

	if fileArg != "" {
		objects, err = parseFile(fileArg)
		if err != nil {
			return nil, fmt.Errorf("failed to parse file: %w", err)
		}
	} else {
		objects, err = parseDirectory(directoryArg)
		if err != nil {
			return nil, fmt.Errorf("failed to parse directory: %w", err)
		}
	}

	return analyzer.NewAnalyzerFromObjects(objects), nil
}

// parseFile parses a Kubernetes YAML manifest file and returns the contained runtime objects.
// Returns an error if the file cannot be parsed.
func parseFile(filename string) ([]runtime.Object, error) {
	p := parser.New()
	return p.ParseFile(filename)
}

// parseDirectory walks through the specified directory, parses all YAML files into Kubernetes runtime objects, and returns the aggregated objects.
// Files that fail to parse are skipped with a warning; the function continues processing remaining files.
func parseDirectory(directory string) ([]runtime.Object, error) {
	var allObjects []runtime.Object
	p := parser.New()
	failedParses := 0

	err := filepath.Walk(directory, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && (filepath.Ext(path) == ".yaml" || filepath.Ext(path) == ".yml") {
			var objects []runtime.Object
			objects, err = p.ParseFile(path)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Warning: Failed to parse %s: %v\n", path, err)
				failedParses++
				return nil
			}
			allObjects = append(allObjects, objects...)
		}
		return nil
	})

	if failedParses > 0 {
		fmt.Fprintf(os.Stderr, "\n%d file(s) failed to parse in directory '%s'.\n", failedParses, directory)
	}

	return allObjects, err
}

// filterPermissions returns a filtered slice of SubjectPermissions based on the specified subject name and risk level.
// Only permissions matching both filters (if provided) are included in the result.
func filterPermissions(
	permissions []analyzer.SubjectPermissions,
	subjectFilter, riskFilter string,
) []analyzer.SubjectPermissions {
	var filtered []analyzer.SubjectPermissions

	for _, perm := range permissions {
		// Apply subject filter
		if subjectFilter != "" {
			if perm.Subject.Name != subjectFilter {
				continue
			}
		}

		// Apply risk level filter
		if riskFilter != "" {
			if string(perm.RiskLevel) != riskFilter {
				continue
			}
		}

		filtered = append(filtered, perm)
	}

	return filtered
}

// outputJSON writes the analyzed subject permissions and a summary to stdout in indented JSON format.
// Returns an error if encoding or writing fails.
func outputJSON(permissions []analyzer.SubjectPermissions, w io.Writer) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(map[string]any{
		"subjects": permissions,
		"summary":  getSummary(permissions),
	})
}

// outputHumanReadable prints a human-readable summary and detailed analysis of RBAC permissions for each subject, including risk distribution and optional rule details.
// Returns an error only if output fails.
//
//nolint:forbidigo // CLI output needs fmt.Print
func outputHumanReadable(permissions []analyzer.SubjectPermissions, showRoles bool, w io.Writer) error {
	if len(permissions) == 0 {
		fmt.Fprintln(w, "No RBAC permissions found matching the criteria.")
		return nil
	}

	// Print summary
	summary := getSummary(permissions)
	fmt.Fprintf(w, "📊 RBAC Analysis Summary\n")
	fmt.Fprintf(w, "========================\n")
	fmt.Fprintf(w, "Total Subjects: %d\n", summary.TotalSubjects)
	fmt.Fprintf(w, "Risk Distribution:\n")
	fmt.Fprintf(w, "  🔴 Critical: %d\n", summary.CriticalRisk)
	fmt.Fprintf(w, "  🟠 High: %d\n", summary.HighRisk)
	fmt.Fprintf(w, "  🟡 Medium: %d\n", summary.MediumRisk)
	fmt.Fprintf(w, "  🟢 Low: %d\n", summary.LowRisk)
	fmt.Fprintf(w, "\n")

	// Print detailed analysis for each subject
	for i, subjectPerm := range permissions {
		if i > 0 {
			fmt.Fprintf(w, "\n%s\n\n", strings.Repeat("─", outputSeparatorLength))
		}

		printSubjectAnalysis(subjectPerm, showRoles, w)
	}

	return nil
}

// printSubjectAnalysis displays a detailed analysis of a subject's permissions, including risk level, roles, and optionally detailed rule information.
// It prints the subject's kind, name, namespace, risk level, and a breakdown of each permission with associated roles and bindings.
// If showRoles is true, detailed permission rules are printed; otherwise, a summary is shown.
//
//nolint:forbidigo // CLI output needs fmt.Print
func printSubjectAnalysis(subjectPerm analyzer.SubjectPermissions, showRoles bool, w io.Writer) {
	// Print subject header
	riskIcon := getRiskIcon(subjectPerm.RiskLevel)
	fmt.Fprintf(w, "%s %s: %s\n", riskIcon, subjectPerm.Subject.Kind, subjectPerm.Subject.Name)

	if subjectPerm.Subject.Namespace != "" {
		fmt.Fprintf(w, "   Namespace: %s\n", subjectPerm.Subject.Namespace)
	}
	fmt.Fprintf(w, "   Risk Level: %s\n", strings.ToUpper(string(subjectPerm.RiskLevel)))
	fmt.Fprintf(w, "   Total Permissions: %d\n\n", len(subjectPerm.Permissions))

	// Print permissions
	for _, perm := range subjectPerm.Permissions {
		fmt.Fprintf(w, "  📋 %s/%s", perm.RoleKind, perm.RoleName)
		if perm.Namespace != "" {
			fmt.Fprintf(w, " (namespace: %s)", perm.Namespace)
		}
		fmt.Fprintf(w, "\n")
		fmt.Fprintf(w, "     Scope: %s\n", perm.Scope)
		fmt.Fprintf(w, "     Bound via: %s/%s\n", perm.BindingKind, perm.BindingName)

		if showRoles && len(perm.Rules) > 0 {
			fmt.Fprintf(w, "\n     🔍 Detailed Permissions:\n")
			for _, rule := range perm.Rules {
				printRuleAnalysis(rule, "       ", w)
			}
		} else if len(perm.Rules) > 0 {
			fmt.Fprintf(w, "     📝 Summary: %s\n", generatePermissionSummary(perm.Rules))
		}
		fmt.Fprintf(w, "\n")
	}
}

// printRuleAnalysis displays a detailed, human-readable analysis of a policy rule, including its description, risk level, concerns, and allowed actions with explanations and examples, using indentation and optional color coding for clarity.
//
//nolint:forbidigo // CLI output needs fmt.Print
func printRuleAnalysis(rule analyzer.PolicyRuleAnalysis, indent string, w io.Writer) {
	fmt.Fprintf(w, "%s• %s\n", indent, rule.HumanReadable)
	fmt.Fprintf(w, "%s  Risk: %s\n", indent, strings.ToUpper(string(rule.SecurityImpact.Level)))

	if len(rule.SecurityImpact.Concerns) > 0 {
		fmt.Fprintf(w, "%s  ⚠️  Concerns: %s\n", indent, strings.Join(rule.SecurityImpact.Concerns, ", "))
	}

	if len(rule.VerbExplanations) > 0 {
		fmt.Fprintf(w, "%s  🔧 Actions allowed:\n", indent)
		for _, verb := range rule.VerbExplanations {
			riskColor := getColorForRisk(verb.RiskLevel)
			fmt.Fprintf(w, "%s    - %s%s%s: %s\n", indent, riskColor, verb.Verb, resetColor(), verb.Explanation)
			if verb.Examples != "" {
				fmt.Fprintf(w, "%s      Example: %s\n", indent, verb.Examples)
			}
		}
	}
	fmt.Fprintf(w, "\n")
}

// generatePermissionSummary returns a summary string describing the number of permission rules and how many are classified as high-risk or critical.
func generatePermissionSummary(rules []analyzer.PolicyRuleAnalysis) string {
	if len(rules) == 0 {
		return "No permissions"
	}

	var summaryParts []string
	highRiskCount := 0

	for _, rule := range rules {
		if rule.SecurityImpact.Level == analyzer.RiskLevelHigh ||
			rule.SecurityImpact.Level == analyzer.RiskLevelCritical {
			highRiskCount++
		}
	}

	summaryParts = append(summaryParts, fmt.Sprintf("%d permission rule(s)", len(rules)))

	if highRiskCount > 0 {
		summaryParts = append(summaryParts, fmt.Sprintf("%d high-risk", highRiskCount))
	}

	return strings.Join(summaryParts, ", ")
}

// getRiskIcon returns an emoji icon representing the specified risk level.
func getRiskIcon(level analyzer.RiskLevel) string {
	switch level {
	case analyzer.RiskLevelCritical:
		return "🔴"
	case analyzer.RiskLevelHigh:
		return "🟠"
	case analyzer.RiskLevelMedium:
		return "🟡"
	case analyzer.RiskLevelLow:
		return "🟢"
	default:
		return "⚪"
	}
}

// isColorSupported returns true if colored output is enabled and supported by the terminal.
func isColorSupported() bool {
	if noColor {
		return false
	}
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	// Check if stdout is a terminal
	fi, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}

// getColorForRisk returns the ANSI color code string corresponding to the given risk level if color output is supported; otherwise, it returns an empty string.
func getColorForRisk(riskLevel string) string {
	if !isColorSupported() {
		return ""
	}
	switch riskLevel {
	case "critical":
		return "\033[91m" // Bright red
	case "high":
		return "\033[31m" // Red
	case "medium":
		return "\033[33m" // Yellow
	case "low":
		return "\033[32m" // Green
	default:
		return ""
	}
}

// resetColor returns the ANSI escape code to reset terminal text formatting if color output is supported, or an empty string otherwise.
func resetColor() string {
	if !isColorSupported() {
		return ""
	}
	return "\033[0m"
}

type AnalysisSummary struct {
	TotalSubjects int `json:"total_subjects"`
	CriticalRisk  int `json:"critical_risk"`
	HighRisk      int `json:"high_risk"`
	MediumRisk    int `json:"medium_risk"`
	LowRisk       int `json:"low_risk"`
}

// getSummary aggregates the total number of subjects and counts of each risk level from the provided permissions.
// It returns an AnalysisSummary with these aggregated values.
func getSummary(permissions []analyzer.SubjectPermissions) AnalysisSummary {
	//nolint:exhaustruct // Risk counts are calculated in the loop below
	summary := AnalysisSummary{
		TotalSubjects: len(permissions),
	}

	for _, perm := range permissions {
		switch perm.RiskLevel {
		case analyzer.RiskLevelCritical:
			summary.CriticalRisk++
		case analyzer.RiskLevelHigh:
			summary.HighRisk++
		case analyzer.RiskLevelMedium:
			summary.MediumRisk++
		case analyzer.RiskLevelLow:
			summary.LowRisk++
		}
	}

	return summary
}
