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
	"github.com/coolguy1771/guardrail/pkg/reporter"
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
)

//nolint:gochecknoglobals // Cobra commands must be global
var analyzeCmd = &cobra.Command{
	Use:   "analyze",
	Short: "Analyze RBAC permissions and explain what subjects can do",
	Long: `Analyze RoleBindings and ClusterRoleBindings to understand what permissions
are granted to users, service accounts, and groups. Provides plain-English
explanations of what each permission allows.`,
	RunE: runAnalyze,
}

//nolint:gochecknoinits // Cobra requires init for command registration
func init() {
	rootCmd.AddCommand(analyzeCmd)

	analyzeCmd.Flags().StringVarP(&analyzeFile, "file", "f", "", "RBAC manifest file to analyze")
	analyzeCmd.Flags().StringVarP(&analyzeDirectory, "dir", "d", "", "Directory of RBAC manifests to analyze")
	analyzeCmd.Flags().BoolVarP(&analyzeCluster, "cluster", "c", false, "Analyze live cluster RBAC")
	analyzeCmd.Flags().StringVar(&kubeconfig, "kubeconfig", "", "Path to kubeconfig file")
	analyzeCmd.Flags().StringVar(&kubectx, "context", "", "Kubernetes context to use")
	analyzeCmd.Flags().StringVarP(&subject, "subject", "s", "", "Filter by subject name")
	analyzeCmd.Flags().BoolVar(&showRoles, "show-roles", false, "Show detailed per-rule breakdown")
	analyzeCmd.Flags().StringVar(&riskLevel, "risk-level", "", "Filter by risk level: low, medium, high, critical (case-insensitive)")

	_ = viper.BindPFlag("analyze.file", analyzeCmd.Flags().Lookup("file"))
	_ = viper.BindPFlag("analyze.directory", analyzeCmd.Flags().Lookup("dir"))
	_ = viper.BindPFlag("analyze.cluster", analyzeCmd.Flags().Lookup("cluster"))
	_ = viper.BindPFlag("analyze.kubeconfig", analyzeCmd.Flags().Lookup("kubeconfig"))
	_ = viper.BindPFlag("analyze.context", analyzeCmd.Flags().Lookup("context"))
	_ = viper.BindPFlag("analyze.subject", analyzeCmd.Flags().Lookup("subject"))
	_ = viper.BindPFlag("analyze.show-roles", analyzeCmd.Flags().Lookup("show-roles"))
	_ = viper.BindPFlag("analyze.risk-level", analyzeCmd.Flags().Lookup("risk-level"))
}

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

	// Count input sources — exactly one required.
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
		_ = cmd.Usage()
		return errors.New("specify one of --file, --dir, or --cluster")
	}
	if inputCount > 1 {
		_ = cmd.Usage()
		return errors.New("--file, --dir, and --cluster are mutually exclusive")
	}

	var a *analyzer.Analyzer
	var err error

	if clusterArg {
		a, err = createClusterAnalyzer(kubeconfigArg, kubectxArg)
		if err != nil {
			return err
		}
	} else {
		a, err = createFileAnalyzer(fileArg, directoryArg)
		if err != nil {
			return err
		}
	}

	permissions, err := a.AnalyzePermissions(context.Background())
	if err != nil {
		return fmt.Errorf("analysis failed: %w", err)
	}

	permissions = filterPermissions(permissions, subjectArg, riskLevelArg)

	var w io.Writer = os.Stdout
	if cmd != nil {
		w = cmd.OutOrStdout()
	}

	switch outputFormat {
	case "json":
		return outputJSON(permissions, w)
	default:
		return outputHumanReadable(permissions, showRolesArg, w)
	}
}

func createClusterAnalyzer(kubeconfigArg, kubectxArg string) (*analyzer.Analyzer, error) {
	client, err := kubernetes.NewClient(kubeconfigArg, kubectxArg)
	if err != nil {
		return nil, fmt.Errorf("cannot connect to cluster: %w", err)
	}
	return analyzer.NewAnalyzer(client.GetRBACReader()), nil
}

func createFileAnalyzer(fileArg, directoryArg string) (*analyzer.Analyzer, error) {
	var objects []runtime.Object
	var err error

	if fileArg != "" {
		objects, err = parseFile(fileArg)
		if err != nil {
			return nil, fmt.Errorf("cannot parse %q: %w", fileArg, err)
		}
	} else {
		objects, err = parseDirectory(directoryArg)
		if err != nil {
			return nil, fmt.Errorf("cannot read directory %q: %w", directoryArg, err)
		}
	}

	return analyzer.NewAnalyzerFromObjects(objects), nil
}

func parseFile(filename string) ([]runtime.Object, error) {
	p := parser.New()
	return p.ParseFile(filename)
}

// listYAMLFiles returns all .yaml/.yml file paths found under dir.
func listYAMLFiles(dir string) ([]string, error) {
	var files []string
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && (filepath.Ext(path) == ".yaml" || filepath.Ext(path) == ".yml") {
			files = append(files, path)
		}
		return nil
	})
	return files, err
}

func parseDirectory(directory string) ([]runtime.Object, error) {
	yamlFiles, err := listYAMLFiles(directory)
	if err != nil {
		return nil, err
	}

	p := parser.New()
	isVerbose := viper.GetBool("verbose")
	failedParses := 0
	var allObjects []runtime.Object

	for _, path := range yamlFiles {
		objects, parseErr := p.ParseFile(path)
		if parseErr != nil {
			if isVerbose {
				fmt.Fprintf(os.Stderr, "warning: skipping %q: %v\n", path, parseErr)
			}
			failedParses++
			continue
		}
		allObjects = append(allObjects, objects...)
	}

	if failedParses > 0 && !isVerbose {
		fmt.Fprintf(os.Stderr, "warning: %d file(s) could not be parsed (run with --verbose for details)\n", failedParses)
	}

	return allObjects, nil
}

// filterPermissions filters by subject name (exact) and risk level (case-insensitive).
func filterPermissions(
	permissions []analyzer.SubjectPermissions,
	subjectFilter, riskFilter string,
) []analyzer.SubjectPermissions {
	if subjectFilter == "" && riskFilter == "" {
		return permissions
	}

	riskFilterNorm := strings.ToLower(riskFilter)

	var filtered []analyzer.SubjectPermissions
	for _, perm := range permissions {
		if subjectFilter != "" && perm.Subject.Name != subjectFilter {
			continue
		}
		if riskFilterNorm != "" && strings.ToLower(string(perm.RiskLevel)) != riskFilterNorm {
			continue
		}
		filtered = append(filtered, perm)
	}
	return filtered
}

func outputJSON(permissions []analyzer.SubjectPermissions, w io.Writer) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(map[string]any{
		"subjects": permissions,
		"summary":  getSummary(permissions),
	})
}

func outputHumanReadable(permissions []analyzer.SubjectPermissions, showRoles bool, w io.Writer) error {
	if len(permissions) == 0 {
		fmt.Fprintln(w, "No RBAC permissions found matching the criteria.")
		return nil
	}

	summary := getSummary(permissions)

	fmt.Fprintf(w, "%s\n", colorLabel("📊 RBAC Analysis Summary", "RBAC Analysis Summary"))
	fmt.Fprintf(w, "========================\n")
	fmt.Fprintf(w, "Total Subjects: %d\n", summary.TotalSubjects)
	fmt.Fprintf(w, "Risk Distribution:\n")

	if reporter.UseColor {
		fmt.Fprintf(w, "  🔴 Critical: %d\n", summary.CriticalRisk)
		fmt.Fprintf(w, "  🟠 High:     %d\n", summary.HighRisk)
		fmt.Fprintf(w, "  🟡 Medium:   %d\n", summary.MediumRisk)
		fmt.Fprintf(w, "  🟢 Low:      %d\n", summary.LowRisk)
	} else {
		fmt.Fprintf(w, "  [CRIT]   Critical: %d\n", summary.CriticalRisk)
		fmt.Fprintf(w, "  [HIGH]   High:     %d\n", summary.HighRisk)
		fmt.Fprintf(w, "  [MED]    Medium:   %d\n", summary.MediumRisk)
		fmt.Fprintf(w, "  [LOW]    Low:      %d\n", summary.LowRisk)
	}
	fmt.Fprintf(w, "\n")

	for i, subjectPerm := range permissions {
		if i > 0 {
			fmt.Fprintf(w, "\n%s\n\n", strings.Repeat("─", outputSeparatorLength))
		}
		printSubjectAnalysis(subjectPerm, showRoles, w)
	}

	return nil
}

func printSubjectAnalysis(subjectPerm analyzer.SubjectPermissions, showRoles bool, w io.Writer) {
	riskIcon := getRiskLabel(subjectPerm.RiskLevel)
	fmt.Fprintf(w, "%s %s: %s\n", riskIcon, subjectPerm.Subject.Kind, subjectPerm.Subject.Name)

	if subjectPerm.Subject.Namespace != "" {
		fmt.Fprintf(w, "   Namespace: %s\n", subjectPerm.Subject.Namespace)
	}
	fmt.Fprintf(w, "   Risk Level: %s\n", strings.ToUpper(string(subjectPerm.RiskLevel)))
	fmt.Fprintf(w, "   Total Permissions: %d\n\n", len(subjectPerm.Permissions))

	for _, perm := range subjectPerm.Permissions {
		fmt.Fprintf(w, "  %s %s/%s", colorLabel("📋", "[role]"), perm.RoleKind, perm.RoleName)
		if perm.Namespace != "" {
			fmt.Fprintf(w, " (namespace: %s)", perm.Namespace)
		}
		fmt.Fprintf(w, "\n")
		fmt.Fprintf(w, "     Scope: %s\n", perm.Scope)
		fmt.Fprintf(w, "     Bound via: %s/%s\n", perm.BindingKind, perm.BindingName)

		if showRoles && len(perm.Rules) > 0 {
			fmt.Fprintf(w, "\n     %s\n", colorLabel("🔍 Detailed Permissions:", "Detailed Permissions:"))
			for _, rule := range perm.Rules {
				printRuleAnalysis(rule, "       ", w)
			}
		} else if len(perm.Rules) > 0 {
			fmt.Fprintf(w, "     Summary: %s\n", generatePermissionSummary(perm.Rules))
		}
		fmt.Fprintf(w, "\n")
	}
}

func printRuleAnalysis(rule analyzer.PolicyRuleAnalysis, indent string, w io.Writer) {
	fmt.Fprintf(w, "%s• %s\n", indent, rule.HumanReadable)
	fmt.Fprintf(w, "%s  Risk: %s\n", indent, strings.ToUpper(string(rule.SecurityImpact.Level)))

	if len(rule.SecurityImpact.Concerns) > 0 {
		fmt.Fprintf(w, "%s  %sConcerns: %s\n", indent,
			colorLabel("⚠️  ", ""), strings.Join(rule.SecurityImpact.Concerns, ", "))
	}

	if len(rule.VerbExplanations) > 0 {
		fmt.Fprintf(w, "%s  %s\n", indent, colorLabel("🔧 Actions allowed:", "Actions allowed:"))
		for _, verb := range rule.VerbExplanations {
			color := getColorForRisk(verb.RiskLevel)
			reset := resetColor()
			fmt.Fprintf(w, "%s    - %s%s%s: %s\n", indent, color, verb.Verb, reset, verb.Explanation)
			if verb.Examples != "" {
				fmt.Fprintf(w, "%s      Example: %s\n", indent, verb.Examples)
			}
		}
	}
	fmt.Fprintf(w, "\n")
}

func generatePermissionSummary(rules []analyzer.PolicyRuleAnalysis) string {
	if len(rules) == 0 {
		return "no permissions"
	}

	highRiskCount := 0
	for _, rule := range rules {
		if rule.SecurityImpact.Level == analyzer.RiskLevelHigh ||
			rule.SecurityImpact.Level == analyzer.RiskLevelCritical {
			highRiskCount++
		}
	}

	s := fmt.Sprintf("%d permission rule(s)", len(rules))
	if highRiskCount > 0 {
		s += fmt.Sprintf(", %d high-risk", highRiskCount)
	}
	return s
}

// getRiskLabel returns an emoji or bracketed label for a risk level.
func getRiskLabel(level analyzer.RiskLevel) string {
	if reporter.UseColor {
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
	switch level {
	case analyzer.RiskLevelCritical:
		return "[CRIT]"
	case analyzer.RiskLevelHigh:
		return "[HIGH]"
	case analyzer.RiskLevelMedium:
		return "[MED] "
	case analyzer.RiskLevelLow:
		return "[LOW] "
	default:
		return "[?]   "
	}
}

// getColorForRisk returns an ANSI escape code for the given risk level when color is enabled.
func getColorForRisk(riskLevel string) string {
	if !reporter.UseColor {
		return ""
	}
	switch strings.ToLower(riskLevel) {
	case "critical":
		return "\033[91m"
	case "high":
		return "\033[31m"
	case "medium":
		return "\033[33m"
	case "low":
		return "\033[32m"
	default:
		return ""
	}
}

func resetColor() string {
	if !reporter.UseColor {
		return ""
	}
	return "\033[0m"
}

// colorLabel returns emoji when color is enabled, otherwise plain text.
func colorLabel(emoji, plain string) string {
	if reporter.UseColor {
		return emoji
	}
	return plain
}

type AnalysisSummary struct {
	TotalSubjects int `json:"total_subjects"`
	CriticalRisk  int `json:"critical_risk"`
	HighRisk      int `json:"high_risk"`
	MediumRisk    int `json:"medium_risk"`
	LowRisk       int `json:"low_risk"`
}

func getSummary(permissions []analyzer.SubjectPermissions) AnalysisSummary {
	s := AnalysisSummary{TotalSubjects: len(permissions)}
	for _, perm := range permissions {
		switch perm.RiskLevel {
		case analyzer.RiskLevelCritical:
			s.CriticalRisk++
		case analyzer.RiskLevelHigh:
			s.HighRisk++
		case analyzer.RiskLevelMedium:
			s.MediumRisk++
		case analyzer.RiskLevelLow:
			s.LowRisk++
		}
	}
	return s
}
