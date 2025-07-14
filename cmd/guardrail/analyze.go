package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/coolguy1771/guardrail/pkg/analyzer"
	"github.com/coolguy1771/guardrail/pkg/kubernetes"
	"github.com/coolguy1771/guardrail/pkg/parser"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"k8s.io/apimachinery/pkg/runtime"
)

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

var analyzeCmd = &cobra.Command{
	Use:   "analyze",
	Short: "Analyze RBAC permissions and explain what subjects can do",
	Long: `Analyze RoleBindings and ClusterRoleBindings to understand what permissions
are granted to users, service accounts, and groups. Provides plain English
explanations of what each permission allows.`,
	RunE: runAnalyze,
}

func init() {
	rootCmd.AddCommand(analyzeCmd)

	analyzeCmd.Flags().StringVarP(&analyzeFile, "file", "f", "", "Path to a single RBAC manifest file")
	analyzeCmd.Flags().StringVarP(&analyzeDirectory, "dir", "d", "", "Path to a directory containing RBAC manifests")
	analyzeCmd.Flags().BoolVarP(&analyzeCluster, "cluster", "c", false, "Analyze live cluster RBAC")
	analyzeCmd.Flags().StringVar(&kubeconfig, "kubeconfig", "", "Path to kubeconfig file")
	analyzeCmd.Flags().StringVar(&kubectx, "context", "", "Kubernetes context to use")
	analyzeCmd.Flags().StringVarP(&subject, "subject", "s", "", "Filter by subject name (user, group, or service account)")
	analyzeCmd.Flags().BoolVar(&showRoles, "show-roles", false, "Show detailed role information")
	analyzeCmd.Flags().StringVar(&riskLevel, "risk-level", "", "Filter by risk level (low, medium, high, critical)")

	viper.BindPFlag("analyze.file", analyzeCmd.Flags().Lookup("file"))
	viper.BindPFlag("analyze.directory", analyzeCmd.Flags().Lookup("dir"))
	viper.BindPFlag("analyze.cluster", analyzeCmd.Flags().Lookup("cluster"))
	viper.BindPFlag("analyze.kubeconfig", analyzeCmd.Flags().Lookup("kubeconfig"))
	viper.BindPFlag("analyze.context", analyzeCmd.Flags().Lookup("context"))
	viper.BindPFlag("analyze.subject", analyzeCmd.Flags().Lookup("subject"))
	viper.BindPFlag("analyze.show-roles", analyzeCmd.Flags().Lookup("show-roles"))
	viper.BindPFlag("analyze.risk-level", analyzeCmd.Flags().Lookup("risk-level"))
}

func runAnalyze(cmd *cobra.Command, args []string) error {
	file := viper.GetString("analyze.file")
	directory := viper.GetString("analyze.directory")
	cluster := viper.GetBool("analyze.cluster")
	kubeconfig := viper.GetString("analyze.kubeconfig")
	kubectx := viper.GetString("analyze.context")
	subject := viper.GetString("analyze.subject")
	showRoles := viper.GetBool("analyze.show-roles")
	riskLevel := viper.GetString("analyze.risk-level")
	outputFormat := viper.GetString("output")

	// Validate input options
	inputCount := 0
	if file != "" {
		inputCount++
	}
	if directory != "" {
		inputCount++
	}
	if cluster {
		inputCount++
	}

	if inputCount == 0 {
		return fmt.Errorf("must specify one of --file, --dir, or --cluster")
	}
	if inputCount > 1 {
		return fmt.Errorf("cannot specify multiple input sources")
	}

	var a *analyzer.Analyzer
	var err error

	if cluster {
		// Analyze live cluster
		client, err := kubernetes.NewClient(kubeconfig)
		if err != nil {
			return fmt.Errorf("failed to create kubernetes client: %w", err)
		}
		a = analyzer.NewAnalyzer(client.GetClientset())
	} else {
		// Analyze files
		var objects []runtime.Object
		
		if file != "" {
			objects, err = parseFile(file)
			if err != nil {
				return fmt.Errorf("failed to parse file: %w", err)
			}
		} else {
			objects, err = parseDirectory(directory)
			if err != nil {
				return fmt.Errorf("failed to parse directory: %w", err)
			}
		}

		a = analyzer.NewAnalyzerFromObjects(objects)
	}

	// Analyze permissions
	ctx := context.Background()
	if kubectx != "" {
		// TODO: Set Kubernetes context
	}

	permissions, err := a.AnalyzePermissions(ctx)
	if err != nil {
		return fmt.Errorf("failed to analyze permissions: %w", err)
	}

	// Apply filters
	permissions = filterPermissions(permissions, subject, riskLevel)

	// Output results
	switch outputFormat {
	case "json":
		return outputJSON(permissions)
	default:
		return outputHumanReadable(permissions, showRoles)
	}
}

func parseFile(filename string) ([]runtime.Object, error) {
	p := parser.New()
	return p.ParseFile(filename)
}

func parseDirectory(directory string) ([]runtime.Object, error) {
	var allObjects []runtime.Object
	p := parser.New()

	err := filepath.Walk(directory, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && (filepath.Ext(path) == ".yaml" || filepath.Ext(path) == ".yml") {
			objects, err := p.ParseFile(path)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Warning: Failed to parse %s: %v\n", path, err)
				return nil
			}
			allObjects = append(allObjects, objects...)
		}
		return nil
	})

	return allObjects, err
}

func filterPermissions(permissions []analyzer.SubjectPermissions, subjectFilter, riskFilter string) []analyzer.SubjectPermissions {
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

func outputJSON(permissions []analyzer.SubjectPermissions) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(map[string]interface{}{
		"subjects": permissions,
		"summary": getSummary(permissions),
	})
}

func outputHumanReadable(permissions []analyzer.SubjectPermissions, showRoles bool) error {
	if len(permissions) == 0 {
		fmt.Println("No RBAC permissions found matching the criteria.")
		return nil
	}

	// Print summary
	summary := getSummary(permissions)
	fmt.Printf("📊 RBAC Analysis Summary\n")
	fmt.Printf("========================\n")
	fmt.Printf("Total Subjects: %d\n", summary.TotalSubjects)
	fmt.Printf("Risk Distribution:\n")
	fmt.Printf("  🔴 Critical: %d\n", summary.CriticalRisk)
	fmt.Printf("  🟠 High: %d\n", summary.HighRisk)
	fmt.Printf("  🟡 Medium: %d\n", summary.MediumRisk)
	fmt.Printf("  🟢 Low: %d\n", summary.LowRisk)
	fmt.Printf("\n")

	// Print detailed analysis for each subject
	for i, subjectPerm := range permissions {
		if i > 0 {
			fmt.Printf("\n" + strings.Repeat("─", 80) + "\n\n")
		}

		printSubjectAnalysis(subjectPerm, showRoles)
	}

	return nil
}

func printSubjectAnalysis(subjectPerm analyzer.SubjectPermissions, showRoles bool) {
	// Print subject header
	riskIcon := getRiskIcon(subjectPerm.RiskLevel)
	fmt.Printf("%s %s: %s\n", riskIcon, subjectPerm.Subject.Kind, subjectPerm.Subject.Name)
	
	if subjectPerm.Subject.Namespace != "" {
		fmt.Printf("   Namespace: %s\n", subjectPerm.Subject.Namespace)
	}
	fmt.Printf("   Risk Level: %s\n", strings.ToUpper(string(subjectPerm.RiskLevel)))
	fmt.Printf("   Total Permissions: %d\n\n", len(subjectPerm.Permissions))

	// Print permissions
	for _, perm := range subjectPerm.Permissions {
		fmt.Printf("  📋 %s/%s", perm.RoleKind, perm.RoleName)
		if perm.Namespace != "" {
			fmt.Printf(" (namespace: %s)", perm.Namespace)
		}
		fmt.Printf("\n")
		fmt.Printf("     Scope: %s\n", perm.Scope)
		fmt.Printf("     Bound via: %s/%s\n", perm.BindingKind, perm.BindingName)

		if showRoles && len(perm.Rules) > 0 {
			fmt.Printf("\n     🔍 Detailed Permissions:\n")
			for _, rule := range perm.Rules {
				printRuleAnalysis(rule, "       ")
			}
		} else if len(perm.Rules) > 0 {
			fmt.Printf("     📝 Summary: %s\n", generatePermissionSummary(perm.Rules))
		}
		fmt.Printf("\n")
	}
}

func printRuleAnalysis(rule analyzer.PolicyRuleAnalysis, indent string) {
	fmt.Printf("%s• %s\n", indent, rule.HumanReadable)
	fmt.Printf("%s  Risk: %s\n", indent, strings.ToUpper(string(rule.SecurityImpact.Level)))
	
	if len(rule.SecurityImpact.Concerns) > 0 {
		fmt.Printf("%s  ⚠️  Concerns: %s\n", indent, strings.Join(rule.SecurityImpact.Concerns, ", "))
	}

	if len(rule.VerbExplanations) > 0 {
		fmt.Printf("%s  🔧 Actions allowed:\n", indent)
		for _, verb := range rule.VerbExplanations {
			riskColor := getColorForRisk(verb.RiskLevel)
			fmt.Printf("%s    - %s%s%s: %s\n", indent, riskColor, verb.Verb, resetColor(), verb.Explanation)
			if verb.Examples != "" {
				fmt.Printf("%s      Example: %s\n", indent, verb.Examples)
			}
		}
	}
	fmt.Printf("\n")
}

func generatePermissionSummary(rules []analyzer.PolicyRuleAnalysis) string {
	if len(rules) == 0 {
		return "No permissions"
	}

	var summaryParts []string
	highRiskCount := 0
	
	for _, rule := range rules {
		if rule.SecurityImpact.Level == analyzer.RiskLevelHigh || rule.SecurityImpact.Level == analyzer.RiskLevelCritical {
			highRiskCount++
		}
	}

	summaryParts = append(summaryParts, fmt.Sprintf("%d permission rule(s)", len(rules)))
	
	if highRiskCount > 0 {
		summaryParts = append(summaryParts, fmt.Sprintf("%d high-risk", highRiskCount))
	}

	return strings.Join(summaryParts, ", ")
}

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

func getColorForRisk(riskLevel string) string {
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

func resetColor() string {
	return "\033[0m"
}

type AnalysisSummary struct {
	TotalSubjects int `json:"total_subjects"`
	CriticalRisk  int `json:"critical_risk"`
	HighRisk      int `json:"high_risk"`
	MediumRisk    int `json:"medium_risk"`
	LowRisk       int `json:"low_risk"`
}

func getSummary(permissions []analyzer.SubjectPermissions) AnalysisSummary {
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