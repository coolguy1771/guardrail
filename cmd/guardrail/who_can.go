package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/coolguy1771/guardrail/pkg/analyzer"
)

//nolint:gochecknoglobals // CLI flags need to be global for Cobra
var (
	whoCanVerb       string
	whoCanResource   string
	whoCanAPIGroup   string
	whoCanFile       string
	whoCanDirectory  string
	whoCanCluster    bool
	whoCanKubeconfig string
	whoCanKubectx    string

	dangerousFile       string
	dangerousDirectory  string
	dangerousCluster    bool
	dangerousKubeconfig string
	dangerousKubectx    string
)

//nolint:gochecknoglobals // Cobra commands must be global
var whoCanCmd = &cobra.Command{
	Use:   "who-can",
	Short: "Show which subjects can perform a specific action",
	Long: `Show which subjects (users, service accounts, groups) have permission to
perform a specific verb on a specific resource, tracing the binding chain.`,
	Example: `  guardrail who-can --verb get --resource secrets -f rbac.yaml
  guardrail who-can --verb create --resource pods --cluster
  guardrail who-can --verb '*' --resource '*' -d ./manifests`,
	RunE: runWhoCan,
}

//nolint:gochecknoglobals // Cobra commands must be global
var dangerousCmd = &cobra.Command{
	Use:   "dangerous",
	Short: "Show subjects with high or critical risk permissions",
	Long: `Show all subjects that have HIGH or CRITICAL risk permissions, with details
about which grants make them dangerous. Useful for a quick security sweep.`,
	Example: `  guardrail dangerous -f rbac.yaml
  guardrail dangerous --cluster
  guardrail dangerous -d ./manifests -o json`,
	RunE: runDangerous,
}

//nolint:gochecknoinits // Cobra requires init for command registration
func init() {
	rootCmd.AddCommand(whoCanCmd)
	rootCmd.AddCommand(dangerousCmd)

	whoCanCmd.Flags().StringVar(&whoCanVerb, "verb", "", "Kubernetes verb to check (e.g. get, list, create, delete, *)")
	whoCanCmd.Flags().StringVar(&whoCanResource, "resource", "", "Resource type to check (e.g. pods, secrets, *)")
	whoCanCmd.Flags().StringVar(&whoCanAPIGroup, "api-group", "", "API group filter (omit or empty = all groups, * = all, or specify a group name)")
	whoCanCmd.Flags().StringVarP(&whoCanFile, "file", "f", "", "RBAC manifest file")
	whoCanCmd.Flags().StringVarP(&whoCanDirectory, "dir", "d", "", "Directory of RBAC manifests")
	whoCanCmd.Flags().BoolVarP(&whoCanCluster, "cluster", "c", false, "Analyze live cluster RBAC")
	whoCanCmd.Flags().StringVar(&whoCanKubeconfig, "kubeconfig", "", "Path to kubeconfig file")
	whoCanCmd.Flags().StringVar(&whoCanKubectx, "context", "", "Kubernetes context to use")

	dangerousCmd.Flags().StringVarP(&dangerousFile, "file", "f", "", "RBAC manifest file")
	dangerousCmd.Flags().StringVarP(&dangerousDirectory, "dir", "d", "", "Directory of RBAC manifests")
	dangerousCmd.Flags().BoolVarP(&dangerousCluster, "cluster", "c", false, "Analyze live cluster RBAC")
	dangerousCmd.Flags().StringVar(&dangerousKubeconfig, "kubeconfig", "", "Path to kubeconfig file")
	dangerousCmd.Flags().StringVar(&dangerousKubectx, "context", "", "Kubernetes context to use")
}

func runWhoCan(cmd *cobra.Command, _ []string) error {
	if whoCanVerb == "" || whoCanResource == "" {
		_ = cmd.Usage()
		return errors.New("--verb and --resource are required")
	}

	a, err := loadAnalyzer(whoCanFile, whoCanDirectory, whoCanCluster, whoCanKubeconfig, whoCanKubectx)
	if err != nil {
		return err
	}

	permissions, err := a.AnalyzePermissions(context.Background())
	if err != nil {
		return fmt.Errorf("analysis failed: %w", err)
	}

	matches := whoCanFilter(permissions, whoCanVerb, whoCanResource, whoCanAPIGroup)

	var w io.Writer = os.Stdout
	if cmd != nil {
		w = cmd.OutOrStdout()
	}

	outputFormat := viper.GetString("output")
	if outputFormat == "json" {
		return outputWhoCanJSON(matches, whoCanVerb, whoCanResource, w)
	}
	return outputWhoCanText(matches, whoCanVerb, whoCanResource, w)
}

func runDangerous(cmd *cobra.Command, _ []string) error {
	a, err := loadAnalyzer(dangerousFile, dangerousDirectory, dangerousCluster, dangerousKubeconfig, dangerousKubectx)
	if err != nil {
		return err
	}

	permissions, err := a.AnalyzePermissions(context.Background())
	if err != nil {
		return fmt.Errorf("analysis failed: %w", err)
	}

	var w io.Writer = os.Stdout
	if cmd != nil {
		w = cmd.OutOrStdout()
	}

	outputFormat := viper.GetString("output")
	if outputFormat == "json" {
		high := analyzer.FilterByRiskLevel(permissions, analyzer.RiskLevelHigh)
		crit := analyzer.FilterByRiskLevel(permissions, analyzer.RiskLevelCritical)
		dangerous := append(crit, high...) //nolint:gocritic // intentional append-to-different-slice
		return outputDangerousJSON(dangerous, w)
	}
	return outputDangerousText(permissions, w)
}

// loadAnalyzer creates an Analyzer from the given input source flags.
func loadAnalyzer(fileArg, dirArg string, clusterArg bool, kubeconfigArg, kubectxArg string) (*analyzer.Analyzer, error) {
	inputCount := 0
	if fileArg != "" {
		inputCount++
	}
	if dirArg != "" {
		inputCount++
	}
	if clusterArg {
		inputCount++
	}

	if inputCount == 0 {
		return nil, errors.New("specify one of --file, --dir, or --cluster")
	}
	if inputCount > 1 {
		return nil, errors.New("--file, --dir, and --cluster are mutually exclusive")
	}

	if clusterArg {
		return createClusterAnalyzer(kubeconfigArg, kubectxArg)
	}
	return createFileAnalyzer(fileArg, dirArg)
}

// WhoCanMatch records a subject and the specific grant that confers the permission.
type WhoCanMatch struct {
	Subject     string `json:"subject"`
	SubjectKind string `json:"subject_kind"`
	Namespace   string `json:"namespace,omitempty"`
	RoleName    string `json:"role_name"`
	RoleKind    string `json:"role_kind"`
	BindingName string `json:"binding_name"`
	BindingKind string `json:"binding_kind"`
	Scope       string `json:"scope"`
}

// whoCanFilter returns subjects that have the requested verb on the requested resource.
func whoCanFilter(permissions []analyzer.SubjectPermissions, verb, resource, apiGroup string) []WhoCanMatch {
	var matches []WhoCanMatch
	seen := make(map[string]bool)

	for _, sp := range permissions {
		for _, grant := range sp.Permissions {
			for _, rule := range grant.Rules {
				if ruleMatches(rule, verb, resource, apiGroup) {
					key := fmt.Sprintf("%s/%s/%s/%s/%s",
						sp.Subject.Kind, sp.Subject.Namespace, sp.Subject.Name,
						grant.BindingKind, grant.BindingName)
					if seen[key] {
						continue
					}
					seen[key] = true
					matches = append(matches, WhoCanMatch{
						Subject:     sp.Subject.Name,
						SubjectKind: sp.Subject.Kind,
						Namespace:   sp.Subject.Namespace,
						RoleName:    grant.RoleName,
						RoleKind:    grant.RoleKind,
						BindingName: grant.BindingName,
						BindingKind: grant.BindingKind,
						Scope:       grant.Scope,
					})
				}
			}
		}
	}

	return matches
}

// ruleMatches checks whether a PolicyRuleAnalysis grants the requested verb+resource.
func ruleMatches(rule analyzer.PolicyRuleAnalysis, verb, resource, apiGroup string) bool {
	verbMatch := false
	for _, v := range rule.Verbs {
		if v == "*" || strings.EqualFold(v, verb) {
			verbMatch = true
			break
		}
	}
	if !verbMatch {
		return false
	}

	resourceMatch := false
	for _, r := range rule.Resources {
		if r == "*" || strings.EqualFold(r, resource) {
			resourceMatch = true
			break
		}
	}
	if !resourceMatch {
		return false
	}

	if apiGroup == "" {
		return true
	}
	for _, g := range rule.APIGroups {
		if g == "*" || strings.EqualFold(g, apiGroup) {
			return true
		}
	}
	return false
}

func outputWhoCanText(matches []WhoCanMatch, verb, resource string, w io.Writer) error {
	if len(matches) == 0 {
		fmt.Fprintf(w, "No subjects can %s %s.\n", verb, resource)
		return nil
	}

	fmt.Fprintf(w, "%sSubjects that can %s %s:\n", colorLabel("🔍 ", ""), verb, resource)
	fmt.Fprintf(w, "%s\n", strings.Repeat("─", outputSeparatorLength))

	for _, m := range matches {
		label := getRiskLabel(analyzer.RiskLevelMedium) // default; could improve with actual risk
		fmt.Fprintf(w, "%s %s/%s", label, m.SubjectKind, m.Subject)
		if m.Namespace != "" {
			fmt.Fprintf(w, " (namespace: %s)", m.Namespace)
		}
		fmt.Fprintf(w, "\n")
		fmt.Fprintf(w, "     via %s/%s → %s/%s  [scope: %s]\n\n",
			m.BindingKind, m.BindingName, m.RoleKind, m.RoleName, m.Scope)
	}

	return nil
}

func outputWhoCanJSON(matches []WhoCanMatch, verb, resource string, w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(map[string]any{
		"verb":     verb,
		"resource": resource,
		"subjects": matches,
		"count":    len(matches),
	})
}

func outputDangerousText(permissions []analyzer.SubjectPermissions, w io.Writer) error {
	critical := analyzer.FilterByRiskLevel(permissions, analyzer.RiskLevelCritical)
	high := analyzer.FilterByRiskLevel(permissions, analyzer.RiskLevelHigh)

	if len(critical)+len(high) == 0 {
		fmt.Fprintln(w, "No subjects with HIGH or CRITICAL permissions found.")
		return nil
	}

	fmt.Fprintf(w, "%sDangerous RBAC Subjects\n", colorLabel("⚠️  ", ""))
	fmt.Fprintf(w, "%s\n\n", strings.Repeat("─", outputSeparatorLength))

	if len(critical) > 0 {

		for _, sp := range critical {
			printSubjectAnalysis(sp, false, w)
		}
	}
	if len(high) > 0 {
		fmt.Fprintf(w, "HIGH (%d)\n", len(high))
		for _, sp := range high {
			printSubjectAnalysis(sp, false, w)
		}
	}

	return nil
}

func outputDangerousJSON(dangerous []analyzer.SubjectPermissions, w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(map[string]any{
		"dangerous_subjects": dangerous,
		"count":              len(dangerous),
	})
}
