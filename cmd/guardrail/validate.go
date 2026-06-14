package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/coolguy1771/guardrail/pkg/kubernetes"
	"github.com/coolguy1771/guardrail/pkg/parser"
	"github.com/coolguy1771/guardrail/pkg/reporter"
	"github.com/coolguy1771/guardrail/pkg/validator"
)

//nolint:gochecknoglobals // CLI flags need to be global for Cobra
var (
	files              []string
	directory          string
	validateCluster    bool
	validateKubeconfig string
	validateKubectx    string
	failOn             string
)

//nolint:gochecknoglobals // Cobra commands must be global
var validateCmd = &cobra.Command{
	Use:   "validate",
	Short: "Validate RBAC manifests",
	Long:  `Validate Kubernetes RBAC manifests against security and compliance rules.`,
	RunE:  runValidate,
}

//nolint:gochecknoinits // Cobra requires init for command registration
func init() {
	rootCmd.AddCommand(validateCmd)

	validateCmd.Flags().
		StringSliceVarP(&files, "file", "f", []string{}, "RBAC manifest file(s) to validate (repeatable)")
	validateCmd.Flags().StringVarP(&directory, "dir", "d", "", "Directory of RBAC manifests to validate")
	validateCmd.Flags().BoolVarP(&validateCluster, "cluster", "c", false, "Validate live cluster RBAC")
	validateCmd.Flags().StringVar(&validateKubeconfig, "kubeconfig", "", "Path to kubeconfig file")
	validateCmd.Flags().StringVar(&validateKubectx, "context", "", "Kubernetes context to use")
	validateCmd.Flags().StringVar(&failOn, "fail-on", "high",
		"Exit non-zero when any finding reaches this severity: none|any|info|low|medium|high|critical")

	_ = viper.BindPFlag("files", validateCmd.Flags().Lookup("file"))
	_ = viper.BindPFlag("directory", validateCmd.Flags().Lookup("dir"))
	_ = viper.BindPFlag("validate.cluster", validateCmd.Flags().Lookup("cluster"))
	_ = viper.BindPFlag("validate.kubeconfig", validateCmd.Flags().Lookup("kubeconfig"))
	_ = viper.BindPFlag("validate.context", validateCmd.Flags().Lookup("context"))
	_ = viper.BindPFlag("validate.fail-on", validateCmd.Flags().Lookup("fail-on"))
}

//nolint:gocognit // Validation logic requires handling multiple cases
func runValidate(cmd *cobra.Command, _ []string) error {
	filesArg := viper.GetStringSlice("files")
	directoryArg := viper.GetString("directory")
	clusterArg := viper.GetBool("validate.cluster")
	kubeconfigArg := viper.GetString("validate.kubeconfig")
	kubectxArg := viper.GetString("validate.context")
	failOnArg := strings.ToLower(viper.GetString("validate.fail-on"))
	outputFormat := viper.GetString("output")
	isVerbose := viper.GetBool("verbose")

	// Validate --fail-on early so the user gets a clear usage error.
	threshold, err := parseSeverityThreshold(failOnArg)
	if err != nil {
		if cmd != nil {
			_ = cmd.Usage()
		}
		return err
	}

	// Count input sources: exactly one required.
	inputCount := 0
	if len(filesArg) > 0 {
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
		return errors.New("specify --file, --dir, or --cluster")
	}
	if inputCount > 1 {
		_ = cmd.Usage()
		return errors.New("--file, --dir, and --cluster are mutually exclusive")
	}

	var allObjects []runtime.Object

	if clusterArg {
		// Live-cluster mode: fetch all RBAC resources from the cluster.
		client, err := kubernetes.NewClient(kubeconfigArg, kubectxArg)
		if err != nil {
			return fmt.Errorf("cannot connect to cluster: %w", err)
		}
		allObjects, err = client.FetchAllRBACResources(context.Background())
		if err != nil {
			return fmt.Errorf("cannot fetch RBAC resources from cluster: %w", err)
		}
		if isVerbose {
			fmt.Fprintf(os.Stderr, "fetched %d object(s) from cluster\n", len(allObjects))
		}
	} else {
		// File/dir mode: collect file list then parse.
		var filesToProcess []string

		if len(filesArg) > 0 {
			filesToProcess = filesArg
		} else {
			err := filepath.Walk(directoryArg, func(path string, info os.FileInfo, err error) error {
				if err != nil {
					return err
				}
				if !info.IsDir() && (filepath.Ext(path) == ".yaml" || filepath.Ext(path) == ".yml") {
					filesToProcess = append(filesToProcess, path)
				}
				return nil
			})
			if err != nil {
				return fmt.Errorf("cannot read directory %q: %w", directoryArg, err)
			}
		}

		if len(filesToProcess) == 0 {
			return fmt.Errorf("no YAML files found in %q", directoryArg)
		}

		p := parser.New()
		parseFailures := 0

		for _, f := range filesToProcess {
			objects, err := p.ParseFile(f)
			if err != nil {
				parseFailures++
				if isVerbose {
					fmt.Fprintf(os.Stderr, "warning: skipping %q: %v\n", f, err)
				}
				continue
			}
			allObjects = append(allObjects, objects...)
		}

		if parseFailures > 0 && !isVerbose {
			fmt.Fprintf(os.Stderr, "warning: %d file(s) could not be parsed (run with --verbose for details)\n", parseFailures)
		}

		if isVerbose {
			fmt.Fprintf(os.Stderr, "parsed %d object(s) from %d file(s)\n", len(allObjects), len(filesToProcess)-parseFailures)
		}
	}

	if len(allObjects) == 0 {
		return errors.New("no valid RBAC resources found — check that the files contain Role, ClusterRole, RoleBinding, or ClusterRoleBinding objects")
	}

	// Validate.
	v := validator.New()
	findings := v.ValidateAll(allObjects)

	// Report.
	var format reporter.Format
	switch outputFormat {
	case "json":
		format = reporter.FormatJSON
	case "sarif":
		format = reporter.FormatSARIF
	default:
		format = reporter.FormatText
	}

	var w io.Writer = os.Stdout
	if cmd != nil {
		w = cmd.OutOrStdout()
	}

	if err := reporter.New(format).Report(findings, w); err != nil {
		return fmt.Errorf("failed to write report: %w", err)
	}

	// Non-zero exit based on --fail-on threshold.
	if threshold < 0 {
		return nil // "none" — never fail
	}
	for _, finding := range findings {
		if validator.SeverityRank[finding.Severity] >= threshold {
			return errors.New("validation failed: findings at or above the configured severity threshold")
		}
	}

	return nil
}

// parseSeverityThreshold converts the --fail-on string to a numeric rank.
// Returns -1 for "none" (never fail), 0 for "any" (fail on anything), or the
// SeverityRank value for named severities. Empty string defaults to "high".
// Returns an error for unknown values.
func parseSeverityThreshold(s string) (int, error) {
	switch s {
	case "none":
		return -1, nil
	case "any":
		return 0, nil
	case "info":
		return validator.SeverityRank[validator.SeverityInfo], nil
	case "low":
		return validator.SeverityRank[validator.SeverityLow], nil
	case "", "high":
		return validator.SeverityRank[validator.SeverityHigh], nil
	case "medium":
		return validator.SeverityRank[validator.SeverityMedium], nil
	case "critical":
		return validator.SeverityRank[validator.SeverityCritical], nil
	default:
		return 0, fmt.Errorf("--fail-on must be one of: none, any, info, low, medium, high, critical")
	}
}
