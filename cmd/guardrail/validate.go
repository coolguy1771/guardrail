package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/coolguy1771/guardrail/pkg/parser"
	"github.com/coolguy1771/guardrail/pkg/reporter"
	"github.com/coolguy1771/guardrail/pkg/validator"
)

//nolint:gochecknoglobals // CLI flags need to be global for Cobra
var (
	files     []string
	directory string
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
		StringSliceVarP(&files, "file", "f", []string{}, "Path to RBAC manifest file(s) (can be specified multiple times)")
	validateCmd.Flags().StringVarP(&directory, "dir", "d", "", "Path to a directory containing RBAC manifests")

	_ = viper.BindPFlag("files", validateCmd.Flags().Lookup("file"))
	_ = viper.BindPFlag("directory", validateCmd.Flags().Lookup("dir"))
}

//nolint:gocognit // Validation logic requires handling multiple cases
func runValidate(cmd *cobra.Command, _ []string) error {
	filesArg := viper.GetStringSlice("files")
	directoryArg := viper.GetString("directory")
	outputFormat := viper.GetString("output")

	if len(filesArg) == 0 && directoryArg == "" {
		return errors.New("either --file or --dir must be specified")
	}

	if len(filesArg) > 0 && directoryArg != "" {
		return errors.New("cannot specify both --file and --dir")
	}

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
			return fmt.Errorf("error walking directory: %w", err)
		}
	}

	if len(filesToProcess) == 0 {
		return errors.New("no YAML files found")
	}

	// Create parser
	p := parser.New()

	// Parse all files
	var allObjects []runtime.Object
	for _, f := range filesToProcess {
		objects, err := p.ParseFile(f)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: Failed to parse %s: %v\n", f, err)
			continue
		}
		allObjects = append(allObjects, objects...)
	}

	if len(allObjects) == 0 {
		return errors.New("no valid RBAC resources found in the provided files")
	}

	// Create validator
	v := validator.New()

	// Validate all objects
	findings := v.ValidateAll(allObjects)

	// Create reporter based on output format
	var format reporter.Format
	switch outputFormat {
	case "json":
		format = reporter.FormatJSON
	case "sarif":
		format = reporter.FormatSARIF
	default:
		format = reporter.FormatText
	}

	r := reporter.New(format)

	// Get output writer
	var writer io.Writer = os.Stdout
	if cmd != nil {
		writer = cmd.OutOrStdout()
	}

	// Report findings
	if err := r.Report(findings, writer); err != nil {
		return fmt.Errorf("failed to report findings: %w", err)
	}

	// Return error if high severity findings exist (for proper exit code)
	for _, finding := range findings {
		if finding.Severity == validator.SeverityHigh {
			return errors.New("validation failed: found high severity issues")
		}
	}

	return nil
}
