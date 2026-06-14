package main

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

//nolint:gochecknoglobals // Cobra commands must be global
var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version information",
	Long:  `Print the version, commit hash, and build date of this binary.`,
	RunE:  runVersion,
}

//nolint:gochecknoinits // Cobra requires init for command registration
func init() {
	rootCmd.AddCommand(versionCmd)
}

type versionInfo struct {
	Version string `json:"version"`
	Commit  string `json:"commit"`
	Date    string `json:"date"`
}

func runVersion(cmd *cobra.Command, _ []string) error {
	info := versionInfo{
		Version: version,
		Commit:  commit,
		Date:    date,
	}

	var w io.Writer = cmd.OutOrStdout()

	if viper.GetString("output") == "json" {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(info)
	}

	fmt.Fprintf(w, "guardrail %s\n", info.Version)
	if info.Commit != "none" && info.Commit != "" {
		fmt.Fprintf(w, "  commit: %s\n", info.Commit)
	}
	if info.Date != "unknown" && info.Date != "" {
		fmt.Fprintf(w, "  built:  %s\n", info.Date)
	}
	return nil
}
