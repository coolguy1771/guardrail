package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/coolguy1771/guardrail/pkg/reporter"
)

//nolint:gochecknoglobals // Set via -ldflags at build time
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

//nolint:gochecknoglobals // CLI flags need to be global for Cobra
var (
	cfgFile string
	verbose bool
)

//nolint:gochecknoglobals // Cobra commands must be global
var rootCmd = &cobra.Command{
	Use:   "guardrail",
	Short: "A Kubernetes RBAC validation tool",
	Long: `Guardrail is a Golang-based Kubernetes RBAC validation tool that helps teams
maintain secure, compliant, and well-structured RBAC configurations.`,
	// Don't print usage on every runtime error — only on actual flag/arg mistakes.
	SilenceUsage: true,
	// Cobra already prints "Error: <msg>" to stderr; suppress the duplicate.
	SilenceErrors: true,
	PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
		noColor, _ := cmd.Root().PersistentFlags().GetBool("no-color")
		_, noColorEnv := os.LookupEnv("NO_COLOR")
		if noColor || noColorEnv {
			reporter.UseColor = false
		}
		return nil
	},
}

// init registers the root command's persistent flags for config, output format, color control, and verbosity, and binds them to Viper for configuration management.
func init() {
	cobra.OnInitialize(initConfig)

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "Config file (default: $HOME/guardrail.yaml or /etc/guardrail/guardrail.yaml)")
	rootCmd.PersistentFlags().StringP("output", "o", "text", "Output format: text, json, sarif")
	rootCmd.PersistentFlags().Bool("no-color", false, "Disable colors and emoji in output (also: NO_COLOR env var)")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Print diagnostic messages (parsed files, skipped docs, config path)")

	_ = viper.BindPFlag("output", rootCmd.PersistentFlags().Lookup("output"))
	_ = viper.BindPFlag("no-color", rootCmd.PersistentFlags().Lookup("no-color"))
	_ = viper.BindPFlag("verbose", rootCmd.PersistentFlags().Lookup("verbose"))
}

// initConfig initializes the application's configuration system by loading Viper from a config file, the GUARDRAIL_CONFIG environment variable, or standard system paths as fallback. Environment variable overrides are enabled. The program exits with status 1 if the home directory lookup fails.
func initConfig() {
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else if envCfg := os.Getenv("GUARDRAIL_CONFIG"); envCfg != "" {
		viper.SetConfigFile(envCfg)
	} else {
		home, err := os.UserHomeDir()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: cannot determine home directory: %v\n", err)
			os.Exit(1)
		}
		viper.AddConfigPath("/etc/guardrail")
		viper.AddConfigPath(home)
		viper.AddConfigPath(".")
		viper.SetConfigType("yaml")
		viper.SetConfigName("guardrail")
	}

	viper.AutomaticEnv()

	if err := viper.ReadInConfig(); err == nil {
		if verbose {
			fmt.Fprintln(os.Stderr, "config:", viper.ConfigFileUsed())
		}
	}
}

// Main initializes the reporter version and executes the root CLI command, exiting with status 1 if execution fails.
func main() {
	reporter.Version = version
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
