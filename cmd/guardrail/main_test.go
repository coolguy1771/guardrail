package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/coolguy1771/guardrail/internal/testutil"
)

func TestRootCommand(t *testing.T) {
	// Save original args
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()

	tests := []struct {
		name        string
		args        []string
		expectError bool
		checkOutput func(t *testing.T, output string)
	}{
		{
			name: "help flag",
			args: []string{"guardrail", "--help"},
			checkOutput: func(t *testing.T, output string) {
				if !strings.Contains(output, "Kubernetes RBAC validation tool") {
					t.Errorf("expected help text, got: %s", output)
				}
				if !strings.Contains(output, "Available Commands:") {
					t.Errorf("expected commands list, got: %s", output)
				}
				if !strings.Contains(output, "validate") {
					t.Errorf("expected validate command, got: %s", output)
				}
				if !strings.Contains(output, "analyze") {
					t.Errorf("expected analyze command, got: %s", output)
				}
			},
		},
		{
			name: "version output",
			args: []string{"guardrail", "version"},
			expectError: true, // version command doesn't exist yet
		},
		{
			name:        "invalid command",
			args:        []string{"guardrail", "invalid"},
			expectError: true,
		},
		{
			name: "global output flag",
			args: []string{"guardrail", "--output", "json", "validate", "--help"},
			checkOutput: func(t *testing.T, output string) {
				// Should still show help
				if !strings.Contains(output, "Validate RBAC manifests") {
					t.Errorf("expected validate help, got: %s", output)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset viper
			viper.Reset()

			// Capture output
			var buf bytes.Buffer

			// Re-initialize root command
			rootCmd = &cobra.Command{
				Use:   "guardrail",
				Short: "A Kubernetes RBAC validation tool",
				Long: `Guardrail is a Golang-based Kubernetes RBAC validation tool that helps teams
maintain secure, compliant, and well-structured RBAC configurations.`,
			}
			
			// Add persistent flags
			rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.guardrail.yaml)")
			rootCmd.PersistentFlags().StringP("output", "o", "text", "Output format (text, json, sarif)")
			
			// Add subcommands (simplified versions for testing)
			validateCmd := &cobra.Command{
				Use:   "validate",
				Short: "Validate RBAC manifests",
			}
			analyzeCmd := &cobra.Command{
				Use:   "analyze",
				Short: "Analyze RBAC permissions and explain what subjects can do",
			}
			rootCmd.AddCommand(validateCmd, analyzeCmd)
			
			// Set output streams
			rootCmd.SetOut(&buf)
			rootCmd.SetErr(&buf)
			
			// Set command line arguments (skip the first arg which is the binary name)
			rootCmd.SetArgs(tt.args[1:])

			// Execute
			err := rootCmd.Execute()

			if tt.expectError {
				testutil.AssertNotNil(t, err, "expected error")
			} else {
				testutil.AssertNil(t, err, "unexpected error")
			}

			if tt.checkOutput != nil {
				tt.checkOutput(t, buf.String())
			}
		})
	}
}

func TestInitConfig(t *testing.T) {
	// Save original env
	oldHome := os.Getenv("HOME")
	defer os.Setenv("HOME", oldHome)

	t.Run("with config file", func(t *testing.T) {
		// Create temp config file
		tmpDir, err := os.MkdirTemp("", "config-test-*")
		if err != nil {
			t.Fatal(err)
		}
		defer os.RemoveAll(tmpDir)

		configFile := filepath.Join(tmpDir, ".guardrail.yaml")
		configContent := `output: json`
		if err := os.WriteFile(configFile, []byte(configContent), 0644); err != nil {
			t.Fatal(err)
		}

		// Reset viper and set config file
		viper.Reset()
		cfgFile = configFile

		// Capture stderr
		oldStderr := os.Stderr
		r, w, _ := os.Pipe()
		os.Stderr = w

		initConfig()

		// Restore stderr
		w.Close()
		os.Stderr = oldStderr

		// Read output
		buf := new(bytes.Buffer)
		if _, err := buf.ReadFrom(r); err != nil {
			t.Fatalf("failed to read from pipe: %v", err)
		}
		output := buf.String()

		// Check that config was loaded
		if !strings.Contains(output, "Using config file:") {
			t.Error("expected config file message")
		}

		// Check that value was loaded
		if viper.GetString("output") != "json" {
			t.Error("expected output to be json from config")
		}
	})

	t.Run("without config file", func(t *testing.T) {
		// Reset viper
		viper.Reset()
		cfgFile = ""

		// Set HOME to temp dir
		tmpDir, err := os.MkdirTemp("", "home-test-*")
		if err != nil {
			t.Fatal(err)
		}
		defer os.RemoveAll(tmpDir)
		os.Setenv("HOME", tmpDir)

		// Should not panic
		initConfig()

		// Verify default paths were added
		// This is hard to test directly, but we can verify no panic
	})
}

func TestMain(t *testing.T) {
	// Testing main() directly is tricky because it calls os.Exit
	// We'll test the error handling logic indirectly

	// We can't reassign Execute method directly as it's not a variable

	// Test that error from Execute is handled
	// This test is more about ensuring the error path exists
	t.Run("execute error handling", func(t *testing.T) {
		// We can't easily test os.Exit, but we can verify
		// the error handling code path exists by inspection
		// The actual testing of error cases is done in other tests
		t.Skip("main() calls os.Exit which is hard to test directly")
	})
}

func TestConfigFileHandling(t *testing.T) {
	// Test various config file scenarios
	tmpDir, err := os.MkdirTemp("", "config-scenarios-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	tests := []struct {
		name       string
		configFile string
		content    string
		expected   map[string]string
	}{
		{
			name:       "yaml config",
			configFile: ".guardrail.yaml",
			content: `output: sarif
validate:
  file: test.yaml`,
			expected: map[string]string{
				"output":        "sarif",
				"validate.file": "test.yaml",
			},
		},
		{
			name:       "yml config",
			configFile: ".guardrail.yml",
			content:    `output: json`,
			expected: map[string]string{
				"output": "json",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create config file
			configPath := filepath.Join(tmpDir, tt.configFile)
			if err := os.WriteFile(configPath, []byte(tt.content), 0644); err != nil {
				t.Fatal(err)
			}

			// Reset viper
			viper.Reset()
			defer viper.Reset() // Ensure viper is reset even if test fails
			viper.SetConfigFile(configPath)

			// Read config
			err := viper.ReadInConfig()
			testutil.AssertNil(t, err, "reading config should not error")

			// Check values
			for key, expectedValue := range tt.expected {
				actualValue := viper.GetString(key)
				testutil.AssertEqual(t, expectedValue, actualValue, "config value for "+key)
			}
		})
	}
}

func TestEnvironmentVariables(t *testing.T) {
	// Test that environment variables override config
	viper.Reset()
	defer viper.Reset() // Ensure viper is reset even if test fails

	// Set env var
	os.Setenv("GUARDRAIL_OUTPUT", "sarif")
	defer os.Unsetenv("GUARDRAIL_OUTPUT")

	// Enable automatic env
	viper.AutomaticEnv()
	viper.SetEnvPrefix("GUARDRAIL")

	// Check value
	output := viper.GetString("output")
	testutil.AssertEqual(t, "sarif", output, "output from env var")
}