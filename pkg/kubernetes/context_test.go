package kubernetes

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/coolguy1771/guardrail/internal/testutil"
	"k8s.io/client-go/tools/clientcmd/api"
)

// createTestKubeconfig creates a temporary kubeconfig file for testing
func createTestKubeconfig(t *testing.T) (string, func()) {
	t.Helper()

	// Create a temporary directory
	tmpDir, err := os.MkdirTemp("", "kubeconfig-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}

	// Create kubeconfig path
	kubeconfigPath := filepath.Join(tmpDir, "config")

	// Create a test kubeconfig
	config := &api.Config{
		Kind:       "Config",
		APIVersion: "v1",
		Clusters: map[string]*api.Cluster{
			"test-cluster": {
				Server:                "https://test-cluster:6443",
				InsecureSkipTLSVerify: true,
			},
			"prod-cluster": {
				Server:                "https://prod-cluster:6443",
				InsecureSkipTLSVerify: true,
			},
		},
		Contexts: map[string]*api.Context{
			"test-context": {
				Cluster:  "test-cluster",
				AuthInfo: "test-user",
			},
			"prod-context": {
				Cluster:  "prod-cluster",
				AuthInfo: "prod-user",
			},
		},
		CurrentContext: "test-context",
		AuthInfos: map[string]*api.AuthInfo{
			"test-user": {
				Token: "test-token",
			},
			"prod-user": {
				Token: "prod-token",
			},
		},
	}

	// Write the config to file
	err = writeTestKubeconfig(*config, kubeconfigPath)
	if err != nil {
		t.Fatalf("Failed to write kubeconfig: %v", err)
	}

	// Return path and cleanup function
	cleanup := func() {
		os.RemoveAll(tmpDir)
	}

	return kubeconfigPath, cleanup
}

func TestLoadKubeConfig(t *testing.T) {
	t.Run("load from specific path", func(t *testing.T) {
		kubeconfigPath, cleanup := createTestKubeconfig(t)
		defer cleanup()

		config, err := loadKubeConfig(kubeconfigPath)
		testutil.AssertNil(t, err, "loadKubeConfig should not return error")
		testutil.AssertNotNil(t, config, "config should not be nil")
		testutil.AssertEqual(t, "test-context", config.CurrentContext, "current context")
		testutil.AssertEqual(t, 2, len(config.Contexts), "number of contexts")
		testutil.AssertEqual(t, 2, len(config.Clusters), "number of clusters")
	})

	t.Run("load from default path", func(t *testing.T) {
		// This will try to load from default locations
		// It may fail if no kubeconfig exists, which is expected in CI
		config, err := loadKubeConfig("")
		if err != nil {
			t.Logf("Expected error when no default kubeconfig exists: %v", err)
		} else {
			testutil.AssertNotNil(t, config, "config should not be nil if found")
		}
	})

	t.Run("load from non-existent path", func(t *testing.T) {
		config, err := loadKubeConfig("/non/existent/path/kubeconfig")
		// GetStartingConfig might return an empty config instead of an error
		if err == nil && config != nil {
			// If no error, we should get an empty or minimal config
			t.Log("Got config without error, checking if it's empty/minimal")
		} else if err != nil {
			t.Logf("Got expected error: %v", err)
		}
	})
}

func TestGetAvailableContexts(t *testing.T) {
	t.Run("get contexts from valid kubeconfig", func(t *testing.T) {
		kubeconfigPath, cleanup := createTestKubeconfig(t)
		defer cleanup()

		contexts, err := GetAvailableContexts(kubeconfigPath)
		testutil.AssertNil(t, err, "GetAvailableContexts should not return error")
		testutil.AssertEqual(t, 2, len(contexts), "number of contexts")

		// Check that both contexts are present (order may vary)
		contextMap := make(map[string]bool)
		for _, ctx := range contexts {
			contextMap[ctx] = true
		}

		if !contextMap["test-context"] {
			t.Error("test-context should be in the list")
		}
		if !contextMap["prod-context"] {
			t.Error("prod-context should be in the list")
		}
	})

	t.Run("get contexts from non-existent kubeconfig", func(t *testing.T) {
		contexts, err := GetAvailableContexts("/non/existent/path/kubeconfig")
		// GetStartingConfig might return an empty config instead of an error
		if err == nil {
			// If no error, we should get an empty context list
			testutil.AssertNotNil(t, contexts, "contexts should not be nil")
			t.Logf("Got %d contexts from non-existent kubeconfig", len(contexts))
		} else {
			testutil.AssertNil(t, contexts, "contexts should be nil on error")
			t.Logf("Got expected error: %v", err)
		}
	})

	t.Run("get contexts from empty path", func(t *testing.T) {
		// This will try default locations
		contexts, err := GetAvailableContexts("")
		if err != nil {
			t.Logf("Expected error when no default kubeconfig exists: %v", err)
		} else {
			testutil.AssertNotNil(t, contexts, "contexts should not be nil if kubeconfig found")
		}
	})
}

func TestBuildConfigWithContext(t *testing.T) {
	t.Run("build config without context override", func(t *testing.T) {
		kubeconfigPath, cleanup := createTestKubeconfig(t)
		defer cleanup()

		config, err := BuildConfigWithContext(kubeconfigPath, "")
		testutil.AssertNil(t, err, "BuildConfigWithContext should not return error")
		testutil.AssertNotNil(t, config, "config should not be nil")
		testutil.AssertEqual(t, "test-context", config.CurrentContext, "should keep original current context")
	})

	t.Run("build config with valid context override", func(t *testing.T) {
		kubeconfigPath, cleanup := createTestKubeconfig(t)
		defer cleanup()

		config, err := BuildConfigWithContext(kubeconfigPath, "prod-context")
		testutil.AssertNil(t, err, "BuildConfigWithContext should not return error")
		testutil.AssertNotNil(t, config, "config should not be nil")
		testutil.AssertEqual(t, "prod-context", config.CurrentContext, "should switch to prod context")
	})

	t.Run("build config with invalid context", func(t *testing.T) {
		kubeconfigPath, cleanup := createTestKubeconfig(t)
		defer cleanup()

		config, err := BuildConfigWithContext(kubeconfigPath, "non-existent-context")
		testutil.AssertNotNil(t, err, "should return error for non-existent context")
		if config != nil {
			t.Error("config should be nil on error")
		}

		// Check error message
		if err != nil {
			expectedError := "context 'non-existent-context' not found in kubeconfig"
			if err.Error() != expectedError {
				t.Errorf("Expected error message '%s', got '%s'", expectedError, err.Error())
			}
		}
	})

	t.Run("build config from non-existent kubeconfig", func(t *testing.T) {
		config, err := BuildConfigWithContext("/non/existent/path/kubeconfig", "test-context")
		// The behavior depends on the implementation - it might return an error or an empty config
		if err != nil {
			if config != nil {
				t.Error("config should be nil on error")
			}
			t.Logf("Got expected error: %v", err)
		} else {
			// If no error, the context check might fail
			t.Log("No error loading non-existent kubeconfig, might fail on context check")
		}
	})
}

// writeTestKubeconfig writes a test kubeconfig to a file
func writeTestKubeconfig(config api.Config, filename string) error {
	// For testing, we'll just create a minimal YAML-like content
	content := []byte(`apiVersion: v1
kind: Config
current-context: ` + config.CurrentContext + `
clusters:
`)
	for name, cluster := range config.Clusters {
		content = append(content, []byte("- name: "+name+"\n  cluster:\n    server: "+cluster.Server+"\n")...)
	}

	content = append(content, []byte("contexts:\n")...)
	for name, context := range config.Contexts {
		content = append(content, []byte("- name: "+name+"\n  context:\n    cluster: "+context.Cluster+"\n    user: "+context.AuthInfo+"\n")...)
	}

	content = append(content, []byte("users:\n")...)
	for name := range config.AuthInfos {
		content = append(content, []byte("- name: "+name+"\n  user:\n    token: <redacted>\n")...)
	}

	return os.WriteFile(filename, content, 0600)
}
