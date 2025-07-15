package kubernetes

import (
	"fmt"

	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/clientcmd/api"
)

// loadKubeConfig loads a Kubernetes kubeconfig file from the specified path or the default location if no path is provided.
// It returns the parsed configuration object or an error if loading fails.
func loadKubeConfig(kubeconfig string) (*api.Config, error) {
	configAccess := clientcmd.NewDefaultPathOptions()
	if kubeconfig != "" {
		configAccess.GlobalFile = kubeconfig
	}
	return configAccess.GetStartingConfig()
}

// GetAvailableContexts retrieves the names of all contexts defined in the specified kubeconfig file.
// Returns a slice of context names or an error if the kubeconfig cannot be loaded.
func GetAvailableContexts(kubeconfig string) ([]string, error) {
	config, err := loadKubeConfig(kubeconfig)
	if err != nil {
		return nil, err
	}
	contexts := make([]string, 0, len(config.Contexts))
	for name := range config.Contexts {
		contexts = append(contexts, name)
	}
	return contexts, nil
}

// BuildConfigWithContext loads a kubeconfig file and sets the current context to the specified value if provided.
// Returns the loaded config with the current context set, or an error if loading fails or the context does not exist.
func BuildConfigWithContext(kubeconfig, context string) (*api.Config, error) {
	config, err := loadKubeConfig(kubeconfig)
	if err != nil {
		return nil, err
	}
	if context != "" {
		if _, ok := config.Contexts[context]; !ok {
			return nil, fmt.Errorf("context '%s' not found in kubeconfig", context)
		}
		config.CurrentContext = context
	}
	return config, nil
}
