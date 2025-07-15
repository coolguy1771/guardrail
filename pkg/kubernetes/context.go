package kubernetes

import (
	"fmt"

	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/clientcmd/api"
)

// loadKubeConfig loads the kubeconfig and returns the config object
func loadKubeConfig(kubeconfig string) (*api.Config, error) {
	configAccess := clientcmd.NewDefaultPathOptions()
	if kubeconfig != "" {
		configAccess.GlobalFile = kubeconfig
	}
	return configAccess.GetStartingConfig()
}

// GetAvailableContexts returns a list of available contexts in the kubeconfig file
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

// BuildConfigWithContext returns an *api.Config for a specific context
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
