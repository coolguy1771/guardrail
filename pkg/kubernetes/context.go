package kubernetes

import (
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/clientcmd/api"
)

// GetAvailableContexts returns a list of available contexts in the kubeconfig file
func GetAvailableContexts(kubeconfig string) ([]string, error) {
	configAccess := clientcmd.NewDefaultPathOptions()
	if kubeconfig != "" {
		configAccess.GlobalFile = kubeconfig
	}
	config, err := configAccess.GetStartingConfig()
	if err != nil {
		return nil, err
	}
	contexts := make([]string, 0, len(config.Contexts))
	for name := range config.Contexts {
		contexts = append(contexts, name)
	}
	return contexts, nil
}

// BuildConfigWithContext builds a rest.Config for a specific context
func BuildConfigWithContext(kubeconfig, context string) (*api.Config, error) {
	configAccess := clientcmd.NewDefaultPathOptions()
	if kubeconfig != "" {
		configAccess.GlobalFile = kubeconfig
	}
	config, err := configAccess.GetStartingConfig()
	if err != nil {
		return nil, err
	}
	if context != "" {
		config.CurrentContext = context
	}
	return config, nil
}
