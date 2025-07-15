package kubernetes

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	rbacv1client "k8s.io/client-go/kubernetes/typed/rbac/v1"
)

// RBACReader provides read-only access to RBAC resources.
type RBACReader interface {
	// Roles returns a read-only interface for roles
	Roles(namespace string) rbacv1client.RoleInterface
	// RoleBindings returns a read-only interface for role bindings
	RoleBindings(namespace string) rbacv1client.RoleBindingInterface
	// ClusterRoles returns a read-only interface for cluster roles
	ClusterRoles() rbacv1client.ClusterRoleInterface
	// ClusterRoleBindings returns a read-only interface for cluster role bindings
	ClusterRoleBindings() rbacv1client.ClusterRoleBindingInterface
}

// rbacReaderImpl implements the RBACReader interface.
type rbacReaderImpl struct {
	rbacClient rbacv1client.RbacV1Interface
}

func (r *rbacReaderImpl) Roles(namespace string) rbacv1client.RoleInterface {
	return r.rbacClient.Roles(namespace)
}

func (r *rbacReaderImpl) RoleBindings(namespace string) rbacv1client.RoleBindingInterface {
	return r.rbacClient.RoleBindings(namespace)
}

func (r *rbacReaderImpl) ClusterRoles() rbacv1client.ClusterRoleInterface {
	return r.rbacClient.ClusterRoles()
}

func (r *rbacReaderImpl) ClusterRoleBindings() rbacv1client.ClusterRoleBindingInterface {
	return r.rbacClient.ClusterRoleBindings()
}

// Client provides methods to fetch RBAC resources from a Kubernetes cluster.
type Client struct {
	clientset kubernetes.Interface
}

// NewClient creates a new Client for interacting with a Kubernetes cluster using the specified kubeconfig file and context name.
// Returns an error if the configuration cannot be loaded or the client cannot be created.
func NewClient(kubeconfig string, contextName string) (*Client, error) {
	config, err := getConfigWithContext(kubeconfig, contextName)
	if err != nil {
		return nil, fmt.Errorf("failed to get kubernetes config: %w", err)
	}
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create kubernetes client: %w", err)
	}
	return &Client{
		clientset: clientset,
	}, nil
}

// NewClientFromConfig returns a new Client using the provided Kubernetes REST configuration.
// Returns an error if the clientset cannot be created.
func NewClientFromConfig(config *rest.Config) (*Client, error) {
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create kubernetes client: %w", err)
	}

	return &Client{
		clientset: clientset,
	}, nil
}

// GetRBACReader returns a read-only interface for RBAC operations.
func (c *Client) GetRBACReader() RBACReader {
	return &rbacReaderImpl{
		rbacClient: c.clientset.RbacV1(),
	}
}

// getConfigWithContext loads a Kubernetes REST config from the specified kubeconfig file, optionally overriding the current context.
// Returns the configured *rest.Config or an error if loading fails.
func getConfigWithContext(kubeconfig, contextName string) (*rest.Config, error) {
	//nolint:exhaustruct // Only ExplicitPath is needed for kubeconfig loading
	loadingRules := &clientcmd.ClientConfigLoadingRules{ExplicitPath: kubeconfig}
	//nolint:exhaustruct // Only CurrentContext is optionally set below
	configOverrides := &clientcmd.ConfigOverrides{}
	if contextName != "" {
		configOverrides.CurrentContext = contextName
	}
	clientConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loadingRules, configOverrides)
	return clientConfig.ClientConfig()
}

// FetchAllRBACResources fetches all RBAC resources from the cluster.
func (c *Client) FetchAllRBACResources(ctx context.Context) ([]runtime.Object, error) {
	var resources []runtime.Object

	// Fetch Roles
	roles, err := c.FetchRoles(ctx, "")
	if err != nil {
		return nil, fmt.Errorf("failed to fetch roles: %w", err)
	}
	resources = append(resources, roles...)

	// Fetch RoleBindings
	roleBindings, err := c.FetchRoleBindings(ctx, "")
	if err != nil {
		return nil, fmt.Errorf("failed to fetch role bindings: %w", err)
	}
	resources = append(resources, roleBindings...)

	// Fetch ClusterRoles
	clusterRoles, err := c.FetchClusterRoles(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch cluster roles: %w", err)
	}
	resources = append(resources, clusterRoles...)

	// Fetch ClusterRoleBindings
	clusterRoleBindings, err := c.FetchClusterRoleBindings(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch cluster role bindings: %w", err)
	}
	resources = append(resources, clusterRoleBindings...)

	return resources, nil
}

// FetchRoles fetches roles from a namespace (or all namespaces if namespace is empty).
func (c *Client) FetchRoles(ctx context.Context, namespace string) ([]runtime.Object, error) {
	var resources []runtime.Object

	roleList, err := c.clientset.RbacV1().
		Roles(namespace).
		List(ctx, metav1.ListOptions{}) //nolint:exhaustruct // K8s API struct
	if err != nil {
		return nil, err
	}

	for i := range roleList.Items {
		resources = append(resources, &roleList.Items[i])
	}

	return resources, nil
}

// FetchRoleBindings fetches role bindings from a namespace (or all namespaces if namespace is empty).
func (c *Client) FetchRoleBindings(ctx context.Context, namespace string) ([]runtime.Object, error) {
	var resources []runtime.Object

	roleBindingList, err := c.clientset.RbacV1().
		RoleBindings(namespace).
		List(ctx, metav1.ListOptions{}) //nolint:exhaustruct // K8s API struct
	if err != nil {
		return nil, err
	}

	for i := range roleBindingList.Items {
		resources = append(resources, &roleBindingList.Items[i])
	}

	return resources, nil
}

// FetchClusterRoles fetches all cluster roles.
func (c *Client) FetchClusterRoles(ctx context.Context) ([]runtime.Object, error) {
	var resources []runtime.Object

	clusterRoleList, err := c.clientset.RbacV1().
		ClusterRoles().
		List(ctx, metav1.ListOptions{}) //nolint:exhaustruct // K8s API struct
	if err != nil {
		return nil, err
	}

	for i := range clusterRoleList.Items {
		resources = append(resources, &clusterRoleList.Items[i])
	}

	return resources, nil
}

// FetchClusterRoleBindings fetches all cluster role bindings.
func (c *Client) FetchClusterRoleBindings(ctx context.Context) ([]runtime.Object, error) {
	var resources []runtime.Object

	clusterRoleBindingList, err := c.clientset.RbacV1().
		ClusterRoleBindings().
		List(ctx, metav1.ListOptions{}) //nolint:exhaustruct // K8s API struct
	if err != nil {
		return nil, err
	}

	for i := range clusterRoleBindingList.Items {
		resources = append(resources, &clusterRoleBindingList.Items[i])
	}

	return resources, nil
}

// FetchSpecificRole fetches a specific role.
func (c *Client) FetchSpecificRole(ctx context.Context, namespace, name string) (*rbacv1.Role, error) {
	return c.clientset.RbacV1().
		Roles(namespace).
		Get(ctx, name, metav1.GetOptions{}) //nolint:exhaustruct // K8s API struct
}

// FetchSpecificRoleBinding fetches a specific role binding.
func (c *Client) FetchSpecificRoleBinding(ctx context.Context, namespace, name string) (*rbacv1.RoleBinding, error) {
	return c.clientset.RbacV1().
		RoleBindings(namespace).
		Get(ctx, name, metav1.GetOptions{}) //nolint:exhaustruct // K8s API struct
}

// FetchSpecificClusterRole fetches a specific cluster role.
func (c *Client) FetchSpecificClusterRole(ctx context.Context, name string) (*rbacv1.ClusterRole, error) {
	return c.clientset.RbacV1().
		ClusterRoles().
		Get(ctx, name, metav1.GetOptions{}) //nolint:exhaustruct // K8s API struct
}

// FetchSpecificClusterRoleBinding fetches a specific cluster role binding.
func (c *Client) FetchSpecificClusterRoleBinding(ctx context.Context, name string) (*rbacv1.ClusterRoleBinding, error) {
	return c.clientset.RbacV1().
		ClusterRoleBindings().
		Get(ctx, name, metav1.GetOptions{}) //nolint:exhaustruct // K8s API struct
}
