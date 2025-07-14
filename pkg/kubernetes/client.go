package kubernetes

import (
	"context"
	"fmt"
	"path/filepath"

	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
)

// Client provides methods to fetch RBAC resources from a Kubernetes cluster
type Client struct {
	clientset kubernetes.Interface
}

// NewClient creates a new Kubernetes client
func NewClient(kubeconfig string) (*Client, error) {
	config, err := getConfig(kubeconfig)
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

// NewClientFromConfig creates a new Kubernetes client from rest.Config
func NewClientFromConfig(config *rest.Config) (*Client, error) {
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create kubernetes client: %w", err)
	}
	
	return &Client{
		clientset: clientset,
	}, nil
}

// GetClientset returns the underlying Kubernetes clientset
func (c *Client) GetClientset() kubernetes.Interface {
	return c.clientset
}

// getConfig returns a kubernetes config
func getConfig(kubeconfig string) (*rest.Config, error) {
	// If running in-cluster
	if kubeconfig == "" {
		config, err := rest.InClusterConfig()
		if err == nil {
			return config, nil
		}
		// If in-cluster config fails, try default kubeconfig
		if home := homedir.HomeDir(); home != "" {
			kubeconfig = filepath.Join(home, ".kube", "config")
		}
	}
	
	// Use the kubeconfig file
	config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		return nil, err
	}
	
	return config, nil
}

// FetchAllRBACResources fetches all RBAC resources from the cluster
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

// FetchRoles fetches roles from a namespace (or all namespaces if namespace is empty)
func (c *Client) FetchRoles(ctx context.Context, namespace string) ([]runtime.Object, error) {
	var resources []runtime.Object
	
	roleList, err := c.clientset.RbacV1().Roles(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	
	for i := range roleList.Items {
		resources = append(resources, &roleList.Items[i])
	}
	
	return resources, nil
}

// FetchRoleBindings fetches role bindings from a namespace (or all namespaces if namespace is empty)
func (c *Client) FetchRoleBindings(ctx context.Context, namespace string) ([]runtime.Object, error) {
	var resources []runtime.Object
	
	roleBindingList, err := c.clientset.RbacV1().RoleBindings(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	
	for i := range roleBindingList.Items {
		resources = append(resources, &roleBindingList.Items[i])
	}
	
	return resources, nil
}

// FetchClusterRoles fetches all cluster roles
func (c *Client) FetchClusterRoles(ctx context.Context) ([]runtime.Object, error) {
	var resources []runtime.Object
	
	clusterRoleList, err := c.clientset.RbacV1().ClusterRoles().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	
	for i := range clusterRoleList.Items {
		resources = append(resources, &clusterRoleList.Items[i])
	}
	
	return resources, nil
}

// FetchClusterRoleBindings fetches all cluster role bindings
func (c *Client) FetchClusterRoleBindings(ctx context.Context) ([]runtime.Object, error) {
	var resources []runtime.Object
	
	clusterRoleBindingList, err := c.clientset.RbacV1().ClusterRoleBindings().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	
	for i := range clusterRoleBindingList.Items {
		resources = append(resources, &clusterRoleBindingList.Items[i])
	}
	
	return resources, nil
}

// FetchSpecificRole fetches a specific role
func (c *Client) FetchSpecificRole(ctx context.Context, namespace, name string) (*rbacv1.Role, error) {
	return c.clientset.RbacV1().Roles(namespace).Get(ctx, name, metav1.GetOptions{})
}

// FetchSpecificRoleBinding fetches a specific role binding
func (c *Client) FetchSpecificRoleBinding(ctx context.Context, namespace, name string) (*rbacv1.RoleBinding, error) {
	return c.clientset.RbacV1().RoleBindings(namespace).Get(ctx, name, metav1.GetOptions{})
}

// FetchSpecificClusterRole fetches a specific cluster role
func (c *Client) FetchSpecificClusterRole(ctx context.Context, name string) (*rbacv1.ClusterRole, error) {
	return c.clientset.RbacV1().ClusterRoles().Get(ctx, name, metav1.GetOptions{})
}

// FetchSpecificClusterRoleBinding fetches a specific cluster role binding
func (c *Client) FetchSpecificClusterRoleBinding(ctx context.Context, name string) (*rbacv1.ClusterRoleBinding, error) {
	return c.clientset.RbacV1().ClusterRoleBindings().Get(ctx, name, metav1.GetOptions{})
}