package analyzer

import (
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// BuiltinClusterRoles holds simplified policy rules for the default Kubernetes ClusterRoles.
// They are injected into the role map so that bindings to built-in roles produce meaningful
// risk assessments even when the ClusterRole manifests are not in the analyzed file set.
//
// Rules are intentionally simplified — they capture the security-relevant grants without
// replicating every aggregation label from the upstream Kubernetes source.
//
//nolint:gochecknoglobals // Package-level registry intentionally shared across analysis paths
var BuiltinClusterRoles = map[string]*rbacv1.ClusterRole{
	"cluster-admin": {
		ObjectMeta: metav1.ObjectMeta{Name: "cluster-admin"},
		Rules: []rbacv1.PolicyRule{
			{Verbs: []string{"*"}, APIGroups: []string{"*"}, Resources: []string{"*"}},
			{Verbs: []string{"*"}, NonResourceURLs: []string{"*"}},
		},
	},
	"admin": {
		ObjectMeta: metav1.ObjectMeta{Name: "admin"},
		Rules: []rbacv1.PolicyRule{
			{
				Verbs:     []string{"*"},
				APIGroups: []string{"", "apps", "batch", "extensions", "networking.k8s.io"},
				Resources: []string{
					"pods", "pods/exec", "pods/log", "pods/portforward",
					"services", "endpoints",
					"deployments", "replicasets", "statefulsets", "daemonsets",
					"jobs", "cronjobs",
					"configmaps", "persistentvolumeclaims", "serviceaccounts",
					"ingresses",
				},
			},
			// Role management within the namespace (privilege escalation risk)
			{
				Verbs:     []string{"*"},
				APIGroups: []string{"rbac.authorization.k8s.io"},
				Resources: []string{"roles", "rolebindings"},
			},
			// Read-only secrets (admin cannot write secrets by default)
			{
				Verbs:     []string{"get", "list", "watch"},
				APIGroups: []string{""},
				Resources: []string{"secrets"},
			},
		},
	},
	"edit": {
		ObjectMeta: metav1.ObjectMeta{Name: "edit"},
		Rules: []rbacv1.PolicyRule{
			{
				Verbs:     []string{"get", "list", "watch", "create", "update", "patch", "delete"},
				APIGroups: []string{"", "apps", "batch", "extensions", "networking.k8s.io"},
				Resources: []string{
					"pods", "pods/exec", "pods/log", "pods/portforward",
					"services", "endpoints",
					"deployments", "replicasets", "statefulsets", "daemonsets",
					"jobs", "cronjobs",
					"configmaps", "persistentvolumeclaims",
					"ingresses",
				},
			},
		},
	},
	"view": {
		ObjectMeta: metav1.ObjectMeta{Name: "view"},
		Rules: []rbacv1.PolicyRule{
			{
				Verbs:     []string{"get", "list", "watch"},
				APIGroups: []string{"", "apps", "batch", "extensions", "networking.k8s.io"},
				Resources: []string{
					"pods", "pods/log",
					"services", "endpoints",
					"deployments", "replicasets", "statefulsets", "daemonsets",
					"jobs", "cronjobs",
					"configmaps",
					"ingresses",
				},
			},
		},
	},
}
