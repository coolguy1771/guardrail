package validator //nolint:testpackage // Uses internal validator fields for testing

import (
	"testing"

	"k8s.io/apimachinery/pkg/runtime"

	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/coolguy1771/guardrail/internal/testutil"
)

func TestValidateServiceAccountTokens(t *testing.T) {
	tests := []struct {
		name          string
		object        runtime.Object
		expectedCount int
	}{
		{
			name: "service account bound to cluster-admin",
			object: &rbacv1.ClusterRoleBinding{
				ObjectMeta: metav1.ObjectMeta{Name: "sa-cluster-admin"},
				RoleRef: rbacv1.RoleRef{
					Kind:     "ClusterRole",
					Name:     "cluster-admin",
					APIGroup: "rbac.authorization.k8s.io",
				},
				Subjects: []rbacv1.Subject{
					{
						Kind:      "ServiceAccount",
						Name:      "high-priv-sa",
						Namespace: "default",
					},
				},
			},
			expectedCount: 1,
		},
		{
			name: "service account bound to admin role",
			object: &rbacv1.RoleBinding{
				ObjectMeta: metav1.ObjectMeta{Name: "sa-admin", Namespace: "default"},
				RoleRef: rbacv1.RoleRef{
					Kind:     "Role",
					Name:     "admin",
					APIGroup: "rbac.authorization.k8s.io",
				},
				Subjects: []rbacv1.Subject{
					{
						Kind:      "ServiceAccount",
						Name:      "admin-sa",
						Namespace: "default",
					},
				},
			},
			expectedCount: 1,
		},
		{
			name: "user bound to admin role (not SA)",
			object: &rbacv1.RoleBinding{
				ObjectMeta: metav1.ObjectMeta{Name: "user-admin", Namespace: "default"},
				RoleRef: rbacv1.RoleRef{
					Kind:     "Role",
					Name:     "admin",
					APIGroup: "rbac.authorization.k8s.io",
				},
				Subjects: []rbacv1.Subject{
					{
						Kind: "User",
						Name: "alice",
					},
				},
			},
			expectedCount: 0,
		},
		{
			name: "service account with safe role",
			object: &rbacv1.RoleBinding{
				ObjectMeta: metav1.ObjectMeta{Name: "sa-view", Namespace: "default"},
				RoleRef: rbacv1.RoleRef{
					Kind:     "ClusterRole",
					Name:     "view",
					APIGroup: "rbac.authorization.k8s.io",
				},
				Subjects: []rbacv1.Subject{
					{
						Kind:      "ServiceAccount",
						Name:      "readonly-sa",
						Namespace: "default",
					},
				},
			},
			expectedCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := validateServiceAccountTokens(tt.object)
			testutil.AssertEqual(t, tt.expectedCount, len(findings), "unexpected number of findings")

			if tt.expectedCount > 0 && len(findings) > 0 {
				testutil.AssertEqual(t, "RBAC005", findings[0].RuleID, "unexpected rule ID")
				testutil.AssertEqual(t, SeverityMedium, findings[0].Severity, "unexpected severity")
			}
		})
	}
}

func TestValidateExecAttachPermissions(t *testing.T) {
	tests := []struct {
		name          string
		object        runtime.Object
		expectedCount int
	}{
		{
			name: "role with pods/exec permission",
			object: &rbacv1.Role{
				ObjectMeta: metav1.ObjectMeta{Name: "exec-role", Namespace: "default"},
				Rules: []rbacv1.PolicyRule{
					{
						APIGroups: []string{""},
						Resources: []string{"pods/exec"},
						Verbs:     []string{"create"},
					},
				},
			},
			expectedCount: 1,
		},
		{
			name: "clusterrole with pods/attach permission",
			object: &rbacv1.ClusterRole{
				ObjectMeta: metav1.ObjectMeta{Name: "attach-role"},
				Rules: []rbacv1.PolicyRule{
					{
						APIGroups: []string{""},
						Resources: []string{"pods/attach"},
						Verbs:     []string{"*"},
					},
				},
			},
			expectedCount: 1,
		},
		{
			name: "role with both exec and attach",
			object: &rbacv1.Role{
				ObjectMeta: metav1.ObjectMeta{Name: "exec-attach-role", Namespace: "default"},
				Rules: []rbacv1.PolicyRule{
					{
						APIGroups: []string{""},
						Resources: []string{"pods/exec", "pods/attach"},
						Verbs:     []string{"create"},
					},
				},
			},
			expectedCount: 2,
		},
		{
			name: "role with only get permission on exec",
			object: &rbacv1.Role{
				ObjectMeta: metav1.ObjectMeta{Name: "safe-exec-role", Namespace: "default"},
				Rules: []rbacv1.PolicyRule{
					{
						APIGroups: []string{""},
						Resources: []string{"pods/exec"},
						Verbs:     []string{"get", "list"},
					},
				},
			},
			expectedCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := validateExecAttachPermissions(tt.object)
			testutil.AssertEqual(t, tt.expectedCount, len(findings), "unexpected number of findings")

			if tt.expectedCount > 0 && len(findings) > 0 {
				testutil.AssertEqual(t, "RBAC006", findings[0].RuleID, "unexpected rule ID")
				testutil.AssertEqual(t, SeverityHigh, findings[0].Severity, "unexpected severity")
			}
		})
	}
}

func TestValidateImpersonationPrivileges(t *testing.T) {
	tests := []struct {
		name          string
		object        runtime.Object
		expectedCount int
	}{
		{
			name: "role with user impersonation",
			object: &rbacv1.Role{
				ObjectMeta: metav1.ObjectMeta{Name: "impersonate-role", Namespace: "default"},
				Rules: []rbacv1.PolicyRule{
					{
						APIGroups: []string{""},
						Resources: []string{"users"},
						Verbs:     []string{"impersonate"},
					},
				},
			},
			expectedCount: 1,
		},
		{
			name: "clusterrole with wildcard verb including impersonate",
			object: &rbacv1.ClusterRole{
				ObjectMeta: metav1.ObjectMeta{Name: "wildcard-impersonate"},
				Rules: []rbacv1.PolicyRule{
					{
						APIGroups: []string{""},
						Resources: []string{"groups"},
						Verbs:     []string{"*"},
					},
				},
			},
			expectedCount: 1,
		},
		{
			name: "role with multiple impersonation resources",
			object: &rbacv1.Role{
				ObjectMeta: metav1.ObjectMeta{Name: "multi-impersonate", Namespace: "default"},
				Rules: []rbacv1.PolicyRule{
					{
						APIGroups: []string{""},
						Resources: []string{"users", "groups", "serviceaccounts"},
						Verbs:     []string{"impersonate"},
					},
				},
			},
			expectedCount: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := validateImpersonationPrivileges(tt.object)
			testutil.AssertEqual(t, tt.expectedCount, len(findings), "unexpected number of findings")

			if tt.expectedCount > 0 && len(findings) > 0 {
				testutil.AssertEqual(t, "RBAC007", findings[0].RuleID, "unexpected rule ID")
				testutil.AssertEqual(t, SeverityHigh, findings[0].Severity, "unexpected severity")
			}
		})
	}
}

func TestValidateEscalateBindVerbs(t *testing.T) {
	tests := []struct {
		name          string
		object        runtime.Object
		expectedCount int
	}{
		{
			name: "role with escalate verb",
			object: &rbacv1.Role{
				ObjectMeta: metav1.ObjectMeta{Name: "escalate-role", Namespace: "default"},
				Rules: []rbacv1.PolicyRule{
					{
						APIGroups: []string{"rbac.authorization.k8s.io"},
						Resources: []string{"roles"},
						Verbs:     []string{"escalate"},
					},
				},
			},
			expectedCount: 1,
		},
		{
			name: "clusterrole with bind verb on clusterroles",
			object: &rbacv1.ClusterRole{
				ObjectMeta: metav1.ObjectMeta{Name: "bind-role"},
				Rules: []rbacv1.PolicyRule{
					{
						APIGroups: []string{"rbac.authorization.k8s.io"},
						Resources: []string{"clusterroles"},
						Verbs:     []string{"bind"},
					},
				},
			},
			expectedCount: 1,
		},
		{
			name: "role with both escalate and bind on multiple resources",
			object: &rbacv1.Role{
				ObjectMeta: metav1.ObjectMeta{Name: "escalate-bind-role", Namespace: "default"},
				Rules: []rbacv1.PolicyRule{
					{
						APIGroups: []string{"rbac.authorization.k8s.io"},
						Resources: []string{"roles", "rolebindings"},
						Verbs:     []string{"escalate", "bind"},
					},
				},
			},
			expectedCount: 4, // 2 resources x 2 verbs
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := validateEscalateBindVerbs(tt.object)
			testutil.AssertEqual(t, tt.expectedCount, len(findings), "unexpected number of findings")

			if tt.expectedCount > 0 && len(findings) > 0 {
				testutil.AssertEqual(t, "RBAC008", findings[0].RuleID, "unexpected rule ID")
				testutil.AssertEqual(t, SeverityHigh, findings[0].Severity, "unexpected severity")
			}
		})
	}
}

func TestValidatePrivilegedContainerAccess(t *testing.T) {
	tests := []struct {
		name          string
		object        runtime.Object
		expectedCount int
	}{
		{
			name: "role with PSP use permission",
			object: &rbacv1.Role{
				ObjectMeta: metav1.ObjectMeta{Name: "psp-role", Namespace: "default"},
				Rules: []rbacv1.PolicyRule{
					{
						APIGroups: []string{"policy"},
						Resources: []string{"podsecuritypolicies"},
						Verbs:     []string{"use"},
					},
				},
			},
			expectedCount: 1,
		},
		{
			name: "clusterrole with SCC wildcard permission",
			object: &rbacv1.ClusterRole{
				ObjectMeta: metav1.ObjectMeta{Name: "scc-role"},
				Rules: []rbacv1.PolicyRule{
					{
						APIGroups: []string{"security.openshift.io"},
						Resources: []string{"securitycontextconstraints"},
						Verbs:     []string{"*"},
					},
				},
			},
			expectedCount: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := validatePrivilegedContainerAccess(tt.object)
			testutil.AssertEqual(t, tt.expectedCount, len(findings), "unexpected number of findings")

			if tt.expectedCount > 0 && len(findings) > 0 {
				testutil.AssertEqual(t, "RBAC009", findings[0].RuleID, "unexpected rule ID")
				testutil.AssertEqual(t, SeverityHigh, findings[0].Severity, "unexpected severity")
			}
		})
	}
}

func TestValidateNodePVAccess(t *testing.T) {
	tests := []struct {
		name          string
		object        runtime.Object
		expectedCount int
	}{
		{
			name: "role with node update permission",
			object: &rbacv1.Role{
				ObjectMeta: metav1.ObjectMeta{Name: "node-role", Namespace: "default"},
				Rules: []rbacv1.PolicyRule{
					{
						APIGroups: []string{""},
						Resources: []string{"nodes"},
						Verbs:     []string{"update", "patch"},
					},
				},
			},
			expectedCount: 2,
		},
		{
			name: "clusterrole with PV delete permission",
			object: &rbacv1.ClusterRole{
				ObjectMeta: metav1.ObjectMeta{Name: "pv-role"},
				Rules: []rbacv1.PolicyRule{
					{
						APIGroups: []string{""},
						Resources: []string{"persistentvolumes"},
						Verbs:     []string{"delete"},
					},
				},
			},
			expectedCount: 1,
		},
		{
			name: "role with node/proxy wildcard",
			object: &rbacv1.Role{
				ObjectMeta: metav1.ObjectMeta{Name: "node-proxy-role", Namespace: "default"},
				Rules: []rbacv1.PolicyRule{
					{
						APIGroups: []string{""},
						Resources: []string{"nodes/proxy"},
						Verbs:     []string{"*"},
					},
				},
			},
			expectedCount: 1,
		},
		{
			name: "role with only read permissions on nodes",
			object: &rbacv1.Role{
				ObjectMeta: metav1.ObjectMeta{Name: "node-read-role", Namespace: "default"},
				Rules: []rbacv1.PolicyRule{
					{
						APIGroups: []string{""},
						Resources: []string{"nodes"},
						Verbs:     []string{"get", "list", "watch"},
					},
				},
			},
			expectedCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := validateNodePVAccess(tt.object)
			testutil.AssertEqual(t, tt.expectedCount, len(findings), "unexpected number of findings")

			if tt.expectedCount > 0 && len(findings) > 0 {
				testutil.AssertEqual(t, "RBAC010", findings[0].RuleID, "unexpected rule ID")
				testutil.AssertEqual(t, SeverityMedium, findings[0].Severity, "unexpected severity")
			}
		})
	}
}

func TestValidateWebhookAccess(t *testing.T) {
	tests := []struct {
		name          string
		object        runtime.Object
		expectedCount int
	}{
		{
			name: "role with mutating webhook create permission",
			object: &rbacv1.Role{
				ObjectMeta: metav1.ObjectMeta{Name: "webhook-role", Namespace: "default"},
				Rules: []rbacv1.PolicyRule{
					{
						APIGroups: []string{"admissionregistration.k8s.io"},
						Resources: []string{"mutatingwebhookconfigurations"},
						Verbs:     []string{"create", "update"},
					},
				},
			},
			expectedCount: 2,
		},
		{
			name: "clusterrole with validating webhook wildcard",
			object: &rbacv1.ClusterRole{
				ObjectMeta: metav1.ObjectMeta{Name: "webhook-wildcard"},
				Rules: []rbacv1.PolicyRule{
					{
						APIGroups: []string{"admissionregistration.k8s.io"},
						Resources: []string{"validatingwebhookconfigurations"},
						Verbs:     []string{"*"},
					},
				},
			},
			expectedCount: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := validateWebhookAccess(tt.object)
			testutil.AssertEqual(t, tt.expectedCount, len(findings), "unexpected number of findings")

			if tt.expectedCount > 0 && len(findings) > 0 {
				testutil.AssertEqual(t, "RBAC011", findings[0].RuleID, "unexpected rule ID")
				testutil.AssertEqual(t, SeverityHigh, findings[0].Severity, "unexpected severity")
			}
		})
	}
}

func TestValidateCRDAPIServiceAccess(t *testing.T) {
	tests := []struct {
		name          string
		object        runtime.Object
		expectedCount int
	}{
		{
			name: "role with CRD create permission",
			object: &rbacv1.Role{
				ObjectMeta: metav1.ObjectMeta{Name: "crd-role", Namespace: "default"},
				Rules: []rbacv1.PolicyRule{
					{
						APIGroups: []string{"apiextensions.k8s.io"},
						Resources: []string{"customresourcedefinitions"},
						Verbs:     []string{"create", "delete"},
					},
				},
			},
			expectedCount: 2,
		},
		{
			name: "clusterrole with APIService update permission",
			object: &rbacv1.ClusterRole{
				ObjectMeta: metav1.ObjectMeta{Name: "apiservice-role"},
				Rules: []rbacv1.PolicyRule{
					{
						APIGroups: []string{"apiregistration.k8s.io"},
						Resources: []string{"apiservices"},
						Verbs:     []string{"update", "patch"},
					},
				},
			},
			expectedCount: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := validateCRDAPIServiceAccess(tt.object)
			testutil.AssertEqual(t, tt.expectedCount, len(findings), "unexpected number of findings")

			if tt.expectedCount > 0 && len(findings) > 0 {
				testutil.AssertEqual(t, "RBAC012", findings[0].RuleID, "unexpected rule ID")
				testutil.AssertEqual(t, SeverityHigh, findings[0].Severity, "unexpected severity")
			}
		})
	}
}

func TestValidateNamespaceIsolation(t *testing.T) {
	tests := []struct {
		name          string
		object        runtime.Object
		expectedCount int
	}{
		{
			name: "rolebinding referencing clusterrole",
			object: &rbacv1.RoleBinding{
				ObjectMeta: metav1.ObjectMeta{Name: "cross-namespace-rb", Namespace: "default"},
				RoleRef: rbacv1.RoleRef{
					Kind:     "ClusterRole",
					Name:     "some-clusterrole",
					APIGroup: "rbac.authorization.k8s.io",
				},
			},
			expectedCount: 1,
		},
		{
			name: "rolebinding referencing role",
			object: &rbacv1.RoleBinding{
				ObjectMeta: metav1.ObjectMeta{Name: "normal-rb", Namespace: "default"},
				RoleRef: rbacv1.RoleRef{
					Kind:     "Role",
					Name:     "some-role",
					APIGroup: "rbac.authorization.k8s.io",
				},
			},
			expectedCount: 0,
		},
		{
			name: "clusterrolebinding (not applicable)",
			object: &rbacv1.ClusterRoleBinding{
				ObjectMeta: metav1.ObjectMeta{Name: "crb"},
				RoleRef: rbacv1.RoleRef{
					Kind:     "ClusterRole",
					Name:     "some-clusterrole",
					APIGroup: "rbac.authorization.k8s.io",
				},
			},
			expectedCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := validateNamespaceIsolation(tt.object)
			testutil.AssertEqual(t, tt.expectedCount, len(findings), "unexpected number of findings")

			if tt.expectedCount > 0 && len(findings) > 0 {
				testutil.AssertEqual(t, "RBAC013", findings[0].RuleID, "unexpected rule ID")
				testutil.AssertEqual(t, SeverityMedium, findings[0].Severity, "unexpected severity")
			}
		})
	}
}

func TestValidateTokenCertificateRequests(t *testing.T) {
	tests := []struct {
		name          string
		object        runtime.Object
		expectedCount int
	}{
		{
			name: "role with token request permission",
			object: &rbacv1.Role{
				ObjectMeta: metav1.ObjectMeta{Name: "token-role", Namespace: "default"},
				Rules: []rbacv1.PolicyRule{
					{
						APIGroups: []string{""},
						Resources: []string{"serviceaccounts/token"},
						Verbs:     []string{"create"},
					},
				},
			},
			expectedCount: 1,
		},
		{
			name: "clusterrole with CSR wildcard permission",
			object: &rbacv1.ClusterRole{
				ObjectMeta: metav1.ObjectMeta{Name: "csr-role"},
				Rules: []rbacv1.PolicyRule{
					{
						APIGroups: []string{"certificates.k8s.io"},
						Resources: []string{"certificatesigningrequests"},
						Verbs:     []string{"*"},
					},
				},
			},
			expectedCount: 1,
		},
		{
			name: "role with only get permission on tokens",
			object: &rbacv1.Role{
				ObjectMeta: metav1.ObjectMeta{Name: "token-read-role", Namespace: "default"},
				Rules: []rbacv1.PolicyRule{
					{
						APIGroups: []string{""},
						Resources: []string{"serviceaccounts/token"},
						Verbs:     []string{"get"},
					},
				},
			},
			expectedCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := validateTokenCertificateRequests(tt.object)
			testutil.AssertEqual(t, tt.expectedCount, len(findings), "unexpected number of findings")

			if tt.expectedCount > 0 && len(findings) > 0 {
				testutil.AssertEqual(t, "RBAC014", findings[0].RuleID, "unexpected rule ID")
				testutil.AssertEqual(t, SeverityHigh, findings[0].Severity, "unexpected severity")
			}
		})
	}
}

func TestHasServiceAccountRisks(t *testing.T) {
	tests := []struct {
		roleName string
		expected bool
	}{
		{"cluster-admin", true},
		{"admin", true},
		{"edit", true},
		{"view", false},
		{"custom-role", false},
		{"editor", false}, // not exact match
	}

	for _, tt := range tests {
		t.Run(tt.roleName, func(t *testing.T) {
			result := hasServiceAccountRisks(tt.roleName)
			testutil.AssertEqual(t, tt.expected, result, "hasServiceAccountRisks result")
		})
	}
}
