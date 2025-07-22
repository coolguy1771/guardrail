package validator //nolint:testpackage // Uses internal validator fields for testing

import (
	"testing"

	"k8s.io/apimachinery/pkg/runtime"

	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/coolguy1771/guardrail/internal/testutil"
)

func TestNew(t *testing.T) {
	v := New()
	testutil.AssertNotNil(t, v, "New() should return a non-nil validator")
	testutil.AssertNotNil(t, v.rules, "validator should have rules")
	testutil.AssertEqual(t, 14, len(v.rules), "validator should have 14 default rules")
}

func TestNewWithRules(t *testing.T) {
	customRules := []Rule{
		{
			ID:          "CUSTOM001",
			Name:        "Custom Rule",
			Description: "A custom validation rule",
			Severity:    SeverityLow,
			Validate:    func(_ runtime.Object) []Finding { return nil },
		},
	}

	v := NewWithRules(customRules)
	testutil.AssertNotNil(t, v, "NewWithRules() should return a non-nil validator")
	testutil.AssertEqual(t, 1, len(v.rules), "validator should have 1 custom rule")
	testutil.AssertEqual(t, "CUSTOM001", v.rules[0].ID, "rule ID should match")
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name     string
		object   runtime.Object
		wantRule string
		wantLen  int
	}{
		{
			name: "role with wildcard verb",
			object: &rbacv1.Role{
				ObjectMeta: metav1.ObjectMeta{Name: "test-role", Namespace: "default"},
				Rules: []rbacv1.PolicyRule{
					{
						APIGroups: []string{""},
						Resources: []string{"pods"},
						Verbs:     []string{"*"},
					},
				},
			},
			wantRule: "RBAC001",
			wantLen:  1,
		},
		{
			name: "clusterrole with wildcard resource",
			object: &rbacv1.ClusterRole{
				ObjectMeta: metav1.ObjectMeta{Name: "test-clusterrole"},
				Rules: []rbacv1.PolicyRule{
					{
						APIGroups: []string{""},
						Resources: []string{"*"},
						Verbs:     []string{"get", "list"},
					},
				},
			},
			wantRule: "RBAC001",
			wantLen:  1,
		},
		{
			name: "role with no wildcards",
			object: &rbacv1.Role{
				ObjectMeta: metav1.ObjectMeta{Name: "safe-role", Namespace: "default"},
				Rules: []rbacv1.PolicyRule{
					{
						APIGroups: []string{""},
						Resources: []string{"pods"},
						Verbs:     []string{"get", "list"},
					},
				},
			},
			wantRule: "",
			wantLen:  0,
		},
	}

	v := New()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := v.Validate(tt.object)
			if tt.wantLen == 0 {
				testutil.AssertEqual(t, 0, len(findings), "expected no findings")
				return
			}

			testutil.AssertEqual(t, tt.wantLen, len(findings), "unexpected number of findings")
			if len(findings) > 0 && tt.wantRule != "" {
				testutil.AssertEqual(t, tt.wantRule, findings[0].RuleID, "unexpected rule ID")
			}
		})
	}
}

func TestValidateAll(t *testing.T) {
	objects := []runtime.Object{
		&rbacv1.Role{
			ObjectMeta: metav1.ObjectMeta{Name: "role1", Namespace: "default"},
			Rules: []rbacv1.PolicyRule{
				{
					APIGroups: []string{"*"},
					Resources: []string{"pods"},
					Verbs:     []string{"get"},
				},
			},
		},
		&rbacv1.ClusterRole{
			ObjectMeta: metav1.ObjectMeta{Name: "clusterrole1"},
			Rules: []rbacv1.PolicyRule{
				{
					APIGroups: []string{""},
					Resources: []string{"secrets"},
					Verbs:     []string{"get", "list"},
				},
			},
		},
	}

	v := New()
	findings := v.ValidateAll(objects)

	// Debug: print all findings
	for i, f := range findings {
		t.Logf("Finding %d: RuleID=%s, Resource=%s, Message=%s", i, f.RuleID, f.Resource, f.Message)
	}

	// The ClusterRole only has namespace-scoped resources (secrets) so RBAC004 triggers too
	testutil.AssertEqual(
		t,
		3,
		len(findings),
		"expected 3 findings (1 wildcard + 1 secrets access + 1 prefer namespaced)",
	)
}

func TestValidateWildcardPermissions(t *testing.T) {
	tests := []struct {
		name          string
		object        runtime.Object
		expectedCount int
		expectedMsg   string
	}{
		{
			name: "wildcard in all fields",
			object: &rbacv1.Role{
				ObjectMeta: metav1.ObjectMeta{Name: "wildcard-all", Namespace: "default"},
				Rules: []rbacv1.PolicyRule{
					{
						APIGroups: []string{"*"},
						Resources: []string{"*"},
						Verbs:     []string{"*"},
					},
				},
			},
			expectedCount: 3,
			expectedMsg:   "Wildcard",
		},
		{
			name: "wildcard only in verbs",
			object: &rbacv1.ClusterRole{
				ObjectMeta: metav1.ObjectMeta{Name: "wildcard-verbs"},
				Rules: []rbacv1.PolicyRule{
					{
						APIGroups: []string{""},
						Resources: []string{"pods"},
						Verbs:     []string{"*"},
					},
				},
			},
			expectedCount: 1,
			expectedMsg:   "Wildcard verb '*' found",
		},
		{
			name:          "non-rbac object",
			object:        &metav1.Status{},
			expectedCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := validateWildcardPermissions(tt.object)
			testutil.AssertEqual(t, tt.expectedCount, len(findings), "unexpected number of findings")

			if tt.expectedCount > 0 && len(findings) > 0 {
				for _, finding := range findings {
					testutil.AssertEqual(t, "RBAC001", finding.RuleID, "unexpected rule ID")
					testutil.AssertEqual(t, SeverityHigh, finding.Severity, "unexpected severity")
					if tt.expectedMsg != "" && finding.Message == "" {
						t.Errorf("expected message to contain '%s', but got empty", tt.expectedMsg)
					}
				}
			}
		})
	}
}

func TestValidateClusterAdminBinding(t *testing.T) {
	tests := []struct {
		name          string
		object        runtime.Object
		expectedCount int
	}{
		{
			name: "clusterrolebinding to cluster-admin",
			object: &rbacv1.ClusterRoleBinding{
				ObjectMeta: metav1.ObjectMeta{Name: "admin-binding"},
				RoleRef: rbacv1.RoleRef{
					Kind:     "ClusterRole",
					Name:     "cluster-admin",
					APIGroup: "rbac.authorization.k8s.io",
				},
			},
			expectedCount: 1,
		},
		{
			name: "rolebinding to cluster-admin",
			object: &rbacv1.RoleBinding{
				ObjectMeta: metav1.ObjectMeta{Name: "admin-binding", Namespace: "default"},
				RoleRef: rbacv1.RoleRef{
					Kind:     "ClusterRole",
					Name:     "cluster-admin",
					APIGroup: "rbac.authorization.k8s.io",
				},
			},
			expectedCount: 1,
		},
		{
			name: "binding to non-admin role",
			object: &rbacv1.ClusterRoleBinding{
				ObjectMeta: metav1.ObjectMeta{Name: "normal-binding"},
				RoleRef: rbacv1.RoleRef{
					Kind:     "ClusterRole",
					Name:     "view",
					APIGroup: "rbac.authorization.k8s.io",
				},
			},
			expectedCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := validateClusterAdminBinding(tt.object)
			testutil.AssertEqual(t, tt.expectedCount, len(findings), "unexpected number of findings")

			if tt.expectedCount > 0 && len(findings) > 0 {
				testutil.AssertEqual(t, "RBAC002", findings[0].RuleID, "unexpected rule ID")
				testutil.AssertEqual(t, SeverityHigh, findings[0].Severity, "unexpected severity")
			}
		})
	}
}

func TestValidateSecretsAccess(t *testing.T) {
	tests := []struct {
		name          string
		object        runtime.Object
		expectedCount int
	}{
		{
			name: "role with get secrets",
			object: &rbacv1.Role{
				ObjectMeta: metav1.ObjectMeta{Name: "secrets-reader", Namespace: "default"},
				Rules: []rbacv1.PolicyRule{
					{
						APIGroups: []string{""},
						Resources: []string{"secrets"},
						Verbs:     []string{"get"},
					},
				},
			},
			expectedCount: 1,
		},
		{
			name: "role with list secrets",
			object: &rbacv1.Role{
				ObjectMeta: metav1.ObjectMeta{Name: "secrets-lister", Namespace: "default"},
				Rules: []rbacv1.PolicyRule{
					{
						APIGroups: []string{""},
						Resources: []string{"secrets"},
						Verbs:     []string{"list"},
					},
				},
			},
			expectedCount: 1,
		},
		{
			name: "role with wildcard verb on secrets",
			object: &rbacv1.ClusterRole{
				ObjectMeta: metav1.ObjectMeta{Name: "secrets-all"},
				Rules: []rbacv1.PolicyRule{
					{
						APIGroups: []string{""},
						Resources: []string{"secrets"},
						Verbs:     []string{"*"},
					},
				},
			},
			expectedCount: 1,
		},
		{
			name: "role with only create/update secrets",
			object: &rbacv1.Role{
				ObjectMeta: metav1.ObjectMeta{Name: "secrets-writer", Namespace: "default"},
				Rules: []rbacv1.PolicyRule{
					{
						APIGroups: []string{""},
						Resources: []string{"secrets"},
						Verbs:     []string{"create", "update"},
					},
				},
			},
			expectedCount: 0,
		},
		{
			name: "role without secrets access",
			object: &rbacv1.Role{
				ObjectMeta: metav1.ObjectMeta{Name: "no-secrets", Namespace: "default"},
				Rules: []rbacv1.PolicyRule{
					{
						APIGroups: []string{""},
						Resources: []string{"pods", "services"},
						Verbs:     []string{"get", "list"},
					},
				},
			},
			expectedCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := validateSecretsAccess(tt.object)
			testutil.AssertEqual(t, tt.expectedCount, len(findings), "unexpected number of findings")

			if tt.expectedCount > 0 && len(findings) > 0 {
				testutil.AssertEqual(t, "RBAC003", findings[0].RuleID, "unexpected rule ID")
				testutil.AssertEqual(t, SeverityMedium, findings[0].Severity, "unexpected severity")
			}
		})
	}
}

func TestValidateNamespacedRoles(t *testing.T) {
	tests := []struct {
		name          string
		object        runtime.Object
		expectedCount int
	}{
		{
			name: "clusterrole with only namespaced resources",
			object: &rbacv1.ClusterRole{
				ObjectMeta: metav1.ObjectMeta{Name: "namespaced-only"},
				Rules: []rbacv1.PolicyRule{
					{
						APIGroups: []string{""},
						Resources: []string{"pods", "services"},
						Verbs:     []string{"get", "list"},
					},
					{
						APIGroups: []string{"apps"},
						Resources: []string{"deployments"},
						Verbs:     []string{"get", "list"},
					},
				},
			},
			expectedCount: 1,
		},
		{
			name: "clusterrole with cluster-scoped resources",
			object: &rbacv1.ClusterRole{
				ObjectMeta: metav1.ObjectMeta{Name: "cluster-scoped"},
				Rules: []rbacv1.PolicyRule{
					{
						APIGroups: []string{""},
						Resources: []string{"namespaces"},
						Verbs:     []string{"get", "list"},
					},
				},
			},
			expectedCount: 0,
		},
		{
			name: "clusterrole with wildcard resources",
			object: &rbacv1.ClusterRole{
				ObjectMeta: metav1.ObjectMeta{Name: "wildcard-resources"},
				Rules: []rbacv1.PolicyRule{
					{
						APIGroups: []string{""},
						Resources: []string{"*"},
						Verbs:     []string{"get"},
					},
				},
			},
			expectedCount: 0,
		},
		{
			name: "empty clusterrole",
			object: &rbacv1.ClusterRole{
				ObjectMeta: metav1.ObjectMeta{Name: "empty"},
				Rules:      []rbacv1.PolicyRule{},
			},
			expectedCount: 0,
		},
		{
			name: "regular role (not clusterrole)",
			object: &rbacv1.Role{
				ObjectMeta: metav1.ObjectMeta{Name: "regular-role", Namespace: "default"},
				Rules: []rbacv1.PolicyRule{
					{
						APIGroups: []string{""},
						Resources: []string{"pods"},
						Verbs:     []string{"get"},
					},
				},
			},
			expectedCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := validateNamespacedRoles(tt.object)
			testutil.AssertEqual(t, tt.expectedCount, len(findings), "unexpected number of findings")

			if tt.expectedCount > 0 && len(findings) > 0 {
				testutil.AssertEqual(t, "RBAC004", findings[0].RuleID, "unexpected rule ID")
				testutil.AssertEqual(t, SeverityLow, findings[0].Severity, "unexpected severity")
			}
		})
	}
}

func TestCheckRulesForWildcards(t *testing.T) {
	tests := []struct {
		name          string
		rules         []rbacv1.PolicyRule
		resourceName  string
		namespace     string
		kind          string
		expectedCount int
	}{
		{
			name: "multiple wildcards in single rule",
			rules: []rbacv1.PolicyRule{
				{
					APIGroups: []string{"*"},
					Resources: []string{"*"},
					Verbs:     []string{"*"},
				},
			},
			resourceName:  "test-role",
			namespace:     "default",
			kind:          "Role",
			expectedCount: 3,
		},
		{
			name: "wildcards in multiple rules",
			rules: []rbacv1.PolicyRule{
				{
					APIGroups: []string{"*"},
					Resources: []string{"pods"},
					Verbs:     []string{"get"},
				},
				{
					APIGroups: []string{""},
					Resources: []string{"*"},
					Verbs:     []string{"list"},
				},
			},
			resourceName:  "test-role",
			namespace:     "",
			kind:          "ClusterRole",
			expectedCount: 2,
		},
		{
			name:          "no wildcards",
			rules:         []rbacv1.PolicyRule{},
			resourceName:  "test-role",
			namespace:     "default",
			kind:          "Role",
			expectedCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := checkRulesForWildcards(tt.rules, tt.resourceName, tt.namespace, tt.kind)
			testutil.AssertEqual(t, tt.expectedCount, len(findings), "unexpected number of findings")

			for _, finding := range findings {
				testutil.AssertEqual(t, "RBAC001", finding.RuleID, "unexpected rule ID")
				testutil.AssertEqual(t, tt.resourceName, finding.Resource, "unexpected resource name")
				testutil.AssertEqual(t, tt.namespace, finding.Namespace, "unexpected namespace")
				testutil.AssertEqual(t, tt.kind, finding.Kind, "unexpected kind")
			}
		})
	}
}

func TestSeverityConstants(t *testing.T) {
	// Test that severity constants have expected values
	testutil.AssertEqual(t, Severity("HIGH"), SeverityHigh, "SeverityHigh constant")
	testutil.AssertEqual(t, Severity("MEDIUM"), SeverityMedium, "SeverityMedium constant")
	testutil.AssertEqual(t, Severity("LOW"), SeverityLow, "SeverityLow constant")
	testutil.AssertEqual(t, Severity("INFO"), SeverityInfo, "SeverityInfo constant")
}

func TestDefaultRules(t *testing.T) {
	rules := defaultRules()
	testutil.AssertEqual(t, 14, len(rules), "expected 14 default rules")

	expectedRules := map[string]string{
		"RBAC001": "Avoid Wildcard Permissions",
		"RBAC002": "Avoid Cluster-Admin Binding",
		"RBAC003": "Avoid Secrets Access",
		"RBAC004": "Prefer Namespaced Roles",
		"RBAC005": "Avoid Service Account Token Automounting",
		"RBAC006": "Restrict Exec and Attach Permissions",
		"RBAC007": "Limit Impersonation Privileges",
		"RBAC008": "Restrict Escalate and Bind Verbs",
		"RBAC009": "Audit Privileged Container Access",
		"RBAC010": "Restrict Node and PersistentVolume Access",
		"RBAC011": "Limit Webhook Configuration Access",
		"RBAC012": "Restrict CRD and APIService Modifications",
		"RBAC013": "Separate Concerns with Namespace Isolation",
		"RBAC014": "Restrict TokenRequest and CertificateSigningRequest",
	}

	for _, rule := range rules {
		expectedName, ok := expectedRules[rule.ID]
		if !ok {
			t.Errorf("unexpected rule ID: %s", rule.ID)
			continue
		}
		testutil.AssertEqual(t, expectedName, rule.Name, "rule name for "+rule.ID)
		testutil.AssertNotNil(t, rule.Validate, "validate function for "+rule.ID)
	}
}
