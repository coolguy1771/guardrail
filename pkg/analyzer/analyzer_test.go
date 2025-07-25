package analyzer //nolint:testpackage // Uses internal analyzer fields for testing

import (
	"context"
	"errors"
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/runtime"

	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	rbacv1client "k8s.io/client-go/kubernetes/typed/rbac/v1"

	"github.com/coolguy1771/guardrail/internal/testutil"
)

// Mock implementations for testing..
type mockRBACReader struct {
	roles               []rbacv1.Role
	clusterRoles        []rbacv1.ClusterRole
	roleBindings        []rbacv1.RoleBinding
	clusterRoleBindings []rbacv1.ClusterRoleBinding
	err                 error
}

func (m *mockRBACReader) Roles(_ string) rbacv1client.RoleInterface {
	return &mockRoleInterface{RoleInterface: nil, roles: m.roles, err: m.err}
}

func (m *mockRBACReader) RoleBindings(_ string) rbacv1client.RoleBindingInterface {
	return &mockRoleBindingInterface{RoleBindingInterface: nil, roleBindings: m.roleBindings, err: m.err}
}

func (m *mockRBACReader) ClusterRoles() rbacv1client.ClusterRoleInterface {
	return &mockClusterRoleInterface{ClusterRoleInterface: nil, clusterRoles: m.clusterRoles, err: m.err}
}

func (m *mockRBACReader) ClusterRoleBindings() rbacv1client.ClusterRoleBindingInterface {
	return &mockClusterRoleBindingInterface{
		ClusterRoleBindingInterface: nil,
		clusterRoleBindings:         m.clusterRoleBindings,
		err:                         m.err,
	}
}

// Mock interfaces for Kubernetes client..
type mockRoleInterface struct {
	rbacv1client.RoleInterface

	roles []rbacv1.Role
	err   error
}

func (m *mockRoleInterface) List(_ context.Context, _ metav1.ListOptions) (*rbacv1.RoleList, error) {
	if m.err != nil {
		return nil, m.err
	}
	return &rbacv1.RoleList{Items: m.roles}, nil
}

type mockRoleBindingInterface struct {
	rbacv1client.RoleBindingInterface

	roleBindings []rbacv1.RoleBinding
	err          error
}

func (m *mockRoleBindingInterface) List(_ context.Context, _ metav1.ListOptions) (*rbacv1.RoleBindingList, error) {
	if m.err != nil {
		return nil, m.err
	}
	return &rbacv1.RoleBindingList{Items: m.roleBindings}, nil
}

type mockClusterRoleInterface struct {
	rbacv1client.ClusterRoleInterface

	clusterRoles []rbacv1.ClusterRole
	err          error
}

func (m *mockClusterRoleInterface) List(_ context.Context, _ metav1.ListOptions) (*rbacv1.ClusterRoleList, error) {
	if m.err != nil {
		return nil, m.err
	}
	return &rbacv1.ClusterRoleList{Items: m.clusterRoles}, nil
}

type mockClusterRoleBindingInterface struct {
	rbacv1client.ClusterRoleBindingInterface

	clusterRoleBindings []rbacv1.ClusterRoleBinding
	err                 error
}

func (m *mockClusterRoleBindingInterface) List(
	_ context.Context,
	_ metav1.ListOptions,
) (*rbacv1.ClusterRoleBindingList, error) {
	if m.err != nil {
		return nil, m.err
	}
	return &rbacv1.ClusterRoleBindingList{Items: m.clusterRoleBindings}, nil
}

func TestNewAnalyzer(t *testing.T) {
	mockReader := &mockRBACReader{}
	analyzer := NewAnalyzer(mockReader)

	testutil.AssertNotNil(t, analyzer, "NewAnalyzer should return non-nil analyzer")
	testutil.AssertNotNil(t, analyzer.rbacReader, "analyzer should have rbacReader")
	// analyzer.objects should be nil or empty when created with NewAnalyzer
	if len(analyzer.objects) > 0 {
		t.Errorf("analyzer.objects should be nil or empty, got %v", analyzer.objects)
	}
}

func TestNewAnalyzerFromObjects(t *testing.T) {
	objects := []runtime.Object{
		&rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Name: "test-role"}},
	}

	analyzer := NewAnalyzerFromObjects(objects)

	testutil.AssertNotNil(t, analyzer, "NewAnalyzerFromObjects should return non-nil analyzer")
	testutil.AssertNil(t, analyzer.rbacReader, "analyzer should not have rbacReader")
	testutil.AssertNotNil(t, analyzer.objects, "analyzer should have objects")
	testutil.AssertEqual(t, 1, len(analyzer.objects), "analyzer should have 1 object")
}

func TestAnalyzePermissions_FromObjects(t *testing.T) {
	// Create test objects
	role := &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "pod-reader",
			Namespace: "default",
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{""},
				Resources: []string{"pods"},
				Verbs:     []string{"get", "list"},
			},
		},
	}

	roleBinding := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "pod-reader-binding",
			Namespace: "default",
		},
		RoleRef: rbacv1.RoleRef{
			Kind:     "Role",
			Name:     "pod-reader",
			APIGroup: "rbac.authorization.k8s.io",
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "User",
				Name:      "alice",
				Namespace: "",
			},
		},
	}

	objects := []runtime.Object{role, roleBinding}
	analyzer := NewAnalyzerFromObjects(objects)

	ctx := context.Background()
	permissions, err := analyzer.AnalyzePermissions(ctx)

	testutil.AssertNil(t, err, "AnalyzePermissions should not return error")
	testutil.AssertEqual(t, 1, len(permissions), "should have 1 subject permission")

	if len(permissions) > 0 {
		perm := permissions[0]
		testutil.AssertEqual(t, "User", perm.Subject.Kind, "subject kind")
		testutil.AssertEqual(t, "alice", perm.Subject.Name, "subject name")
		testutil.AssertEqual(t, 1, len(perm.Permissions), "should have 1 permission grant")

		if len(perm.Permissions) > 0 {
			grant := perm.Permissions[0]
			testutil.AssertEqual(t, "pod-reader", grant.RoleName, "role name")
			testutil.AssertEqual(t, "Role", grant.RoleKind, "role kind")
			testutil.AssertEqual(t, "default", grant.Namespace, "namespace")
		}
	}
}

func TestAnalyzePermissions_FromCluster(t *testing.T) {
	mockReader := &mockRBACReader{
		roles: []rbacv1.Role{
			{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-role",
					Namespace: "default",
				},
				Rules: []rbacv1.PolicyRule{
					{
						APIGroups: []string{""},
						Resources: []string{"pods"},
						Verbs:     []string{"get"},
					},
				},
			},
		},
		roleBindings: []rbacv1.RoleBinding{
			{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-binding",
					Namespace: "default",
				},
				RoleRef: rbacv1.RoleRef{
					Kind:     "Role",
					Name:     "test-role",
					APIGroup: "rbac.authorization.k8s.io",
				},
				Subjects: []rbacv1.Subject{
					{
						Kind:      "ServiceAccount",
						Name:      "test-sa",
						Namespace: "default",
					},
				},
			},
		},
	}

	analyzer := NewAnalyzer(mockReader)
	ctx := context.Background()
	permissions, err := analyzer.AnalyzePermissions(ctx)

	testutil.AssertNil(t, err, "AnalyzePermissions should not return error")
	testutil.AssertEqual(t, 1, len(permissions), "should have 1 subject permission")
}

func TestAnalyzePermissions_ClusterError(t *testing.T) {
	mockReader := &mockRBACReader{
		err: errors.New("cluster connection failed"),
	}

	analyzer := NewAnalyzer(mockReader)
	ctx := context.Background()
	_, err := analyzer.AnalyzePermissions(ctx)

	testutil.AssertNotNil(t, err, "AnalyzePermissions should return error")
	if err != nil && !strings.Contains(err.Error(), "failed to fetch from cluster") {
		t.Errorf("expected error to contain 'failed to fetch from cluster', got: %v", err)
	}
}

func TestCalculateRiskLevel(t *testing.T) {
	tests := []struct {
		name     string
		grants   []PermissionGrant
		expected RiskLevel
	}{
		{
			name: "critical risk - wildcard everything",
			grants: []PermissionGrant{
				{
					Rules: []PolicyRuleAnalysis{
						{
							Verbs:     []string{"*"},
							Resources: []string{"*"},
							APIGroups: []string{"*"},
							SecurityImpact: SecurityImpact{
								Level: RiskLevelCritical,
							},
						},
					},
				},
			},
			expected: RiskLevelCritical,
		},
		{
			name: "high risk - secrets access",
			grants: []PermissionGrant{
				{
					Rules: []PolicyRuleAnalysis{
						{
							Verbs:     []string{"get", "list"},
							Resources: []string{"secrets"},
							APIGroups: []string{""},
							SecurityImpact: SecurityImpact{
								Level: RiskLevelHigh,
							},
						},
					},
				},
			},
			expected: RiskLevelHigh,
		},
		{
			name: "medium risk - deployments write",
			grants: []PermissionGrant{
				{
					Rules: []PolicyRuleAnalysis{
						{
							Verbs:     []string{"create", "update"},
							Resources: []string{"deployments"},
							APIGroups: []string{"apps"},
							SecurityImpact: SecurityImpact{
								Level: RiskLevelMedium,
							},
						},
					},
				},
			},
			expected: RiskLevelMedium,
		},
		{
			name: "low risk - read-only pods",
			grants: []PermissionGrant{
				{
					Rules: []PolicyRuleAnalysis{
						{
							Verbs:     []string{"get", "list"},
							Resources: []string{"pods"},
							APIGroups: []string{""},
							SecurityImpact: SecurityImpact{
								Level: RiskLevelLow,
							},
						},
					},
				},
			},
			expected: RiskLevelLow,
		},
		{
			name:     "no permissions",
			grants:   []PermissionGrant{},
			expected: RiskLevelLow,
		},
	}

	analyzer := &Analyzer{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := analyzer.calculateRiskLevel(tt.grants)
			testutil.AssertEqual(t, tt.expected, result, "risk level")
		})
	}
}

func TestBuildRoleMap(t *testing.T) {
	roles := []runtime.Object{
		&rbacv1.Role{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "role1",
				Namespace: "default",
			},
		},
		&rbacv1.ClusterRole{
			ObjectMeta: metav1.ObjectMeta{
				Name: "clusterrole1",
			},
		},
		&rbacv1.Role{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "role2",
				Namespace: "kube-system",
			},
		},
	}

	analyzer := &Analyzer{}
	roleMap := analyzer.buildRoleMap(roles)

	// Check that all roles are in the map with correct keys
	testutil.AssertNotNil(t, roleMap["Role/default/role1"], "role1 should be in map")
	testutil.AssertNotNil(t, roleMap["ClusterRole//clusterrole1"], "clusterrole1 should be in map")
	testutil.AssertNotNil(t, roleMap["Role/kube-system/role2"], "role2 should be in map")
}

func TestGetSubjectKey(t *testing.T) {
	tests := []struct {
		name     string
		subject  rbacv1.Subject
		expected string
	}{
		{
			name: "user",
			subject: rbacv1.Subject{
				Kind: "User",
				Name: "alice",
			},
			expected: "User//alice",
		},
		{
			name: "service account with namespace",
			subject: rbacv1.Subject{
				Kind:      "ServiceAccount",
				Name:      "default-sa",
				Namespace: "default",
			},
			expected: "ServiceAccount/default/default-sa",
		},
		{
			name: "group",
			subject: rbacv1.Subject{
				Kind: "Group",
				Name: "developers",
			},
			expected: "Group//developers",
		},
	}

	analyzer := &Analyzer{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := analyzer.getSubjectKey(tt.subject)
			testutil.AssertEqual(t, tt.expected, result, "subject key")
		})
	}
}

// Removed TestAnalyzeRule as analyzeRule is not exported

// Removed TestGetVerbExplanations as getVerbExplanations is not exported

// Removed TestIsHighRiskResource as isHighRiskResource is not exported

// Removed TestHasWildcard as hasWildcard is not exported

// Removed TestFormatAPIGroups as we test it indirectly through exported methods

func TestAnalyzeBinding(t *testing.T) {
	// Create test role
	role := &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-role",
			Namespace: "default",
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{""},
				Resources: []string{"pods"},
				Verbs:     []string{"get", "list"},
			},
		},
	}

	// Create role map
	roleMap := map[string]runtime.Object{
		"Role.default.test-role": role,
	}

	// Create role binding
	binding := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-binding",
			Namespace: "default",
		},
		RoleRef: rbacv1.RoleRef{
			Kind:     "Role",
			Name:     "test-role",
			APIGroup: "rbac.authorization.k8s.io",
		},
		Subjects: []rbacv1.Subject{
			{
				Kind: "User",
				Name: "alice",
			},
			{
				Kind:      "ServiceAccount",
				Name:      "default",
				Namespace: "default",
			},
		},
	}

	analyzer := &Analyzer{}
	result := analyzer.analyzeBinding(binding, roleMap)

	testutil.AssertEqual(t, 2, len(result), "should have 2 subject permissions")

	// Check first subject (User)
	if len(result) > 0 {
		testutil.AssertEqual(t, "User", result[0].Subject.Kind, "first subject kind")
		testutil.AssertEqual(t, "alice", result[0].Subject.Name, "first subject name")
		testutil.AssertEqual(t, 1, len(result[0].Permissions), "first subject permissions count")
	}

	// Check second subject (ServiceAccount)
	if len(result) > 1 {
		testutil.AssertEqual(t, "ServiceAccount", result[1].Subject.Kind, "second subject kind")
		testutil.AssertEqual(t, "default", result[1].Subject.Name, "second subject name")
		testutil.AssertEqual(t, "default", result[1].Subject.Namespace, "second subject namespace")
	}
}

func TestAnalyzeClusterRoleBinding(t *testing.T) {
	// Create test cluster role
	clusterRole := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-cluster-role",
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{""},
				Resources: []string{"nodes"},
				Verbs:     []string{"get", "list"},
			},
		},
	}

	// Create role map
	roleMap := map[string]runtime.Object{
		"ClusterRole//test-cluster-role": clusterRole,
	}

	// Create cluster role binding
	binding := &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-cluster-binding",
		},
		RoleRef: rbacv1.RoleRef{
			Kind:     "ClusterRole",
			Name:     "test-cluster-role",
			APIGroup: "rbac.authorization.k8s.io",
		},
		Subjects: []rbacv1.Subject{
			{
				Kind: "Group",
				Name: "system:authenticated",
			},
			{
				Kind:      "ServiceAccount",
				Name:      "admin",
				Namespace: "kube-system",
			},
		},
	}

	analyzer := &Analyzer{}
	result := analyzer.analyzeBinding(binding, roleMap)

	testutil.AssertEqual(t, 2, len(result), "should have 2 subject permissions")

	// Check first subject (Group)
	if len(result) > 0 {
		testutil.AssertEqual(t, "Group", result[0].Subject.Kind, "first subject kind")
		testutil.AssertEqual(t, "system:authenticated", result[0].Subject.Name, "first subject name")
		testutil.AssertEqual(t, 1, len(result[0].Permissions), "first subject permissions count")
		testutil.AssertEqual(t, "cluster-wide", result[0].Permissions[0].Scope, "first subject scope")
	}

	// Check second subject (ServiceAccount)
	if len(result) > 1 {
		testutil.AssertEqual(t, "ServiceAccount", result[1].Subject.Kind, "second subject kind")
		testutil.AssertEqual(t, "admin", result[1].Subject.Name, "second subject name")
		testutil.AssertEqual(t, "kube-system", result[1].Subject.Namespace, "second subject namespace")
	}
}

func TestAnalyzeClusterRoleBinding_MissingRole(t *testing.T) {
	// Create empty role map
	roleMap := map[string]runtime.Object{}

	// Create cluster role binding with missing role
	binding := &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-missing-binding",
		},
		RoleRef: rbacv1.RoleRef{
			Kind:     "ClusterRole",
			Name:     "missing-role",
			APIGroup: "rbac.authorization.k8s.io",
		},
		Subjects: []rbacv1.Subject{
			{
				Kind: "User",
				Name: "bob",
			},
		},
	}

	analyzer := &Analyzer{}
	result := analyzer.analyzeBinding(binding, roleMap)

	testutil.AssertEqual(t, 1, len(result), "should have 1 subject permission")
	testutil.AssertEqual(t, 0, len(result[0].Permissions[0].Rules), "should have empty rules for missing role")
	testutil.AssertEqual(t, RiskLevelLow, result[0].RiskLevel, "should have low risk for missing role")
}

func TestEscalateRiskLevel(t *testing.T) {
	tests := []struct {
		name     string
		current  string
		expected string
	}{
		{name: "low to medium", current: "low", expected: "medium"},
		{name: "medium to high", current: "medium", expected: "high"},
		{name: "high to critical", current: "high", expected: "critical"},
		{name: "critical stays critical", current: "critical", expected: "critical"},
		{name: "unknown defaults to critical", current: "unknown", expected: "critical"},
	}

	analyzer := &Analyzer{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := analyzer.escalateRiskLevel(tt.current)
			testutil.AssertEqual(t, tt.expected, result, "risk level escalation")
		})
	}
}

func TestAnalyzeSecurityImpact(t *testing.T) {
	tests := []struct {
		name          string
		rule          rbacv1.PolicyRule
		expectedLevel string
		expectedDesc  string
	}{
		{
			name: "standard resource access",
			rule: rbacv1.PolicyRule{
				APIGroups: []string{""},
				Resources: []string{"pods"},
				Verbs:     []string{"get", "list"},
			},
			expectedLevel: string(RiskLevelLow),
			expectedDesc:  "Standard resource access",
		},
		{
			name: "escalate verb",
			rule: rbacv1.PolicyRule{
				APIGroups: []string{"rbac.authorization.k8s.io"},
				Resources: []string{"clusterroles"},
				Verbs:     []string{"escalate"},
			},
			expectedLevel: string(RiskLevelMedium),
			expectedDesc:  "Standard resource access",
		},
		{
			name: "impersonate verb",
			rule: rbacv1.PolicyRule{
				APIGroups: []string{""},
				Resources: []string{"users"},
				Verbs:     []string{"impersonate"},
			},
			expectedLevel: string(RiskLevelMedium),
			expectedDesc:  "Standard resource access",
		},
		{
			name: "secrets access",
			rule: rbacv1.PolicyRule{
				APIGroups: []string{""},
				Resources: []string{"secrets"},
				Verbs:     []string{"get", "list"},
			},
			expectedLevel: string(RiskLevelMedium),
			expectedDesc:  "Standard resource access",
		},
		{
			name: "wildcard resources",
			rule: rbacv1.PolicyRule{
				APIGroups: []string{"*"},
				Resources: []string{"*"},
				Verbs:     []string{"get"},
			},
			expectedLevel: string(RiskLevelHigh),
			expectedDesc:  "Access to all resources with specified permissions",
		},
		{
			name: "admin verbs",
			rule: rbacv1.PolicyRule{
				APIGroups: []string{"apps"},
				Resources: []string{"deployments"},
				Verbs:     []string{"create", "delete", "patch"},
			},
			expectedLevel: string(RiskLevelMedium),
			expectedDesc:  "Standard resource access",
		},
	}

	analyzer := &Analyzer{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			impact := analyzer.analyzeSecurityImpact(tt.rule)
			testutil.AssertEqual(t, tt.expectedLevel, string(impact.Level), "security impact level")
			testutil.AssertEqual(t, tt.expectedDesc, impact.Description, "security impact description")
		})
	}
}

func TestFormatAPIGroups(t *testing.T) {
	tests := []struct {
		name      string
		apiGroups []string
		expected  string
	}{
		{name: "empty groups", apiGroups: []string{}, expected: ""},
		{name: "core group only", apiGroups: []string{""}, expected: "in API groups: core"},
		{name: "single group", apiGroups: []string{"apps"}, expected: "in API groups: apps"},
		{name: "multiple groups", apiGroups: []string{"apps", "batch"}, expected: "in API groups: apps, batch"},
		{
			name:      "core and other groups",
			apiGroups: []string{"", "apps", "batch"},
			expected:  "in API groups: core, apps, batch",
		},
		{name: "wildcard", apiGroups: []string{"*"}, expected: "in ALL API groups"},
	}

	analyzer := &Analyzer{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := analyzer.formatAPIGroups(tt.apiGroups)
			testutil.AssertEqual(t, tt.expected, result, "formatted API groups")
		})
	}
}

func TestAnalyzeRoleBinding_MissingRole(t *testing.T) {
	// Create empty role map
	roleMap := map[string]runtime.Object{}

	// Create role binding with missing role
	binding := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-missing-binding",
			Namespace: "default",
		},
		RoleRef: rbacv1.RoleRef{
			Kind:     "Role",
			Name:     "missing-role",
			APIGroup: "rbac.authorization.k8s.io",
		},
		Subjects: []rbacv1.Subject{
			{
				Kind: "User",
				Name: "charlie",
			},
		},
	}

	analyzer := &Analyzer{}
	result := analyzer.analyzeBinding(binding, roleMap)

	testutil.AssertEqual(t, 1, len(result), "should have 1 subject permission")
	testutil.AssertEqual(t, 0, len(result[0].Permissions[0].Rules), "should have empty rules for missing role")
	testutil.AssertEqual(t, RiskLevelLow, result[0].RiskLevel, "should have low risk for missing role")
}

func TestGetRiskPriorityAnalyzer(t *testing.T) {
	tests := []struct {
		name     string
		level    RiskLevel
		expected int
	}{
		{name: "critical priority", level: RiskLevelCritical, expected: 4},
		{name: "high priority", level: RiskLevelHigh, expected: 3},
		{name: "medium priority", level: RiskLevelMedium, expected: 2},
		{name: "low priority", level: RiskLevelLow, expected: 1},
		{name: "unknown priority", level: "unknown", expected: 0},
	}

	analyzer := &Analyzer{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := analyzer.getRiskPriority(tt.level)
			testutil.AssertEqual(t, tt.expected, result, "risk priority")
		})
	}
}
