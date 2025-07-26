package testutil_test

import (
	"testing"

	"k8s.io/apimachinery/pkg/runtime"

	rbacv1 "k8s.io/api/rbac/v1"

	"github.com/coolguy1771/guardrail/internal/testutil"
)

func TestNewTestRole(t *testing.T) {
	role := testutil.NewTestRole("test-role", "test-namespace")

	testutil.AssertNotNil(t, role, "Role should not be nil")
	testutil.AssertEqual(t, "rbac.authorization.k8s.io/v1", role.APIVersion, "API version mismatch")
	testutil.AssertEqual(t, "Role", role.Kind, "Kind mismatch")
	testutil.AssertEqual(t, "test-role", role.Name, "Name mismatch")
	testutil.AssertEqual(t, "test-namespace", role.Namespace, "Namespace mismatch")
	testutil.AssertLen(t, role.Rules, 0, "Rules should be empty")
}

func TestNewTestClusterRole(t *testing.T) {
	clusterRole := testutil.NewTestClusterRole("test-cluster-role")

	testutil.AssertNotNil(t, clusterRole, "ClusterRole should not be nil")
	testutil.AssertEqual(t, "rbac.authorization.k8s.io/v1", clusterRole.APIVersion, "API version mismatch")
	testutil.AssertEqual(t, "ClusterRole", clusterRole.Kind, "Kind mismatch")
	testutil.AssertEqual(t, "test-cluster-role", clusterRole.Name, "Name mismatch")
	testutil.AssertLen(t, clusterRole.Rules, 0, "Rules should be empty")
}

func TestNewTestRoleBinding(t *testing.T) {
	roleRef := rbacv1.RoleRef{
		APIGroup: "rbac.authorization.k8s.io",
		Kind:     "Role",
		Name:     "test-role",
	}

	roleBinding := testutil.NewTestRoleBinding("test-binding", "test-namespace", roleRef)

	testutil.AssertNotNil(t, roleBinding, "RoleBinding should not be nil")
	testutil.AssertEqual(t, "rbac.authorization.k8s.io/v1", roleBinding.APIVersion, "API version mismatch")
	testutil.AssertEqual(t, "RoleBinding", roleBinding.Kind, "Kind mismatch")
	testutil.AssertEqual(t, "test-binding", roleBinding.Name, "Name mismatch")
	testutil.AssertEqual(t, "test-namespace", roleBinding.Namespace, "Namespace mismatch")
	testutil.AssertEqual(t, roleRef.Name, roleBinding.RoleRef.Name, "RoleRef name mismatch")
	testutil.AssertLen(t, roleBinding.Subjects, 0, "Subjects should be empty")
}

func TestNewTestClusterRoleBinding(t *testing.T) {
	roleRef := rbacv1.RoleRef{
		APIGroup: "rbac.authorization.k8s.io",
		Kind:     "ClusterRole",
		Name:     "test-cluster-role",
	}

	clusterRoleBinding := testutil.NewTestClusterRoleBinding("test-cluster-binding", roleRef)

	testutil.AssertNotNil(t, clusterRoleBinding, "ClusterRoleBinding should not be nil")
	testutil.AssertEqual(t, "rbac.authorization.k8s.io/v1", clusterRoleBinding.APIVersion, "API version mismatch")
	testutil.AssertEqual(t, "ClusterRoleBinding", clusterRoleBinding.Kind, "Kind mismatch")
	testutil.AssertEqual(t, "test-cluster-binding", clusterRoleBinding.Name, "Name mismatch")
	testutil.AssertEqual(t, roleRef.Name, clusterRoleBinding.RoleRef.Name, "RoleRef name mismatch")
	testutil.AssertLen(t, clusterRoleBinding.Subjects, 0, "Subjects should be empty")
}

func TestAddRule(t *testing.T) {
	t.Run("AddRule to Role", func(t *testing.T) {
		role := testutil.NewTestRole("test-role", "test-namespace")
		rule := testutil.NewPolicyRule([]string{""}, []string{"pods"}, []string{"get", "list"})

		testutil.AddRule(role, rule)

		testutil.AssertLen(t, role.Rules, 1, "Role should have one rule")
		testutil.AssertEqual(t, "pods", role.Rules[0].Resources[0], "Resource mismatch")
	})

	t.Run("AddRule to ClusterRole", func(t *testing.T) {
		clusterRole := testutil.NewTestClusterRole("test-cluster-role")
		rule := testutil.NewPolicyRule([]string{"apps"}, []string{"deployments"}, []string{"create", "update"})

		testutil.AddRule(clusterRole, rule)

		testutil.AssertLen(t, clusterRole.Rules, 1, "ClusterRole should have one rule")
		testutil.AssertEqual(t, "apps", clusterRole.Rules[0].APIGroups[0], "APIGroup mismatch")
	})

	t.Run("AddRule panics on unsupported type", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Errorf("AddRule should panic on unsupported type")
			}
		}()

		testutil.AddRule(&rbacv1.RoleBinding{}, rbacv1.PolicyRule{})
	})
}

func TestAddSubject(t *testing.T) {
	t.Run("AddSubject to RoleBinding", func(t *testing.T) {
		roleRef := rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "Role",
			Name:     "test-role",
		}
		roleBinding := testutil.NewTestRoleBinding("test-binding", "test-namespace", roleRef)
		subject := testutil.NewSubject("ServiceAccount", "test-sa", "test-namespace")

		testutil.AddSubject(roleBinding, subject)

		testutil.AssertLen(t, roleBinding.Subjects, 1, "RoleBinding should have one subject")
		testutil.AssertEqual(t, "ServiceAccount", roleBinding.Subjects[0].Kind, "Subject kind mismatch")
		testutil.AssertEqual(t, "test-sa", roleBinding.Subjects[0].Name, "Subject name mismatch")
	})

	t.Run("AddSubject to ClusterRoleBinding", func(t *testing.T) {
		roleRef := rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     "test-cluster-role",
		}
		clusterRoleBinding := testutil.NewTestClusterRoleBinding("test-cluster-binding", roleRef)
		subject := testutil.NewSubject("User", "test-user", "")

		testutil.AddSubject(clusterRoleBinding, subject)

		testutil.AssertLen(t, clusterRoleBinding.Subjects, 1, "ClusterRoleBinding should have one subject")
		testutil.AssertEqual(t, "User", clusterRoleBinding.Subjects[0].Kind, "Subject kind mismatch")
		testutil.AssertEqual(t, "test-user", clusterRoleBinding.Subjects[0].Name, "Subject name mismatch")
	})

	t.Run("AddSubject panics on unsupported type", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Errorf("AddSubject should panic on unsupported type")
			}
		}()

		testutil.AddSubject(&rbacv1.Role{}, rbacv1.Subject{})
	})
}

func TestNewPolicyRule(t *testing.T) {
	apiGroups := []string{""}
	resources := []string{"pods", "services"}
	verbs := []string{"get", "list", "watch"}

	rule := testutil.NewPolicyRule(apiGroups, resources, verbs)

	testutil.AssertLen(t, rule.APIGroups, 1, "APIGroups length mismatch")
	testutil.AssertLen(t, rule.Resources, 2, "Resources length mismatch")
	testutil.AssertLen(t, rule.Verbs, 3, "Verbs length mismatch")
	testutil.AssertContains(t, rule.Resources, "pods", "Resources should contain pods")
	testutil.AssertContains(t, rule.Resources, "services", "Resources should contain services")
	testutil.AssertContains(t, rule.Verbs, "get", "Verbs should contain get")
}

func TestNewSubject(t *testing.T) {
	subject := testutil.NewSubject("ServiceAccount", "test-sa", "test-namespace")

	testutil.AssertEqual(t, "ServiceAccount", subject.Kind, "Kind mismatch")
	testutil.AssertEqual(t, "test-sa", subject.Name, "Name mismatch")
	testutil.AssertEqual(t, "test-namespace", subject.Namespace, "Namespace mismatch")
}

func TestAssertEqual(t *testing.T) {
	// Test passing case
	testutil.AssertEqual(t, "test", "test", "Values should be equal")

	// Test failing case
	mockT := &testing.T{}
	testutil.AssertEqual(mockT, "expected", "actual", "Test message")
	if !mockT.Failed() {
		t.Error("AssertEqual should have failed")
	}
}

func TestAssertNotNil(t *testing.T) {
	// Test passing case
	value := "not nil"
	testutil.AssertNotNil(t, value, "Value should not be nil")

	// Test failing case
	mockT := &testing.T{}
	testutil.AssertNotNil(mockT, nil, "Test message")
	if !mockT.Failed() {
		t.Error("AssertNotNil should have failed")
	}
}

func TestAssertNil(t *testing.T) {
	// Test passing case
	var value interface{}
	testutil.AssertNil(t, value, "Value should be nil")

	// Test failing case
	mockT := &testing.T{}
	testutil.AssertNil(mockT, "not nil", "Test message")
	if !mockT.Failed() {
		t.Error("AssertNil should have failed")
	}
}

func TestAssertContains(t *testing.T) {
	// Test passing case
	slice := []string{"apple", "banana", "orange"}
	testutil.AssertContains(t, slice, "banana", "Slice should contain banana")

	// Test failing case
	mockT := &testing.T{}
	testutil.AssertContains(mockT, slice, "grape", "Test message")
	if !mockT.Failed() {
		t.Error("AssertContains should have failed")
	}
}

func TestAssertLen(t *testing.T) {
	t.Run("string slice", func(t *testing.T) {
		slice := []string{"one", "two", "three"}
		testutil.AssertLen(t, slice, 3, "String slice length")
	})

	t.Run("PolicyRule slice", func(t *testing.T) {
		rules := []rbacv1.PolicyRule{
			{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get"}},
			{APIGroups: []string{"apps"}, Resources: []string{"deployments"}, Verbs: []string{"list"}},
		}
		testutil.AssertLen(t, rules, 2, "PolicyRule slice length")
	})

	t.Run("Subject slice", func(t *testing.T) {
		subjects := []rbacv1.Subject{
			{Kind: "User", Name: "user1"},
			{Kind: "ServiceAccount", Name: "sa1"},
			{Kind: "Group", Name: "group1"},
		}
		testutil.AssertLen(t, subjects, 3, "Subject slice length")
	})

	t.Run("runtime.Object slice", func(t *testing.T) {
		objects := []runtime.Object{
			testutil.NewTestRole("role1", "ns1"),
			testutil.NewTestClusterRole("clusterrole1"),
		}
		testutil.AssertLen(t, objects, 2, "runtime.Object slice length")
	})

	t.Run("failing case", func(t *testing.T) {
		mockT := &testing.T{}
		slice := []string{"one", "two"}
		testutil.AssertLen(mockT, slice, 3, "Test message")
		if !mockT.Failed() {
			t.Error("AssertLen should have failed")
		}
	})
}
