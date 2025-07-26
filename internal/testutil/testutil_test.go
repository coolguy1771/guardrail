package testutil

import (
	"testing"

	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

func TestNewTestRole(t *testing.T) {
	role := NewTestRole("test-role", "test-namespace")

	AssertNotNil(t, role, "Role should not be nil")
	AssertEqual(t, "rbac.authorization.k8s.io/v1", role.APIVersion, "API version mismatch")
	AssertEqual(t, "Role", role.Kind, "Kind mismatch")
	AssertEqual(t, "test-role", role.Name, "Name mismatch")
	AssertEqual(t, "test-namespace", role.Namespace, "Namespace mismatch")
	AssertLen(t, role.Rules, 0, "Rules should be empty")
}

func TestNewTestClusterRole(t *testing.T) {
	clusterRole := NewTestClusterRole("test-cluster-role")

	AssertNotNil(t, clusterRole, "ClusterRole should not be nil")
	AssertEqual(t, "rbac.authorization.k8s.io/v1", clusterRole.APIVersion, "API version mismatch")
	AssertEqual(t, "ClusterRole", clusterRole.Kind, "Kind mismatch")
	AssertEqual(t, "test-cluster-role", clusterRole.Name, "Name mismatch")
	AssertLen(t, clusterRole.Rules, 0, "Rules should be empty")
}

func TestNewTestRoleBinding(t *testing.T) {
	roleRef := rbacv1.RoleRef{
		APIGroup: "rbac.authorization.k8s.io",
		Kind:     "Role",
		Name:     "test-role",
	}

	roleBinding := NewTestRoleBinding("test-binding", "test-namespace", roleRef)

	AssertNotNil(t, roleBinding, "RoleBinding should not be nil")
	AssertEqual(t, "rbac.authorization.k8s.io/v1", roleBinding.APIVersion, "API version mismatch")
	AssertEqual(t, "RoleBinding", roleBinding.Kind, "Kind mismatch")
	AssertEqual(t, "test-binding", roleBinding.Name, "Name mismatch")
	AssertEqual(t, "test-namespace", roleBinding.Namespace, "Namespace mismatch")
	AssertEqual(t, roleRef.Name, roleBinding.RoleRef.Name, "RoleRef name mismatch")
	AssertLen(t, roleBinding.Subjects, 0, "Subjects should be empty")
}

func TestNewTestClusterRoleBinding(t *testing.T) {
	roleRef := rbacv1.RoleRef{
		APIGroup: "rbac.authorization.k8s.io",
		Kind:     "ClusterRole",
		Name:     "test-cluster-role",
	}

	clusterRoleBinding := NewTestClusterRoleBinding("test-cluster-binding", roleRef)

	AssertNotNil(t, clusterRoleBinding, "ClusterRoleBinding should not be nil")
	AssertEqual(t, "rbac.authorization.k8s.io/v1", clusterRoleBinding.APIVersion, "API version mismatch")
	AssertEqual(t, "ClusterRoleBinding", clusterRoleBinding.Kind, "Kind mismatch")
	AssertEqual(t, "test-cluster-binding", clusterRoleBinding.Name, "Name mismatch")
	AssertEqual(t, roleRef.Name, clusterRoleBinding.RoleRef.Name, "RoleRef name mismatch")
	AssertLen(t, clusterRoleBinding.Subjects, 0, "Subjects should be empty")
}

func TestAddRule(t *testing.T) {
	t.Run("AddRule to Role", func(t *testing.T) {
		role := NewTestRole("test-role", "test-namespace")
		rule := NewPolicyRule([]string{""}, []string{"pods"}, []string{"get", "list"})

		AddRule(role, rule)

		AssertLen(t, role.Rules, 1, "Role should have one rule")
		AssertEqual(t, "pods", role.Rules[0].Resources[0], "Resource mismatch")
	})

	t.Run("AddRule to ClusterRole", func(t *testing.T) {
		clusterRole := NewTestClusterRole("test-cluster-role")
		rule := NewPolicyRule([]string{"apps"}, []string{"deployments"}, []string{"create", "update"})

		AddRule(clusterRole, rule)

		AssertLen(t, clusterRole.Rules, 1, "ClusterRole should have one rule")
		AssertEqual(t, "apps", clusterRole.Rules[0].APIGroups[0], "APIGroup mismatch")
	})

	t.Run("AddRule panics on unsupported type", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Errorf("AddRule should panic on unsupported type")
			}
		}()

		AddRule(&rbacv1.RoleBinding{}, rbacv1.PolicyRule{})
	})
}

func TestAddSubject(t *testing.T) {
	t.Run("AddSubject to RoleBinding", func(t *testing.T) {
		roleRef := rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "Role",
			Name:     "test-role",
		}
		roleBinding := NewTestRoleBinding("test-binding", "test-namespace", roleRef)
		subject := NewSubject("ServiceAccount", "test-sa", "test-namespace")

		AddSubject(roleBinding, subject)

		AssertLen(t, roleBinding.Subjects, 1, "RoleBinding should have one subject")
		AssertEqual(t, "ServiceAccount", roleBinding.Subjects[0].Kind, "Subject kind mismatch")
		AssertEqual(t, "test-sa", roleBinding.Subjects[0].Name, "Subject name mismatch")
	})

	t.Run("AddSubject to ClusterRoleBinding", func(t *testing.T) {
		roleRef := rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     "test-cluster-role",
		}
		clusterRoleBinding := NewTestClusterRoleBinding("test-cluster-binding", roleRef)
		subject := NewSubject("User", "test-user", "")

		AddSubject(clusterRoleBinding, subject)

		AssertLen(t, clusterRoleBinding.Subjects, 1, "ClusterRoleBinding should have one subject")
		AssertEqual(t, "User", clusterRoleBinding.Subjects[0].Kind, "Subject kind mismatch")
		AssertEqual(t, "test-user", clusterRoleBinding.Subjects[0].Name, "Subject name mismatch")
	})

	t.Run("AddSubject panics on unsupported type", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Errorf("AddSubject should panic on unsupported type")
			}
		}()

		AddSubject(&rbacv1.Role{}, rbacv1.Subject{})
	})
}

func TestNewPolicyRule(t *testing.T) {
	apiGroups := []string{""}
	resources := []string{"pods", "services"}
	verbs := []string{"get", "list", "watch"}

	rule := NewPolicyRule(apiGroups, resources, verbs)

	AssertLen(t, rule.APIGroups, 1, "APIGroups length mismatch")
	AssertLen(t, rule.Resources, 2, "Resources length mismatch")
	AssertLen(t, rule.Verbs, 3, "Verbs length mismatch")
	AssertContains(t, rule.Resources, "pods", "Resources should contain pods")
	AssertContains(t, rule.Resources, "services", "Resources should contain services")
	AssertContains(t, rule.Verbs, "get", "Verbs should contain get")
}

func TestNewSubject(t *testing.T) {
	subject := NewSubject("ServiceAccount", "test-sa", "test-namespace")

	AssertEqual(t, "ServiceAccount", subject.Kind, "Kind mismatch")
	AssertEqual(t, "test-sa", subject.Name, "Name mismatch")
	AssertEqual(t, "test-namespace", subject.Namespace, "Namespace mismatch")
}

func TestAssertEqual(t *testing.T) {
	// Test passing case
	AssertEqual(t, "test", "test", "Values should be equal")

	// Test failing case
	mockT := &testing.T{}
	AssertEqual(mockT, "expected", "actual", "Test message")
	if !mockT.Failed() {
		t.Error("AssertEqual should have failed")
	}
}

func TestAssertNotNil(t *testing.T) {
	// Test passing case
	value := "not nil"
	AssertNotNil(t, value, "Value should not be nil")

	// Test failing case
	mockT := &testing.T{}
	AssertNotNil(mockT, nil, "Test message")
	if !mockT.Failed() {
		t.Error("AssertNotNil should have failed")
	}
}

func TestAssertNil(t *testing.T) {
	// Test passing case
	var value interface{}
	AssertNil(t, value, "Value should be nil")

	// Test failing case
	mockT := &testing.T{}
	AssertNil(mockT, "not nil", "Test message")
	if !mockT.Failed() {
		t.Error("AssertNil should have failed")
	}
}

func TestAssertContains(t *testing.T) {
	// Test passing case
	slice := []string{"apple", "banana", "orange"}
	AssertContains(t, slice, "banana", "Slice should contain banana")

	// Test failing case
	mockT := &testing.T{}
	AssertContains(mockT, slice, "grape", "Test message")
	if !mockT.Failed() {
		t.Error("AssertContains should have failed")
	}
}

func TestAssertLen(t *testing.T) {
	t.Run("string slice", func(t *testing.T) {
		slice := []string{"one", "two", "three"}
		AssertLen(t, slice, 3, "String slice length")
	})

	t.Run("PolicyRule slice", func(t *testing.T) {
		rules := []rbacv1.PolicyRule{
			{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get"}},
			{APIGroups: []string{"apps"}, Resources: []string{"deployments"}, Verbs: []string{"list"}},
		}
		AssertLen(t, rules, 2, "PolicyRule slice length")
	})

	t.Run("Subject slice", func(t *testing.T) {
		subjects := []rbacv1.Subject{
			{Kind: "User", Name: "user1"},
			{Kind: "ServiceAccount", Name: "sa1"},
			{Kind: "Group", Name: "group1"},
		}
		AssertLen(t, subjects, 3, "Subject slice length")
	})

	t.Run("runtime.Object slice", func(t *testing.T) {
		objects := []runtime.Object{
			NewTestRole("role1", "ns1"),
			NewTestClusterRole("clusterrole1"),
		}
		AssertLen(t, objects, 2, "runtime.Object slice length")
	})

	t.Run("failing case", func(t *testing.T) {
		mockT := &testing.T{}
		slice := []string{"one", "two"}
		AssertLen(mockT, slice, 3, "Test message")
		if !mockT.Failed() {
			t.Error("AssertLen should have failed")
		}
	})
}
