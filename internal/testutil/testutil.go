package testutil

import (
	"fmt"
	"testing"

	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// NewTestRole creates a test Role with common defaults
func NewTestRole(name, namespace string) *rbacv1.Role {
	return &rbacv1.Role{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "rbac.authorization.k8s.io/v1",
			Kind:       "Role",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Rules: []rbacv1.PolicyRule{},
	}
}

// NewTestClusterRole creates a test ClusterRole with common defaults
func NewTestClusterRole(name string) *rbacv1.ClusterRole {
	return &rbacv1.ClusterRole{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "rbac.authorization.k8s.io/v1",
			Kind:       "ClusterRole",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Rules: []rbacv1.PolicyRule{},
	}
}

// NewTestRoleBinding creates a test RoleBinding with common defaults
func NewTestRoleBinding(name, namespace string, roleRef rbacv1.RoleRef) *rbacv1.RoleBinding {
	return &rbacv1.RoleBinding{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "rbac.authorization.k8s.io/v1",
			Kind:       "RoleBinding",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		RoleRef: roleRef,
		Subjects: []rbacv1.Subject{},
	}
}

// NewTestClusterRoleBinding creates a test ClusterRoleBinding with common defaults
func NewTestClusterRoleBinding(name string, roleRef rbacv1.RoleRef) *rbacv1.ClusterRoleBinding {
	return &rbacv1.ClusterRoleBinding{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "rbac.authorization.k8s.io/v1",
			Kind:       "ClusterRoleBinding",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		RoleRef: roleRef,
		Subjects: []rbacv1.Subject{},
	}
}

// AddRule adds a PolicyRule to a Role or ClusterRole
func AddRule(obj runtime.Object, rule rbacv1.PolicyRule) {
	switch v := obj.(type) {
	case *rbacv1.Role:
		v.Rules = append(v.Rules, rule)
	case *rbacv1.ClusterRole:
		v.Rules = append(v.Rules, rule)
	default:
		panic(fmt.Sprintf("AddRule: unsupported object type %T", obj))
	}
}

// AddSubject adds a Subject to a RoleBinding or ClusterRoleBinding
func AddSubject(obj runtime.Object, subject rbacv1.Subject) {
	switch v := obj.(type) {
	case *rbacv1.RoleBinding:
		v.Subjects = append(v.Subjects, subject)
	case *rbacv1.ClusterRoleBinding:
		v.Subjects = append(v.Subjects, subject)
	default:
		panic(fmt.Sprintf("AddSubject: unsupported object type %T", obj))
	}
}

// NewPolicyRule creates a PolicyRule with common defaults
func NewPolicyRule(apiGroups, resources, verbs []string) rbacv1.PolicyRule {
	return rbacv1.PolicyRule{
		APIGroups: apiGroups,
		Resources: resources,
		Verbs:     verbs,
	}
}

// NewSubject creates a Subject with common defaults
func NewSubject(kind, name, namespace string) rbacv1.Subject {
	return rbacv1.Subject{
		Kind:      kind,
		Name:      name,
		Namespace: namespace,
	}
}

// AssertEqual is a simple equality assertion helper
func AssertEqual(t *testing.T, expected, actual interface{}, message string) {
	t.Helper()
	if expected != actual {
		t.Errorf("%s: expected %v, got %v", message, expected, actual)
	}
}

// AssertNotNil asserts that a value is not nil
func AssertNotNil(t *testing.T, value interface{}, message string) {
	t.Helper()
	if value == nil {
		t.Errorf("%s: expected non-nil value", message)
	}
}

// AssertNil asserts that a value is nil
func AssertNil(t *testing.T, value interface{}, message string) {
	t.Helper()
	if value != nil {
		t.Errorf("%s: expected nil, got %v", message, value)
	}
}

// AssertContains asserts that a slice contains a specific value
func AssertContains(t *testing.T, slice []string, value string, message string) {
	t.Helper()
	for _, v := range slice {
		if v == value {
			return
		}
	}
	t.Errorf("%s: expected slice to contain %s, but it didn't", message, value)
}

// AssertLen asserts that a slice has a specific length
func AssertLen(t *testing.T, slice interface{}, expectedLen int, message string) {
	t.Helper()
	var actualLen int
	switch v := slice.(type) {
	case []string:
		actualLen = len(v)
	case []rbacv1.PolicyRule:
		actualLen = len(v)
	case []rbacv1.Subject:
		actualLen = len(v)
	case []runtime.Object:
		actualLen = len(v)
	default:
		t.Fatalf("%s: unsupported slice type", message)
	}
	
	if actualLen != expectedLen {
		t.Errorf("%s: expected length %d, got %d", message, expectedLen, actualLen)
	}
}