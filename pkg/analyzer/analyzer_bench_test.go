package analyzer //nolint:testpackage // Uses internal analyzer fields for testing

import (
	"context"
	"fmt"
	"testing"

	"k8s.io/apimachinery/pkg/runtime"

	rbacv1 "k8s.io/api/rbac/v1"

	"github.com/coolguy1771/guardrail/internal/testutil"
)

func BenchmarkAnalyzePermissions(b *testing.B) {
	// Create test data
	objects := createBenchmarkObjects()
	analyzer := NewAnalyzerFromObjects(objects)
	ctx := context.Background()

	b.ResetTimer()
	for range b.N {
		_, err := analyzer.AnalyzePermissions(ctx)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkAnalyzePermissionsLarge(b *testing.B) {
	// Create large test data set
	objects := createLargeBenchmarkObjects()
	analyzer := NewAnalyzerFromObjects(objects)
	ctx := context.Background()

	b.ResetTimer()
	for range b.N {
		_, err := analyzer.AnalyzePermissions(ctx)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkFilterBySubject(b *testing.B) {
	objects := createBenchmarkObjects()
	analyzer := NewAnalyzerFromObjects(objects)
	ctx := context.Background()
	permissions, err := analyzer.AnalyzePermissions(ctx)
	if err != nil {
		b.Fatalf("failed to analyze permissions: %v", err)
	}

	b.ResetTimer()
	for range b.N {
		_ = FilterBySubject(permissions, "admin")
	}
}

func BenchmarkFilterByRiskLevel(b *testing.B) {
	objects := createBenchmarkObjects()
	analyzer := NewAnalyzerFromObjects(objects)
	ctx := context.Background()
	permissions, err := analyzer.AnalyzePermissions(ctx)
	if err != nil {
		b.Fatalf("failed to analyze permissions: %v", err)
	}

	b.ResetTimer()
	for range b.N {
		_ = FilterByRiskLevel(permissions, RiskLevelHigh)
	}
}

func createBenchmarkObjects() []runtime.Object {
	var objects []runtime.Object

	// Create roles
	for i := range 10 {
		roleName := fmt.Sprintf("test-role-%d", i)
		role := testutil.NewTestRole(roleName, "default")
		testutil.AddRule(role, rbacv1.PolicyRule{
			APIGroups: []string{""},
			Resources: []string{"pods", "services"},
			Verbs:     []string{"get", "list", "watch"},
		})
		objects = append(objects, role)
	}

	// Create bindings
	for i := range 10 {
		bindingName := fmt.Sprintf("test-binding-%d", i)
		roleName := fmt.Sprintf("test-role-%d", i)
		binding := testutil.NewTestRoleBinding(bindingName, "default", rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "Role",
			Name:     roleName,
		})
		testutil.AddSubject(binding, rbacv1.Subject{
			Kind: "User",
			Name: fmt.Sprintf("user-%d", i),
		})
		objects = append(objects, binding)
	}

	return objects
}

func createLargeBenchmarkObjects() []runtime.Object {
	var objects []runtime.Object

	// Create many roles with various permissions
	for i := range 100 {
		roleName := fmt.Sprintf("cluster-role-%d", i)
		role := testutil.NewTestClusterRole(roleName)
		for range 5 {
			testutil.AddRule(role, rbacv1.PolicyRule{
				APIGroups: []string{"", "apps", "batch"},
				Resources: []string{"pods", "deployments", "jobs"},
				Verbs:     []string{"get", "list", "watch", "create", "update", "patch", "delete"},
			})
		}
		objects = append(objects, role)
	}

	// Create many bindings
	for i := range 200 {
		bindingName := fmt.Sprintf("cluster-binding-%d", i)
		// Map each binding to a role (cycling through the 100 roles)
		roleName := fmt.Sprintf("cluster-role-%d", i%100)
		binding := testutil.NewTestClusterRoleBinding(bindingName, rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     roleName,
		})
		for j := range 3 {
			testutil.AddSubject(binding, rbacv1.Subject{
				Kind: "User",
				Name: fmt.Sprintf("user-%d-%d", i, j),
			})
		}
		objects = append(objects, binding)
	}

	return objects
}
