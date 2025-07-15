package analyzer

import (
	"testing"

	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/coolguy1771/guardrail/internal/testutil"
)

func BenchmarkAnalyzePermissions(b *testing.B) {
	// Create test data
	objects := createBenchmarkObjects()
	analyzer := NewAnalyzerFromObjects(objects)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := analyzer.AnalyzePermissions()
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkAnalyzePermissionsLarge(b *testing.B) {
	// Create large test data set
	objects := createLargeBenchmarkObjects()
	analyzer := NewAnalyzerFromObjects(objects)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := analyzer.AnalyzePermissions()
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkFilterBySubject(b *testing.B) {
	objects := createBenchmarkObjects()
	analyzer := NewAnalyzerFromObjects(objects)
	permissions, _ := analyzer.AnalyzePermissions()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = filterBySubject(permissions, "admin")
	}
}

func BenchmarkFilterByRiskLevel(b *testing.B) {
	objects := createBenchmarkObjects()
	analyzer := NewAnalyzerFromObjects(objects)
	permissions, _ := analyzer.AnalyzePermissions()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = filterByRiskLevel(permissions, RiskLevelHigh)
	}
}

func createBenchmarkObjects() []runtime.Object {
	var objects []runtime.Object

	// Create roles
	for i := 0; i < 10; i++ {
		role := testutil.NewTestRole("test-role", "default")
		testutil.AddRule(role, rbacv1.PolicyRule{
			APIGroups: []string{""},
			Resources: []string{"pods", "services"},
			Verbs:     []string{"get", "list", "watch"},
		})
		objects = append(objects, role)
	}

	// Create bindings
	for i := 0; i < 10; i++ {
		binding := testutil.NewTestRoleBinding("test-binding", "default", rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "Role",
			Name:     "test-role",
		})
		testutil.AddSubject(binding, rbacv1.Subject{
			Kind: "User",
			Name: "user",
		})
		objects = append(objects, binding)
	}

	return objects
}

func createLargeBenchmarkObjects() []runtime.Object {
	var objects []runtime.Object

	// Create many roles with various permissions
	for i := 0; i < 100; i++ {
		role := testutil.NewTestClusterRole("cluster-role")
		for j := 0; j < 5; j++ {
			testutil.AddRule(role, rbacv1.PolicyRule{
				APIGroups: []string{"", "apps", "batch"},
				Resources: []string{"pods", "deployments", "jobs"},
				Verbs:     []string{"get", "list", "watch", "create", "update", "patch", "delete"},
			})
		}
		objects = append(objects, role)
	}

	// Create many bindings
	for i := 0; i < 200; i++ {
		binding := testutil.NewTestClusterRoleBinding("cluster-binding", rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     "cluster-role",
		})
		for j := 0; j < 3; j++ {
			testutil.AddSubject(binding, rbacv1.Subject{
				Kind: "User",
				Name: "user",
			})
		}
		objects = append(objects, binding)
	}

	return objects
}