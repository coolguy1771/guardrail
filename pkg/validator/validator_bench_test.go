package validator

import (
	"testing"

	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/coolguy1771/guardrail/internal/testutil"
)

func BenchmarkValidateRole(b *testing.B) {
	v := New()
	role := testutil.NewTestRole("test-role", "default")
	testutil.AddRule(role, rbacv1.PolicyRule{
		APIGroups: []string{"*"},
		Resources: []string{"*"},
		Verbs:     []string{"*"},
	})

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		v.ValidateObject(role)
	}
}

func BenchmarkValidateMultipleObjects(b *testing.B) {
	v := New()
	objects := createBenchmarkObjects()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		v.ValidateObjects(objects)
	}
}

func BenchmarkValidateComplexRules(b *testing.B) {
	v := New()
	role := testutil.NewTestClusterRole("complex-role")
	
	// Add many complex rules
	for i := 0; i < 20; i++ {
		testutil.AddRule(role, rbacv1.PolicyRule{
			APIGroups: []string{"", "apps", "batch", "extensions"},
			Resources: []string{"pods", "deployments", "services", "configmaps", "secrets"},
			Verbs:     []string{"get", "list", "watch", "create", "update", "patch", "delete"},
		})
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		v.ValidateObject(role)
	}
}

func BenchmarkWildcardDetection(b *testing.B) {
	v := New()
	
	// Create roles with different wildcard patterns
	roles := []runtime.Object{
		createRoleWithWildcard("*", "pods", "get"),
		createRoleWithWildcard("apps", "*", "list"),
		createRoleWithWildcard("", "configmaps", "*"),
		createRoleWithWildcard("*", "*", "*"),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, role := range roles {
			v.ValidateObject(role)
		}
	}
}

func createRoleWithWildcard(apiGroup, resource, verb string) *rbacv1.Role {
	role := testutil.NewTestRole("wildcard-role", "default")
	testutil.AddRule(role, rbacv1.PolicyRule{
		APIGroups: []string{apiGroup},
		Resources: []string{resource},
		Verbs:     []string{verb},
	})
	return role
}

func createBenchmarkObjects() []runtime.Object {
	var objects []runtime.Object

	// Mix of different RBAC objects
	for i := 0; i < 10; i++ {
		// Role with wildcard
		role1 := testutil.NewTestRole("role-wildcard", "default")
		testutil.AddRule(role1, rbacv1.PolicyRule{
			APIGroups: []string{"*"},
			Resources: []string{"pods"},
			Verbs:     []string{"*"},
		})
		objects = append(objects, role1)

		// ClusterRole with admin binding
		cr := testutil.NewTestClusterRole("test-admin")
		objects = append(objects, cr)
		
		crb := testutil.NewTestClusterRoleBinding("admin-binding", rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     "cluster-admin",
		})
		objects = append(objects, crb)

		// Role with secrets access
		role2 := testutil.NewTestRole("secrets-role", "default")
		testutil.AddRule(role2, rbacv1.PolicyRule{
			APIGroups: []string{""},
			Resources: []string{"secrets"},
			Verbs:     []string{"get", "list"},
		})
		objects = append(objects, role2)
	}

	return objects
}