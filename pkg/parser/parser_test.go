package parser_test

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"

	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/coolguy1771/guardrail/internal/testutil"
	"github.com/coolguy1771/guardrail/pkg/parser"
)

const validRoleYAML = `
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: pod-reader
  namespace: default
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "list", "watch"]
`

const validClusterRoleYAML = `
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: secret-reader
rules:
- apiGroups: [""]
  resources: ["secrets"]
  verbs: ["get", "list"]
`

const validRoleBindingYAML = `
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: read-pods
  namespace: default
subjects:
- kind: User
  name: jane
  apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: Role
  name: pod-reader
  apiGroup: rbac.authorization.k8s.io
`

const validClusterRoleBindingYAML = `
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: read-secrets-global
subjects:
- kind: Group
  name: developers
  apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: ClusterRole
  name: secret-reader
  apiGroup: rbac.authorization.k8s.io
`

const multiDocumentYAML = `
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: role1
  namespace: default
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: role2
  namespace: default
rules:
- apiGroups: [""]
  resources: ["services"]
  verbs: ["list"]
`

const nonRBACYAML = `
apiVersion: v1
kind: ConfigMap
metadata:
  name: test-config
data:
  key: value
`

const mixedYAML = `
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: test-role
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get"]
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: test-config
data:
  key: value
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: test-cluster-role
rules:
- apiGroups: [""]
  resources: ["nodes"]
  verbs: ["list"]
`

const invalidYAML = `
this is not valid YAML
{ "also": "not yaml"
`

const emptyDocumentYAML = `
---
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: test-role
rules: []
---
---
`

func TestNew(t *testing.T) {
	p := parser.New()
	testutil.AssertNotNil(t, p, "New() should return non-nil parser")
	// Cannot test unexported field decoder in external test package
}

func TestParse_ValidRole(t *testing.T) {
	p := parser.New()
	reader := strings.NewReader(validRoleYAML)

	objects, err := p.Parse(reader)
	testutil.AssertNil(t, err, "Parse should not return error for valid YAML")
	testutil.AssertEqual(t, 1, len(objects), "should parse 1 object")

	if len(objects) > 0 {
		role, ok := objects[0].(*rbacv1.Role)
		if !ok {
			t.Fatalf("expected *rbacv1.Role, got %T", objects[0])
		}
		testutil.AssertEqual(t, "pod-reader", role.Name, "role name")
		testutil.AssertEqual(t, "default", role.Namespace, "role namespace")
		testutil.AssertEqual(t, 1, len(role.Rules), "role should have 1 rule")
	}
}

func TestParse_ValidClusterRole(t *testing.T) {
	p := parser.New()
	reader := strings.NewReader(validClusterRoleYAML)

	objects, err := p.Parse(reader)
	testutil.AssertNil(t, err, "Parse should not return error")
	testutil.AssertEqual(t, 1, len(objects), "should parse 1 object")

	if len(objects) > 0 {
		cr, ok := objects[0].(*rbacv1.ClusterRole)
		if !ok {
			t.Fatalf("expected *rbacv1.ClusterRole, got %T", objects[0])
		}
		testutil.AssertEqual(t, "secret-reader", cr.Name, "cluster role name")
		testutil.AssertEqual(t, 1, len(cr.Rules), "should have 1 rule")
	}
}

func TestParse_ValidRoleBinding(t *testing.T) {
	p := parser.New()
	reader := strings.NewReader(validRoleBindingYAML)

	objects, err := p.Parse(reader)
	testutil.AssertNil(t, err, "Parse should not return error")
	testutil.AssertEqual(t, 1, len(objects), "should parse 1 object")

	if len(objects) > 0 {
		rb, ok := objects[0].(*rbacv1.RoleBinding)
		if !ok {
			t.Fatalf("expected *rbacv1.RoleBinding, got %T", objects[0])
		}
		testutil.AssertEqual(t, "read-pods", rb.Name, "role binding name")
		testutil.AssertEqual(t, 1, len(rb.Subjects), "should have 1 subject")
		testutil.AssertEqual(t, "jane", rb.Subjects[0].Name, "subject name")
	}
}

func TestParse_ValidClusterRoleBinding(t *testing.T) {
	p := parser.New()
	reader := strings.NewReader(validClusterRoleBindingYAML)

	objects, err := p.Parse(reader)
	testutil.AssertNil(t, err, "Parse should not return error")
	testutil.AssertEqual(t, 1, len(objects), "should parse 1 object")

	if len(objects) > 0 {
		crb, ok := objects[0].(*rbacv1.ClusterRoleBinding)
		if !ok {
			t.Fatalf("expected *rbacv1.ClusterRoleBinding, got %T", objects[0])
		}
		testutil.AssertEqual(t, "read-secrets-global", crb.Name, "cluster role binding name")
		testutil.AssertEqual(t, "developers", crb.Subjects[0].Name, "subject group name")
	}
}

func TestParse_MultiDocument(t *testing.T) {
	p := parser.New()
	reader := strings.NewReader(multiDocumentYAML)

	objects, err := p.Parse(reader)
	testutil.AssertNil(t, err, "Parse should not return error")
	testutil.AssertEqual(t, 2, len(objects), "should parse 2 objects")

	// Check both roles
	for i, obj := range objects {
		role, ok := obj.(*rbacv1.Role)
		if !ok {
			t.Fatalf("expected *rbacv1.Role for object %d, got %T", i, obj)
		}
		expectedName := fmt.Sprintf("role%d", i+1)
		testutil.AssertEqual(t, expectedName, role.Name, "role name")
	}
}

func TestParse_NonRBAC(t *testing.T) {
	p := parser.New()
	reader := strings.NewReader(nonRBACYAML)

	objects, err := p.Parse(reader)
	testutil.AssertNil(t, err, "Parse should not return error")
	testutil.AssertEqual(t, 0, len(objects), "should parse 0 RBAC objects")
}

func TestParse_Mixed(t *testing.T) {
	p := parser.New()
	reader := strings.NewReader(mixedYAML)

	objects, err := p.Parse(reader)
	testutil.AssertNil(t, err, "Parse should not return error")
	testutil.AssertEqual(t, 2, len(objects), "should parse 2 RBAC objects (ignoring ConfigMap)")

	// Check that we got the right types
	roleFound := false
	clusterRoleFound := false

	for _, obj := range objects {
		switch obj.(type) {
		case *rbacv1.Role:
			roleFound = true
		case *rbacv1.ClusterRole:
			clusterRoleFound = true
		}
	}

	if !roleFound {
		t.Error("expected to find Role")
	}
	if !clusterRoleFound {
		t.Error("expected to find ClusterRole")
	}
}

func TestParse_InvalidYAML(t *testing.T) {
	p := parser.New()
	reader := strings.NewReader(invalidYAML)

	_, err := p.Parse(reader)
	testutil.AssertNotNil(t, err, "Parse should return error for invalid YAML")
	if err != nil && !strings.Contains(err.Error(), "failed to decode YAML") {
		t.Errorf("expected error to contain 'failed to decode YAML', got: %v", err)
	}
}

func TestParse_EmptyDocuments(t *testing.T) {
	p := parser.New()
	reader := strings.NewReader(emptyDocumentYAML)

	objects, err := p.Parse(reader)
	testutil.AssertNil(t, err, "Parse should not return error")
	testutil.AssertEqual(t, 1, len(objects), "should parse 1 object (ignoring empty documents)")
}

func TestParse_EmptyReader(t *testing.T) {
	p := parser.New()
	reader := strings.NewReader("")

	objects, err := p.Parse(reader)
	testutil.AssertNil(t, err, "Parse should not return error for empty input")
	testutil.AssertEqual(t, 0, len(objects), "should parse 0 objects")
}

func TestParseFile(t *testing.T) {
	// Create a temporary file with valid YAML
	tmpfile, err := os.CreateTemp(t.TempDir(), "test-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpfile.Name())

	if _, writeErr := tmpfile.WriteString(validRoleYAML); writeErr != nil {
		t.Fatal(writeErr)
	}
	if closeErr := tmpfile.Close(); closeErr != nil {
		t.Fatal(closeErr)
	}

	p := parser.New()
	objects, err := p.ParseFile(tmpfile.Name())
	testutil.AssertNil(t, err, "ParseFile should not return error")
	testutil.AssertEqual(t, 1, len(objects), "should parse 1 object")
}

func TestParseFile_NonExistent(t *testing.T) {
	p := parser.New()
	_, err := p.ParseFile("/non/existent/file.yaml")
	testutil.AssertNotNil(t, err, "ParseFile should return error for non-existent file")
	if err != nil && !strings.Contains(err.Error(), "failed to open file") {
		t.Errorf("expected error to contain 'failed to open file', got: %v", err)
	}
}

func TestGetObjectKind(t *testing.T) {
	tests := []struct {
		name     string
		object   runtime.Object
		expected string
	}{
		{
			name:     "Role",
			object:   &rbacv1.Role{},
			expected: "Role",
		},
		{
			name:     "RoleBinding",
			object:   &rbacv1.RoleBinding{},
			expected: "RoleBinding",
		},
		{
			name:     "ClusterRole",
			object:   &rbacv1.ClusterRole{},
			expected: "ClusterRole",
		},
		{
			name:     "ClusterRoleBinding",
			object:   &rbacv1.ClusterRoleBinding{},
			expected: "ClusterRoleBinding",
		},
		{
			name:     "Unknown",
			object:   &metav1.Status{},
			expected: "Unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parser.GetObjectKind(tt.object)
			testutil.AssertEqual(t, tt.expected, result, "object kind")
		})
	}
}

func TestGetObjectGVK(t *testing.T) {
	tests := []struct {
		name         string
		object       runtime.Object
		expectedKind string
		isEmpty      bool
	}{
		{
			name:         "Role",
			object:       &rbacv1.Role{},
			expectedKind: "Role",
			isEmpty:      false,
		},
		{
			name:         "RoleBinding",
			object:       &rbacv1.RoleBinding{},
			expectedKind: "RoleBinding",
			isEmpty:      false,
		},
		{
			name:         "ClusterRole",
			object:       &rbacv1.ClusterRole{},
			expectedKind: "ClusterRole",
			isEmpty:      false,
		},
		{
			name:         "ClusterRoleBinding",
			object:       &rbacv1.ClusterRoleBinding{},
			expectedKind: "ClusterRoleBinding",
			isEmpty:      false,
		},
		{
			name:         "Unknown",
			object:       &metav1.Status{},
			expectedKind: "",
			isEmpty:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parser.GetObjectGVK(tt.object)

			if tt.isEmpty {
				if result != (schema.GroupVersionKind{}) {
					t.Errorf("expected empty GVK, got %v", result)
				}
			} else {
				testutil.AssertEqual(t, tt.expectedKind, result.Kind, "GVK kind")
				testutil.AssertEqual(t, "rbac.authorization.k8s.io", result.Group, "GVK group")
				testutil.AssertEqual(t, "v1", result.Version, "GVK version")
			}
		})
	}
}

// Custom reader that returns an error after some data.
type errorReader struct {
	data []byte
	err  error
}

func (r *errorReader) Read(p []byte) (int, error) {
	if len(r.data) > 0 {
		n := copy(p, r.data)
		r.data = r.data[n:]
		return n, nil
	}
	return 0, r.err
}

func TestParse_ReaderError(t *testing.T) {
	p := parser.New()
	reader := &errorReader{
		data: []byte("invalid: yaml: content:"),
		err:  errors.New("read error"),
	}

	_, err := p.Parse(reader)
	testutil.AssertNotNil(t, err, "Parse should return error when reader fails")
}

func TestParse_YAMLMarshalError(t *testing.T) {
	// This test is difficult to trigger naturally as yaml.Marshal rarely fails
	// with valid input from yaml.Decode. Skipping for now.
	t.Skip("Difficult to trigger yaml.Marshal error with valid decoded data")
}
