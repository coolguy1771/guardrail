package parser

import (
	"fmt"
	"io"
	"os"

	"gopkg.in/yaml.v3"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer"
)

// Parser handles parsing of Kubernetes RBAC YAML manifests
type Parser struct {
	decoder runtime.Decoder
}

// New creates a new Parser instance
func New() *Parser {
	scheme := runtime.NewScheme()
	rbacv1.AddToScheme(scheme)
	
	codecFactory := serializer.NewCodecFactory(scheme)
	decoder := codecFactory.UniversalDeserializer()
	
	return &Parser{
		decoder: decoder,
	}
}

// ParseFile parses a single RBAC YAML file
func (p *Parser) ParseFile(filename string) ([]runtime.Object, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	return p.Parse(file)
}

// Parse parses RBAC YAML from a reader
func (p *Parser) Parse(reader io.Reader) ([]runtime.Object, error) {
	var objects []runtime.Object
	
	decoder := yaml.NewDecoder(reader)
	for {
		var doc interface{}
		err := decoder.Decode(&doc)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("failed to decode YAML: %w", err)
		}
		
		// Skip empty documents
		if doc == nil {
			continue
		}
		
		// Convert back to YAML bytes for k8s decoder
		yamlBytes, err := yaml.Marshal(doc)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal YAML: %w", err)
		}
		
		obj, gvk, err := p.decoder.Decode(yamlBytes, nil, nil)
		if err != nil {
			// Skip non-RBAC resources
			continue
		}
		
		// Only process RBAC resources
		if gvk.Group == "rbac.authorization.k8s.io" {
			objects = append(objects, obj)
		}
	}
	
	return objects, nil
}

// GetObjectKind returns the kind of the runtime object
func GetObjectKind(obj runtime.Object) string {
	switch obj.(type) {
	case *rbacv1.Role:
		return "Role"
	case *rbacv1.RoleBinding:
		return "RoleBinding"
	case *rbacv1.ClusterRole:
		return "ClusterRole"
	case *rbacv1.ClusterRoleBinding:
		return "ClusterRoleBinding"
	default:
		return "Unknown"
	}
}

// GetObjectGVK returns the GroupVersionKind of the runtime object
func GetObjectGVK(obj runtime.Object) schema.GroupVersionKind {
	switch obj.(type) {
	case *rbacv1.Role:
		return rbacv1.SchemeGroupVersion.WithKind("Role")
	case *rbacv1.RoleBinding:
		return rbacv1.SchemeGroupVersion.WithKind("RoleBinding")
	case *rbacv1.ClusterRole:
		return rbacv1.SchemeGroupVersion.WithKind("ClusterRole")
	case *rbacv1.ClusterRoleBinding:
		return rbacv1.SchemeGroupVersion.WithKind("ClusterRoleBinding")
	default:
		return schema.GroupVersionKind{}
	}
}