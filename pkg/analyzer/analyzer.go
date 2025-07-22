package analyzer

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"strings"

	"k8s.io/apimachinery/pkg/runtime"

	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/coolguy1771/guardrail/pkg/kubernetes"
)

// Analyzer provides RBAC analysis capabilities.
type Analyzer struct {
	rbacReader kubernetes.RBACReader
	objects    []runtime.Object
}

// NewAnalyzer returns a new Analyzer that uses the provided RBACReader to fetch RBAC resources from a live Kubernetes cluster.
func NewAnalyzer(rbacReader kubernetes.RBACReader) *Analyzer {
	//nolint:exhaustruct // objects field is intentionally nil for cluster-based analysis
	return &Analyzer{
		rbacReader: rbacReader,
	}
}

// NewAnalyzerFromObjects returns a new Analyzer that uses the provided Kubernetes runtime objects for RBAC analysis instead of fetching data from a live cluster.
func NewAnalyzerFromObjects(objects []runtime.Object) *Analyzer {
	//nolint:exhaustruct // rbacReader field is intentionally nil for object-based analysis
	return &Analyzer{
		objects: objects,
	}
}

// SubjectPermissions represents permissions for a specific subject.
type SubjectPermissions struct {
	Subject     rbacv1.Subject    `json:"subject"`
	Permissions []PermissionGrant `json:"permissions"`
	RiskLevel   RiskLevel         `json:"risk_level"`
}

// PermissionGrant represents a specific permission grant.
type PermissionGrant struct {
	RoleName    string               `json:"role_name"`
	RoleKind    string               `json:"role_kind"`
	Namespace   string               `json:"namespace,omitempty"`
	Scope       string               `json:"scope"`
	Rules       []PolicyRuleAnalysis `json:"rules"`
	BindingName string               `json:"binding_name"`
	BindingKind string               `json:"binding_kind"`
}

// PolicyRuleAnalysis provides detailed analysis of a policy rule.
type PolicyRuleAnalysis struct {
	APIGroups        []string          `json:"api_groups"`
	Resources        []string          `json:"resources"`
	Verbs            []string          `json:"verbs"`
	ResourceNames    []string          `json:"resource_names,omitempty"`
	NonResourceURLs  []string          `json:"non_resource_urls,omitempty"`
	HumanReadable    string            `json:"human_readable"`
	SecurityImpact   SecurityImpact    `json:"security_impact"`
	VerbExplanations []VerbExplanation `json:"verb_explanations"`
}

// VerbExplanation provides plain English explanation of what a verb allows.
type VerbExplanation struct {
	Verb        string `json:"verb"`
	Explanation string `json:"explanation"`
	RiskLevel   string `json:"risk_level"`
	Examples    string `json:"examples"`
}

// SecurityImpact describes the security implications of a rule.
type SecurityImpact struct {
	Level       RiskLevel `json:"level"`
	Description string    `json:"description"`
	Concerns    []string  `json:"concerns"`
}

// RiskLevel represents the risk level of permissions.
type RiskLevel string

const (
	RiskLevelLow      RiskLevel = "low"
	RiskLevelMedium   RiskLevel = "medium"
	RiskLevelHigh     RiskLevel = "high"
	RiskLevelCritical RiskLevel = "critical"

	// Risk priority values.
	riskPriorityCritical = 4
	riskPriorityHigh     = 3
	riskPriorityMedium   = 2
	riskPriorityLow      = 1
	riskPriorityDefault  = 0
)

// AnalyzePermissions analyzes all subjects and their permissions.
func (a *Analyzer) AnalyzePermissions(ctx context.Context) ([]SubjectPermissions, error) {
	var allBindings []runtime.Object
	var allRoles []runtime.Object

	if a.rbacReader != nil {
		// Fetch from cluster
		bindings, roles, err := a.fetchFromCluster(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch from cluster: %w", err)
		}
		allBindings = bindings
		allRoles = roles
	} else {
		// Use provided objects
		for _, obj := range a.objects {
			switch obj.(type) {
			case *rbacv1.RoleBinding, *rbacv1.ClusterRoleBinding:
				allBindings = append(allBindings, obj)
			case *rbacv1.Role, *rbacv1.ClusterRole:
				allRoles = append(allRoles, obj)
			}
		}
	}

	// Build role map for quick lookup
	roleMap := a.buildRoleMap(allRoles)

	// Group permissions by subject
	subjectMap := make(map[string]*SubjectPermissions)

	for _, binding := range allBindings {
		permissions := a.analyzeBinding(binding, roleMap)
		for _, perm := range permissions {
			key := a.getSubjectKey(perm.Subject)
			if existing, exists := subjectMap[key]; exists {
				existing.Permissions = append(existing.Permissions, perm.Permissions...)
			} else {
				subjectMap[key] = perm
			}
		}
	}

	// Calculate risk levels and convert to slice
	var result []SubjectPermissions
	for _, subject := range subjectMap {
		subject.RiskLevel = a.calculateRiskLevel(subject.Permissions)
		result = append(result, *subject)
	}

	// Sort by risk level and subject name
	sort.Slice(result, func(i, j int) bool {
		if result[i].RiskLevel != result[j].RiskLevel {
			return a.getRiskPriority(result[i].RiskLevel) > a.getRiskPriority(result[j].RiskLevel)
		}
		return result[i].Subject.Name < result[j].Subject.Name
	})

	return result, nil
}

// fetchFromCluster fetches RBAC resources from the cluster.
func (a *Analyzer) fetchFromCluster(ctx context.Context) ([]runtime.Object, []runtime.Object, error) {
	var bindings, roles []runtime.Object

	// Fetch RoleBindings
	roleBindings, err := a.rbacReader.RoleBindings("").
		List(ctx, metav1.ListOptions{}) //nolint:exhaustruct // K8s API struct
	if err != nil {
		return nil, nil, fmt.Errorf("failed to fetch role bindings: %w", err)
	}
	for i := range roleBindings.Items {
		bindings = append(bindings, &roleBindings.Items[i])
	}

	// Fetch ClusterRoleBindings
	clusterRoleBindings, err := a.rbacReader.ClusterRoleBindings().
		List(ctx, metav1.ListOptions{}) //nolint:exhaustruct // K8s API struct
	if err != nil {
		return nil, nil, fmt.Errorf("failed to fetch cluster role bindings: %w", err)
	}
	for i := range clusterRoleBindings.Items {
		bindings = append(bindings, &clusterRoleBindings.Items[i])
	}

	// Fetch Roles
	roleList, err := a.rbacReader.Roles("").List(ctx, metav1.ListOptions{}) //nolint:exhaustruct // K8s API struct
	if err != nil {
		return nil, nil, fmt.Errorf("failed to fetch roles: %w", err)
	}
	for i := range roleList.Items {
		roles = append(roles, &roleList.Items[i])
	}

	// Fetch ClusterRoles
	clusterRoleList, err := a.rbacReader.ClusterRoles().
		List(ctx, metav1.ListOptions{}) //nolint:exhaustruct // K8s API struct
	if err != nil {
		return nil, nil, fmt.Errorf("failed to fetch cluster roles: %w", err)
	}
	for i := range clusterRoleList.Items {
		roles = append(roles, &clusterRoleList.Items[i])
	}

	return bindings, roles, nil
}

// buildRoleMap creates a map for quick role lookup.
func (a *Analyzer) buildRoleMap(roles []runtime.Object) map[string]runtime.Object {
	roleMap := make(map[string]runtime.Object)

	for _, role := range roles {
		switch r := role.(type) {
		case *rbacv1.Role:
			key := fmt.Sprintf("Role/%s/%s", r.Namespace, r.Name)
			roleMap[key] = role
		case *rbacv1.ClusterRole:
			key := fmt.Sprintf("ClusterRole//%s", r.Name)
			roleMap[key] = role
		}
	}

	return roleMap
}

// analyzeBinding analyzes a single binding and returns permissions for each subject.
func (a *Analyzer) analyzeBinding(binding runtime.Object, roleMap map[string]runtime.Object) []*SubjectPermissions {
	var result []*SubjectPermissions

	switch b := binding.(type) {
	case *rbacv1.RoleBinding:
		result = a.analyzeRoleBinding(b, roleMap)
	case *rbacv1.ClusterRoleBinding:
		result = a.analyzeClusterRoleBinding(b, roleMap)
	}

	return result
}

// analyzeRoleBinding analyzes a RoleBinding.
func (a *Analyzer) analyzeRoleBinding(
	binding *rbacv1.RoleBinding,
	roleMap map[string]runtime.Object,
) []*SubjectPermissions {
	var result []*SubjectPermissions

	// Find the referenced role
	var roleKey string
	var scope string
	if binding.RoleRef.Kind == "ClusterRole" {
		roleKey = fmt.Sprintf("ClusterRole//%s", binding.RoleRef.Name)
		scope = fmt.Sprintf("namespace:%s", binding.Namespace)
	} else {
		roleKey = fmt.Sprintf("Role/%s/%s", binding.Namespace, binding.RoleRef.Name)
		scope = fmt.Sprintf("namespace:%s", binding.Namespace)
	}

	role, exists := roleMap[roleKey]
	if !exists {
		// Role not found, create a placeholder
		for _, subject := range binding.Subjects {
			//nolint:exhaustruct // RiskLevel is calculated after all permissions are collected
			result = append(result, &SubjectPermissions{
				Subject: subject,
				Permissions: []PermissionGrant{
					{
						RoleName:    binding.RoleRef.Name,
						RoleKind:    binding.RoleRef.Kind,
						Namespace:   binding.Namespace,
						Scope:       scope,
						Rules:       []PolicyRuleAnalysis{},
						BindingName: binding.Name,
						BindingKind: "RoleBinding",
					},
				},
			})
		}
		return result
	}

	// Analyze the role
	var rules []rbacv1.PolicyRule
	switch r := role.(type) {
	case *rbacv1.Role:
		rules = r.Rules
	case *rbacv1.ClusterRole:
		rules = r.Rules
	}

	analyzedRules := a.analyzeRules(rules)

	// Create permissions for each subject
	for _, subject := range binding.Subjects {
		//nolint:exhaustruct // RiskLevel is calculated after all permissions are collected
		result = append(result, &SubjectPermissions{
			Subject: subject,
			Permissions: []PermissionGrant{
				{
					RoleName:    binding.RoleRef.Name,
					RoleKind:    binding.RoleRef.Kind,
					Namespace:   binding.Namespace,
					Scope:       scope,
					Rules:       analyzedRules,
					BindingName: binding.Name,
					BindingKind: "RoleBinding",
				},
			},
		})
	}

	return result
}

// analyzeClusterRoleBinding analyzes a ClusterRoleBinding.
func (a *Analyzer) analyzeClusterRoleBinding(
	binding *rbacv1.ClusterRoleBinding,
	roleMap map[string]runtime.Object,
) []*SubjectPermissions {
	var result []*SubjectPermissions

	roleKey := fmt.Sprintf("ClusterRole//%s", binding.RoleRef.Name)
	role, exists := roleMap[roleKey]

	if !exists {
		// Role not found, create a placeholder
		for _, subject := range binding.Subjects {
			//nolint:exhaustruct // RiskLevel is calculated after all permissions are collected
			result = append(result, &SubjectPermissions{
				Subject: subject,
				Permissions: []PermissionGrant{
					//nolint:exhaustruct // Namespace is empty for cluster-wide permissions
					{
						RoleName:    binding.RoleRef.Name,
						RoleKind:    binding.RoleRef.Kind,
						Scope:       "cluster-wide",
						Rules:       []PolicyRuleAnalysis{},
						BindingName: binding.Name,
						BindingKind: "ClusterRoleBinding",
					},
				},
			})
		}
		return result
	}

	clusterRole, ok := role.(*rbacv1.ClusterRole)
	if !ok {
		// This should not happen, but handle it gracefully
		return result
	}
	analyzedRules := a.analyzeRules(clusterRole.Rules)

	// Create permissions for each subject
	for _, subject := range binding.Subjects {
		//nolint:exhaustruct // RiskLevel is calculated after all permissions are collected
		result = append(result, &SubjectPermissions{
			Subject: subject,
			Permissions: []PermissionGrant{
				//nolint:exhaustruct // Namespace is empty for cluster-wide permissions
				{
					RoleName:    binding.RoleRef.Name,
					RoleKind:    binding.RoleRef.Kind,
					Scope:       "cluster-wide",
					Rules:       analyzedRules,
					BindingName: binding.Name,
					BindingKind: "ClusterRoleBinding",
				},
			},
		})
	}

	return result
}

// analyzeRules analyzes policy rules and provides human-readable explanations.
func (a *Analyzer) analyzeRules(rules []rbacv1.PolicyRule) []PolicyRuleAnalysis {
	var result []PolicyRuleAnalysis

	for _, rule := range rules {
		//nolint:exhaustruct // HumanReadable, SecurityImpact, and VerbExplanations are populated below
		analysis := PolicyRuleAnalysis{
			APIGroups:       rule.APIGroups,
			Resources:       rule.Resources,
			Verbs:           rule.Verbs,
			ResourceNames:   rule.ResourceNames,
			NonResourceURLs: rule.NonResourceURLs,
		}

		// Generate human-readable explanation
		analysis.HumanReadable = a.generateHumanReadableExplanation(rule)

		// Analyze security impact
		analysis.SecurityImpact = a.analyzeSecurityImpact(rule)

		// Explain each verb
		analysis.VerbExplanations = a.explainVerbs(rule.Verbs, rule.Resources)

		result = append(result, analysis)
	}

	return result
}

// generateHumanReadableExplanation creates a human-readable explanation of the rule.
func (a *Analyzer) generateHumanReadableExplanation(rule rbacv1.PolicyRule) string {
	var parts []string

	// Handle non-resource URLs
	if len(rule.NonResourceURLs) > 0 {
		parts = append(parts, fmt.Sprintf("Access to API endpoints: %s", strings.Join(rule.NonResourceURLs, ", ")))
		return strings.Join(parts, ". ")
	}

	// Handle resources
	resources := rule.Resources
	if len(resources) == 0 || (len(resources) == 1 && resources[0] == "*") {
		parts = append(parts, "Access to ALL resources")
	} else {
		parts = append(parts, fmt.Sprintf("Access to: %s", strings.Join(resources, ", ")))
	}

	// Handle API groups
	if apiGroupPart := a.formatAPIGroups(rule.APIGroups); apiGroupPart != "" {
		parts = append(parts, apiGroupPart)
	}

	// Handle verbs
	verbs := rule.Verbs
	if len(verbs) == 1 && verbs[0] == "*" {
		parts = append(parts, "with ALL permissions")
	} else {
		parts = append(parts, fmt.Sprintf("with permissions: %s", strings.Join(verbs, ", ")))
	}

	// Handle resource names
	if len(rule.ResourceNames) > 0 {
		parts = append(parts, fmt.Sprintf("limited to specific resources: %s", strings.Join(rule.ResourceNames, ", ")))
	}

	return strings.Join(parts, " ")
}

// explainVerbs provides detailed explanations for each verb.
func (a *Analyzer) explainVerbs(verbs []string, resources []string) []VerbExplanation {
	var explanations []VerbExplanation

	verbMap := map[string]VerbExplanation{
		"get": {
			Verb:        "get",
			Explanation: "Read/retrieve individual resources by name",
			RiskLevel:   "low",
			Examples:    "kubectl get pod my-pod, viewing resource details",
		},
		"list": {
			Verb:        "list",
			Explanation: "List/view all resources of this type",
			RiskLevel:   "low",
			Examples:    "kubectl get pods, viewing all resources in namespace",
		},
		"watch": {
			Verb:        "watch",
			Explanation: "Monitor resources for changes in real-time",
			RiskLevel:   "low",
			Examples:    "kubectl get pods -w, real-time monitoring",
		},
		"create": {
			Verb:        "create",
			Explanation: "Create new resources",
			RiskLevel:   "medium",
			Examples:    "kubectl create, kubectl apply (for new resources)",
		},
		"update": {
			Verb:        "update",
			Explanation: "Modify existing resources (full replacement)",
			RiskLevel:   "medium",
			Examples:    "kubectl replace, updating entire resource definition",
		},
		"patch": {
			Verb:        "patch",
			Explanation: "Partially modify existing resources",
			RiskLevel:   "medium",
			Examples:    "kubectl patch, kubectl apply (for existing resources)",
		},
		"delete": {
			Verb:        "delete",
			Explanation: "Remove/destroy resources",
			RiskLevel:   "high",
			Examples:    "kubectl delete, removing resources permanently",
		},
		"deletecollection": {
			Verb:        "deletecollection",
			Explanation: "Delete multiple resources at once",
			RiskLevel:   "high",
			Examples:    "kubectl delete pods --all, bulk deletion",
		},
		"bind": {
			Verb:        "bind",
			Explanation: "Bind resources (typically used for persistent volumes)",
			RiskLevel:   "medium",
			Examples:    "PVC binding to PV, resource allocation",
		},
		"escalate": {
			Verb:        "escalate",
			Explanation: "Grant additional permissions (privilege escalation)",
			RiskLevel:   "critical",
			Examples:    "Granting higher privileges, security risk",
		},
		"impersonate": {
			Verb:        "impersonate",
			Explanation: "Act as another user or service account",
			RiskLevel:   "critical",
			Examples:    "kubectl --as=user, assuming another identity",
		},
		"use": {
			Verb:        "use",
			Explanation: "Use specific resources (typically for security contexts)",
			RiskLevel:   "medium",
			Examples:    "Using pod security policies, security contexts",
		},
		"*": {
			Verb:        "*",
			Explanation: "ALL POSSIBLE ACTIONS - complete control over resources",
			RiskLevel:   "critical",
			Examples:    "Full administrative access, can do anything",
		},
	}

	// Adjust risk levels based on resources
	for _, verb := range verbs {
		if explanation, exists := verbMap[verb]; exists {
			// Increase risk for sensitive resources
			if a.isSensitiveResource(resources) {
				explanation.RiskLevel = a.escalateRiskLevel(explanation.RiskLevel)
			}
			explanations = append(explanations, explanation)
		} else {
			// Unknown verb
			explanations = append(explanations, VerbExplanation{
				Verb:        verb,
				Explanation: "Custom or unknown action",
				RiskLevel:   "medium",
				Examples:    "Custom resource verb, check API documentation",
			})
		}
	}

	return explanations
}

// isSensitiveResource checks if resources are considered sensitive.
func (a *Analyzer) isSensitiveResource(resources []string) bool {
	sensitiveResources := map[string]bool{
		"*":                               true,
		"secrets":                         true,
		"serviceaccounts":                 true,
		"roles":                           true,
		"rolebindings":                    true,
		"clusterroles":                    true,
		"clusterrolebindings":             true,
		"nodes":                           true,
		"persistentvolumes":               true,
		"podsecuritypolicies":             true,
		"networkpolicies":                 true,
		"pods/exec":                       true,
		"pods/portforward":                true,
		"pods/proxy":                      true,
		"configmaps":                      true,
		"certificatesigningrequests":      true,
		"validatingwebhookconfigurations": true,
		"mutatingwebhookconfigurations":   true,
		"customresourcedefinitions":       true,
		"apiservices":                     true,
		"tokenreviews":                    true,
		"subjectaccessreviews":            true,
		"selfsubjectaccessreviews":        true,
		"nodes/proxy":                     true,
		"services/proxy":                  true,
		"namespaces":                      true,
		"events":                          true,
		"pods/attach":                     true,
		"pods/log":                        true,
		"priorityclasses":                 true,
		"storageclasses":                  true,
		"volumeattachments":               true,
		"csidrivers":                      true,
		"csinodes":                        true,
		"admissionregistration.k8s.io/*":  true,
		"authentication.k8s.io/*":         true,
		"authorization.k8s.io/*":          true,
		"certificates.k8s.io/*":           true,
		"rbac.authorization.k8s.io/*":     true,
		"policy/*":                        true,
		"security.openshift.io/*":         true,
		"oauth.openshift.io/*":            true,
		"user.openshift.io/*":             true,
		"ingresses":                       true,
		"ingressclasses":                  true,
		"nodes/status":                    true,
		"pods/eviction":                   true,
		"deployments/scale":               true,
		"replicasets/scale":               true,
		"statefulsets/scale":              true,
		"horizontalpodautoscalers":        true,
		"verticalpodautoscalers":          true,
		"poddisruptionbudgets":            true,
		"resourcequotas":                  true,
		"limitranges":                     true,
		"endpoints":                       true,
		"endpointslices":                  true,
		"nodes/metrics":                   true,
		"pods/metrics":                    true,
		"bindings":                        true,
		"componentstatuses":               true,
		"localsubjectaccessreviews":       true,
		"selfsubjectrulesreviews":         true,
		"subjectaccessreviews/*":          true,
		"clusterrolebindings/*":           true,
		"clusterroles/*":                  true,
		"rolebindings/*":                  true,
		"roles/*":                         true,
		"secrets/*":                       true,
		"serviceaccounts/*":               true,
		"serviceaccounts/token":           true,
	}

	for _, resource := range resources {
		if sensitiveResources[resource] {
			return true
		}
	}
	return false
}

// escalateRiskLevel increases the risk level.
func (a *Analyzer) escalateRiskLevel(currentLevel string) string {
	switch currentLevel {
	case "low":
		return "medium"
	case "medium":
		return "high"
	case "high":
		return "critical"
	default:
		return "critical"
	}
}

// analyzeSecurityImpact analyzes the security implications of a rule.
func (a *Analyzer) analyzeSecurityImpact(rule rbacv1.PolicyRule) SecurityImpact {
	impact := SecurityImpact{
		Level:       RiskLevelLow,
		Description: "Standard resource access",
		Concerns:    []string{},
	}

	// Check for wildcards
	hasWildcardVerb := slices.Contains(rule.Verbs, "*")
	hasWildcardResource := slices.Contains(rule.Resources, "*")
	hasWildcardAPIGroup := slices.Contains(rule.APIGroups, "*")

	// Analyze risk factors
	switch {
	case hasWildcardVerb && hasWildcardResource && hasWildcardAPIGroup:
		impact.Level = RiskLevelCritical
		impact.Description = "Complete cluster administrative access"
		impact.Concerns = append(impact.Concerns, "Can perform any action on any resource")
	case hasWildcardVerb:
		impact.Level = RiskLevelHigh
		impact.Description = "Unrestricted actions on specified resources"
		impact.Concerns = append(impact.Concerns, "Can perform any action on these resources")
	case hasWildcardResource:
		impact.Level = RiskLevelHigh
		impact.Description = "Access to all resources with specified permissions"
		impact.Concerns = append(impact.Concerns, "Can access any resource type")
	}

	// Check for dangerous verbs
	dangerousVerbs := []string{"delete", "deletecollection", "escalate", "impersonate"}
	for _, verb := range rule.Verbs {
		for _, dangerous := range dangerousVerbs {
			if verb == dangerous {
				if impact.Level == RiskLevelLow {
					impact.Level = RiskLevelMedium
				}
				impact.Concerns = append(impact.Concerns, fmt.Sprintf("Can %s resources", verb))
			}
		}
	}

	// Check for sensitive resources
	if a.isSensitiveResource(rule.Resources) {
		if impact.Level == RiskLevelLow {
			impact.Level = RiskLevelMedium
		}
		impact.Concerns = append(impact.Concerns, "Accesses sensitive resources")
	}

	// Check for non-resource URLs
	if len(rule.NonResourceURLs) > 0 {
		impact.Concerns = append(impact.Concerns, "Can access API endpoints directly")
	}

	return impact
}

// Helper functions

func (a *Analyzer) getSubjectKey(subject rbacv1.Subject) string {
	return fmt.Sprintf("%s/%s/%s", subject.Kind, subject.Namespace, subject.Name)
}

func (a *Analyzer) calculateRiskLevel(permissions []PermissionGrant) RiskLevel {
	maxRisk := RiskLevelLow

	for _, perm := range permissions {
		for _, rule := range perm.Rules {
			if a.getRiskPriority(rule.SecurityImpact.Level) > a.getRiskPriority(maxRisk) {
				maxRisk = rule.SecurityImpact.Level
			}
		}
	}

	return maxRisk
}

func (a *Analyzer) getRiskPriority(level RiskLevel) int {
	switch level {
	case RiskLevelCritical:
		return riskPriorityCritical
	case RiskLevelHigh:
		return riskPriorityHigh
	case RiskLevelMedium:
		return riskPriorityMedium
	case RiskLevelLow:
		return riskPriorityLow
	default:
		return riskPriorityDefault
	}
}

// formatAPIGroups formats API groups for human-readable output.
func (a *Analyzer) formatAPIGroups(apiGroups []string) string {
	if len(apiGroups) == 0 {
		return ""
	}

	if len(apiGroups) == 1 && apiGroups[0] == "*" {
		return "in ALL API groups"
	}

	cleanGroups := make([]string, 0, len(apiGroups))
	for _, group := range apiGroups {
		if group == "" {
			cleanGroups = append(cleanGroups, "core")
		} else {
			cleanGroups = append(cleanGroups, group)
		}
	}
	return fmt.Sprintf("in API groups: %s", strings.Join(cleanGroups, ", "))
}

// filterBySubject returns only the permissions for subjects matching the given name.
func filterBySubject(permissions []SubjectPermissions, subjectName string) []SubjectPermissions {
	var filtered []SubjectPermissions
	for _, perm := range permissions {
		if perm.Subject.Name == subjectName {
			filtered = append(filtered, perm)
		}
	}
	return filtered
}

// filterByRiskLevel returns only the permissions matching the given risk level.
func filterByRiskLevel(permissions []SubjectPermissions, riskLevel RiskLevel) []SubjectPermissions {
	var filtered []SubjectPermissions
	for _, perm := range permissions {
		if perm.RiskLevel == riskLevel {
			filtered = append(filtered, perm)
		}
	}
	return filtered
}
