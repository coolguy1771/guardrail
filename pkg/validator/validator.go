package validator

import (
	"fmt"

	"k8s.io/apimachinery/pkg/runtime"

	rbacv1 "k8s.io/api/rbac/v1"
)

// Validator validates RBAC resources against security policies.
type Validator struct {
	rules []Rule
}

// Rule represents a validation rule.
type Rule struct {
	ID          string
	Name        string
	Description string
	Severity    Severity
	Validate    func(obj runtime.Object) []Finding
}

// Severity represents the severity of a finding.
type Severity string

const (
	SeverityHigh   Severity = "HIGH"
	SeverityMedium Severity = "MEDIUM"
	SeverityLow    Severity = "LOW"
	SeverityInfo   Severity = "INFO"
)

// Finding represents a validation finding.
type Finding struct {
	RuleID      string
	RuleName    string
	Severity    Severity
	Message     string
	Resource    string
	Namespace   string
	Kind        string
	Remediation string
}

// New creates a new Validator with default rules.
func New() *Validator {
	return &Validator{
		rules: defaultRules(),
	}
}

// NewWithRules creates a new Validator with custom rules.
func NewWithRules(rules []Rule) *Validator {
	return &Validator{
		rules: rules,
	}
}

// Validate validates a Kubernetes object.
func (v *Validator) Validate(obj runtime.Object) []Finding {
	var findings []Finding

	for _, rule := range v.rules {
		ruleFindings := rule.Validate(obj)
		findings = append(findings, ruleFindings...)
	}

	return findings
}

// ValidateAll validates multiple Kubernetes objects.
func (v *Validator) ValidateAll(objects []runtime.Object) []Finding {
	var allFindings []Finding

	for _, obj := range objects {
		findings := v.Validate(obj)
		allFindings = append(allFindings, findings...)
	}

	return allFindings
}

// defaultRules returns the default set of validation rules.
func defaultRules() []Rule {
	return []Rule{
		{
			ID:          "RBAC001",
			Name:        "Avoid Wildcard Permissions",
			Description: "Using wildcard (*) in verbs, resources, or apiGroups can grant excessive permissions",
			Severity:    SeverityHigh,
			Validate:    validateWildcardPermissions,
		},
		{
			ID:          "RBAC002",
			Name:        "Avoid Cluster-Admin Binding",
			Description: "Binding to cluster-admin role should be avoided unless absolutely necessary",
			Severity:    SeverityHigh,
			Validate:    validateClusterAdminBinding,
		},
		{
			ID:          "RBAC003",
			Name:        "Avoid Secrets Access",
			Description: "Direct access to secrets should be limited and audited",
			Severity:    SeverityMedium,
			Validate:    validateSecretsAccess,
		},
		{
			ID:          "RBAC004",
			Name:        "Prefer Namespaced Roles",
			Description: "Use Role instead of ClusterRole when permissions are only needed in specific namespaces",
			Severity:    SeverityLow,
			Validate:    validateNamespacedRoles,
		},
		// NIST SP 800-190 based rules
		{
			ID:          "RBAC005",
			Name:        "Avoid Service Account Token Automounting",
			Description: "Service accounts with excessive permissions should not automount tokens (NIST SP 800-190)",
			Severity:    SeverityMedium,
			Validate:    validateServiceAccountTokens,
		},
		{
			ID:          "RBAC006",
			Name:        "Restrict Exec and Attach Permissions",
			Description: "Exec and attach verbs allow interactive container access and should be restricted (NIST SP 800-190)",
			Severity:    SeverityHigh,
			Validate:    validateExecAttachPermissions,
		},
		{
			ID:          "RBAC007",
			Name:        "Limit Impersonation Privileges",
			Description: "Impersonation allows users to act as other users/groups and should be strictly limited (NIST SP 800-190)",
			Severity:    SeverityHigh,
			Validate:    validateImpersonationPrivileges,
		},
		{
			ID:          "RBAC008",
			Name:        "Restrict Escalate and Bind Verbs",
			Description: "Escalate and bind verbs can lead to privilege escalation (NIST SP 800-190)",
			Severity:    SeverityHigh,
			Validate:    validateEscalateBindVerbs,
		},
		{
			ID:          "RBAC009",
			Name:        "Audit Privileged Container Access",
			Description: "Access to privileged containers and host namespaces should be audited (NIST SP 800-190)",
			Severity:    SeverityHigh,
			Validate:    validatePrivilegedContainerAccess,
		},
		{
			ID:          "RBAC010",
			Name:        "Restrict Node and PersistentVolume Access",
			Description: "Direct node and persistent volume access should be restricted (NIST SP 800-190)",
			Severity:    SeverityMedium,
			Validate:    validateNodePVAccess,
		},
		{
			ID:          "RBAC011",
			Name:        "Limit Webhook Configuration Access",
			Description: "Webhook configurations can intercept API requests and should be protected (NIST SP 800-190)",
			Severity:    SeverityHigh,
			Validate:    validateWebhookAccess,
		},
		{
			ID:          "RBAC012",
			Name:        "Restrict CRD and APIService Modifications",
			Description: "Custom Resource Definitions and API services extend the API and require protection (NIST SP 800-190)",
			Severity:    SeverityHigh,
			Validate:    validateCRDAPIServiceAccess,
		},
		{
			ID:          "RBAC013",
			Name:        "Separate Concerns with Namespace Isolation",
			Description: "Cross-namespace access should be minimized for proper isolation (NIST SP 800-190)",
			Severity:    SeverityMedium,
			Validate:    validateNamespaceIsolation,
		},
		{
			ID:          "RBAC014",
			Name:        "Restrict TokenRequest and CertificateSigningRequest",
			Description: "Token and certificate requests can be used for authentication bypass (NIST SP 800-190)",
			Severity:    SeverityHigh,
			Validate:    validateTokenCertificateRequests,
		},
	}
}

// validateWildcardPermissions checks for wildcard usage in permissions.
func validateWildcardPermissions(obj runtime.Object) []Finding {
	var findings []Finding

	switch v := obj.(type) {
	case *rbacv1.Role:
		findings = checkRulesForWildcards(v.Rules, v.Name, v.Namespace, "Role")
	case *rbacv1.ClusterRole:
		findings = checkRulesForWildcards(v.Rules, v.Name, "", "ClusterRole")
	}

	return findings
}

// checkRulesForWildcards checks PolicyRules for wildcard usage.
func checkRulesForWildcards(rules []rbacv1.PolicyRule, name, namespace, kind string) []Finding {
	var findings []Finding

	for _, rule := range rules {
		// Check for wildcard in verbs
		for _, verb := range rule.Verbs {
			if verb == "*" {
				findings = append(findings, Finding{
					RuleID:      "RBAC001",
					RuleName:    "Avoid Wildcard Permissions",
					Severity:    SeverityHigh,
					Message:     fmt.Sprintf("Wildcard verb '*' found in %s", kind),
					Resource:    name,
					Namespace:   namespace,
					Kind:        kind,
					Remediation: "Replace wildcard verb with specific verbs like 'get', 'list', 'watch', 'create', 'update', 'patch', 'delete'",
				})
			}
		}

		// Check for wildcard in resources
		for _, resource := range rule.Resources {
			if resource == "*" {
				findings = append(findings, Finding{
					RuleID:      "RBAC001",
					RuleName:    "Avoid Wildcard Permissions",
					Severity:    SeverityHigh,
					Message:     fmt.Sprintf("Wildcard resource '*' found in %s", kind),
					Resource:    name,
					Namespace:   namespace,
					Kind:        kind,
					Remediation: "Replace wildcard resource with specific resources like 'pods', 'services', 'deployments'",
				})
			}
		}

		// Check for wildcard in API groups
		for _, apiGroup := range rule.APIGroups {
			if apiGroup == "*" {
				findings = append(findings, Finding{
					RuleID:      "RBAC001",
					RuleName:    "Avoid Wildcard Permissions",
					Severity:    SeverityHigh,
					Message:     fmt.Sprintf("Wildcard API group '*' found in %s", kind),
					Resource:    name,
					Namespace:   namespace,
					Kind:        kind,
					Remediation: "Replace wildcard API group with specific groups like '', 'apps', 'batch'",
				})
			}
		}
	}

	return findings
}

// validateClusterAdminBinding checks for bindings to cluster-admin role.
func validateClusterAdminBinding(obj runtime.Object) []Finding {
	var findings []Finding

	switch v := obj.(type) {
	case *rbacv1.ClusterRoleBinding:
		if v.RoleRef.Name == "cluster-admin" {
			findings = append(findings, Finding{
				RuleID:      "RBAC002",
				RuleName:    "Avoid Cluster-Admin Binding",
				Severity:    SeverityHigh,
				Message:     "ClusterRoleBinding references cluster-admin role",
				Resource:    v.Name,
				Namespace:   "",
				Kind:        "ClusterRoleBinding",
				Remediation: "Create a custom ClusterRole with only the required permissions instead of using cluster-admin",
			})
		}
	case *rbacv1.RoleBinding:
		if v.RoleRef.Kind == "ClusterRole" && v.RoleRef.Name == "cluster-admin" {
			findings = append(findings, Finding{
				RuleID:      "RBAC002",
				RuleName:    "Avoid Cluster-Admin Binding",
				Severity:    SeverityHigh,
				Message:     "RoleBinding references cluster-admin ClusterRole",
				Resource:    v.Name,
				Namespace:   v.Namespace,
				Kind:        "RoleBinding",
				Remediation: "Create a custom Role or ClusterRole with only the required permissions instead of using cluster-admin",
			})
		}
	}

	return findings
}

// validateSecretsAccess checks for direct access to secrets.
//
//nolint:gocognit // Secret access validation requires complex rule evaluation
func validateSecretsAccess(obj runtime.Object) []Finding {
	var findings []Finding

	checkSecretsInRules := func(rules []rbacv1.PolicyRule, name, namespace, kind string) {
		for _, rule := range rules {
			for _, resource := range rule.Resources {
				if resource == "secrets" {
					hasGet := false
					hasList := false

					for _, verb := range rule.Verbs {
						switch verb {
						case "get":
							hasGet = true
						case "list":
							hasList = true
						case "*":
							hasGet = true
							hasList = true
						}
					}

					if hasGet || hasList {
						findings = append(findings, Finding{
							RuleID:      "RBAC003",
							RuleName:    "Avoid Secrets Access",
							Severity:    SeverityMedium,
							Message:     fmt.Sprintf("Direct read access to secrets found in %s", kind),
							Resource:    name,
							Namespace:   namespace,
							Kind:        kind,
							Remediation: "Limit secrets access to specific named resources or use service accounts with mounted secrets instead",
						})
					}
				}
			}
		}
	}

	switch v := obj.(type) {
	case *rbacv1.Role:
		checkSecretsInRules(v.Rules, v.Name, v.Namespace, "Role")
	case *rbacv1.ClusterRole:
		checkSecretsInRules(v.Rules, v.Name, "", "ClusterRole")
	}

	return findings
}

// validateNamespacedRoles suggests using Role instead of ClusterRole for namespace-scoped resources.
func validateNamespacedRoles(obj runtime.Object) []Finding {
	var findings []Finding

	if cr, ok := obj.(*rbacv1.ClusterRole); ok {
		// Check if all rules only reference namespace-scoped resources
		allNamespaced := true
		namespacedResources := map[string]bool{
			"pods":         true,
			"services":     true,
			"deployments":  true,
			"replicasets":  true,
			"statefulsets": true,
			"daemonsets":   true,
			"configmaps":   true,
			"secrets":      true,
			"ingresses":    true,
			"jobs":         true,
			"cronjobs":     true,
		}

		for _, rule := range cr.Rules {
			for _, resource := range rule.Resources {
				if resource == "*" || !namespacedResources[resource] {
					allNamespaced = false
					break
				}
			}
			if !allNamespaced {
				break
			}
		}

		if allNamespaced && len(cr.Rules) > 0 {
			findings = append(findings, Finding{
				RuleID:      "RBAC004",
				RuleName:    "Prefer Namespaced Roles",
				Severity:    SeverityLow,
				Message:     "ClusterRole only contains namespace-scoped resources",
				Resource:    cr.Name,
				Namespace:   "",
				Kind:        "ClusterRole",
				Remediation: "Consider using a Role instead of ClusterRole for namespace-scoped permissions",
			})
		}
	}

	return findings
}
