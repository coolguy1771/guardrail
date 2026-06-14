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
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
	SeverityInfo     Severity = "INFO"
)

// SeverityRank maps severities to an ordinal for threshold comparisons.
var SeverityRank = map[Severity]int{
	SeverityCritical: 4,
	SeverityHigh:     3,
	SeverityMedium:   2,
	SeverityLow:      1,
	SeverityInfo:     0,
}

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

// ruleValidateFuncs maps rule IDs to their implementation.
// This is the join between the static catalog (rules.go) and the validate functions.
//
//nolint:gochecknoglobals // package-level map is the idiomatic join between catalog and implementations
var ruleValidateFuncs = map[string]func(runtime.Object) []Finding{
	"RBAC001": validateWildcardPermissions,
	"RBAC002": validateBuiltinRoleBindings,
	"RBAC003": validateSecretsAccess,
	"RBAC004": validateNamespacedRoles,
	"RBAC005": validateServiceAccountTokens,
	"RBAC006": validateExecAttachPermissions,
	"RBAC007": validateImpersonationPrivileges,
	"RBAC008": validateEscalateBindVerbs,
	"RBAC009": validatePrivilegedContainerAccess,
	"RBAC010": validateNodePVAccess,
	"RBAC011": validateWebhookAccess,
	"RBAC012": validateCRDAPIServiceAccess,
	"RBAC013": validateNamespaceIsolation,
	"RBAC014": validateTokenCertificateRequests,
}

// defaultRules builds the rule list from Catalog + ruleValidateFuncs.
func defaultRules() []Rule {
	rules := make([]Rule, 0, len(Catalog))
	for _, meta := range Catalog {
		fn, ok := ruleValidateFuncs[meta.ID]
		if !ok {
			continue
		}
		rules = append(rules, Rule{
			ID:          meta.ID,
			Name:        meta.Name,
			Description: meta.Description,
			Severity:    meta.DefaultSeverity,
			Validate:    fn,
		})
	}
	return rules
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
	meta := Catalog[0] // RBAC001
	var findings []Finding

	newFinding := func(msg string) Finding {
		return Finding{
			RuleID:      meta.ID,
			RuleName:    meta.Name,
			Severity:    meta.DefaultSeverity,
			Message:     msg,
			Resource:    name,
			Namespace:   namespace,
			Kind:        kind,
			Remediation: meta.Remediation,
		}
	}

	for _, rule := range rules {
		for _, verb := range rule.Verbs {
			if verb == "*" {
				findings = append(findings, newFinding(fmt.Sprintf("Wildcard verb '*' found in %s", kind)))
			}
		}
		for _, resource := range rule.Resources {
			if resource == "*" {
				findings = append(findings, newFinding(fmt.Sprintf("Wildcard resource '*' found in %s", kind)))
			}
		}
		for _, apiGroup := range rule.APIGroups {
			if apiGroup == "*" {
				findings = append(findings, newFinding(fmt.Sprintf("Wildcard API group '*' found in %s", kind)))
			}
		}
	}

	return findings
}

// riskyBuiltinRole maps a built-in role name to the severity of binding it.
type riskyBuiltinRole struct {
	severity Severity
	note     string // appended to the finding message
}

// riskyBuiltinRoles is the set of built-in roles that trigger RBAC002.
// Ordered by decreasing severity so the first match wins in future lookup tables.
//
//nolint:gochecknoglobals // intentional package-level policy table
var riskyBuiltinRoles = map[string]riskyBuiltinRole{
	"cluster-admin": {SeverityCritical, "grants superuser access across the entire cluster"},
	"admin":         {SeverityHigh, "grants broad write access to most namespace resources"},
	"edit":          {SeverityMedium, "grants write access to most namespace resources"},
}

// validateBuiltinRoleBindings flags bindings to overly permissive built-in roles.
func validateBuiltinRoleBindings(obj runtime.Object) []Finding {
	meta := Catalog[1] // RBAC002
	var findings []Finding

	switch v := obj.(type) {
	case *rbacv1.ClusterRoleBinding:
		if risky, ok := riskyBuiltinRoles[v.RoleRef.Name]; ok {
			findings = append(findings, Finding{
				RuleID:      meta.ID,
				RuleName:    meta.Name,
				Severity:    risky.severity,
				Message:     fmt.Sprintf("ClusterRoleBinding %q binds to %q (%s)", v.Name, v.RoleRef.Name, risky.note),
				Resource:    v.Name,
				Kind:        "ClusterRoleBinding",
				Remediation: meta.Remediation,
			})
		}
	case *rbacv1.RoleBinding:
		if v.RoleRef.Kind != "ClusterRole" {
			break
		}
		if risky, ok := riskyBuiltinRoles[v.RoleRef.Name]; ok {
			findings = append(findings, Finding{
				RuleID:      meta.ID,
				RuleName:    meta.Name,
				Severity:    risky.severity,
				Message:     fmt.Sprintf("RoleBinding %q in namespace %q binds to ClusterRole %q (%s)", v.Name, v.Namespace, v.RoleRef.Name, risky.note),
				Resource:    v.Name,
				Namespace:   v.Namespace,
				Kind:        "RoleBinding",
				Remediation: meta.Remediation,
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
