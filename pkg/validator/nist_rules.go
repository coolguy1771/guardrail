package validator

import (
	"fmt"
	"slices"

	"k8s.io/apimachinery/pkg/runtime"

	rbacv1 "k8s.io/api/rbac/v1"
)

// Common verb constants.
const (
	verbCreate = "create"
	verbUpdate = "update"
	verbPatch  = "patch"
	verbDelete = "delete"
	verbAll    = "*"
)

// Common RBAC kind constants.
const (
	kindClusterRole = "ClusterRole"
)

// validateServiceAccountTokens checks for service accounts with risky token mounting.
func validateServiceAccountTokens(obj runtime.Object) []Finding {
	var findings []Finding

	// This rule primarily applies to RoleBindings/ClusterRoleBindings
	// that grant permissions to service accounts
	switch v := obj.(type) {
	case *rbacv1.RoleBinding:
		for _, subject := range v.Subjects {
			if subject.Kind == "ServiceAccount" {
				// Check if the role grants sensitive permissions
				if hasServiceAccountRisks(v.RoleRef.Name) {
					findings = append(findings, Finding{
						RuleID:      "RBAC005",
						RuleName:    "Avoid Service Account Token Automounting",
						Severity:    SeverityMedium,
						Message:     fmt.Sprintf("Service account '%s' bound to potentially risky role", subject.Name),
						Resource:    v.Name,
						Namespace:   v.Namespace,
						Kind:        "RoleBinding",
						Remediation: "Consider disabling automountServiceAccountToken for this service account or reducing permissions",
					})
				}
			}
		}
	case *rbacv1.ClusterRoleBinding:
		for _, subject := range v.Subjects {
			if subject.Kind == "ServiceAccount" {
				if hasServiceAccountRisks(v.RoleRef.Name) {
					findings = append(findings, Finding{
						RuleID:      "RBAC005",
						RuleName:    "Avoid Service Account Token Automounting",
						Severity:    SeverityMedium,
						Message:     fmt.Sprintf("Service account '%s' in namespace '%s' bound to potentially risky cluster role", subject.Name, subject.Namespace),
						Resource:    v.Name,
						Namespace:   "",
						Kind:        "ClusterRoleBinding",
						Remediation: "Consider disabling automountServiceAccountToken for this service account or reducing permissions",
					})
				}
			}
		}
	}

	return findings
}

// hasServiceAccountRisks checks if a role name suggests risky permissions.
func hasServiceAccountRisks(roleName string) bool {
	riskyRoles := []string{"cluster-admin", "admin", "edit"}
	return slices.Contains(riskyRoles, roleName)
}

// validateExecAttachPermissions checks for exec and attach permissions.
func validateExecAttachPermissions(obj runtime.Object) []Finding {
	return checkResourceVerbAccess(obj, resourceVerbCheck{
		resources: []string{"pods/exec", "pods/attach"},
		verbs:     []string{verbCreate},
		ruleID:    "RBAC006",
		ruleName:  "Restrict Exec and Attach Permissions",
		severity:  SeverityHigh,
		getMessage: func(resource, kind string) string {
			return fmt.Sprintf("Permission to %s containers found in %s", resource, kind)
		},
		remediation: "Limit exec/attach permissions to specific users/groups and implement additional authentication",
	})
}

// validateImpersonationPrivileges checks for impersonation permissions.
func validateImpersonationPrivileges(obj runtime.Object) []Finding {
	return checkResourceVerbAccess(obj, resourceVerbCheck{
		resources: []string{"users", "groups", "serviceaccounts"},
		verbs:     []string{"impersonate"},
		ruleID:    "RBAC007",
		ruleName:  "Limit Impersonation Privileges",
		severity:  SeverityHigh,
		getMessage: func(resource, kind string) string {
			return fmt.Sprintf("Impersonation permission for %s found in %s", resource, kind)
		},
		remediation: "Restrict impersonation to specific identities and implement strict auditing",
	})
}

// validateEscalateBindVerbs checks for escalate and bind permissions.
func validateEscalateBindVerbs(obj runtime.Object) []Finding {
	return checkResourceVerbAccess(obj, resourceVerbCheck{
		resources: []string{"roles", "clusterroles", "rolebindings", "clusterrolebindings"},
		verbs:     []string{"escalate", "bind"},
		ruleID:    "RBAC008",
		ruleName:  "Restrict Escalate and Bind Verbs",
		severity:  SeverityHigh,
		getMessage: func(resource, kind string) string {
			return fmt.Sprintf("Privilege escalation permissions on '%s' found in %s", resource, kind)
		},
		remediation: "Limit escalate/bind permissions to cluster administrators only",
	})
}

// validatePrivilegedContainerAccess checks for access to security-sensitive pod specs.
func validatePrivilegedContainerAccess(obj runtime.Object) []Finding {
	return checkResourceVerbAccess(obj, resourceVerbCheck{
		resources: []string{"podsecuritypolicies", "securitycontextconstraints"},
		verbs:     []string{"use"},
		ruleID:    "RBAC009",
		ruleName:  "Audit Privileged Container Access",
		severity:  SeverityHigh,
		getMessage: func(resource, _ string) string {
			return fmt.Sprintf("Access to %s which may allow privileged containers", resource)
		},
		remediation: "Restrict PSP/SCC usage and audit all privileged container deployments",
	})
}

// validateNodePVAccess checks for direct node and persistent volume access.
func validateNodePVAccess(obj runtime.Object) []Finding {
	return checkResourceVerbAccess(obj, resourceVerbCheck{
		resources: []string{"nodes", "nodes/proxy", "persistentvolumes"},
		verbs:     []string{verbUpdate, verbPatch, verbDelete},
		ruleID:    "RBAC010",
		ruleName:  "Restrict Node and PersistentVolume Access",
		severity:  SeverityMedium,
		getMessage: func(resource, kind string) string {
			return fmt.Sprintf("Direct write access to %s found in %s", resource, kind)
		},
		remediation: "Limit node/PV access to cluster operators and use PVCs for storage access",
	})
}

// validateWebhookAccess checks for webhook configuration permissions.
func validateWebhookAccess(obj runtime.Object) []Finding {
	return checkResourceVerbAccess(obj, resourceVerbCheck{
		resources: []string{"mutatingwebhookconfigurations", "validatingwebhookconfigurations"},
		verbs:     []string{verbCreate, verbUpdate, verbPatch},
		ruleID:    "RBAC011",
		ruleName:  "Limit Webhook Configuration Access",
		severity:  SeverityHigh,
		getMessage: func(resource, kind string) string {
			return fmt.Sprintf("Permission to modify %s found in %s", resource, kind)
		},
		remediation: "Restrict webhook configuration to cluster administrators only",
	})
}

// validateCRDAPIServiceAccess checks for CRD and APIService modification permissions.
func validateCRDAPIServiceAccess(obj runtime.Object) []Finding {
	return checkResourceVerbAccess(obj, resourceVerbCheck{
		resources: []string{"customresourcedefinitions", "apiservices"},
		verbs:     []string{verbCreate, verbUpdate, verbPatch, verbDelete},
		ruleID:    "RBAC012",
		ruleName:  "Restrict CRD and APIService Modifications",
		severity:  SeverityHigh,
		getMessage: func(resource, kind string) string {
			return fmt.Sprintf("Permission to modify %s found in %s", resource, kind)
		},
		remediation: "Limit CRD/APIService modifications to cluster administrators",
	})
}

// validateNamespaceIsolation checks for cross-namespace access patterns.
func validateNamespaceIsolation(obj runtime.Object) []Finding {
	var findings []Finding

	// Check RoleBindings that reference ClusterRoles
	if rb, ok := obj.(*rbacv1.RoleBinding); ok {
		if rb.RoleRef.Kind == kindClusterRole {
			// This could indicate cross-namespace access
			findings = append(findings, Finding{
				RuleID:      "RBAC013",
				RuleName:    "Separate Concerns with Namespace Isolation",
				Severity:    SeverityMedium,
				Message:     "RoleBinding references ClusterRole which may grant cross-namespace access",
				Resource:    rb.Name,
				Namespace:   rb.Namespace,
				Kind:        "RoleBinding",
				Remediation: "Consider using namespace-specific Roles instead of ClusterRoles for better isolation",
			})
		}
	}

	return findings
}

// validateTokenCertificateRequests checks for token and certificate request permissions.
func validateTokenCertificateRequests(obj runtime.Object) []Finding {
	return checkResourceVerbAccess(obj, resourceVerbCheck{
		resources: []string{"serviceaccounts/token", "certificatesigningrequests"},
		verbs:     []string{verbCreate},
		ruleID:    "RBAC014",
		ruleName:  "Restrict TokenRequest and CertificateSigningRequest",
		severity:  SeverityHigh,
		getMessage: func(resource, kind string) string {
			return fmt.Sprintf("Permission to create %s found in %s", resource, kind)
		},
		remediation: "Restrict token/certificate creation to authorized components only",
	})
}

// checkResourceVerbAccess is a helper function to check for specific resource/verb combinations.
type resourceVerbCheck struct {
	resources   []string
	verbs       []string
	ruleID      string
	ruleName    string
	severity    Severity
	getMessage  func(resource, kind string) string
	remediation string
}

func checkResourceVerbAccess(obj runtime.Object, check resourceVerbCheck) []Finding {
	var findings []Finding

	// Get rules and metadata based on object type
	var rules []rbacv1.PolicyRule
	var name, namespace, kind string

	switch v := obj.(type) {
	case *rbacv1.Role:
		rules = v.Rules
		name = v.Name
		namespace = v.Namespace
		kind = "Role"
	case *rbacv1.ClusterRole:
		rules = v.Rules
		name = v.Name
		namespace = ""
		kind = kindClusterRole
	default:
		return findings
	}

	// Check each rule
	for _, rule := range rules {
		findings = append(findings, checkSingleRule(rule, check, name, namespace, kind)...)
	}

	return findings
}

// checkSingleRule checks if a single rule matches the resource/verb criteria.
func checkSingleRule(rule rbacv1.PolicyRule, check resourceVerbCheck, name, namespace, kind string) []Finding {
	// Check if verbs match
	verbInfo := getMatchingVerbInfo(rule.Verbs, check.verbs)
	if verbInfo.count == 0 {
		return nil
	}

	// Create findings for matching resources
	return createFindingsForResources(rule.Resources, check, verbInfo.count, name, namespace, kind)
}

// verbMatchInfo encapsulates the result of analyzing RBAC verbs to determine
// how many security findings should be generated per resource.
//
// This type is used by the NIST RBAC validation rules to handle the special
// case where wildcard verbs ("*") should generate only one finding per resource,
// while explicit verb matches (e.g., ["create", "update"]) should generate one
// finding for each matching verb.
//
// For example:
//   - Rule with verbs ["*"] matching ["create", "update", "delete"] → count = 1
//   - Rule with verbs ["create", "update"] matching ["create", "update", "delete"] → count = 2
type verbMatchInfo struct {
	// count represents the number of findings to create for each matching resource.
	// When a wildcard verb is present, this will always be 1 regardless of how many
	// target verbs are being checked. For explicit verb matches, this equals the
	// number of verbs that match between the rule and the validation criteria.
	count int
}

// getMatchingVerbInfo analyzes verbs and returns match information.
func getMatchingVerbInfo(ruleVerbs []string, targetVerbs []string) verbMatchInfo {
	var matchCount int
	hasWildcard := false

	for _, verb := range ruleVerbs {
		if verb == "*" {
			hasWildcard = true
			break
		}
		// Count matching verbs
		for _, target := range targetVerbs {
			if verb == target {
				matchCount++
			}
		}
	}

	// If wildcard verb, create only one finding per resource
	if hasWildcard {
		return verbMatchInfo{count: 1}
	}

	return verbMatchInfo{count: matchCount}
}

// createFindingsForResources creates findings for each matching resource.
func createFindingsForResources(
	resources []string,
	check resourceVerbCheck,
	verbCount int,
	name, namespace, kind string,
) []Finding {
	var findings []Finding

	for _, resource := range resources {
		if resource == "*" {
			// Wildcard matches all target resources
			findings = append(
				findings,
				createFindingsForTargets(check.resources, check, verbCount, name, namespace, kind)...)
			break // Don't process more after wildcard
		}

		// Check specific resource matches
		for _, target := range check.resources {
			if resource == target {
				findings = append(
					findings,
					createMultipleFindings(resource, check, verbCount, name, namespace, kind)...)
			}
		}
	}

	return findings
}

// createFindingsForTargets creates findings for multiple target resources.
func createFindingsForTargets(
	targets []string,
	check resourceVerbCheck,
	verbCount int,
	name, namespace, kind string,
) []Finding {
	var findings []Finding
	for _, target := range targets {
		findings = append(findings, createMultipleFindings(target, check, verbCount, name, namespace, kind)...)
	}
	return findings
}

// createMultipleFindings creates the specified number of findings for a resource.
func createMultipleFindings(
	resource string,
	check resourceVerbCheck,
	count int,
	name, namespace, kind string,
) []Finding {
	findings := make([]Finding, 0, count)
	for range count {
		findings = append(findings, Finding{
			RuleID:      check.ruleID,
			RuleName:    check.ruleName,
			Severity:    check.severity,
			Message:     check.getMessage(resource, kind),
			Resource:    name,
			Namespace:   namespace,
			Kind:        kind,
			Remediation: check.remediation,
		})
	}
	return findings
}
