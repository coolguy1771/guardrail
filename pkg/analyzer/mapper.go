package analyzer

import (
	"fmt"
	"slices"
	"sort"
	"strings"

	rbacv1 "k8s.io/api/rbac/v1"
)

// PermissionMapper provides functionality to map and search permissions.
type PermissionMapper struct {
	permissions []SubjectPermissions
}

// NewPermissionMapper returns a PermissionMapper initialized with the provided subject permissions.
func NewPermissionMapper(permissions []SubjectPermissions) *PermissionMapper {
	return &PermissionMapper{
		permissions: permissions,
	}
}

// WhoCanDo finds subjects that can perform a specific action on resources.
func (pm *PermissionMapper) WhoCanDo(verb, resource, apiGroup string) []PermissionMatch {
	var matches []PermissionMatch

	for _, subjectPerm := range pm.permissions {
		for _, perm := range subjectPerm.Permissions {
			for _, rule := range perm.Rules {
				if pm.ruleMatches(rule, verb, resource, apiGroup) {
					matches = append(matches, PermissionMatch{
						Subject:     pm.convertSubject(subjectPerm.Subject),
						Permission:  perm,
						Rule:        rule,
						MatchReason: pm.getMatchReason(rule, verb, resource, apiGroup),
					})
				}
			}
		}
	}

	// Sort by risk level (highest first)
	sort.Slice(matches, func(i, j int) bool {
		return pm.getRiskPriority(matches[i].Rule.SecurityImpact.Level) >
			pm.getRiskPriority(matches[j].Rule.SecurityImpact.Level)
	})

	return matches
}

// WhatCanSubjectDo returns all permissions for a specific subject.
func (pm *PermissionMapper) WhatCanSubjectDo(subjectKind, subjectName string) []SubjectPermissions {
	var matches []SubjectPermissions

	for _, subjectPerm := range pm.permissions {
		if (subjectKind == "" || subjectPerm.Subject.Kind == subjectKind) &&
			(subjectName == "" || subjectPerm.Subject.Name == subjectName) {
			matches = append(matches, subjectPerm)
		}
	}

	return matches
}

// GetDangerousPermissions returns subjects with high-risk permissions.
func (pm *PermissionMapper) GetDangerousPermissions() []DangerousPermission {
	var dangerous []DangerousPermission

	for _, subjectPerm := range pm.permissions {
		for _, perm := range subjectPerm.Permissions {
			for _, rule := range perm.Rules {
				if rule.SecurityImpact.Level == RiskLevelHigh ||
					rule.SecurityImpact.Level == RiskLevelCritical {
					dangerous = append(dangerous, DangerousPermission{
						Subject:     pm.convertSubject(subjectPerm.Subject),
						Permission:  perm,
						Rule:        rule,
						RiskLevel:   rule.SecurityImpact.Level,
						Explanation: rule.SecurityImpact.Description,
						Concerns:    rule.SecurityImpact.Concerns,
					})
				}
			}
		}
	}

	// Sort by risk level
	sort.Slice(dangerous, func(i, j int) bool {
		return pm.getRiskPriority(dangerous[i].RiskLevel) >
			pm.getRiskPriority(dangerous[j].RiskLevel)
	})

	return dangerous
}

// GetPrivilegeEscalationPaths finds potential privilege escalation paths.
func (pm *PermissionMapper) GetPrivilegeEscalationPaths() []EscalationPath {
	var paths []EscalationPath

	for _, subjectPerm := range pm.permissions {
		escalationRisks := pm.analyzeEscalationRisk(subjectPerm)
		if len(escalationRisks) > 0 {
			paths = append(paths, EscalationPath{
				Subject: pm.convertSubject(subjectPerm.Subject),
				Risks:   escalationRisks,
			})
		}
	}

	return paths
}

// GetResourceAccess shows who has access to specific resources.
func (pm *PermissionMapper) GetResourceAccess(resource, apiGroup string) ResourceAccessMap {
	accessMap := ResourceAccessMap{
		Resource: resource,
		APIGroup: apiGroup,
		Access:   make(map[string][]ResourceAccess),
	}

	verbs := []string{
		"get",
		"list",
		"watch",
		"create",
		"update",
		"patch",
		"delete",
		"bind",
		"escalate",
		"impersonate",
		"*",
	}

	for _, verb := range verbs {
		matches := pm.WhoCanDo(verb, resource, apiGroup)
		for _, match := range matches {
			accessMap.Access[verb] = append(accessMap.Access[verb], ResourceAccess{
				Subject:    match.Subject,
				Permission: match.Permission,
				RiskLevel:  match.Rule.SecurityImpact.Level,
			})
		}
	}

	return accessMap
}

// Helper methods

func (pm *PermissionMapper) ruleMatches(rule PolicyRuleAnalysis, verb, resource, apiGroup string) bool {
	// Check verbs
	if !pm.matchesVerb(rule.Verbs, verb) {
		return false
	}

	// Check resources
	if !pm.matchesResource(rule.Resources, resource) {
		return false
	}

	// Check API groups
	if !pm.matchesAPIGroup(rule.APIGroups, apiGroup) {
		return false
	}

	return true
}

func (pm *PermissionMapper) matchesVerb(ruleVerbs []string, targetVerb string) bool {
	for _, verb := range ruleVerbs {
		if verb == "*" || verb == targetVerb {
			return true
		}
	}
	return false
}

func (pm *PermissionMapper) matchesResource(ruleResources []string, targetResource string) bool {
	for _, resource := range ruleResources {
		if resource == "*" || resource == targetResource {
			return true
		}
		// Handle subresources (e.g., pods/exec matches pods)
		if strings.Contains(targetResource, "/") {
			parts := strings.Split(targetResource, "/")
			if resource == parts[0] {
				return true
			}
		}
	}
	return false
}

func (pm *PermissionMapper) matchesAPIGroup(ruleAPIGroups []string, targetAPIGroup string) bool {
	for _, apiGroup := range ruleAPIGroups {
		if apiGroup == "*" || apiGroup == targetAPIGroup {
			return true
		}
		// Empty string in rule matches core API group
		if apiGroup == "" && targetAPIGroup == "core" {
			return true
		}
		// Core API group in rule matches empty string target
		if apiGroup == "core" && targetAPIGroup == "" {
			return true
		}
	}
	return false
}

func (pm *PermissionMapper) getMatchReason(rule PolicyRuleAnalysis, verb, resource, apiGroup string) string {
	var reasons []string

	// Check if wildcard matches
	if slices.Contains(rule.Verbs, "*") {
		reasons = append(reasons, fmt.Sprintf("wildcard verb permission (requested: %s)", verb))
	}

	if slices.Contains(rule.Resources, "*") {
		reasons = append(reasons, fmt.Sprintf("wildcard resource permission (requested: %s)", resource))
	}

	if slices.Contains(rule.APIGroups, "*") {
		reasons = append(reasons, fmt.Sprintf("wildcard API group permission (requested: %s)", apiGroup))
	}

	if len(reasons) == 0 {
		// Build explicit match reason showing what matched
		matchDetails := []string{}
		if verb != "" {
			matchDetails = append(matchDetails, fmt.Sprintf("verb=%s", verb))
		}
		if resource != "" {
			matchDetails = append(matchDetails, fmt.Sprintf("resource=%s", resource))
		}
		if apiGroup != "" {
			matchDetails = append(matchDetails, fmt.Sprintf("apiGroup=%s", apiGroup))
		}
		reasons = append(reasons, fmt.Sprintf("explicit permission match (%s)", strings.Join(matchDetails, ", ")))
	}

	return strings.Join(reasons, ", ")
}

//nolint:gocognit // Escalation risk analysis requires complex logic
func (pm *PermissionMapper) analyzeEscalationRisk(subjectPerm SubjectPermissions) []EscalationRisk {
	var risks []EscalationRisk

	for _, perm := range subjectPerm.Permissions {
		for _, rule := range perm.Rules {
			// Check for escalate verb
			for _, verb := range rule.Verbs {
				if verb == "escalate" {
					risks = append(risks, EscalationRisk{
						Type:        "Privilege Escalation",
						Description: "Can escalate privileges through RBAC",
						Severity:    RiskLevelCritical,
						Rule:        rule,
					})
				}

				if verb == "impersonate" {
					risks = append(risks, EscalationRisk{
						Type:        "Identity Impersonation",
						Description: "Can impersonate other users or service accounts",
						Severity:    RiskLevelCritical,
						Rule:        rule,
					})
				}

				if verb == "*" {
					risks = append(risks, EscalationRisk{
						Type:        "Unrestricted Access",
						Description: "Has wildcard permissions on resources",
						Severity:    RiskLevelHigh,
						Rule:        rule,
					})
				}
			}

			// Check for dangerous resource combinations
			hasSecretsAccess := false
			hasRBACAccess := false

			for _, resource := range rule.Resources {
				if resource == "secrets" || resource == "*" {
					hasSecretsAccess = true
				}
				// Explicitly match known RBAC resource names including cluster-scoped
				if resource == "role" || resource == "roles" ||
					resource == "rolebinding" || resource == "rolebindings" ||
					resource == "clusterrole" || resource == "clusterroles" ||
					resource == "clusterrolebinding" || resource == "clusterrolebindings" ||
					resource == "*" {
					hasRBACAccess = true
				}
			}

			if hasSecretsAccess && hasRBACAccess {
				risks = append(risks, EscalationRisk{
					Type:        "Secrets + RBAC Access",
					Description: "Can access secrets and modify RBAC - potential for privilege escalation",
					Severity:    RiskLevelHigh,
					Rule:        rule,
				})
			}
		}
	}

	return risks
}

func (pm *PermissionMapper) getRiskPriority(level RiskLevel) int {
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

func (pm *PermissionMapper) convertSubject(subject rbacv1.Subject) SubjectRef {
	return SubjectRef{
		Kind:      subject.Kind,
		Name:      subject.Name,
		Namespace: subject.Namespace,
	}
}

// Data structures for mapping results

// PermissionMatch represents a subject that matches a permission query.
type PermissionMatch struct {
	Subject     SubjectRef         `json:"subject"`
	Permission  PermissionGrant    `json:"permission"`
	Rule        PolicyRuleAnalysis `json:"rule"`
	MatchReason string             `json:"match_reason"`
}

// DangerousPermission represents a high-risk permission.
type DangerousPermission struct {
	Subject     SubjectRef         `json:"subject"`
	Permission  PermissionGrant    `json:"permission"`
	Rule        PolicyRuleAnalysis `json:"rule"`
	RiskLevel   RiskLevel          `json:"risk_level"`
	Explanation string             `json:"explanation"`
	Concerns    []string           `json:"concerns"`
}

// EscalationPath represents potential privilege escalation.
type EscalationPath struct {
	Subject SubjectRef       `json:"subject"`
	Risks   []EscalationRisk `json:"risks"`
}

// EscalationRisk represents a specific escalation risk.
type EscalationRisk struct {
	Type        string             `json:"type"`
	Description string             `json:"description"`
	Severity    RiskLevel          `json:"severity"`
	Rule        PolicyRuleAnalysis `json:"rule"`
}

// ResourceAccessMap shows who can access a resource.
type ResourceAccessMap struct {
	Resource string                      `json:"resource"`
	APIGroup string                      `json:"api_group"`
	Access   map[string][]ResourceAccess `json:"access"`
}

// ResourceAccess represents access to a resource.
type ResourceAccess struct {
	Subject    SubjectRef      `json:"subject"`
	Permission PermissionGrant `json:"permission"`
	RiskLevel  RiskLevel       `json:"risk_level"`
}

// SubjectRef is a simplified subject reference.
type SubjectRef struct {
	Kind      string `json:"kind"`
	Name      string `json:"name"`
	Namespace string `json:"namespace,omitempty"`
}
