package analyzer //nolint:testpackage // Uses internal analyzer fields for testing

import (
	"strings"
	"testing"

	rbacv1 "k8s.io/api/rbac/v1"

	"github.com/coolguy1771/guardrail/internal/testutil"
)

func TestNewPermissionMapper(t *testing.T) {
	permissions := []SubjectPermissions{
		{
			Subject: rbacv1.Subject{
				Kind: "User",
				Name: "alice",
			},
			Permissions: []PermissionGrant{},
		},
	}

	mapper := NewPermissionMapper(permissions)
	testutil.AssertNotNil(t, mapper, "NewPermissionMapper should return non-nil mapper")
	testutil.AssertEqual(t, 1, len(mapper.permissions), "mapper should have 1 permission")
}

func TestWhoCanDo(t *testing.T) {
	// Create test permissions
	permissions := []SubjectPermissions{
		{
			Subject: rbacv1.Subject{
				Kind: "User",
				Name: "alice",
			},
			Permissions: []PermissionGrant{
				{
					RoleName: "pod-reader",
					RoleKind: "Role",
					Rules: []PolicyRuleAnalysis{
						{
							Verbs:     []string{"get", "list"},
							Resources: []string{"pods"},
							APIGroups: []string{""},
							SecurityImpact: SecurityImpact{
								Level: RiskLevelLow,
							},
						},
					},
				},
			},
		},
		{
			Subject: rbacv1.Subject{
				Kind: "ServiceAccount",
				Name: "admin-sa",
			},
			Permissions: []PermissionGrant{
				{
					RoleName: "admin",
					RoleKind: "ClusterRole",
					Rules: []PolicyRuleAnalysis{
						{
							Verbs:     []string{"*"},
							Resources: []string{"*"},
							APIGroups: []string{"*"},
							SecurityImpact: SecurityImpact{
								Level: RiskLevelCritical,
							},
						},
					},
				},
			},
		},
	}

	mapper := NewPermissionMapper(permissions)

	tests := []struct {
		name        string
		verb        string
		resource    string
		apiGroup    string
		expectCount int
		expectFirst string // expected first subject name
	}{
		{
			name:        "who can get pods",
			verb:        "get",
			resource:    "pods",
			apiGroup:    "",
			expectCount: 2,          // both alice and admin-sa
			expectFirst: "admin-sa", // admin-sa should be first (critical risk)
		},
		{
			name:        "who can delete secrets",
			verb:        "delete",
			resource:    "secrets",
			apiGroup:    "",
			expectCount: 1, // only admin-sa
			expectFirst: "admin-sa",
		},
		{
			name:        "who can create deployments",
			verb:        "create",
			resource:    "deployments",
			apiGroup:    "apps",
			expectCount: 1, // only admin-sa with wildcard
			expectFirst: "admin-sa",
		},
		{
			name:        "who can impersonate users",
			verb:        "impersonate",
			resource:    "users",
			apiGroup:    "",
			expectCount: 1, // admin-sa with wildcard can do anything
			expectFirst: "admin-sa",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches := mapper.WhoCanDo(tt.verb, tt.resource, tt.apiGroup)
			testutil.AssertEqual(t, tt.expectCount, len(matches), "number of matches")

			if tt.expectCount > 0 && len(matches) > 0 {
				testutil.AssertEqual(t, tt.expectFirst, matches[0].Subject.Name, "first subject name")
			}
		})
	}
}

func TestWhatCanSubjectDo(t *testing.T) {
	permissions := []SubjectPermissions{
		{
			Subject: rbacv1.Subject{
				Kind: "User",
				Name: "alice",
			},
			Permissions: []PermissionGrant{
				{RoleName: "reader"},
			},
		},
		{
			Subject: rbacv1.Subject{
				Kind: "User",
				Name: "bob",
			},
			Permissions: []PermissionGrant{
				{RoleName: "writer"},
			},
		},
		{
			Subject: rbacv1.Subject{
				Kind: "ServiceAccount",
				Name: "default",
			},
			Permissions: []PermissionGrant{
				{RoleName: "viewer"},
			},
		},
	}

	mapper := NewPermissionMapper(permissions)

	tests := []struct {
		name        string
		subjectKind string
		subjectName string
		expectCount int
	}{
		{
			name:        "specific user",
			subjectKind: "User",
			subjectName: "alice",
			expectCount: 1,
		},
		{
			name:        "all users",
			subjectKind: "User",
			subjectName: "",
			expectCount: 2,
		},
		{
			name:        "all subjects named default",
			subjectKind: "",
			subjectName: "default",
			expectCount: 1,
		},
		{
			name:        "non-existent subject",
			subjectKind: "User",
			subjectName: "charlie",
			expectCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := mapper.WhatCanSubjectDo(tt.subjectKind, tt.subjectName)
			testutil.AssertEqual(t, tt.expectCount, len(result), "number of results")
		})
	}
}

func TestGetDangerousPermissions(t *testing.T) {
	permissions := []SubjectPermissions{
		{
			Subject: rbacv1.Subject{
				Kind: "User",
				Name: "alice",
			},
			Permissions: []PermissionGrant{
				{
					RoleName: "reader",
					Rules: []PolicyRuleAnalysis{
						{
							Verbs:     []string{"get", "list"},
							Resources: []string{"pods"},
							SecurityImpact: SecurityImpact{
								Level:       RiskLevelLow,
								Description: "Read pods",
							},
						},
					},
				},
			},
		},
		{
			Subject: rbacv1.Subject{
				Kind: "ServiceAccount",
				Name: "admin-sa",
			},
			Permissions: []PermissionGrant{
				{
					RoleName: "admin",
					Rules: []PolicyRuleAnalysis{
						{
							Verbs:     []string{"*"},
							Resources: []string{"*"},
							SecurityImpact: SecurityImpact{
								Level:       RiskLevelCritical,
								Description: "Full cluster access",
								Concerns:    []string{"Can do anything"},
							},
						},
					},
				},
				{
					RoleName: "secrets-reader",
					Rules: []PolicyRuleAnalysis{
						{
							Verbs:     []string{"get", "list"},
							Resources: []string{"secrets"},
							SecurityImpact: SecurityImpact{
								Level:       RiskLevelHigh,
								Description: "Read secrets",
								Concerns:    []string{"Access to sensitive data"},
							},
						},
					},
				},
			},
		},
	}

	mapper := NewPermissionMapper(permissions)
	dangerous := mapper.GetDangerousPermissions()

	// Should have 2 dangerous permissions (critical and high)
	testutil.AssertEqual(t, 2, len(dangerous), "number of dangerous permissions")

	// Check that they're sorted by risk (critical first)
	if len(dangerous) >= 2 {
		testutil.AssertEqual(t, RiskLevelCritical, dangerous[0].RiskLevel, "first should be critical")
		testutil.AssertEqual(t, RiskLevelHigh, dangerous[1].RiskLevel, "second should be high")
	}
}

func TestGetPrivilegeEscalationPaths(t *testing.T) {
	permissions := []SubjectPermissions{
		{
			Subject: rbacv1.Subject{
				Kind: "User",
				Name: "escalator",
			},
			Permissions: []PermissionGrant{
				{
					Rules: []PolicyRuleAnalysis{
						{
							Verbs:     []string{"escalate"},
							Resources: []string{"roles"},
							APIGroups: []string{"rbac.authorization.k8s.io"},
						},
					},
				},
			},
		},
		{
			Subject: rbacv1.Subject{
				Kind: "ServiceAccount",
				Name: "impersonator",
			},
			Permissions: []PermissionGrant{
				{
					Rules: []PolicyRuleAnalysis{
						{
							Verbs:     []string{"impersonate"},
							Resources: []string{"users"},
							APIGroups: []string{""},
						},
					},
				},
			},
		},
		{
			Subject: rbacv1.Subject{
				Kind: "User",
				Name: "normal-user",
			},
			Permissions: []PermissionGrant{
				{
					Rules: []PolicyRuleAnalysis{
						{
							Verbs:     []string{"get", "list"},
							Resources: []string{"pods"},
							APIGroups: []string{""},
						},
					},
				},
			},
		},
	}

	mapper := NewPermissionMapper(permissions)
	paths := mapper.GetPrivilegeEscalationPaths()

	// Should have 2 escalation paths (escalator and impersonator)
	testutil.AssertEqual(t, 2, len(paths), "number of escalation paths")

	// Check the types of risks found
	foundEscalate := false
	foundImpersonate := false
	for _, path := range paths {
		for _, risk := range path.Risks {
			if risk.Type == "Privilege Escalation" {
				foundEscalate = true
			}
			if risk.Type == "Identity Impersonation" {
				foundImpersonate = true
			}
		}
	}

	if !foundEscalate {
		t.Error("expected to find privilege escalation risk")
	}
	if !foundImpersonate {
		t.Error("expected to find identity impersonation risk")
	}
}

func TestGetResourceAccess(t *testing.T) {
	permissions := []SubjectPermissions{
		{
			Subject: rbacv1.Subject{
				Kind: "User",
				Name: "reader",
			},
			Permissions: []PermissionGrant{
				{
					RoleName: "pod-reader",
					Rules: []PolicyRuleAnalysis{
						{
							Verbs:     []string{"get", "list"},
							Resources: []string{"pods"},
							APIGroups: []string{""},
							SecurityImpact: SecurityImpact{
								Level: RiskLevelLow,
							},
						},
					},
				},
			},
		},
		{
			Subject: rbacv1.Subject{
				Kind: "User",
				Name: "writer",
			},
			Permissions: []PermissionGrant{
				{
					RoleName: "pod-writer",
					Rules: []PolicyRuleAnalysis{
						{
							Verbs:     []string{"create", "update", "delete"},
							Resources: []string{"pods"},
							APIGroups: []string{""},
							SecurityImpact: SecurityImpact{
								Level: RiskLevelMedium,
							},
						},
					},
				},
			},
		},
	}

	mapper := NewPermissionMapper(permissions)
	accessMap := mapper.GetResourceAccess("pods", "")

	testutil.AssertEqual(t, "pods", accessMap.Resource, "resource name")
	testutil.AssertEqual(t, "", accessMap.APIGroup, "api group")
	testutil.AssertNotNil(t, accessMap.Access, "access map")

	// Check specific verb access
	getAccess := accessMap.Access["get"]
	testutil.AssertEqual(t, 1, len(getAccess), "one user can get pods")
	if len(getAccess) > 0 {
		testutil.AssertEqual(t, "reader", getAccess[0].Subject.Name, "reader can get pods")
	}

	createAccess := accessMap.Access["create"]
	testutil.AssertEqual(t, 1, len(createAccess), "one user can create pods")
	if len(createAccess) > 0 {
		testutil.AssertEqual(t, "writer", createAccess[0].Subject.Name, "writer can create pods")
	}
}

func TestRuleMatches(t *testing.T) {
	mapper := &PermissionMapper{}

	tests := []struct {
		name     string
		rule     PolicyRuleAnalysis
		verb     string
		resource string
		apiGroup string
		expected bool
	}{
		{
			name: "exact match",
			rule: PolicyRuleAnalysis{
				Verbs:     []string{"get", "list"},
				Resources: []string{"pods"},
				APIGroups: []string{""},
			},
			verb:     "get",
			resource: "pods",
			apiGroup: "",
			expected: true,
		},
		{
			name: "wildcard verb match",
			rule: PolicyRuleAnalysis{
				Verbs:     []string{"*"},
				Resources: []string{"pods"},
				APIGroups: []string{""},
			},
			verb:     "delete",
			resource: "pods",
			apiGroup: "",
			expected: true,
		},
		{
			name: "wildcard resource match",
			rule: PolicyRuleAnalysis{
				Verbs:     []string{"get"},
				Resources: []string{"*"},
				APIGroups: []string{"apps"},
			},
			verb:     "get",
			resource: "deployments",
			apiGroup: "apps",
			expected: true,
		},
		{
			name: "wildcard api group match",
			rule: PolicyRuleAnalysis{
				Verbs:     []string{"get"},
				Resources: []string{"deployments"},
				APIGroups: []string{"*"},
			},
			verb:     "get",
			resource: "deployments",
			apiGroup: "apps",
			expected: true,
		},
		{
			name: "no match - wrong verb",
			rule: PolicyRuleAnalysis{
				Verbs:     []string{"get", "list"},
				Resources: []string{"pods"},
				APIGroups: []string{""},
			},
			verb:     "delete",
			resource: "pods",
			apiGroup: "",
			expected: false,
		},
		{
			name: "no match - wrong resource",
			rule: PolicyRuleAnalysis{
				Verbs:     []string{"get"},
				Resources: []string{"pods"},
				APIGroups: []string{""},
			},
			verb:     "get",
			resource: "services",
			apiGroup: "",
			expected: false,
		},
		{
			name: "no match - wrong api group",
			rule: PolicyRuleAnalysis{
				Verbs:     []string{"get"},
				Resources: []string{"deployments"},
				APIGroups: []string{"apps"},
			},
			verb:     "get",
			resource: "deployments",
			apiGroup: "extensions",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := mapper.ruleMatches(tt.rule, tt.verb, tt.resource, tt.apiGroup)
			testutil.AssertEqual(t, tt.expected, result, "rule match")
		})
	}
}

func TestMatchesResource(t *testing.T) {
	mapper := &PermissionMapper{}

	tests := []struct {
		name           string
		ruleResources  []string
		targetResource string
		expected       bool
	}{
		{
			name:           "exact match",
			ruleResources:  []string{"pods", "services"},
			targetResource: "pods",
			expected:       true,
		},
		{
			name:           "wildcard match",
			ruleResources:  []string{"*"},
			targetResource: "anything",
			expected:       true,
		},
		{
			name:           "subresource match - rule has base",
			ruleResources:  []string{"pods"},
			targetResource: "pods/exec",
			expected:       true,
		},
		{
			name:           "no match",
			ruleResources:  []string{"pods", "services"},
			targetResource: "deployments",
			expected:       false,
		},
		{
			name:           "no match - subresource",
			ruleResources:  []string{"services"},
			targetResource: "pods/exec",
			expected:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := mapper.matchesResource(tt.ruleResources, tt.targetResource)
			testutil.AssertEqual(t, tt.expected, result, "resource match")
		})
	}
}

func TestMatchesAPIGroup(t *testing.T) {
	mapper := &PermissionMapper{}

	tests := []struct {
		name           string
		ruleAPIGroups  []string
		targetAPIGroup string
		expected       bool
	}{
		{
			name:           "exact match",
			ruleAPIGroups:  []string{"apps", "extensions"},
			targetAPIGroup: "apps",
			expected:       true,
		},
		{
			name:           "wildcard match",
			ruleAPIGroups:  []string{"*"},
			targetAPIGroup: "anything",
			expected:       true,
		},
		{
			name:           "core group - empty string to core",
			ruleAPIGroups:  []string{""},
			targetAPIGroup: "core",
			expected:       true,
		},
		{
			name:           "core group - core to empty string",
			ruleAPIGroups:  []string{"core"},
			targetAPIGroup: "",
			expected:       true,
		},
		{
			name:           "no match",
			ruleAPIGroups:  []string{"apps"},
			targetAPIGroup: "batch",
			expected:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := mapper.matchesAPIGroup(tt.ruleAPIGroups, tt.targetAPIGroup)
			testutil.AssertEqual(t, tt.expected, result, "API group match")
		})
	}
}

func TestAnalyzeEscalationRisk(t *testing.T) {
	mapper := &PermissionMapper{}

	tests := []struct {
		name        string
		permissions SubjectPermissions
		expectRisks int
		expectTypes []string
	}{
		{
			name: "escalate verb",
			permissions: SubjectPermissions{
				Permissions: []PermissionGrant{
					{
						Rules: []PolicyRuleAnalysis{
							{
								Verbs:     []string{"escalate"},
								Resources: []string{"roles"},
							},
						},
					},
				},
			},
			expectRisks: 1,
			expectTypes: []string{"Privilege Escalation"},
		},
		{
			name: "impersonate verb",
			permissions: SubjectPermissions{
				Permissions: []PermissionGrant{
					{
						Rules: []PolicyRuleAnalysis{
							{
								Verbs:     []string{"impersonate"},
								Resources: []string{"users"},
							},
						},
					},
				},
			},
			expectRisks: 1,
			expectTypes: []string{"Identity Impersonation"},
		},
		{
			name: "wildcard verb",
			permissions: SubjectPermissions{
				Permissions: []PermissionGrant{
					{
						Rules: []PolicyRuleAnalysis{
							{
								Verbs:     []string{"*"},
								Resources: []string{"pods"},
							},
						},
					},
				},
			},
			expectRisks: 1,
			expectTypes: []string{"Unrestricted Access"},
		},
		{
			name: "secrets and rbac access",
			permissions: SubjectPermissions{
				Permissions: []PermissionGrant{
					{
						Rules: []PolicyRuleAnalysis{
							{
								Verbs:     []string{"get"},
								Resources: []string{"secrets", "roles"},
							},
						},
					},
				},
			},
			expectRisks: 1,
			expectTypes: []string{"Secrets + RBAC Access"},
		},
		{
			name: "multiple risks",
			permissions: SubjectPermissions{
				Permissions: []PermissionGrant{
					{
						Rules: []PolicyRuleAnalysis{
							{
								Verbs:     []string{"*"},
								Resources: []string{"*"},
							},
							{
								Verbs:     []string{"impersonate"},
								Resources: []string{"users"},
							},
						},
					},
				},
			},
			expectRisks: 3, // wildcard, impersonate, secrets+rbac
			expectTypes: []string{"Unrestricted Access", "Identity Impersonation", "Secrets + RBAC Access"},
		},
		{
			name: "no risks",
			permissions: SubjectPermissions{
				Permissions: []PermissionGrant{
					{
						Rules: []PolicyRuleAnalysis{
							{
								Verbs:     []string{"get", "list"},
								Resources: []string{"pods"},
							},
						},
					},
				},
			},
			expectRisks: 0,
			expectTypes: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			risks := mapper.analyzeEscalationRisk(tt.permissions)
			testutil.AssertEqual(t, tt.expectRisks, len(risks), "number of risks")

			// Check that expected risk types are present
			for _, expectedType := range tt.expectTypes {
				found := false
				for _, risk := range risks {
					if risk.Type == expectedType {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("expected to find risk type %s, but didn't", expectedType)
				}
			}
		})
	}
}

func TestGetRiskPriority(t *testing.T) {
	mapper := &PermissionMapper{}

	tests := []struct {
		level    RiskLevel
		expected int
	}{
		{RiskLevelCritical, riskPriorityCritical},
		{RiskLevelHigh, riskPriorityHigh},
		{RiskLevelMedium, riskPriorityMedium},
		{RiskLevelLow, riskPriorityLow},
		{RiskLevel("unknown"), riskPriorityDefault},
	}

	for _, tt := range tests {
		t.Run(string(tt.level), func(t *testing.T) {
			result := mapper.getRiskPriority(tt.level)
			testutil.AssertEqual(t, tt.expected, result, "risk priority")
		})
	}
}

func TestConvertSubject(t *testing.T) {
	mapper := &PermissionMapper{}

	subject := rbacv1.Subject{
		Kind:      "ServiceAccount",
		Name:      "default",
		Namespace: "kube-system",
	}

	result := mapper.convertSubject(subject)

	testutil.AssertEqual(t, subject.Kind, result.Kind, "subject kind")
	testutil.AssertEqual(t, subject.Name, result.Name, "subject name")
	testutil.AssertEqual(t, subject.Namespace, result.Namespace, "subject namespace")
}

func TestGetMatchReason(t *testing.T) {
	mapper := &PermissionMapper{}

	tests := []struct {
		name     string
		rule     PolicyRuleAnalysis
		verb     string
		resource string
		apiGroup string
		contains string
	}{
		{
			name: "wildcard verb",
			rule: PolicyRuleAnalysis{
				Verbs:     []string{"*"},
				Resources: []string{"pods"},
				APIGroups: []string{""},
			},
			verb:     "delete",
			resource: "pods",
			apiGroup: "",
			contains: "wildcard verb permission",
		},
		{
			name: "wildcard resource",
			rule: PolicyRuleAnalysis{
				Verbs:     []string{"get"},
				Resources: []string{"*"},
				APIGroups: []string{""},
			},
			verb:     "get",
			resource: "secrets",
			apiGroup: "",
			contains: "wildcard resource permission",
		},
		{
			name: "wildcard api group",
			rule: PolicyRuleAnalysis{
				Verbs:     []string{"get"},
				Resources: []string{"deployments"},
				APIGroups: []string{"*"},
			},
			verb:     "get",
			resource: "deployments",
			apiGroup: "apps",
			contains: "wildcard API group permission",
		},
		{
			name: "explicit match",
			rule: PolicyRuleAnalysis{
				Verbs:     []string{"get", "list"},
				Resources: []string{"pods"},
				APIGroups: []string{""},
			},
			verb:     "get",
			resource: "pods",
			apiGroup: "",
			contains: "explicit permission match",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reason := mapper.getMatchReason(tt.rule, tt.verb, tt.resource, tt.apiGroup)
			if tt.contains != "" && !strings.Contains(reason, tt.contains) {
				t.Errorf("expected reason to contain '%s', got: %s", tt.contains, reason)
			}
		})
	}
}
