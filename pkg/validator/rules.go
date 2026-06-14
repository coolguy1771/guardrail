package validator

// RuleMeta holds static metadata for a validation rule.
// It is the single source of truth for rule IDs, descriptions, default severities,
// and remediation text — shared by the validator, reporter (SARIF), and config loader.
type RuleMeta struct {
	ID          string
	Name        string
	Description string
	Remediation string
	DefaultSeverity Severity
}

// Catalog is the complete list of built-in rules in ID order.
// The Validate function for each rule lives in validator.go / nist_rules.go.
//
//nolint:gochecknoglobals // Package-level catalog referenced by multiple callers
var Catalog = []RuleMeta{
	{
		ID:              "RBAC001",
		Name:            "Avoid Wildcard Permissions",
		Description:     "Wildcard (*) in verbs, resources, or apiGroups grants every possible permission, including future ones.",
		Remediation:     "Replace wildcards with the specific verbs and resources your workload actually needs.",
		DefaultSeverity: SeverityCritical,
	},
	{
		ID:              "RBAC002",
		Name:            "Avoid Overly Permissive Built-in Role Bindings",
		Description:     "Binding to cluster-admin, admin, or edit grants far more access than most workloads require.",
		Remediation:     "Create a custom Role/ClusterRole with only the permissions your workload needs.",
		DefaultSeverity: SeverityCritical, // cluster-admin; lower-severity sub-findings use overrides
	},
	{
		ID:              "RBAC003",
		Name:            "Avoid Secrets Access",
		Description:     "Direct get/list access to secrets exposes credentials to any compromise of the bound subject.",
		Remediation:     "Limit secrets access to specific named resources, or mount secrets as volumes instead.",
		DefaultSeverity: SeverityMedium,
	},
	{
		ID:              "RBAC004",
		Name:            "Prefer Namespaced Roles",
		Description:     "A ClusterRole whose rules only reference namespace-scoped resources should be a Role instead.",
		Remediation:     "Convert this ClusterRole to a Role in the specific namespace where it is needed.",
		DefaultSeverity: SeverityLow,
	},
	{
		ID:              "RBAC005",
		Name:            "Avoid Service Account Token Automounting",
		Description:     "Service accounts with risky role names should not automount tokens (NIST SP 800-190).",
		Remediation:     "Set automountServiceAccountToken: false on the ServiceAccount, or reduce its bound permissions.",
		DefaultSeverity: SeverityMedium,
	},
	{
		ID:              "RBAC006",
		Name:            "Restrict Exec and Attach Permissions",
		Description:     "The exec and attach verbs allow interactive shell access to running containers (NIST SP 800-190).",
		Remediation:     "Grant exec/attach only to cluster administrators and audit all usage.",
		DefaultSeverity: SeverityHigh,
	},
	{
		ID:              "RBAC007",
		Name:            "Limit Impersonation Privileges",
		Description:     "Impersonation lets a subject act as any other user, group, or service account (NIST SP 800-190).",
		Remediation:     "Restrict impersonate permission to a minimal, audited set of automation accounts.",
		DefaultSeverity: SeverityHigh,
	},
	{
		ID:              "RBAC008",
		Name:            "Restrict Escalate and Bind Verbs",
		Description:     "The escalate and bind verbs bypass normal permission checks and enable privilege escalation (NIST SP 800-190).",
		Remediation:     "Remove escalate/bind unless the subject is a trusted role-management controller.",
		DefaultSeverity: SeverityHigh,
	},
	{
		ID:              "RBAC009",
		Name:            "Audit Privileged Container Access",
		Description:     "Access to PodSecurityPolicy or SecurityContextConstraints can enable privileged containers (NIST SP 800-190).",
		Remediation:     "Restrict PSP/SCC access and require explicit security context reviews.",
		DefaultSeverity: SeverityHigh,
	},
	{
		ID:              "RBAC010",
		Name:            "Restrict Node and PersistentVolume Access",
		Description:     "Direct node and persistent-volume access bypasses namespace isolation (NIST SP 800-190).",
		Remediation:     "Grant node/PV access only to the kubelet and storage controllers.",
		DefaultSeverity: SeverityMedium,
	},
	{
		ID:              "RBAC011",
		Name:            "Limit Webhook Configuration Access",
		Description:     "Write access to webhook configurations can intercept or mutate every API request (NIST SP 800-190).",
		Remediation:     "Restrict webhook configuration mutations to your cluster-management tooling.",
		DefaultSeverity: SeverityHigh,
	},
	{
		ID:              "RBAC012",
		Name:            "Restrict CRD and APIService Modifications",
		Description:     "CRDs and APIServices extend the Kubernetes API surface; write access can affect all workloads (NIST SP 800-190).",
		Remediation:     "Limit CRD/APIService write access to your GitOps or operator tooling.",
		DefaultSeverity: SeverityHigh,
	},
	{
		ID:              "RBAC013",
		Name:            "Separate Concerns with Namespace Isolation",
		Description:     "ClusterRoles with cross-namespace resource access undermine multi-tenant isolation (NIST SP 800-190).",
		Remediation:     "Scope roles to the namespace they operate in; avoid cluster-wide read of namespace-scoped resources.",
		DefaultSeverity: SeverityMedium,
	},
	{
		ID:              "RBAC014",
		Name:            "Restrict TokenRequest and CertificateSigningRequest",
		Description:     "Creating tokens or signing certificates can forge identities and bypass authentication (NIST SP 800-190).",
		Remediation:     "Restrict token and certificate creation to your PKI and service-mesh automation only.",
		DefaultSeverity: SeverityHigh,
	},
}

// CatalogByID returns a map of rule ID → RuleMeta for O(1) lookups.
func CatalogByID() map[string]RuleMeta {
	m := make(map[string]RuleMeta, len(Catalog))
	for _, r := range Catalog {
		m[r.ID] = r
	}
	return m
}
