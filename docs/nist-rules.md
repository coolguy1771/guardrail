# NIST SP 800-190 Based RBAC Security Rules

This document describes the RBAC security rules implemented in Guardrail based on NIST Special Publication 800-190 "Application Container Security Guide".

## Overview

NIST SP 800-190 provides comprehensive guidance for securing containerized applications. The following rules help enforce the RBAC-related security recommendations from this publication.

## Rules

### RBAC005: Avoid Service Account Token Automounting
**Severity:** Medium

Service accounts with excessive permissions (cluster-admin, admin, edit) should disable automatic token mounting to reduce the risk of token compromise.

**What it detects:**
- Service accounts bound to high-privilege roles
- RoleBindings/ClusterRoleBindings that grant admin-level access to service accounts

**Remediation:**
- Set `automountServiceAccountToken: false` in pod specs or service account definitions
- Use more restrictive roles for service accounts
- Consider using projected volumes for specific token needs

### RBAC006: Restrict Exec and Attach Permissions
**Severity:** High

The `pods/exec` and `pods/attach` permissions allow interactive access to running containers, which can be used for privilege escalation and lateral movement.

**What it detects:**
- Roles/ClusterRoles with `create` or `*` verbs on `pods/exec` or `pods/attach`

**Remediation:**
- Remove exec/attach permissions from non-administrative roles
- Implement additional authentication mechanisms (e.g., kubectl-sudo)
- Use admission controllers to restrict exec/attach usage
- Enable audit logging for exec/attach operations

### RBAC007: Limit Impersonation Privileges
**Severity:** High

User impersonation allows a subject to act as another user, group, or service account, potentially bypassing security controls.

**What it detects:**
- Roles/ClusterRoles with `impersonate` verb on users, groups, or serviceaccounts
- Wildcard permissions that include impersonation

**Remediation:**
- Restrict impersonation to cluster administrators only
- Implement strict auditing for impersonation events
- Use specific resource names instead of wildcards
- Consider using external authentication providers

### RBAC008: Restrict Escalate and Bind Verbs
**Severity:** High

The `escalate` and `bind` verbs on RBAC resources can lead to privilege escalation by modifying roles or creating new bindings.

**What it detects:**
- Roles/ClusterRoles with `escalate` or `bind` verbs on RBAC resources

**Remediation:**
- Limit these permissions to cluster administrators
- Use admission webhooks to validate RBAC changes
- Implement the principle of least privilege
- Monitor RBAC modifications through audit logs

### RBAC009: Audit Privileged Container Access
**Severity:** High

Access to PodSecurityPolicies (PSPs) or SecurityContextConstraints (SCCs) can allow running privileged containers with host-level access.

**What it detects:**
- Roles/ClusterRoles with `use` verb on PSPs or SCCs

**Remediation:**
- Restrict PSP/SCC usage to specific, trusted workloads
- Implement Pod Security Standards (replacement for PSPs)
- Use admission controllers to enforce security policies
- Regularly audit privileged container usage

### RBAC010: Restrict Node and PersistentVolume Access
**Severity:** Medium

Direct access to nodes and persistent volumes can bypass namespace isolation and access sensitive host resources.

**What it detects:**
- Write permissions (`update`, `patch`, `delete`, `*`) on nodes, nodes/proxy, or persistentvolumes

**Remediation:**
- Limit node access to cluster operators
- Use PersistentVolumeClaims (PVCs) instead of direct PV access
- Implement node restriction admission controller
- Use network policies to restrict node communication

### RBAC011: Limit Webhook Configuration Access
**Severity:** High

Admission webhooks can intercept and modify API requests, making them a powerful attack vector if compromised.

**What it detects:**
- Create/update permissions on mutating or validating webhook configurations

**Remediation:**
- Restrict webhook management to cluster administrators
- Implement webhook certificate rotation
- Monitor webhook configurations for changes
- Use namespace-scoped webhooks when possible

### RBAC012: Restrict CRD and APIService Modifications
**Severity:** High

Custom Resource Definitions (CRDs) and API services extend the Kubernetes API and can introduce security vulnerabilities.

**What it detects:**
- Modification permissions on CRDs or APIServices

**Remediation:**
- Limit CRD/APIService management to platform teams
- Implement CRD validation schemas
- Use admission webhooks to validate custom resources
- Regular security reviews of custom APIs

### RBAC013: Separate Concerns with Namespace Isolation
**Severity:** Medium

RoleBindings that reference ClusterRoles can grant cross-namespace permissions, violating the principle of namespace isolation.

**What it detects:**
- RoleBindings with ClusterRole references

**Remediation:**
- Use namespace-specific Roles instead of ClusterRoles
- Implement namespace isolation policies
- Use network policies for additional isolation
- Regular review of cross-namespace permissions

### RBAC014: Restrict TokenRequest and CertificateSigningRequest
**Severity:** High

Creating service account tokens or certificate signing requests can be used to bypass authentication mechanisms.

**What it detects:**
- Create permissions on `serviceaccounts/token` or `certificatesigningrequests`

**Remediation:**
- Restrict token/certificate creation to authorized components
- Use bound service account tokens
- Implement short-lived token policies
- Monitor token and certificate creation events

## Implementation Notes

These rules are designed to work alongside the existing RBAC validation rules in Guardrail:
- RBAC001: Avoid Wildcard Permissions
- RBAC002: Avoid Cluster-Admin Binding
- RBAC003: Avoid Secrets Access
- RBAC004: Prefer Namespaced Roles

Together, they provide comprehensive coverage of RBAC security best practices as recommended by NIST SP 800-190.

## Testing

Use the `testdata/nist-violations.yaml` file to test these rules:

```bash
# Validate a file with NIST violations
guardrail validate -f testdata/nist-violations.yaml

# Analyze permissions with risk assessment
guardrail analyze -f testdata/nist-violations.yaml
```

## References

- [NIST SP 800-190: Application Container Security Guide](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-190.pdf)
- [Kubernetes RBAC Documentation](https://kubernetes.io/docs/reference/access-authn-authz/rbac/)
- [Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)