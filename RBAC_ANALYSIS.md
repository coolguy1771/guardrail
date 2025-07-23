# RBAC Analysis Feature

Guardrail now includes powerful RBAC analysis capabilities that explain what permissions subjects (users, groups, service accounts) have in plain English.

## Features

### 🔍 **Permission Analysis**
- Analyzes RoleBindings and ClusterRoleBindings
- Shows what each subject can do in human-readable format
- Explains every verb with examples and risk levels
- Identifies security concerns and risks

### 📊 **Risk Assessment**
- **Critical**: Complete admin access, impersonation, escalation
- **High**: Dangerous permissions like delete, broad access
- **Medium**: Sensitive resource access, some elevated permissions  
- **Low**: Read-only access, standard operations

### 🔧 **Verb Explanations**

Each Kubernetes RBAC verb is explained in plain English:

| Verb | Explanation | Risk Level | Example |
|------|-------------|------------|---------|
| `get` | Read/retrieve individual resources by name | Low | `kubectl get pod my-pod` |
| `list` | List/view all resources of this type | Low | `kubectl get pods` |
| `watch` | Monitor resources for changes in real-time | Low | `kubectl get pods -w` |
| `create` | Create new resources | Medium | `kubectl create`, `kubectl apply` |
| `update` | Modify existing resources (full replacement) | Medium | `kubectl replace` |
| `patch` | Partially modify existing resources | Medium | `kubectl patch` |
| `delete` | Remove/destroy resources | High | `kubectl delete` |
| `deletecollection` | Delete multiple resources at once | High | `kubectl delete pods --all` |
| `bind` | Bind resources (typically PVs) | Medium | PVC binding to PV |
| `escalate` | Grant additional permissions | **Critical** | Privilege escalation |
| `impersonate` | Act as another user/service account | **Critical** | `kubectl --as=user` |
| `use` | Use specific resources | Medium | Pod security policies |
| `*` | **ALL POSSIBLE ACTIONS** | **Critical** | Complete control |

### 🚨 **Security Impact Analysis**

The analyzer automatically identifies:
- **Wildcard permissions** (`*` in verbs, resources, or API groups)
- **Dangerous combinations** (secrets + RBAC access)
- **Privilege escalation paths**
- **Impersonation capabilities**
- **Over-privileged accounts**

## Usage

### Basic Analysis
```bash
# Analyze RBAC files
guardrail analyze -f rbac-manifest.yaml
guardrail analyze -d ./rbac-configs/

# Analyze live cluster
guardrail analyze --cluster

# Filter by subject
guardrail analyze --cluster --subject admin@company.com

# Filter by risk level
guardrail analyze --cluster --risk-level critical

# Show detailed role information
guardrail analyze -f rbac.yaml --show-roles
```

### Example Output

The demo shows analysis of complex RBAC configurations:

```bash
go run ./examples/analyze-demo.go
```

**Sample Output:**
```
📊 RBAC Analysis Summary
========================
Total Subjects: 6
Risk Distribution:
  🔴 Critical: 2
  🟠 High: 1
  🟡 Medium: 2
  🟢 Low: 1

🔴 User: admin@company.com
   Risk Level: CRITICAL
   Summary: Complete cluster administrative access via cluster-admin role

  📋 Detailed Permissions:
     • ALL POSSIBLE ACTIONS - complete control over resources
       Risk: CRITICAL
       ⚠️  Concerns: Can perform any action on any resource
       🔧 Actions allowed:
         - *: ALL POSSIBLE ACTIONS - complete control over resources
           Example: Full administrative access, can do anything
```

### Understanding the Output

#### 🎯 **Subject Information**
- **Kind**: User, Group, or ServiceAccount
- **Name**: Subject identifier
- **Namespace**: For namespaced subjects
- **Risk Level**: Overall risk assessment

#### 📋 **Permission Details**
- **Role Information**: Which role grants the permissions
- **Scope**: Cluster-wide or namespace-specific
- **Binding**: How the subject is bound to the role

#### 🔧 **Action Explanations**
- **Verb**: The Kubernetes action (get, create, delete, etc.)
- **Explanation**: What the action allows in plain English
- **Risk Level**: Security risk of this specific action
- **Examples**: Real-world command examples

#### ⚠️ **Security Concerns**
- Specific risks identified in the permissions
- Potential attack vectors
- Compliance issues

## Key Security Findings

The analyzer identifies common security issues:

### 🔴 **Critical Issues**
- **Cluster-admin access**: Complete control over cluster
- **Impersonation rights**: Can act as other users
- **Escalation permissions**: Can grant additional privileges
- **Wildcard permissions**: Unrestricted access patterns

### 🟠 **High Risk Issues** 
- **Broad resource access**: Access to many resource types
- **Dangerous verbs**: Delete, create on sensitive resources
- **Secrets access**: Direct access to sensitive data
- **Cross-namespace access**: Permissions beyond intended scope

### 🟡 **Medium Risk Issues**
- **Elevated permissions**: More than standard read-only
- **Sensitive resources**: Access to specific high-value resources
- **Pod execution**: Ability to run commands in containers

## Best Practices Recommendations

Based on analysis results, Guardrail provides actionable recommendations:

### 🛡️ **Security Hardening**
- Replace cluster-admin with custom roles
- Remove impersonation unless absolutely necessary
- Scope permissions to specific namespaces
- Add resource name restrictions
- Implement regular RBAC audits

### 📏 **Principle of Least Privilege**
- Grant minimum required permissions
- Use Role instead of ClusterRole when possible
- Specify exact resources instead of wildcards
- Limit verbs to necessary actions only

### 🔍 **Monitoring & Auditing**
- Regular permission reviews
- Monitor high-risk subjects
- Audit privilege escalation attempts
- Track access to sensitive resources

## Advanced Features

### Permission Mapping
```go
// Who can delete pods?
matches := mapper.WhoCanDo("delete", "pods", "")

// What can a specific user do?
permissions := mapper.WhatCanSubjectDo("User", "admin@company.com")

// Find dangerous permissions
dangerous := mapper.GetDangerousPermissions()

// Identify privilege escalation paths
paths := mapper.GetPrivilegeEscalationPaths()
```

### Custom Risk Assessment
The analyzer considers:
- Resource sensitivity (secrets, RBAC resources, nodes)
- Verb danger level (delete > create > get)
- Scope breadth (cluster > namespace > specific resources)
- Permission combinations (secrets + RBAC = high risk)

## Integration

The RBAC analysis integrates with existing Guardrail features:

- **Validation**: Combines with policy validation
- **Reporting**: Available in text, JSON, and SARIF formats
- **CI/CD**: Use in pipelines to catch privilege escalation
- **Monitoring**: Continuous analysis of live clusters

This feature transforms complex RBAC configurations into clear, actionable security insights, helping teams maintain secure Kubernetes environments.