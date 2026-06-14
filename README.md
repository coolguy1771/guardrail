# Guardrail

Guardrail is a Kubernetes RBAC security scanner. It validates Role, ClusterRole, RoleBinding, and ClusterRoleBinding manifests against a built-in rule catalog covering wildcards, overly permissive bindings, secrets access, privilege escalation, and more — and it can analyze live clusters too.

[![Go Report Card](https://goreportcard.com/badge/github.com/coolguy1771/guardrail)](https://goreportcard.com/report/github.com/coolguy1771/guardrail)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

---

## Installation

```bash
go install github.com/coolguy1771/guardrail/cmd/guardrail@latest
```

Or download a pre-built binary from the [Releases](https://github.com/coolguy1771/guardrail/releases) page.

---

## Quick start

```bash
# Validate a single manifest file
guardrail validate -f path/to/role.yaml

# Validate every YAML file in a directory
guardrail validate -d path/to/manifests/

# Validate live cluster RBAC (requires kubeconfig)
guardrail validate --cluster

# Analyze who has what permissions
guardrail analyze -f path/to/manifests/

# See which subjects can get secrets
guardrail who-can --verb get --resource secrets -f rbac.yaml

# List all subjects with HIGH or CRITICAL risk
guardrail dangerous -d ./manifests/
```

---

## Commands

### `guardrail validate`

Validates RBAC manifests against the security rule catalog.

```
Usage:
  guardrail validate [flags]

Flags:
  -f, --file strings      RBAC manifest file(s) to validate (repeatable)
  -d, --dir string        Directory of RBAC manifests to validate
  -c, --cluster           Validate live cluster RBAC
      --kubeconfig string Path to kubeconfig file (default: KUBECONFIG env / ~/.kube/config)
      --context string    Kubernetes context to use
      --fail-on string    Exit non-zero at this severity: none|any|info|low|medium|high|critical (default: high)
  -o, --output string     Output format: text|json|sarif (default: text)
      --no-color          Disable color output
      --verbose           Print per-file parse details
```

**Exit codes**

| Code | Meaning |
|------|---------|
| `0`  | No findings at or above the `--fail-on` threshold |
| `1`  | One or more findings at or above the threshold, or a fatal error |

### `guardrail analyze`

Analyzes all subjects and explains their effective permissions in plain English.

```
Usage:
  guardrail analyze [flags]

Flags:
  -f, --file string       RBAC manifest file to analyze
  -d, --dir string        Directory of RBAC manifests
  -c, --cluster           Analyze live cluster
      --kubeconfig string Path to kubeconfig file
      --context string    Kubernetes context to use
  -s, --subject string    Filter by subject name (exact match)
      --risk-level string Filter by risk: low|medium|high|critical (case-insensitive)
      --show-roles        Include per-rule permission details
  -o, --output string     Output format: text|json
```

### `guardrail who-can`

Shows which subjects can perform a specific verb on a specific resource, with the binding chain that grants the permission.

```
Usage:
  guardrail who-can --verb <verb> --resource <resource> [flags]

Flags:
      --verb string       Kubernetes verb (e.g. get, list, create, delete, *)  [required]
      --resource string   Resource type (e.g. pods, secrets, *)               [required]
      --api-group string  API group filter (empty = core API, * = all)
  -f, --file string / -d, --dir string / -c, --cluster (same as analyze)

Examples:
  guardrail who-can --verb get --resource secrets -f rbac.yaml
  guardrail who-can --verb '*' --resource '*' --cluster
```

### `guardrail dangerous`

Shows all subjects with HIGH or CRITICAL risk permissions, useful as a quick security sweep.

```
Usage:
  guardrail dangerous [flags]

Flags:
  -f, --file / -d, --dir / -c, --cluster (same as analyze)
  -o, --output string  text|json
```

### `guardrail version`

Prints version, commit hash, and build date.

```
guardrail version
guardrail version -o json
```

---

## Rule catalog

| Rule ID | Name | Default Severity | Description |
|---------|------|-----------------|-------------|
| RBAC001 | Avoid Wildcard Permissions | CRITICAL | Wildcard (`*`) in verbs, resources, or apiGroups grants every possible permission |
| RBAC002 | Avoid Overly Permissive Built-in Role Bindings | CRITICAL | Binding to `cluster-admin` (CRITICAL), `admin` (HIGH), or `edit` (MEDIUM) |
| RBAC003 | Avoid Secrets Access | MEDIUM | Direct `get`/`list` access to secrets exposes credentials |
| RBAC004 | Prefer Namespaced Roles | LOW | ClusterRole whose rules only touch namespace-scoped resources |
| RBAC005 | Avoid Service Account Token Automounting | MEDIUM | Service accounts with risky role names should not automount tokens |
| RBAC006 | Restrict Exec and Attach Permissions | HIGH | `exec` and `attach` verbs allow interactive shell access to containers |
| RBAC007 | Limit Impersonation Privileges | HIGH | `impersonate` lets a subject act as any other user or service account |
| RBAC008 | Restrict Escalate and Bind Verbs | HIGH | `escalate` and `bind` bypass normal permission checks |
| RBAC009 | Audit Privileged Container Access | HIGH | Access to PodSecurityPolicy / SecurityContextConstraints |
| RBAC010 | Restrict Node and PersistentVolume Access | MEDIUM | Direct node and PV access bypasses namespace isolation |
| RBAC011 | Limit Webhook Configuration Access | HIGH | Write access to webhook configs can intercept every API request |
| RBAC012 | Restrict CRD and APIService Modifications | HIGH | CRDs and APIServices extend the API surface for all workloads |
| RBAC013 | Separate Concerns with Namespace Isolation | MEDIUM | ClusterRoles with cross-namespace resource access |
| RBAC014 | Restrict TokenRequest and CertificateSigningRequest | HIGH | Creating tokens or certificates can forge identities |

Severities can be overridden per-rule in `configs/guardrail.yaml`.

---

## Output formats

### Text (default)

```
Found 2 issue(s)

[CRIT]   CRITICAL (1)
--------------------------------------------------------------------------------
Rule:         RBAC001 - Avoid Wildcard Permissions
Resource:     ClusterRole/superuser
Message:      Wildcard verb '*' found in ClusterRole
Remediation:  Replace wildcards with the specific verbs and resources your workload actually needs.

[HIGH]   HIGH (1)
--------------------------------------------------------------------------------
Rule:         RBAC002 - Avoid Overly Permissive Built-in Role Bindings
Resource:     ClusterRoleBinding/bind-admin
Message:      ClusterRoleBinding "bind-admin" binds to "admin" (grants broad write access...)
```

### JSON (`-o json`)

```json
{
  "timestamp": "2026-06-14T20:00:00Z",
  "summary": {
    "total": 2,
    "by_severity": { "CRITICAL": 1, "HIGH": 1 }
  },
  "findings": [ ... ]
}
```

### SARIF (`-o sarif`)

SARIF 2.1.0 output compatible with GitHub Advanced Security, VS Code, and other SARIF consumers. All 14 rules are always present in the `rules` array (with `helpUri` and remediation text), even when a rule produces no findings.

```bash
guardrail validate -d ./manifests/ -o sarif > guardrail.sarif
```

---

## Configuration

Guardrail looks for a config file in the following order:

1. `$GUARDRAIL_CONFIG` environment variable
2. `/etc/guardrail/guardrail.yaml`
3. `$HOME/.guardrail/guardrail.yaml`
4. `./guardrail.yaml` (current directory)

A fully annotated example is at [`configs/guardrail.yaml`](configs/guardrail.yaml).

**Per-rule severity override:**

```yaml
rules:
  RBAC003:
    enabled: true
    severity: HIGH   # promote secrets access to HIGH in your environment
```

---

## CI integration

### GitHub Actions (with SARIF upload)

Copy [`.github/workflows/rbac-validate.yml`](.github/workflows/rbac-validate.yml) into your repository.  
It runs `guardrail validate --dir .` on every push and PR, and uploads SARIF results to the GitHub Security tab.

```yaml
- name: Validate RBAC manifests
  run: guardrail validate --dir . --fail-on high
```

### Pre-commit hook

Add to `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/coolguy1771/guardrail
    rev: v0.1.0
    hooks:
      - id: guardrail-validate
```

---

## Environment variables

| Variable | Effect |
|----------|--------|
| `GUARDRAIL_CONFIG` | Path to config file |
| `NO_COLOR` | Disable color and emoji output |
| `KUBECONFIG` | Path to kubeconfig (same as kubectl) |

---

## Project structure

```
cmd/guardrail/     CLI entry point and command implementations
pkg/analyzer/      RBAC permission analysis and risk scoring
pkg/kubernetes/    Live cluster client
pkg/parser/        YAML parser for RBAC manifests
pkg/reporter/      Text, JSON, and SARIF output formatters
pkg/validator/     Security rule engine and rule catalog
configs/           Default configuration file
testdata/          Example manifests for testing
```

---

## Contributing

Contributions are welcome — open an issue or pull request. Run `make test` before submitting.

## License

[Apache 2.0](LICENSE)
