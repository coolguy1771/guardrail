# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| > 0.1.x | :white_check_mark: |
| < 0.1.0 | :x:                |

## Reporting a Vulnerability

We take the security of Guardrail seriously. If you have discovered a security vulnerability in our project, we appreciate your help in disclosing it to us in a responsible manner.

### Reporting Process

1. **DO NOT** create a public GitHub issue for security vulnerabilities
2. Use GitHub's private vulnerability reporting:
   - Go to the Security tab in this repository
   - Click "Report a vulnerability"
   - Fill out the security advisory form
3. Include the following information:
   - Type of vulnerability
   - Full paths of affected source files
   - Steps to reproduce the vulnerability
   - Proof-of-concept or exploit code (if possible)
   - Impact assessment

### Response Timeline

- **Initial Response**: Within 48 hours
- **Status Update**: Within 5 business days
- **Resolution Target**: Based on severity (see below)

### Severity Levels and Response Times

| Severity | Description | Resolution Target |
|----------|-------------|-------------------|
| Critical | Remote code execution, privilege escalation in Guardrail itself | 7 days |
| High | Information disclosure, denial of service | 14 days |
| Medium | Limited information disclosure, requires user interaction | 30 days |
| Low | Minor issues with limited impact | 60 days |

## Security Considerations for Guardrail Users

### Secure Usage Guidelines

1. **Kubeconfig Security**
   - Store kubeconfig files with restricted permissions (600)
   - Use separate kubeconfig files for different environments
   - Rotate credentials regularly
   - Never commit kubeconfig files to version control

2. **RBAC Analysis Results**
   - Treat analysis reports as sensitive information
   - Reports may contain details about your cluster's security posture
   - Store reports in secure locations with appropriate access controls
   - Sanitize reports before sharing externally

3. **Integration Security**
   - When using Guardrail in CI/CD pipelines, use secure credential storage
   - Implement least-privilege access for automation accounts
   - Use temporary credentials where possible
   - Audit automation logs regularly

### Security Best Practices

1. **Input Validation**
   - Guardrail validates all YAML input to prevent injection attacks
   - Only process RBAC manifests from trusted sources
   - Review manifests before analysis

2. **Cluster Access**
   - Use read-only service accounts for live cluster analysis
   - Implement network policies to restrict cluster access
   - Enable audit logging for Guardrail operations

3. **Output Handling**
   - Be cautious when sharing JSON/SARIF reports
   - Reports may reveal security weaknesses
   - Consider redacting sensitive namespace/resource names

## Security Features

### Built-in Security Measures

1. **Read-Only Operations**
   - Guardrail only performs read operations on clusters
   - No write permissions required or used
   - Cannot modify RBAC configurations

2. **Local Analysis**
   - File-based analysis runs entirely locally
   - No data sent to external services
   - All processing happens on your machine

3. **Secure Defaults**
   - Conservative risk assessments
   - Highlights potential privilege escalation paths
   - Warns about overly permissive configurations

### Security-Focused Design

1. **Minimal Permissions**
   - Requires only RBAC read permissions for cluster analysis
   - No cluster-admin access needed
   - Works with view-only service accounts

2. **Dependency Security**
   - Regular dependency updates
   - Automated vulnerability scanning in CI
   - Uses official Kubernetes client libraries

3. **Code Security**
   - Static analysis with gosec
   - Regular security audits
   - Input sanitization for all user inputs

## Development Security Practices

### For Contributors

1. **Code Review Requirements**
   - All PRs require security-conscious review
   - Look for potential security issues
   - Verify input validation

2. **Testing Security**
   - Include security test cases
   - Test with malformed inputs
   - Verify error handling doesn't leak information

3. **Dependency Management**
   - Run `go mod tidy` regularly
   - Check for vulnerable dependencies
   - Update dependencies promptly

### Security Checklist for PRs

- [ ] No hardcoded credentials or secrets
- [ ] Proper input validation added
- [ ] Error messages don't expose sensitive information
- [ ] No new external network calls
- [ ] Documentation updated for security implications
- [ ] Tests include negative/malicious input cases

## Vulnerability Disclosure Policy

We follow responsible disclosure practices:

1. Security issues are fixed in private
2. Patches are released with minimal details
3. Full disclosure after 30 days or when majority of users have updated
4. Credit given to reporters (unless they prefer anonymity)

## Security Audits

- Automated security scanning on every commit
- Quarterly dependency vulnerability reviews
- Annual third-party security assessment (planned)

## Contact

For security concerns:
- **Preferred**: Use GitHub's private vulnerability reporting feature (Security → Report a vulnerability)
- **Alternative**: Create a security advisory on GitHub (for maintainers with repository access)

## Acknowledgments

We thank the following researchers for responsibly disclosing security issues:
- (List will be updated as issues are reported and fixed)

---

This security policy is adapted from best practices in the Kubernetes ecosystem and follows CNCF security guidelines.