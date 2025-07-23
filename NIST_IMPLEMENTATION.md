# NIST SP 800-190 RBAC Rules Implementation

This document summarizes the implementation of NIST SP 800-190 based RBAC security rules in Guardrail.

## What Was Added

### 10 New Security Rules

All rules are based on NIST SP 800-190 "Application Container Security Guide" recommendations:

1. **RBAC005**: Avoid Service Account Token Automounting (Medium)
2. **RBAC006**: Restrict Exec and Attach Permissions (High)
3. **RBAC007**: Limit Impersonation Privileges (High)
4. **RBAC008**: Restrict Escalate and Bind Verbs (High)
5. **RBAC009**: Audit Privileged Container Access (High)
6. **RBAC010**: Restrict Node and PersistentVolume Access (Medium)
7. **RBAC011**: Limit Webhook Configuration Access (High)
8. **RBAC012**: Restrict CRD and APIService Modifications (High)
9. **RBAC013**: Separate Concerns with Namespace Isolation (Medium)
10. **RBAC014**: Restrict TokenRequest and CertificateSigningRequest (High)

### Files Created/Modified

1. **pkg/validator/validator.go**
   - Updated `defaultRules()` to include all 14 rules (4 original + 10 NIST)
   
2. **pkg/validator/nist_rules.go** (new)
   - Contains all NIST-based validation functions
   - Clean separation of concerns from original rules

3. **pkg/validator/validator_nist_test.go** (new)
   - Comprehensive tests for all new validation rules
   - Tests cover positive and negative cases

4. **pkg/validator/validator_test.go**
   - Updated to expect 14 default rules instead of 4

5. **testdata/nist-violations.yaml** (new)
   - Example RBAC configurations that violate NIST guidelines
   - Useful for testing and demonstration

6. **docs/nist-rules.md** (new)
   - Comprehensive documentation for all NIST rules
   - Includes detection criteria and remediation guidance

## Testing

Run the validator against the NIST violations example:

```bash
# Build the binary
go build -o guardrail ./cmd/guardrail/...

# Validate NIST violations
./guardrail validate -f testdata/nist-violations.yaml

# Run with JSON output
./guardrail validate -f testdata/nist-violations.yaml -o json

# Run analyzer for risk assessment
./guardrail analyze -f testdata/nist-violations.yaml
```

## Example Output

When validating the `nist-violations.yaml` file, Guardrail now detects:
- Service accounts bound to high-privilege roles
- Exec/attach permissions that could be abused
- Impersonation capabilities
- Privilege escalation risks
- Webhook configuration access
- And many more security issues

Total: 41 issues found (31 High, 8 Medium, 2 Low severity)

## Benefits

1. **Comprehensive Coverage**: Now covers major RBAC security risks identified by NIST
2. **Clear Remediation**: Each rule provides specific remediation guidance
3. **Risk-Based**: Severity levels help prioritize fixes
4. **Standards Compliance**: Helps organizations meet NIST SP 800-190 requirements
5. **Prevention**: Catches security issues before they reach production

## Future Enhancements

Consider adding:
- Integration with admission controllers
- Automated remediation suggestions
- Policy-as-code templates
- Integration with CI/CD pipelines
- Custom rule definitions via configuration