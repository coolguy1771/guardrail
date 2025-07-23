# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Guardrail is a Kubernetes RBAC validation and analysis tool written in Go. It helps teams maintain secure, compliant RBAC configurations by detecting dangerous permissions, analyzing security risks, and providing actionable insights.

## Common Development Commands

### Building and Running
```bash
make build                 # Build binary to ./build/guardrail
make install              # Install binary using go install
make run-example          # Test with example files in testdata/
```

### Testing
```bash
make test                 # Run all tests with race detection
make test-coverage        # Generate coverage report (opens coverage.html)
go test -v ./pkg/analyzer/   # Test specific package
go test -v -run TestFunctionName ./pkg/validator/  # Run specific test
```

### Code Quality
```bash
make lint                 # Run golangci-lint (must be installed)
make fmt                  # Format all Go code
make pre-commit           # Run all checks before committing (fmt, tidy, lint, test)
```

## Architecture Overview

### Package Structure
- **cmd/guardrail/** - CLI commands using Cobra framework
  - `validate` command: Validates RBAC manifests against security policies
  - `analyze` command: Provides human-readable RBAC permission analysis
  
- **pkg/** - Core business logic
  - `analyzer/`: RBAC analysis engine with risk assessment and permission mapping
  - `validator/`: Policy validation rules for detecting dangerous permissions
  - `parser/`: YAML manifest parsing and RBAC object extraction
  - `reporter/`: Multi-format output (text, JSON, SARIF)
  - `kubernetes/`: Kubernetes client integration for live cluster analysis

### Key Design Patterns
1. **Command Pattern**: Cobra CLI with subcommands for different operations
2. **Strategy Pattern**: Reporter interface for pluggable output formats
3. **Factory Pattern**: Kubernetes client creation with context handling
4. **Validation Pipeline**: Parser → Validator/Analyzer → Reporter

### RBAC Analysis Architecture
The analyzer package implements a sophisticated permission analysis system:
- Maps RBAC rules to human-readable explanations
- Calculates risk levels (Critical/High/Medium/Low) based on permission scope
- Detects privilege escalation paths (bind, escalate, impersonate verbs)
- Supports both file-based and live cluster analysis

### Important Implementation Details
- Uses official Kubernetes client-go libraries (v0.33.2)
- Supports multiple kubeconfig contexts
- Handles both namespaced and cluster-scoped resources
- Risk assessment considers wildcards, admin permissions, and sensitive resources
- SARIF output enables integration with security scanning tools

## Testing Strategy
- Unit tests for each package with table-driven test patterns
- Integration tests using example RBAC manifests in testdata/
- CI runs tests on multiple OS (Linux, macOS, Windows) and Go versions (1.23, 1.24)
- Race detection enabled by default in tests

## Current Development Focus
The `feat/analyzer` branch adds comprehensive RBAC analysis capabilities with:
- Human-readable permission explanations
- Risk-based security assessment
- Subject-focused permission mapping
- Enhanced privilege escalation detection