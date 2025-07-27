# Guardrail

Guardrail is a Golang-based Kubernetes RBAC validation tool that helps teams maintain secure, compliant, and well-structured RBAC configurations.

## Features

* **YAML Parsing**: Easily parses Kubernetes RBAC YAML manifests.
* **Policy Enforcement**: Validates RBAC definitions against configurable security and compliance rules.
* **Reporting**: Provides clear, actionable reports in both CLI and JSON formats.
* **Kubernetes Integration**: Optionally fetches live RBAC definitions directly from Kubernetes clusters.

## Quick Start

### Installation

```bash
go install github.com/coolguy1771/guardrail/cmd/guardrail@latest
```

### Usage

Validate a single RBAC manifest file:

```bash
guardrail validate -f path/to/role.yaml
```

Validate a directory containing RBAC manifests:

```bash
guardrail validate -d path/to/manifests/
```

Output validation results in JSON format:

```bash
guardrail validate -f path/to/role.yaml -o json
```

Output validation results in SARIF format:

```bash
guardrail validate -f path/to/role.yaml -o sairf
```

## Project Structure

* `cmd/`: Entry point for the CLI application.
* `pkg/`: Core functionality, including YAML parsing, validation logic, reporting, and Kubernetes integration.
* `configs/`: Default and customizable rule definitions.
* `testdata/`: Example YAML files for testing.

## Contributing

Contributions are welcome! Please open issues and submit pull requests with any improvements or features you'd like to see.

## License

[Apache 2.0 License](LICENSE)
