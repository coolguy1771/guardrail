.PHONY: build test clean install lint

# Variables
BINARY_NAME=guardrail
BINARY_PATH=./build/$(BINARY_NAME)
CMD_PATH=./cmd/guardrail
GO_FILES=$(shell find . -name '*.go' -type f)

# Build the binary
build:
	@echo "Building $(BINARY_NAME)..."
	@mkdir -p build
	@go build -o $(BINARY_PATH) $(CMD_PATH)
	@echo "Build complete: $(BINARY_PATH)"

# Install the binary
install:
	@echo "Installing $(BINARY_NAME)..."
	@go install $(CMD_PATH)
	@echo "Installation complete"

# Run tests
test:
	@echo "Running tests..."
	@go test -v -race -covermode=atomic ./...

# Run tests with coverage
test-coverage:
	@echo "Running tests with coverage..."
	@go test -v -race -coverprofile=coverage.out -covermode=atomic ./...
	@go tool cover -html=coverage.out -o coverage.html
	@go tool cover -func=coverage.out | tail -n 1
	@echo "Coverage report generated: coverage.html"

# Check coverage with cov
cov:
	@echo "Checking coverage with cov..."
	@go test -coverprofile=coverage.out ./... > /dev/null 2>&1
	@if command -v cov &> /dev/null; then \
		cov --threshold 70 coverage.out; \
	else \
		echo "cov not installed. Install with: go install github.com/PaloAltoNetworks/cov@latest"; \
		exit 1; \
	fi

# Check coverage for PR changes
cov-pr:
	@echo "Checking PR coverage..."
	@go test -coverprofile=coverage.out ./... > /dev/null 2>&1
	@if command -v cov &> /dev/null; then \
		cov --branch main --threshold 80 coverage.out; \
	else \
		echo "cov not installed. Install with: go install github.com/PaloAltoNetworks/cov@latest"; \
		exit 1; \
	fi

# Run integration tests
test-integration:
	@echo "Running integration tests..."
	@./scripts/integration-test.sh

# Run benchmarks
test-bench:
	@echo "Running benchmarks..."
	@go test -bench=. -benchmem ./... | tee benchmark.txt

# Run specific test
test-pkg:
	@echo "Running tests for package $(PKG)..."
	@go test -v -race ./pkg/$(PKG)/...

# Run linter
lint:
	@echo "Running linter..."
	@if command -v golangci-lint &> /dev/null; then \
		golangci-lint run; \
	else \
		echo "golangci-lint not installed. Install with: go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest"; \
	fi

# Format code
fmt:
	@echo "Formatting code..."
	@go fmt ./...

# Tidy dependencies
tidy:
	@echo "Tidying dependencies..."
	@go mod tidy

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	@rm -rf build/
	@rm -f coverage.out coverage.html
	@echo "Clean complete"

# Run the tool with example files
run-example:
	@echo "Running guardrail on example files..."
	@go run $(CMD_PATH) validate -d testdata/

# Run all checks before commit
pre-commit: fmt tidy lint test
	@echo "All pre-commit checks passed!"

# Display help
help:
	@echo "Available targets:"
	@echo "  build              - Build the binary"
	@echo "  install            - Install the binary using go install"
	@echo "  test               - Run tests with race detection"
	@echo "  test-coverage      - Run tests with coverage report"
	@echo "  test-integration   - Run integration tests"
	@echo "  test-bench         - Run benchmarks"
	@echo "  test-pkg PKG=name  - Run tests for specific package"
	@echo "  cov                - Check coverage with cov (70% threshold)"
	@echo "  cov-pr             - Check PR coverage with cov (80% threshold)"
	@echo "  lint               - Run linter (requires golangci-lint)"
	@echo "  fmt                - Format code"
	@echo "  tidy               - Tidy go.mod dependencies"
	@echo "  clean              - Remove build artifacts"
	@echo "  run-example        - Run guardrail on test data"
	@echo "  pre-commit         - Run all checks (fmt, tidy, lint, test)"
	@echo "  help               - Display this help message"