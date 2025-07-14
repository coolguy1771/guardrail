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
	@go test -v ./...

# Run tests with coverage
test-coverage:
	@echo "Running tests with coverage..."
	@go test -coverprofile=coverage.out ./...
	@go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

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
	@echo "  build         - Build the binary"
	@echo "  install       - Install the binary using go install"
	@echo "  test          - Run tests"
	@echo "  test-coverage - Run tests with coverage report"
	@echo "  lint          - Run linter (requires golangci-lint)"
	@echo "  fmt           - Format code"
	@echo "  tidy          - Tidy go.mod dependencies"
	@echo "  clean         - Remove build artifacts"
	@echo "  run-example   - Run guardrail on test data"
	@echo "  pre-commit    - Run all checks (fmt, tidy, lint, test)"
	@echo "  help          - Display this help message"