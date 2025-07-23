#!/bin/bash

# Script to create GitHub labels for the guardrail repository

# Colors for different types of labels
COLOR_FEATURE="0e8a16"      # Green - feature/component labels
COLOR_CATEGORY="d93f0b"     # Red - category labels
COLOR_META="fbca04"         # Yellow - meta labels
COLOR_INFRA="1d76db"       # Blue - infrastructure labels
COLOR_LANG="f9d0c4"        # Light pink - language labels

echo "Creating GitHub labels for the guardrail repository..."

# Function to create a label
create_label() {
    local name=$1
    local color=$2
    local description=$3
    
    echo "Creating label: $name"
    gh label create "$name" --color "$color" --description "$description" --force || echo "Label $name already exists or error occurred"
}

# Create labels based on labeler.yml configuration

# Documentation
create_label "documentation" "$COLOR_CATEGORY" "Documentation changes"

# Language
create_label "go" "$COLOR_LANG" "Go source code changes"

# CLI/Features
create_label "cli" "$COLOR_FEATURE" "CLI/Command changes"
create_label "core" "$COLOR_FEATURE" "Core package changes"
create_label "analyzer" "$COLOR_FEATURE" "RBAC analyzer feature"
create_label "validator" "$COLOR_FEATURE" "RBAC validator feature"
create_label "kubernetes" "$COLOR_FEATURE" "Kubernetes integration"
create_label "parser" "$COLOR_FEATURE" "YAML/Manifest parser"
create_label "reporter" "$COLOR_FEATURE" "Output/Reporter changes"

# Development
create_label "test" "$COLOR_CATEGORY" "Test changes"
create_label "ci" "$COLOR_INFRA" "CI/CD changes"
create_label "docker" "$COLOR_INFRA" "Docker-related changes"
create_label "dependencies" "$COLOR_META" "Dependency updates"
create_label "renovate" "$COLOR_META" "Renovate bot updates"
create_label "config" "$COLOR_META" "Configuration changes"
create_label "security" "$COLOR_CATEGORY" "Security-related changes"
create_label "github" "$COLOR_INFRA" "GitHub-specific changes"
create_label "build" "$COLOR_INFRA" "Build/Release changes"
create_label "repo" "$COLOR_META" "Root repository files"

echo "Label creation complete!"