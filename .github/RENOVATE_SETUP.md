# Renovate Setup Guide

This project uses [Renovate](https://docs.renovatebot.com/) for automated dependency management instead of Dependabot. Renovate provides more advanced features and better customization options.

## Configuration

The main configuration is in [`renovate.json`](../renovate.json) which includes:

### Features Enabled
- **Dependency Dashboard**: Creates and maintains an issue with all pending updates
- **Semantic Commits**: Uses conventional commit format
- **Security Updates**: Prioritizes security vulnerabilities
- **Grouped Updates**: Groups related dependencies together
- **Auto-merge**: Automatically merges trusted patch updates
- **Vulnerability Alerts**: Integrates with GitHub security advisories

### Package Rules

#### Go Modules
- Groups all Go module updates together
- Runs `go mod tidy` after updates
- Updates import paths when needed
- 3-day minimum release age for stability

#### Kubernetes Dependencies
- Groups k8s.io and sigs.k8s.io packages
- Separate handling due to synchronized releases

#### GitHub Actions
- Groups all GitHub Actions updates
- Pins action digests for security
- Auto-merges patch updates

#### Docker
- Pins base image digests
- 3-day minimum release age

### Security
- **OSV Vulnerability Alerts**: Enabled
- **OpenSSF Scorecard**: Checks package security scores
- **Digest Pinning**: For Docker images and GitHub Actions
- **Priority Handling**: Security updates get highest priority

## Setup Instructions

### 1. Install Renovate GitHub App

Visit [GitHub Apps - Renovate](https://github.com/apps/renovate) and install it on your repository.

### 2. Configure Repository Secrets (Optional)

For the self-hosted workflow, you can add these secrets:

- `RENOVATE_TOKEN`: GitHub personal access token with `repo` and `workflow` scopes

### 3. Repository Settings

#### Branch Protection
Ensure your main branch has these protection rules:
- Require status checks to pass before merging
- Require branches to be up to date before merging
- Include the CI workflow in required status checks

#### Auto-merge Setup
To enable auto-merge for trusted updates:
1. Go to Settings → General → Pull Requests
2. Enable "Allow auto-merge"
3. Set "Automatically delete head branches"

### 4. Customization

#### Schedule
Currently set to run Monday mornings. Modify in `renovate.json`:
```json
{
  "schedule": ["before 4am on monday"]
}
```

#### Auto-merge Rules
Add packages to auto-merge list:
```json
{
  "packageRules": [
    {
      "matchPackagePatterns": ["your-trusted-package/*"],
      "automerge": true
    }
  ]
}
```

#### Assignees/Reviewers
Update in `renovate.json`:
```json
{
  "assignees": ["your-username"],
  "reviewers": ["your-username"]
}
```

## Monitoring

### Dependency Dashboard
Renovate creates a "Dependency Dashboard" issue that shows:
- Pending updates
- Rate-limited PRs
- Error logs
- Configuration warnings

### Logs
Check the Actions tab for Renovate workflow runs to see detailed logs.

### Metrics
Renovate provides metrics on:
- Update frequency
- Time to merge
- Security update response time

## Comparison with Dependabot

| Feature | Renovate | Dependabot |
|---------|----------|------------|
| Language Support | 60+ | 20+ |
| Scheduling | Flexible | Limited |
| Grouping | Advanced | Basic |
| Auto-merge | Conditional | Yes/No |
| Security Focus | High | Medium |
| Customization | Extensive | Limited |
| Self-hosted | Yes | No |

## Troubleshooting

### Common Issues

1. **Rate Limiting**: Renovate respects GitHub API limits
2. **Large PRs**: Configure grouping to reduce PR count
3. **Failed Updates**: Check logs in Dependency Dashboard issue

### Debug Mode
Enable debug logging by setting `LOG_LEVEL: debug` in the workflow.

### Validation
The configuration is automatically validated on every push using the `renovate.yml` workflow.

## Best Practices

1. **Start Conservative**: Begin with fewer auto-merge rules
2. **Monitor Dashboard**: Check the dependency dashboard regularly
3. **Review Major Updates**: Always manually review major version updates
4. **Test Thoroughly**: Ensure CI passes before merging
5. **Security First**: Prioritize security updates over feature updates

## Resources

- [Renovate Documentation](https://docs.renovatebot.com/)
- [Configuration Options](https://docs.renovatebot.com/configuration-options/)
- [Preset Configs](https://docs.renovatebot.com/presets/)
- [Migration Guide](https://docs.renovatebot.com/migration/)