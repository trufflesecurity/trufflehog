# GitHub Workflows

This directory contains GitHub Actions workflows for the TruffleHog repository.

## PR Approval Check (`pr-approval-check.yml`)

This workflow enforces that at least one PR approver must be an **active** member of the `@trufflesecurity/product-eng` team or any of its child teams.

### How it works:

1. **Triggers**: The workflow runs on:
   - `pull_request_review` events when a review is submitted (`submitted` type)
   - `pull_request` events when a PR is opened, reopened, or synchronized (`opened`, `reopened`, `synchronize` types)

2. **Approval Check Process**: The workflow:
   - Fetches all reviews for the PR using the GitHub API
   - Filters for reviews with state `APPROVED`
   - Gets all child teams of `@trufflesecurity/product-eng` using `listChildInOrg` API
   - Checks if any approver is an **active** member (not pending) of either:
     - The parent `@trufflesecurity/product-eng` team, OR
     - Any of its child teams
   - Sets a commit status accordingly

3. **Status Check**: Creates a commit status named `product-eng-approval` with:
   - ✅ **Success**: When at least one approver is an active member of `@trufflesecurity/product-eng` or any child team
   - ❌ **Failure**: When there are no approvals or there are approvals but none from active `@trufflesecurity/product-eng` members

### Error Handling

If there are errors listing reviews or checking team membership, the workflow reports a failure status and also fails itself.

### Branch Protection

To make this check required:

1. Go to Settings → Branches
2. Add or edit a branch protection rule for your main branch
3. Enable "Require status checks to pass before merging"
4. Add `pr-approval-check` to the required status checks

### Permissions

The workflow uses the default `GITHUB_TOKEN` which has sufficient permissions to:
- Read PR reviews
- List child teams and check team membership (for public teams)
- Create commit statuses

**Note**: If the `product-eng` team or its child teams are private, you may need to use a personal access token with appropriate permissions. The Github API returns 404 for non-members and for lack of permissions.