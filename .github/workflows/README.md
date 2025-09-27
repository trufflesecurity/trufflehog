# GitHub Workflows

This directory contains GitHub Actions workflows for the TruffleHog repository.

## PR Approval Check (`pr-approval-check.yml`)

This workflow enforces that at least one PR approver must be a member of the `@trufflesecurity/product-eng` team or any of its child teams.

### How it works:

1. **Triggers**: The workflow runs on:
   - `pull_request_review` events when a review is submitted
   - `pull_request` events when a PR is opened, reopened, or synchronized

2. **Approval Check**: The workflow:
   - Fetches all reviews for the PR
   - Filters for approved reviews
   - Gets all child teams of `@trufflesecurity/product-eng` 
   - Checks if any approver is an active member of the parent team or any child team
   - Sets a commit status accordingly

3. **Status Check**: Creates a commit status named `product-eng-approval` with:
   - ✅ **Success**: When at least one approver is a `@trufflesecurity/product-eng` or child team member
   - ❌ **Failure**: When no `@trufflesecurity/product-eng` or child team members have approved
   - ⏳ **Pending**: When waiting for reviews

### Branch Protection

To make this check required:

1. Go to Settings → Branches
2. Add or edit a branch protection rule for your main branch
3. Enable "Require status checks to pass before merging"
4. Add `product-eng-approval` to the required status checks

### Permissions

The workflow uses the default `GITHUB_TOKEN` which has sufficient permissions to:
- Read PR reviews
- Check team membership (for public teams)
- Create commit statuses

**Note**: If the `product-eng` team or its child teams are private, you may need to use a personal access token with appropriate permissions.