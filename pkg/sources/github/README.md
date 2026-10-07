# GitHub Source

## Overview

The GitHub source lets TruffleHog scan GitHub repositories, gists, wikis, issues, pull requests, and their comments for secrets, credentials, and sensitive data. It uses the GitHub API to find repositories, then clones and scans each one with the git source underneath.

## GitHub Fundamentals

### What does this source scan?

This source finds repositories through the GitHub API (by organization, user, or an explicit list), then clones and scans each repository the same way the git source does. On top of that, it can also scan a repository's wiki, and the text of issues, pull requests, gists, and their comments through the API directly.

### Key GitHub Terminology

| Term | Description |
|------|-------------|
| **Organization** | A GitHub account that holds repositories owned by a team or company |
| **Repository** | A single project, holding its git history |
| **Fork** | A copy of another repository, made under a different owner |
| **Gist** | A small, standalone snippet of code or text, with its own git history |
| **GitHub App** | An identity registered with GitHub that can be installed into an organization or account to access its repositories |
| **Installation** | A GitHub App added to a specific organization or account, with access scoped to that installation |
| **GitHub Enterprise Server (GHES)** | A self hosted copy of GitHub, running on the customer's own infrastructure |
| **GHE.com** | GitHub Enterprise Cloud with data residency, hosted by GitHub on a dedicated subdomain |

## Features

- **Multiple Authentication Methods**: Personal access token, GitHub App, username and password, or unauthenticated for public repositories
- **Multiple Scan Targets**: Scan by organization, by user, or by an explicit list of repositories
- **Repository Filtering**: Include or exclude repositories in an organization or user scan using glob patterns, exclude forks and archived repositories
- **Comment Scanning**: Optionally scan issue, pull request, and gist comments, limited to a number of past days if needed
- **Wiki Scanning**: Optionally scan a repository's wiki alongside its code
- **Self Hosted Support**: Works with GitHub Enterprise Server and GHE.com in addition to github.com
- **Concurrent Processing**: Repositories are cloned and scanned in parallel across a configurable number of workers

## Configuration

### Authentication Methods

#### 1. Personal Access Token

**CLI Usage:**
```bash
trufflehog github --org my-org --token ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

**YAML Configuration:**
```yaml
sources:
- connection:
    '@type': type.googleapis.com/sources.GitHub
    organizations:
    - my-org
    token: "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
  name: github-scan
  type: SOURCE_TYPE_GITHUB
  verify: true
```

On the CLI, the token can also be set with the `GITHUB_TOKEN` environment variable instead of `--token`. This does not apply to a YAML config file, since TruffleHog does not read environment variables while loading YAML. Without a token, the CLI falls back to an unauthenticated scan.

---

#### 2. GitHub App

Uses a GitHub App installed into an organization or account. This method is only available in the YAML config, not the CLI.

**YAML Configuration:**
```yaml
sources:
- connection:
    '@type': type.googleapis.com/sources.GitHub
    organizations:
    - my-org
    github_app:
      app_id: "123456"
      installation_id: "789012"
      private_key: |
        -----BEGIN RSA PRIVATE KEY-----
        ...
        -----END RSA PRIVATE KEY-----
  name: github-scan
  type: SOURCE_TYPE_GITHUB
  verify: true
```

Set `scan_all_installations: true` to scan every organization and account the app is installed into, instead of a single `installation_id`. Some things still need a fallback installation even with `scan_all_installations` set, such as gists, scanning organization members, or repositories that no installation listing owns. Keep `installation_id` set alongside `scan_all_installations` if you use any of those, otherwise they are skipped with a log message instead of failing the scan.

---

#### 3. Username and Password

This method is only available in the YAML config, not the CLI.

**YAML Configuration:**
```yaml
sources:
- connection:
    '@type': type.googleapis.com/sources.GitHub
    organizations:
    - my-org
    basic_auth:
      username: my-username
      password: my-password
  name: github-scan
  type: SOURCE_TYPE_GITHUB
  verify: true
```

---

#### 4. Unauthenticated

Only works for public repositories, and is heavily rate limited by GitHub.

**CLI Usage:**
```bash
trufflehog github --org my-org
```

**YAML Configuration:**
```yaml
sources:
- connection:
    '@type': type.googleapis.com/sources.GitHub
    organizations:
    - my-org
    unauthenticated: {}
  name: github-scan
  type: SOURCE_TYPE_GITHUB
  verify: true
```

### Choosing What to Scan

On the CLI, exactly one of `--org` or `--repo` must be given, the CLI rejects both together. A YAML config file does not have this restriction: `organizations` and `repositories` can both be set at once, and the source scans the explicit repositories plus whatever the organizations enumerate.

**Scan an Organization or User**

```bash
trufflehog github --org my-org --token ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

The same flag works for a user account, since the source tries an organization lookup first and falls back to a user lookup if that fails.

**Scan Specific Repositories**

```bash
trufflehog github --repo https://github.com/my-org/my-repo --token ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

`--repo` can be repeated. When repositories are given directly, they bypass `--include-repos` and `--exclude-repos` entirely, since those filters only apply to repositories found through an organization or user scan.

### Filtering What Gets Scanned

**Include or Exclude Repositories**

Only applies to an organization or user scan, and cannot be combined with `--repo`.

```bash
trufflehog github --org my-org --token ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx --include-repos "my-org/prod-*"
```

```bash
trufflehog github --org my-org --token ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx --exclude-repos "my-org/test-*"
```

**Include Forks**

Forks are excluded by default.

```bash
trufflehog github --org my-org --token ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx --include-forks
```

**Exclude Archived Repositories**

```bash
trufflehog github --org my-org --token ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx --exclude-archived
```

**Include or Exclude Files**

Both flags take a path to a file that holds one regex per line. Blank lines and lines starting with `#` are ignored.

```bash
trufflehog github --org my-org --token ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx --include-paths include-patterns.txt
```

```bash
trufflehog github --org my-org --token ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx --exclude-paths exclude-patterns.txt
```

**Number of Workers**

There is no GitHub specific flag for this. Use TruffleHog's global `--concurrency` flag to set how many repositories are cloned and scanned at the same time.

```bash
trufflehog github --org my-org --token ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx --concurrency 10
```

### Scanning Comments and Wikis

**Issue and Pull Request Comments**

```bash
trufflehog github --org my-org --token ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx --issue-comments --pr-comments
```

**Gist Comments**

```bash
trufflehog github --org my-org --token ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx --gist-comments
```

**Limit Comments to Recent Days**

```bash
trufflehog github --org my-org --token ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx --issue-comments --comments-timeframe 30
```

**Repository Wikis**

```bash
trufflehog github --org my-org --token ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx --include-wikis
```

**Scan Organization Members**

Also scans the personal repositories and gists of every member of a scanned organization.

```bash
trufflehog github --org my-org --token ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx --include-members
```

**Ignore Gists**

Gists are only fetched for a user account, not a genuine organization: when `--org` is a username rather than an organization name, when scanning the token owner's own account, or when `--include-members` finds a member. They are included by default in those cases. This flag turns that off.

```bash
trufflehog github --org my-org --token ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx --ignore-gists
```

### Self Hosted GitHub

Point at a GitHub Enterprise Server or GHE.com instance instead of github.com.

```bash
trufflehog github --org my-org --token ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx --endpoint https://github.mycompany.com
```

### Clone Location and Cleanup

By default, each repository is cloned into a temporary directory and deleted after scanning. `--clone-path` clones into a given directory instead, and `--no-cleanup` (only valid together with `--clone-path`) keeps the clones on disk afterward instead of deleting them.

```bash
trufflehog github --org my-org --token ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx --clone-path /path/to/clones --no-cleanup
```

With `--clone-path` set, each repository still gets its own fresh subdirectory created inside it (named `trufflehog-<repo-name>-...`), TruffleHog never clones into `--clone-path` itself. Without `--no-cleanup`, that subdirectory is deleted after the repository is scanned, but `--clone-path` itself and anything else already in it is left alone.

## How Scanning Works

### Scanning Process

1. **Enumeration**: Depending on the auth method and target, lists repositories from the given organizations, users, or the explicit repository list, applying the include, exclude, fork, and archived filters
2. **Repository Cloning**: Clones each enumerated repository using the git source, the same way the git source scans a remote repository
3. **Commit Scanning**: Scans every commit in the clone for secrets, the same way the git source does
4. **Wiki Scanning**: If `--include-wikis` is set and a repository has a wiki, clones and scans the wiki as its own repository
5. **Comment Scanning**: If any comment flags are set, fetches issues, pull requests, or gist comments through the GitHub API and scans their text
6. **Progress Tracking**: Keeps track of which repositories have already been scanned, so a scan can be resumed without redoing work

### What Gets Scanned

- Every commit in every repository matching the scan target and filters
- Wiki commits, when `--include-wikis` is set and the repository has a wiki
- Issue, pull request, and gist text and comments, when the corresponding flags are set

### What Doesn't Get Scanned

- Forked repositories, unless `--include-forks` is set
- Archived repositories, when `--exclude-archived` is set
- Repositories excluded by `--include-repos` or `--exclude-repos`, for an organization or user scan
- Gists, when `--ignore-gists` is set, or when the scan target is a genuine organization rather than a user (gists only surface for user accounts, see the note above)
- Comments older than the configured comments timeframe, when one is set

## Usage Examples

### Scanning an Organization

```bash
trufflehog github --org my-org --token ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

### Scanning Specific Repositories

```bash
trufflehog github --repo https://github.com/my-org/repo-one --repo https://github.com/my-org/repo-two --token ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

### Scanning an Organization Including Comments and Wikis

```bash
trufflehog github --org my-org --token ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx --issue-comments --pr-comments --include-wikis
```

### Scanning a Public Repository Without Authentication

```bash
trufflehog github --repo https://github.com/my-org/public-repo
```

### Scanning GitHub Enterprise Server

```bash
trufflehog github --org my-org --token ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx --endpoint https://github.mycompany.com
```

## Troubleshooting

### Common Issues

**Issue**: Authentication failures when connecting to GitHub
**Solution**: Check that the token, GitHub App credentials, or username and password are correct and have permission to read the target repositories.

---

**Issue**: `invalid config: you must specify at least one organization or repository`
**Solution**: Pass either `--org` or `--repo`, exactly one of the two.

---

**Issue**: `invalid config: --include-repos and --exclude-repos only apply to organization or user scans and cannot be used with --repo`
**Solution**: These filters only affect repositories discovered through an organization or user scan. Remove `--repo` or remove the include and exclude filters.

---

**Issue**: Rate limiting during a large scan
**Solution**: Use an authenticated token or GitHub App instead of an unauthenticated scan, since unauthenticated requests have a much lower rate limit.

---

**Issue**: A repository's wiki is not scanned even with `--include-wikis`
**Solution**: GitHub's API can report that a repository has a wiki even when it does not. TruffleHog ignores a wiki clone that comes back as not found.
